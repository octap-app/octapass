//! Wayland: the `org.freedesktop.portal.RemoteDesktop` portal. Each run opens a session asking for
//! the keyboard only; the desktop shows its own permission dialog the first time, and the restore
//! token it returns (kept in memory, never on disk) skips the dialog for the rest of the app's run.
//! Keystrokes are keysyms, so any character types. The session closes when typing ends.
//!
//! Wayland doesn't tell apps which window is focused, so this platform answers `None` and the
//! engine types only what the user picked in the quick-access window.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

use super::lock;
use crate::engine::{Backend, Permission, Platform, PlatformError, PlatformResult};
use crate::keysym;
use crate::sequence::Key;
use crate::window::FocusedWindow;

const PORTAL: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const REMOTE_DESKTOP: &str = "org.freedesktop.portal.RemoteDesktop";
const KEYBOARD: u32 = 1;
/// Keep the permission until the user revokes it, so the restore token works (portal version 2).
const PERSIST_UNTIL_REVOKED: u32 = 2;
const PRESSED: u32 = 1;
const RELEASED: u32 = 0;

pub struct PortalPlatform {
    bus: Option<Connection>,
    session: Mutex<Option<OwnedObjectPath>>,
    restore_token: Mutex<Option<String>>,
    tokens: AtomicU32,
}

fn bus_error(error: zbus::Error) -> PlatformError {
    PlatformError(format!("the RemoteDesktop portal: {error}"))
}

impl PortalPlatform {
    pub fn new() -> Self {
        let bus = Connection::session().ok().filter(keyboard_available);
        Self {
            bus,
            session: Mutex::new(None),
            restore_token: Mutex::new(None),
            tokens: AtomicU32::new(0),
        }
    }

    /// No display server we can type into: the app copies instead.
    pub fn unavailable() -> Self {
        Self {
            bus: None,
            session: Mutex::new(None),
            restore_token: Mutex::new(None),
            tokens: AtomicU32::new(0),
        }
    }

    fn bus(&self) -> PlatformResult<&Connection> {
        self.bus
            .as_ref()
            .ok_or_else(|| PlatformError("the RemoteDesktop portal isn't available".into()))
    }

    fn portal(&self) -> PlatformResult<Proxy<'_>> {
        Proxy::new(self.bus()?, PORTAL, PORTAL_PATH, REMOTE_DESKTOP).map_err(bus_error)
    }

    /// Calls a portal method that answers through a `Request` object's `Response` signal.
    fn request(
        &self,
        method: &str,
        session: Option<&ObjectPath<'_>>,
        mut options: HashMap<&str, Value<'_>>,
    ) -> PlatformResult<HashMap<String, OwnedValue>> {
        let bus = self.bus()?;
        let token = format!("octapass{}", self.tokens.fetch_add(1, Ordering::Relaxed));
        let sender = bus
            .unique_name()
            .map(|name| name.trim_start_matches(':').replace('.', "_"))
            .ok_or_else(|| PlatformError("no D-Bus name".into()))?;
        let path = format!("{PORTAL_PATH}/request/{sender}/{token}");
        let request = Proxy::new(bus, PORTAL, path.as_str(), "org.freedesktop.portal.Request")
            .map_err(bus_error)?;
        // Subscribe before calling, or a fast answer is missed.
        let mut responses = request.receive_signal("Response").map_err(bus_error)?;
        options.insert("handle_token", Value::from(token.clone()));
        let portal = self.portal()?;
        match (method, session) {
            ("Start", Some(session)) => portal.call_method(method, &(session, "", options)),
            (_, Some(session)) => portal.call_method(method, &(session, options)),
            (_, None) => portal.call_method(method, &(options,)),
        }
        .map_err(bus_error)?;
        let response = responses
            .next()
            .ok_or_else(|| PlatformError("the portal didn't answer".into()))?;
        let (code, results): (u32, HashMap<String, OwnedValue>) =
            response.body().deserialize().map_err(bus_error)?;
        match code {
            0 => Ok(results),
            1 => Err(PlatformError("you didn't allow Octa Pass to type".into())),
            _ => Err(PlatformError(format!("the portal refused ({code})"))),
        }
    }

    fn open_session(&self) -> PlatformResult<OwnedObjectPath> {
        if let Some(session) = self
            .session
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
        {
            return Ok(session);
        }
        let created = self.request(
            "CreateSession",
            None,
            HashMap::from([("session_handle_token", Value::from("octapass"))]),
        )?;
        let session = created
            .get("session_handle")
            .and_then(|handle| String::try_from(handle.clone()).ok())
            .and_then(|handle| OwnedObjectPath::try_from(handle).ok())
            .ok_or_else(|| PlatformError("the portal didn't create a session".into()))?;

        let mut options = HashMap::from([
            ("types", Value::from(KEYBOARD)),
            ("persist_mode", Value::from(PERSIST_UNTIL_REVOKED)),
        ]);
        let token = self
            .restore_token
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(token) = &token {
            options.insert("restore_token", Value::from(token.as_str()));
        }
        self.request("SelectDevices", Some(&session), options)?;
        let started = self.request("Start", Some(&session), HashMap::new())?;
        let devices = started
            .get("devices")
            .and_then(|devices| u32::try_from(devices.clone()).ok())
            .unwrap_or(0);
        if devices & KEYBOARD == 0 {
            return Err(PlatformError(
                "you didn't allow Octa Pass to use the keyboard".into(),
            ));
        }
        if let Some(token) = started
            .get("restore_token")
            .and_then(|token| String::try_from(token.clone()).ok())
        {
            *self.restore_token.lock().unwrap_or_else(|p| p.into_inner()) = Some(token);
        }
        *self.session.lock().unwrap_or_else(|p| p.into_inner()) = Some(session.clone());
        Ok(session)
    }

    fn keysym(&self, sym: u32) -> PlatformResult<()> {
        let session = self.open_session()?;
        let portal = self.portal()?;
        for state in [PRESSED, RELEASED] {
            let options: HashMap<&str, Value<'_>> = HashMap::new();
            portal
                .call_method(
                    "NotifyKeyboardKeysym",
                    &(&session, options, sym as i32, state),
                )
                .map_err(bus_error)?;
        }
        Ok(())
    }
}

/// The portal is there and offers a keyboard.
fn keyboard_available(bus: &Connection) -> bool {
    Proxy::new(bus, PORTAL, PORTAL_PATH, REMOTE_DESKTOP)
        .and_then(|portal| portal.get_property::<u32>("AvailableDeviceTypes"))
        .is_ok_and(|types| types & KEYBOARD != 0)
}

impl Platform for PortalPlatform {
    fn backend(&self) -> Backend {
        if self.bus.is_some() {
            Backend::Portal
        } else {
            Backend::Clipboard
        }
    }

    fn permission(&self) -> Permission {
        Permission::Granted
    }

    fn screen_locked(&self) -> bool {
        lock::screen_locked()
    }

    fn focused_window(&self) -> PlatformResult<Option<FocusedWindow>> {
        Ok(None)
    }

    /// The compositor gives focus back when the quick-access window closes; apps can't ask.
    fn activate(&self, _: &FocusedWindow) -> PlatformResult<()> {
        Ok(())
    }

    fn modifiers_held(&self) -> bool {
        false
    }

    fn type_char(&self, c: char) -> PlatformResult<()> {
        self.keysym(keysym::for_char(c))
    }

    fn press(&self, key: Key) -> PlatformResult<()> {
        self.keysym(keysym::for_key(key))
    }

    fn finish(&self) {
        let Some(session) = self
            .session
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        else {
            return;
        };
        if let Ok(bus) = self.bus()
            && let Ok(proxy) = Proxy::new(
                bus,
                PORTAL,
                session.as_str(),
                "org.freedesktop.portal.Session",
            )
        {
            let _ = proxy.call_method("Close", &());
        }
    }
}
