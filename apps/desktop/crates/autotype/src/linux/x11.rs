//! X11: the focused window from `_NET_ACTIVE_WINDOW`, keystrokes through XTest. Characters are
//! typed by mapping their keysym to a spare keycode for a moment, as `xdotool` does, so any
//! Unicode character works on any layout. The spare keycodes
//! are put back to nothing in [`Platform::finish`].

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use x11rb::connection::{Connection, RequestConnection};
use x11rb::protocol::xproto::{
    AtomEnum, ClientMessageEvent, ConnectionExt as _, EventMask, KeyButMask, Keycode, Keysym,
    Window,
};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use super::lock;
use crate::engine::{Backend, Permission, Platform, PlatformError, PlatformResult};
use crate::keysym;
use crate::sequence::Key;
use crate::window::FocusedWindow;

x11rb::atom_manager! {
    Atoms: AtomsCookie {
        _NET_ACTIVE_WINDOW,
        _NET_WM_NAME,
        _NET_WM_PID,
        UTF8_STRING,
    }
}

const KEY_PRESS: u8 = 2;
const KEY_RELEASE: u8 = 3;
/// Lets the app read the key before its keycode is mapped to something else.
const REMAP_DELAY: Duration = Duration::from_millis(12);
const SCRATCH_KEYS: usize = 4;

struct Keyboard {
    min_keycode: Keycode,
    per_keycode: u8,
    /// Keysyms by keycode, from `min_keycode`.
    map: Vec<Keysym>,
    /// Keycodes with nothing on them, used in turn.
    scratch: Vec<Keycode>,
    next: usize,
    remapped: bool,
}

pub struct X11Platform {
    conn: RustConnection,
    root: Window,
    atoms: Atoms,
    keyboard: Mutex<Keyboard>,
}

fn x11_error(error: impl std::fmt::Display) -> PlatformError {
    PlatformError(format!("X11: {error}"))
}

impl X11Platform {
    pub fn connect() -> PlatformResult<Self> {
        let (conn, screen) = RustConnection::connect(None).map_err(x11_error)?;
        let root = conn.setup().roots[screen].root;
        let atoms = Atoms::new(&conn)
            .map_err(x11_error)?
            .reply()
            .map_err(x11_error)?;
        conn.extension_information(x11rb::protocol::xtest::X11_EXTENSION_NAME)
            .map_err(x11_error)?
            .ok_or_else(|| PlatformError("the X server has no XTest extension".into()))?;
        let keyboard = Mutex::new(read_keyboard(&conn)?);
        Ok(Self {
            conn,
            root,
            atoms,
            keyboard,
        })
    }

    fn property(&self, window: Window, name: u32, kind: impl Into<u32>) -> Option<Vec<u8>> {
        let reply = self
            .conn
            .get_property(false, window, name, kind, 0, 1024)
            .ok()?
            .reply()
            .ok()?;
        (reply.value_len > 0).then_some(reply.value)
    }

    fn cardinal(&self, window: Window, name: u32, kind: impl Into<u32>) -> Option<u32> {
        let value = self.property(window, name, kind)?;
        Some(u32::from_ne_bytes(value.get(..4)?.try_into().ok()?))
    }

    fn key(&self, keycode: Keycode) -> PlatformResult<()> {
        for kind in [KEY_PRESS, KEY_RELEASE] {
            self.conn
                .xtest_fake_input(kind, keycode, x11rb::CURRENT_TIME, self.root, 0, 0, 0)
                .map_err(x11_error)?;
        }
        self.sync()
    }

    /// A round trip, so the server has handled everything sent so far.
    fn sync(&self) -> PlatformResult<()> {
        self.conn
            .get_input_focus()
            .map_err(x11_error)?
            .reply()
            .map_err(x11_error)?;
        Ok(())
    }

    /// Types `sym` on a spare keycode with `sym` in every column, so neither Shift nor the active
    /// layout group (an Arabic layout next to a Latin one) can change what's typed.
    fn type_keysym(&self, sym: Keysym) -> PlatformResult<()> {
        let mut keyboard = self.keyboard.lock().unwrap_or_else(|p| p.into_inner());
        let Some(&keycode) = keyboard
            .scratch
            .get(keyboard.next % keyboard.scratch.len().max(1))
        else {
            return Err(PlatformError(
                "no spare key to type this character with".into(),
            ));
        };
        keyboard.next += 1;
        keyboard.remapped = true;
        let syms = vec![sym; usize::from(keyboard.per_keycode)];
        self.conn
            .change_keyboard_mapping(1, keycode, keyboard.per_keycode, &syms)
            .map_err(x11_error)?;
        drop(keyboard);
        self.sync()?;
        self.key(keycode)?;
        std::thread::sleep(REMAP_DELAY);
        Ok(())
    }
}

impl Keyboard {
    fn unshifted(&self, sym: Keysym) -> Option<Keycode> {
        let per = usize::from(self.per_keycode);
        (0..self.map.len() / per.max(1))
            .find(|&index| self.map[index * per] == sym)
            .map(|index| self.min_keycode + index as u8)
    }
}

fn read_keyboard(conn: &RustConnection) -> PlatformResult<Keyboard> {
    let setup = conn.setup();
    let (min, max) = (setup.min_keycode, setup.max_keycode);
    let reply = conn
        .get_keyboard_mapping(min, max - min + 1)
        .map_err(x11_error)?
        .reply()
        .map_err(x11_error)?;
    let per = usize::from(reply.keysyms_per_keycode).max(1);
    let scratch = reply
        .keysyms
        .chunks(per)
        .enumerate()
        .filter(|(_, syms)| syms.iter().all(|&sym| sym == 0))
        .map(|(index, _)| min + index as u8)
        .rev()
        .take(SCRATCH_KEYS)
        .collect();
    Ok(Keyboard {
        min_keycode: min,
        per_keycode: reply.keysyms_per_keycode,
        map: reply.keysyms,
        scratch,
        next: 0,
        remapped: false,
    })
}

impl Platform for X11Platform {
    fn backend(&self) -> Backend {
        Backend::XTest
    }

    fn permission(&self) -> Permission {
        Permission::Granted
    }

    fn screen_locked(&self) -> bool {
        lock::screen_locked()
    }

    fn focused_window(&self) -> PlatformResult<Option<FocusedWindow>> {
        let Some(window) =
            self.cardinal(self.root, self.atoms._NET_ACTIVE_WINDOW, AtomEnum::WINDOW)
        else {
            return Ok(None);
        };
        if window == 0 {
            return Ok(None);
        }
        let title = self
            .property(window, self.atoms._NET_WM_NAME, self.atoms.UTF8_STRING)
            .map(|name| String::from_utf8_lossy(&name).into_owned())
            .or_else(|| {
                // `WM_NAME` is Latin-1.
                let name = self.property(window, AtomEnum::WM_NAME.into(), AtomEnum::STRING)?;
                Some(name.iter().map(|&b| char::from(b)).collect())
            })
            .unwrap_or_default();
        // `WM_CLASS` is "instance\0Class\0".
        let class = self
            .property(window, AtomEnum::WM_CLASS.into(), AtomEnum::STRING)
            .map(|class| {
                class
                    .split(|&b| b == 0)
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let pid = self
            .cardinal(window, self.atoms._NET_WM_PID, AtomEnum::CARDINAL)
            .unwrap_or(0);
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        let app_id = exe
            .as_deref()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
            .or_else(|| class.first().cloned())
            .unwrap_or_default()
            .to_lowercase();
        Ok(Some(FocusedWindow {
            pid,
            app_name: class.get(1).cloned().unwrap_or_else(|| app_id.clone()),
            app_id,
            title,
            url: None,
            handle: u64::from(window),
        }))
    }

    fn activate(&self, window: &FocusedWindow) -> PlatformResult<()> {
        // EWMH: source 2 is a pager, which window managers obey.
        let event = ClientMessageEvent::new(
            32,
            window.handle as Window,
            self.atoms._NET_ACTIVE_WINDOW,
            [2, x11rb::CURRENT_TIME, 0, 0, 0],
        );
        self.conn
            .send_event(
                false,
                self.root,
                EventMask::SUBSTRUCTURE_REDIRECT | EventMask::SUBSTRUCTURE_NOTIFY,
                event,
            )
            .map_err(x11_error)?;
        self.sync()
    }

    fn modifiers_held(&self) -> bool {
        let Ok(Ok(pointer)) = self
            .conn
            .query_pointer(self.root)
            .map(|cookie| cookie.reply())
        else {
            return false;
        };
        let held = KeyButMask::SHIFT | KeyButMask::CONTROL | KeyButMask::MOD1 | KeyButMask::MOD4;
        u16::from(pointer.mask) & u16::from(held) != 0
    }

    fn type_char(&self, c: char) -> PlatformResult<()> {
        self.type_keysym(keysym::for_char(c))
    }

    /// Tab and Return are the same in every layout, so their own keys are used when there are.
    fn press(&self, key: Key) -> PlatformResult<()> {
        let sym = keysym::for_key(key);
        let keycode = self
            .keyboard
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .unshifted(sym);
        match keycode {
            Some(keycode) => self.key(keycode),
            None => self.type_keysym(sym),
        }
    }

    fn finish(&self) {
        let mut keyboard = self.keyboard.lock().unwrap_or_else(|p| p.into_inner());
        if !keyboard.remapped {
            return;
        }
        std::thread::sleep(REMAP_DELAY * 4);
        let empty = vec![0; usize::from(keyboard.per_keycode)];
        for &keycode in &keyboard.scratch {
            let _ = self
                .conn
                .change_keyboard_mapping(1, keycode, keyboard.per_keycode, &empty);
        }
        let _ = self.conn.flush();
        keyboard.remapped = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_without_modifiers_are_found() {
        let keyboard = Keyboard {
            min_keycode: 8,
            per_keycode: 2,
            map: vec![0x61, 0x41, keysym::TAB, 0, 0, 0],
            scratch: vec![10],
            next: 0,
            remapped: false,
        };
        assert_eq!(keyboard.unshifted(0x61), Some(8));
        assert_eq!(keyboard.unshifted(keysym::TAB), Some(9));
        assert_eq!(keyboard.unshifted(0x41), None);
    }
}
