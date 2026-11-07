//! macOS: keystrokes are `CGEvent`s carrying the character itself
//! (`CGEventKeyboardSetUnicodeString`), so the keyboard layout doesn't matter. Posting events and
//! reading other apps' windows both need the Accessibility permission, which only the user can
//! give, in System Settings.

use std::ffi::{c_char, c_void};
use std::path::{Path, PathBuf};
use std::ptr;

use core_foundation::array::CFArray;
use core_foundation::base::{CFRelease, CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::bundle::CFBundle;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::url::CFURL;

use crate::engine::{Backend, Permission, Platform, PlatformError, PlatformResult};
use crate::sequence::Key;
use crate::window::FocusedWindow;

/// Privacy & Security → Accessibility.
pub const ACCESSIBILITY_SETTINGS: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility";

type AxElement = CFTypeRef;
type EventRef = *mut c_void;

#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXIsProcessTrusted() -> bool;
    fn AXUIElementCreateSystemWide() -> AxElement;
    fn AXUIElementCreateApplication(pid: i32) -> AxElement;
    fn AXUIElementCopyAttributeValue(
        element: AxElement,
        attribute: CFStringRef,
        value: *mut CFTypeRef,
    ) -> i32;
    fn AXUIElementSetAttributeValue(
        element: AxElement,
        attribute: CFStringRef,
        value: CFTypeRef,
    ) -> i32;
    fn AXUIElementGetPid(element: AxElement, pid: *mut i32) -> i32;
    fn AXUIElementSetMessagingTimeout(element: AxElement, seconds: f32) -> i32;
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGEventCreateKeyboardEvent(source: *const c_void, key: u16, down: bool) -> EventRef;
    fn CGEventKeyboardSetUnicodeString(event: EventRef, length: usize, string: *const u16);
    fn CGEventSetFlags(event: EventRef, flags: u64);
    fn CGEventPost(tap: u32, event: EventRef);
    fn CGEventSourceFlagsState(state: i32) -> u64;
    fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
}

const HID_EVENT_TAP: u32 = 0;
const HID_SYSTEM_STATE: i32 = 1;
/// Shift, Control, Option, Command.
const MODIFIER_FLAGS: u64 = 0x0002_0000 | 0x0004_0000 | 0x0008_0000 | 0x0010_0000;
const TAB_KEYCODE: u16 = 48;
const RETURN_KEYCODE: u16 = 36;
/// An app that doesn't answer Accessibility within this is skipped, not waited for.
const AX_TIMEOUT: f32 = 0.5;
/// How much of a browser window is searched for its page.
const MAX_NODES: usize = 600;

pub struct MacPlatform;

impl MacPlatform {
    pub fn new() -> Self {
        Self
    }
}

/// An owned Accessibility element.
struct Element(CFType);

impl Element {
    /// Takes ownership of a `Create` or `Copy` result.
    fn owned(raw: CFTypeRef) -> Option<Self> {
        (!raw.is_null()).then(|| Self(unsafe { CFType::wrap_under_create_rule(raw) }))
    }

    fn raw(&self) -> AxElement {
        self.0.as_CFTypeRef()
    }

    fn attribute(&self, name: &'static str) -> Option<CFType> {
        let name = CFString::from_static_string(name);
        let mut value: CFTypeRef = ptr::null();
        let error = unsafe {
            AXUIElementCopyAttributeValue(self.raw(), name.as_concrete_TypeRef(), &mut value)
        };
        if error != 0 || value.is_null() {
            return None;
        }
        Some(unsafe { CFType::wrap_under_create_rule(value) })
    }

    fn string(&self, name: &'static str) -> Option<String> {
        Some(self.attribute(name)?.downcast::<CFString>()?.to_string())
    }

    fn element(&self, name: &'static str) -> Option<Element> {
        self.attribute(name).map(Element)
    }

    fn children(&self) -> Vec<Element> {
        let Some(children) = self.attribute("AXChildren") else {
            return Vec::new();
        };
        let Some(children) = children.downcast::<CFArray<*const c_void>>() else {
            return Vec::new();
        };
        children
            .iter()
            .map(|child| Element(unsafe { CFType::wrap_under_get_rule(*child) }))
            .collect()
    }

    fn set_true(&self, name: &'static str) -> bool {
        let name = CFString::from_static_string(name);
        let value = CFBoolean::true_value();
        unsafe {
            AXUIElementSetAttributeValue(
                self.raw(),
                name.as_concrete_TypeRef(),
                value.as_CFTypeRef(),
            ) == 0
        }
    }

    fn pid(&self) -> Option<u32> {
        let mut pid = 0;
        (unsafe { AXUIElementGetPid(self.raw(), &mut pid) } == 0).then_some(pid as u32)
    }
}

fn application(pid: u32) -> Option<Element> {
    let app = Element::owned(unsafe { AXUIElementCreateApplication(pid as i32) })?;
    unsafe { AXUIElementSetMessagingTimeout(app.raw(), AX_TIMEOUT) };
    Some(app)
}

impl Platform for MacPlatform {
    fn backend(&self) -> Backend {
        Backend::Accessibility
    }

    fn permission(&self) -> Permission {
        if unsafe { AXIsProcessTrusted() } {
            Permission::Granted
        } else {
            Permission::Missing {
                settings_url: ACCESSIBILITY_SETTINGS,
            }
        }
    }

    /// Locked, at the login window, or switched to another user: no session on the console.
    fn screen_locked(&self) -> bool {
        let raw = unsafe { CGSessionCopyCurrentDictionary() };
        if raw.is_null() {
            return true;
        }
        let session: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_create_rule(raw) };
        let flag = |key: &'static str| {
            session
                .find(CFString::from_static_string(key))
                .and_then(|value| value.downcast::<CFBoolean>())
                .map(bool::from)
        };
        flag("CGSSessionScreenIsLocked") == Some(true)
            || flag("kCGSSessionOnConsoleKey") == Some(false)
    }

    fn focused_window(&self) -> PlatformResult<Option<FocusedWindow>> {
        let system = Element::owned(unsafe { AXUIElementCreateSystemWide() })
            .ok_or_else(|| PlatformError("no Accessibility element for the system".into()))?;
        unsafe { AXUIElementSetMessagingTimeout(system.raw(), AX_TIMEOUT) };
        let Some(app) = system.element("AXFocusedApplication") else {
            return Ok(None);
        };
        let Some(pid) = app.pid() else {
            return Ok(None);
        };
        let window = app.element("AXFocusedWindow");
        let executable = executable(pid);
        let bundle = executable.as_deref().and_then(bundle_of);
        let app_id = bundle
            .as_deref()
            .and_then(bundle_identifier)
            .or_else(|| {
                executable
                    .as_deref()
                    .and_then(Path::file_name)
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .unwrap_or_default()
            .to_lowercase();
        let mut focused = FocusedWindow {
            pid,
            app_name: app.string("AXTitle").unwrap_or_default(),
            app_id,
            title: window
                .as_ref()
                .and_then(|window| window.string("AXTitle"))
                .unwrap_or_default(),
            url: None,
            handle: 0,
        };
        if focused.is_browser()
            && let Some(window) = &window
        {
            // Chromium builds its accessibility tree only for clients that ask for it.
            app.set_true("AXManualAccessibility");
            focused.url = page_url(window);
        }
        Ok(Some(focused))
    }

    fn activate(&self, window: &FocusedWindow) -> PlatformResult<()> {
        let app = application(window.pid)
            .ok_or_else(|| PlatformError(format!("no Accessibility element for {}", window.pid)))?;
        if app.set_true("AXFrontmost") {
            Ok(())
        } else {
            Err(PlatformError(format!(
                "couldn't bring {} to the front",
                window.describe()
            )))
        }
    }

    fn modifiers_held(&self) -> bool {
        unsafe { CGEventSourceFlagsState(HID_SYSTEM_STATE) & MODIFIER_FLAGS != 0 }
    }

    fn type_char(&self, c: char) -> PlatformResult<()> {
        let mut units = [0u16; 2];
        let units = c.encode_utf16(&mut units);
        for down in [true, false] {
            post(0, down, Some(units))?;
        }
        Ok(())
    }

    fn press(&self, key: Key) -> PlatformResult<()> {
        let code = match key {
            Key::Tab => TAB_KEYCODE,
            Key::Enter => RETURN_KEYCODE,
        };
        for down in [true, false] {
            post(code, down, None)?;
        }
        Ok(())
    }
}

/// Posts one key event, with no modifiers, so a held Command can't turn it into a shortcut.
fn post(code: u16, down: bool, text: Option<&[u16]>) -> PlatformResult<()> {
    let event = unsafe { CGEventCreateKeyboardEvent(ptr::null(), code, down) };
    if event.is_null() {
        return Err(PlatformError("couldn't create a key event".into()));
    }
    unsafe {
        if let Some(text) = text {
            CGEventKeyboardSetUnicodeString(event, text.len(), text.as_ptr());
        }
        CGEventSetFlags(event, 0);
        CGEventPost(HID_EVENT_TAP, event);
        CFRelease(event as CFTypeRef);
    }
    Ok(())
}

/// The address of the page in a browser window: its web area's `AXURL`.
fn page_url(window: &Element) -> Option<String> {
    let mut queue = std::collections::VecDeque::from([window.0.clone()]);
    let mut seen = 0;
    while let Some(node) = queue.pop_front() {
        seen += 1;
        if seen > MAX_NODES {
            return None;
        }
        let node = Element(node);
        if node.string("AXRole").as_deref() == Some("AXWebArea") {
            let url = node.attribute("AXURL")?.downcast::<CFURL>()?;
            return Some(url.get_string().to_string());
        }
        queue.extend(node.children().into_iter().map(|child| child.0));
    }
    None
}

fn executable(pid: u32) -> Option<PathBuf> {
    unsafe extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut c_char, size: u32) -> i32;
    }
    let mut buffer = vec![0u8; libc::PATH_MAX as usize * 4];
    let len = unsafe { proc_pidpath(pid as i32, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if len <= 0 {
        return None;
    }
    buffer.truncate(len as usize);
    Some(PathBuf::from(String::from_utf8_lossy(&buffer).into_owned()))
}

/// The innermost `.app` the executable is in.
fn bundle_of(executable: &Path) -> Option<PathBuf> {
    executable
        .ancestors()
        .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        .map(Path::to_owned)
}

fn bundle_identifier(bundle: &Path) -> Option<String> {
    let bundle = CFBundle::new(CFURL::from_path(bundle, true)?)?;
    let info = bundle.info_dictionary();
    let id = info.find(CFString::from_static_string("CFBundleIdentifier"))?;
    Some(id.downcast::<CFString>()?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundles_are_found_from_their_executables() {
        let safari = Path::new("/Applications/Safari.app/Contents/MacOS/Safari");
        assert_eq!(
            bundle_of(safari).as_deref(),
            Some(Path::new("/Applications/Safari.app"))
        );
        let nested = Path::new(
            "/Applications/Xcode.app/Contents/Developer/Applications/Simulator.app/Contents/MacOS/Simulator",
        );
        assert!(bundle_of(nested).unwrap().ends_with("Simulator.app"));
        assert_eq!(bundle_of(Path::new("/usr/bin/vim")), None);
        assert_eq!(
            bundle_identifier(Path::new("/System/Applications/TextEdit.app")).as_deref(),
            Some("com.apple.TextEdit")
        );
    }

    /// Types into a TextEdit window this test opens, with the real engine and `CGEvent`s, and
    /// reads the text back through Accessibility. Needs the Accessibility permission for the
    /// terminal running the tests; without it (CI), or with TextEdit already open (it could have
    /// the user's documents), it says why and skips.
    #[test]
    fn types_into_a_real_window() {
        use std::process::Command;
        use std::time::{Duration, Instant};

        use zeroize::Zeroizing;

        use crate::sequence::{Field, Sequence};
        use crate::window::ItemRules;

        let platform = MacPlatform::new();
        if platform.permission() != Permission::Granted {
            eprintln!(
                "SKIPPED types_into_a_real_window: this terminal doesn't have the Accessibility \
                 permission (System Settings → Privacy & Security → Accessibility)"
            );
            return;
        }
        if platform.screen_locked() {
            eprintln!("SKIPPED types_into_a_real_window: the screen is locked");
            return;
        }
        let running = Command::new("pgrep")
            .args(["-x", "TextEdit"])
            .output()
            .unwrap();
        if running.status.success() {
            eprintln!(
                "SKIPPED types_into_a_real_window: TextEdit is already open, and may have your documents"
            );
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let name = format!("octapass-autotype-{}", std::process::id());
        let file = dir.path().join(format!("{name}.txt"));
        std::fs::write(&file, "").unwrap();
        let opened = Command::new("open")
            .args(["-F", "-a", "TextEdit"])
            .arg(&file)
            .status()
            .unwrap();
        assert!(opened.success());
        let quit = || {
            let _ = Command::new("pkill").args(["-x", "TextEdit"]).status();
        };

        let deadline = Instant::now() + Duration::from_secs(15);
        let window = loop {
            match platform.focused_window() {
                Ok(Some(window)) if window.title.contains(&name) => break window,
                _ if Instant::now() > deadline => {
                    quit();
                    panic!("TextEdit didn't come to the front");
                }
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        };
        assert_eq!(window.app_id, "com.apple.textedit");
        assert!(!window.is_browser());

        let item = ItemRules {
            id: "test".into(),
            title: "Not this title".into(),
            window_titles: vec![name.clone()],
            ..Default::default()
        };
        let actions = Sequence::parse("{USERNAME}{TAB}{PASSWORD}{ENTER}done")
            .unwrap()
            .actions(&|field| {
                Some(Zeroizing::new(
                    match field {
                        Field::Username => "ada@example.com",
                        _ => "pässwörd ب€😀",
                    }
                    .to_owned(),
                ))
            })
            .unwrap();
        let typed = crate::run(
            &platform,
            &crate::Request {
                own_pid: std::process::id(),
                item: &item,
                actions: &actions,
                target: Some(&window),
                picked: false,
            },
        );

        std::thread::sleep(Duration::from_millis(300));
        let system = Element::owned(unsafe { AXUIElementCreateSystemWide() }).unwrap();
        let text = system
            .element("AXFocusedUIElement")
            .and_then(|field| field.string("AXValue"));
        quit();
        assert!(typed.is_ok(), "{typed:?}");
        assert_eq!(
            text.as_deref(),
            Some("ada@example.com\tpässwörd ب€😀\ndone")
        );
    }

    #[test]
    fn this_process_has_an_executable_and_a_session() {
        let me = executable(std::process::id()).unwrap();
        assert_eq!(me, std::env::current_exe().unwrap().canonicalize().unwrap());
        // Run from a logged-in terminal, there's a console session, and nothing here locks it.
        let _ = MacPlatform::new().screen_locked();
        let _ = MacPlatform::new().modifiers_held();
    }
}
