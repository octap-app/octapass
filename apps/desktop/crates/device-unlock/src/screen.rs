//! Is the screen locked? Polled by the desktop app while it stays unlocked (plan 18): a lock
//! ends "revealing and copying asked once". Each platform's answer comes from the system's own
//! session state, never from Octa Pass guessing at idleness.

#[cfg(target_os = "macos")]
pub(crate) fn locked() -> Option<bool> {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::CFString;

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    // SAFETY: takes nothing and returns a dictionary we own (the Create rule), or null outside
    // a GUI session.
    let raw = unsafe { CGSessionCopyCurrentDictionary() };
    if raw.is_null() {
        return None;
    }
    // SAFETY: non-null, owned by us, released when dropped.
    let session: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(raw) };
    let key = CFString::from_static_string("CGSSessionScreenIsLocked");
    Some(
        session
            .find(&key)
            .and_then(|value| value.downcast::<CFBoolean>())
            .is_some_and(bool::from),
    )
}

#[cfg(windows)]
pub(crate) fn locked() -> Option<bool> {
    use windows::Win32::System::StationsAndDesktops::{
        CloseDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_SWITCHDESKTOP, OpenInputDesktop,
    };

    // The input desktop can't be opened while the secure desktop (the lock screen) has it.
    // SAFETY: plain Win32 calls; the handle is closed right away.
    match unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_SWITCHDESKTOP) } {
        Ok(desktop) => {
            let _ = unsafe { CloseDesktop(desktop) };
            Some(false)
        }
        Err(_) => Some(true),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn locked() -> Option<bool> {
    use std::sync::OnceLock;

    use zbus::blocking::{Connection, Proxy};

    static BUS: OnceLock<Option<Connection>> = OnceLock::new();
    let connection = BUS.get_or_init(|| Connection::system().ok()).as_ref()?;
    let session = Proxy::new(
        connection,
        "org.freedesktop.login1",
        "/org/freedesktop/login1/session/auto",
        "org.freedesktop.login1.Session",
    )
    .ok()?;
    session.get_property::<bool>("LockedHint").ok()
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
pub(crate) fn locked() -> Option<bool> {
    None
}
