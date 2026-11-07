//! Whether the screen is locked: logind's `LockedHint` for this session (GNOME, KDE and most
//! lockers set it), or the session's screensaver saying it's active.

use zbus::blocking::{Connection, Proxy};

pub fn screen_locked() -> bool {
    locked_hint() == Some(true) || screensaver_active() == Some(true)
}

fn locked_hint() -> Option<bool> {
    let bus = Connection::system().ok()?;
    let session = Proxy::new(
        &bus,
        "org.freedesktop.login1",
        "/org/freedesktop/login1/session/auto",
        "org.freedesktop.login1.Session",
    )
    .ok()?;
    session.get_property::<bool>("LockedHint").ok()
}

fn screensaver_active() -> Option<bool> {
    let bus = Connection::session().ok()?;
    [
        (
            "org.freedesktop.ScreenSaver",
            "/org/freedesktop/ScreenSaver",
        ),
        ("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver"),
    ]
    .into_iter()
    .find_map(|(name, path)| {
        let proxy = Proxy::new(&bus, name, path, name).ok()?;
        proxy.call::<_, _, bool>("GetActive", &()).ok()
    })
}
