//! Linux: XTest on X11; on Wayland, which lets no app type into another or see which window is
//! focused, the `xdg-desktop-portal` RemoteDesktop portal (the desktop asks the user once per app
//! run). Without the portal, [`Backend::Clipboard`](crate::Backend::Clipboard): the app copies.

mod lock;
mod portal;
mod x11;

use crate::engine::Platform;

pub fn platform() -> Box<dyn Platform> {
    let var = |name: &str| std::env::var_os(name).filter(|value| !value.is_empty());
    let wayland = var("WAYLAND_DISPLAY").is_some()
        || std::env::var("XDG_SESSION_TYPE").is_ok_and(|kind| kind == "wayland");
    if wayland {
        return Box::new(portal::PortalPlatform::new());
    }
    match x11::X11Platform::connect() {
        Ok(platform) => Box::new(platform),
        Err(error) => {
            eprintln!("auto-type: no X11 display ({error}), so it can't type");
            Box::new(portal::PortalPlatform::unavailable())
        }
    }
}
