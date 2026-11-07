//! Auto-type for the desktop app (plan 05): types a login's username ⇥ password ↵, or the item's
//! own sequence, into the focused window, after checking that the window belongs to the login.
//!
//! - [`sequence`]: the sequence language (`{USERNAME}{TAB}{PASSWORD}{ENTER}`).
//! - [`window`]: which login a window belongs to.
//! - [`engine`]: the checks and the typing, over a [`Platform`].
//! - The platforms: macOS `CGEvent` (with the Accessibility permission), Windows `SendInput`,
//!   X11 XTest, and Wayland's RemoteDesktop portal. Each types Unicode characters directly, so
//!   the keyboard layout doesn't matter. Where none works, [`Backend::Clipboard`] tells the app
//!   to copy instead.
//!
//! The logic is tested everywhere with [`fake::FakePlatform`]; only the FFI is behind `cfg`.

pub mod engine;
#[cfg(any(test, feature = "fake"))]
pub mod fake;
pub mod keysym;
pub mod sequence;
pub mod window;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

pub use engine::{Backend, Permission, Platform, PlatformError, Refusal, Request, Typed, run};
pub use sequence::{
    Action, DEFAULT_SEQUENCE, Field, Key, PASSWORD_SEQUENCE, Sequence, SequenceError,
};
pub use window::{FocusedWindow, ItemRules, Reason};

/// This computer's platform.
pub fn platform() -> Box<dyn Platform> {
    #[cfg(target_os = "macos")]
    return Box::new(macos::MacPlatform::new());
    #[cfg(windows)]
    return Box::new(windows::WindowsPlatform);
    #[cfg(target_os = "linux")]
    return linux::platform();
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    return Box::new(Unsupported);
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
struct Unsupported;

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
impl Platform for Unsupported {
    fn backend(&self) -> Backend {
        Backend::Clipboard
    }
    fn permission(&self) -> Permission {
        Permission::Granted
    }
    fn screen_locked(&self) -> bool {
        false
    }
    fn focused_window(&self) -> engine::PlatformResult<Option<FocusedWindow>> {
        Ok(None)
    }
    fn activate(&self, _: &FocusedWindow) -> engine::PlatformResult<()> {
        Ok(())
    }
    fn modifiers_held(&self) -> bool {
        false
    }
    fn type_char(&self, _: char) -> engine::PlatformResult<()> {
        Err(PlatformError("auto-type isn't available here".into()))
    }
    fn press(&self, _: Key) -> engine::PlatformResult<()> {
        Err(PlatformError("auto-type isn't available here".into()))
    }
}
