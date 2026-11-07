//! The native messaging host for the Octa Pass browser extension. Browsers start it when the
//! extension connects; it checks which extension that is and that a known browser started it,
//! then relays each request to the running desktop app, which does the work (and the Touch ID /
//! Windows Hello prompt).
//!
//! The library half is shared with the app: the protocol types, the local channel, the checks on
//! who is at either end of it ([`trust`]), and the manifests the app installs and removes.

pub mod browsers;
pub mod caller;
pub mod framing;
pub mod ipc;
pub mod manifests;
pub mod protocol;
pub mod system;
#[cfg(feature = "testing")]
pub mod testing;
pub mod trust;
