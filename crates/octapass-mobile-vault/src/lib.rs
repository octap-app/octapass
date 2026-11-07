//! The mobile apps' vault: everything behind their commands except the UI. It runs on
//! `octapass-ffi`, so the app and its autofill extensions share one encrypted `LocalStore`, talks
//! to the sync server, and unlocks with the master password or the phone's own lock. Keys stay
//! in this process; the web view only receives what it renders.

pub mod accounts;
#[cfg(all(feature = "desktop", any(target_os = "macos", target_os = "linux")))]
pub mod desktop;
pub mod error;
pub mod health;
pub mod http;
pub mod masked_email;
pub mod model;
pub mod native;
pub mod outbox;
pub mod site_icons;
pub mod vault;

pub use error::{ErrorCode, Result, VaultError};
pub use native::{ChipKey, DeviceLock, Native};
pub use vault::{Config, Event, SessionSnapshot, Vault};
