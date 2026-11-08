//! `OctaPassVault`: the UniFFI API the native iPhone and Android apps are built on (plan 17). It
//! wraps the mobile vault (`crates/octapass-mobile-vault`), which keeps the account in the encrypted
//! store the autofill extensions share, and adds what the phone's web-view screens did in
//! TypeScript: typed items for every type, list order, health and the recovery map, QR codes and
//! Wi-Fi, masked email, sharing, families, share links, emergency access, devices, the security
//! log, settings and exports. Swift and Kotlin do UI and platform services only.
//!
//! The autofill extensions keep using the smaller `octapass-ffi`.
//!
//! Generated bindings: `OctaPassVault` (Swift) and `app.octap.vault` (Kotlin). See
//! `README.md` for the API, which calls block, and the build scripts.

uniffi::setup_scaffolding!();

#[cfg(target_os = "android")]
mod android;
mod api;
mod background;
pub mod desktop;
pub mod emergency;
pub mod environments;
pub mod error;
pub mod health;
pub mod icons;
pub mod items;
pub mod links;
pub mod list;
pub mod local;
pub mod local_vaults;
pub mod masked_email;
pub mod platform;
pub mod push;
pub mod qr;
pub mod safe;
pub mod sharing;
pub mod ssh;
pub mod stay_unlocked;
pub mod structured;
pub mod tools;
pub mod transfer;
pub mod usage;
pub mod vault;
pub mod watch;

pub use error::{ErrorCode, Result, VaultError};
pub use vault::OctaPassVault;
