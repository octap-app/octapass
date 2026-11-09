//! The Octa Pass crypto core, shared by every client.
//!
//! Pure Rust with no I/O: callers pass in randomness and the current time, so the same code runs
//! natively, in WebAssembly and in deterministic tests. See `README.md` for the formats.

pub mod account;
pub mod attachment;
/// Backup files belong to local mode.
#[cfg(feature = "strength")]
pub mod backup;
pub mod credentials;
pub mod device;
pub mod encoding;
pub mod envelope;
// Environments (plan 16): the `.env` reader and writer, stages and projects.
pub mod environment;
pub mod error;
pub mod export;
// The health report's signed site lists (plan 06).
pub mod health_data;
pub mod import;
// Saving while locked (plan 03): entries sealed to the account's own public keys, merged at unlock.
pub mod inbox;
pub mod item;
pub mod item_fields;
pub mod kdf;
pub mod keys;
/// Local vaults require a strong master password (zxcvbn score 4), so they need the `strength` feature.
/// The web vault, which never offers local mode, builds without it.
#[cfg(feature = "strength")]
pub mod local;
pub mod matching;
pub mod opaque;
pub mod passkey;
// Nearby (plan 01): places, and which one the device is at, worked out on the device.
pub mod places;
pub mod recovery;
pub mod rules;
// Octa Pass Safe (plan 16): the encrypted drive's format. No I/O, like the rest of the core.
pub mod safe;
pub mod secret_key;
pub mod service_account;
pub mod session;
pub mod sharing;
mod stream;
pub mod tools;
// The key log (plan 03): signed key records, Merkle proofs and what clients check.
pub mod transparency;

pub use error::{Error, Result};
