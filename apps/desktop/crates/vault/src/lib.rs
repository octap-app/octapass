//! The desktop app's vault: everything behind its commands except the UI. It links the Open
//! Pass core directly, talks to the sync server, keeps an encrypted local copy, and unlocks with
//! the master password or the device's own lock. Keys stay in this process.

pub mod api;
pub mod autofill;
pub mod bridge;
pub mod cache;
pub mod cli_session;
pub mod error;
pub mod health;
pub mod masked_email;
pub mod model;
pub mod service_account;
pub mod site_icons;
pub mod ssh_agent;
pub mod store;
pub mod tools;
pub mod vault;
pub mod windows_passkey;

pub use error::{ErrorCode, Result, VaultError};
pub use vault::{Config, Event, SessionSnapshot, Vault};
