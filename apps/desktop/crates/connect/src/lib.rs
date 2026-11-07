//! Octa Pass Connect (plan 03, "Non-human access"; plan 16): one generic local helper that hands
//! a secret to a tool asking by `octapass://` reference. No integration is built for one product.
//!
//! This crate is the part the CLI and the desktop app share: the reference and field model
//! ([`reference`]), the local HTTP service ([`server`]), approved clients ([`clients`]), the record
//! of what was handed out ([`log`]), a small client ([`client`]), and live OAuth2 tokens
//! ([`oauth`]). Each app plugs in a [`server::Backend`]: how to ask the person, and how to reach
//! the vault.

pub mod client;
pub mod clients;
pub mod log;
pub mod oauth;
pub mod reference;
pub mod server;
pub mod vault_backend;

use std::path::PathBuf;

/// Where a Connect service is, for clients: `unix:/path/to.sock`, or `http://127.0.0.1:port`.
pub const ENDPOINT_ENV: &str = "OCTAPASS_CONNECT";
const FOLDER: &str = "com.octapass.connect";

/// The folder of this user's Connect service: one per user, shared by the CLI and the desktop app,
/// so tools find it in one place. `base` is the OS's per-user data folder.
pub fn folder(base: PathBuf) -> PathBuf {
    base.join(FOLDER)
}
