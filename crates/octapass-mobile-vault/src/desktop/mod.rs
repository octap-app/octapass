//! The desktop services on the native vault (plan 19, phase 3), for the Mac app: what the Tauri
//! app runs over `octapass-desktop-vault`, with the same wire protocols and the same checks.
//! Each listens on a local socket and answers from the open vault; keys and secrets never pass
//! through the app's UI code.
//!
//! - [`bridge`]: the browser extension, through `octapass-native-host` (plan 13).
//! - [`cli_session`]: the `octapass` CLI unlocking through the app (plan 05).
//! - [`ssh_agent`]: the SSH agent, asking before every signature (plans 05 and 16).

pub mod bridge;
pub mod cli_session;
pub mod socket;
pub mod ssh_agent;
pub mod wrap;

pub use socket::Service;
