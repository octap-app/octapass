//! The Octa Pass push relay (plan 04, "Push relay").
//!
//! Apple and Google only deliver pushes signed with the app publisher's credentials, so a
//! self-hosted Octa Pass server can't wake the official phone apps by itself. This relay holds
//! those credentials. A server registers once and gets an installation id and key; after that it
//! sends `{token, kind}` pairs, and the relay passes each on through APNs or FCM.
//!
//! What it never sees: accounts, emails, vaults, items or anything decrypted. A push says only
//! `sync` or `alert`. Push tokens pass through in memory and are never stored or logged; the
//! database holds installations and nothing else.

pub mod api;
pub mod apns;
pub mod config;
pub mod db;
pub mod fcm;
pub mod jwt;
pub mod limits;

pub use api::{AppState, router};
pub use config::Config;

use serde::{Deserialize, Serialize};

/// What a push asks the phone to do. There is nothing else in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Something in a vault changed: sync, silently.
    Sync,
    /// Sharing, a family invite or emergency access: show the app's generic notice, and sync.
    Alert,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Sync => "sync",
            Kind::Alert => "alert",
        }
    }
}

/// What became of one push.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Sent,
    /// The token is dead (the app was removed, or the token isn't this app's): the server should
    /// forget it.
    Unregistered,
    /// Apple or Google didn't take it this time, or this relay has no credentials for the
    /// platform. Nothing to do; a later push may work.
    Failed,
}
