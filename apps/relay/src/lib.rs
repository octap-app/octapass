//! The Octa Pass masked email relay (plan 06, Phase B).
//!
//! It receives mail for random aliases and passes it on to the account's verified email inside
//! the SMTP transaction: there is no queue, and no message reaches a disk or a log. Replies go
//! back out through per-sender reverse aliases. It is a service of its own, off unless configured,
//! and it never touches vault data.

pub mod address;
pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod dsn;
pub mod keys;
pub mod limits;
pub mod notice;
pub mod outbound;
pub mod pipeline;
pub mod rewrite;
pub mod server;
pub mod smtp;
pub mod srs;

pub use config::Config;
pub use server::{Running, start};
