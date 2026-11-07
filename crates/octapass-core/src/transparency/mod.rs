//! Key transparency (plan 03): an append-only log of account public keys, which clients verify so
//! the server can't swap a key without it showing.
//!
//! - [`merkle`]: the RFC 9162 tree, its proofs, and the compact form monitors keep.
//! - [`record`]: the statement an account signs about its own keys.
//! - [`head`]: signed tree heads and the log's identity.
//! - [`label`]: the VOPRF that turns an email into a private, verifiable log label.
//! - [`client`]: what a client pins and checks.
//! - [`publish`]: publishing this account's record from an unlocked session.
//!
//! Not audited. It needs the external review plan 09's risks table calls for, and it doesn't stop
//! a server that shows different people different logs: see plan 03, "What it doesn't do".

pub mod client;
pub mod head;
pub mod label;
pub mod merkle;
pub mod publish;
pub mod record;
