//! The parts of the developer toolkit (plan 16) that can't live in the I/O-free core: reading a
//! certificate from a live host, fetching a JWKS, talking to an ACME CA, and the system trust store.
//!
//! Everything else in the toolkit is offline. Each function here is the one place its network or
//! system access happens, and each is named after what it reaches, so a caller can tell the user
//! first (plan 16 §6). Nothing from the vault goes out: a TLS probe sends a hostname, a JWKS fetch
//! sends a URL, and ACME sends public keys, a CSR and signatures.

pub mod acme;
pub mod dns;
pub mod fetch;
pub mod tls;
pub mod trust;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("{0}")]
    Network(String),
    #[error("{0}")]
    Usage(String),
    #[error("the CA said: {0}")]
    Acme(String),
    #[error("{0}")]
    System(String),
    #[error(transparent)]
    Core(#[from] octapass_core::Error),
}

pub type Result<T, E = NetError> = std::result::Result<T, E>;

/// Whether a URL may be used without TLS: only to this machine, for tests and local CAs such as
/// Pebble.
pub(crate) fn is_loopback_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', ':']).next().unwrap_or_default();
    matches!(host, "localhost" | "127.0.0.1") || rest.starts_with("[::1]")
}

pub(crate) fn check_url(url: &str) -> Result<()> {
    if url.starts_with("https://") || is_loopback_url(url) {
        Ok(())
    } else {
        Err(NetError::Usage("Use an https:// address.".to_owned()))
    }
}
