//! Local tools that never send secrets anywhere: TOTP, QR codes, generators, strength and breach
//! checks, SSH keys, Wi-Fi tags.

#[cfg(feature = "age-files")]
pub mod age;
#[cfg(any(feature = "age-files", feature = "toolkit"))]
pub mod age_keys;
pub mod breach;
pub mod generator;
#[cfg(feature = "pgp")]
pub mod gpg;
pub mod masked_email;
pub mod otpauth;
pub mod payment_qr;
pub mod qr;
pub mod ssh;
#[cfg(feature = "strength")]
pub mod strength;
// The developer toolkit (plan 16).
#[cfg(feature = "toolkit")]
pub mod toolkit;
pub mod totp;
pub mod wifi;
