//! Device unlock for the desktop app: the operating system's own lock (Touch ID or the Mac login
//! password, Windows Hello including its PIN, the Linux system password through polkit) releases a
//! 32-byte device secret. The vault wraps the account key with it (`octapass_core::device`), so
//! the secret alone is worthless without the wrapped key stored next to the account, and the
//! wrapped key is worthless without the device's lock.
//!
//! Each platform is written as a small piece of logic over a narrow OS interface, so the logic is
//! compiled and tested everywhere with a fake interface, and only the FFI is behind `cfg`.
//!
//! The same trait covers **Stay unlocked** (plan 18): a secret kept behind the OS user account
//! only (Keychain with no access-control flags, DPAPI, the Secret Service), so the app opens
//! without a prompt while the user is logged in.

use std::fmt;

use zeroize::Zeroizing;

#[cfg(any(test, feature = "fake"))]
pub mod fake;
pub mod linux;
pub mod macos;
mod screen;
pub mod windows;

pub const SECRET_LEN: usize = 32;

/// The secret device unlock releases. Zeroed when dropped.
pub type DeviceSecret = Zeroizing<[u8; SECRET_LEN]>;

/// How this device proves it's the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Touch ID, with the Mac login password as the fallback.
    TouchId,
    /// A Mac without Touch ID (or with none enrolled): the login password.
    MacPassword,
    /// Face, fingerprint or the Windows Hello PIN.
    WindowsHello,
    /// The Linux user's password (or fingerprint through fprintd) via polkit.
    SystemPassword,
}

impl Method {
    /// The English name the UI shows; the web vault translates by platform.
    pub fn label(self) -> &'static str {
        match self {
            Method::TouchId => "Touch ID",
            Method::MacPassword => "your Mac password",
            Method::WindowsHello => "Windows Hello",
            Method::SystemPassword => "your system password",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// How device unlock would ask; `None` when it can't be used here.
    pub method: Option<Method>,
    /// The OS account has a password, passcode or PIN. Fill without unlocking is only offered
    /// when it doesn't. (A Windows account can have a password but no Windows Hello set up: then
    /// there is no `method`, and still a lock.)
    pub device_lock: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("the user cancelled")]
    Cancelled,
    /// Wrong fingerprint or password too many times, or the OS refused for another reason.
    #[error("the device lock refused")]
    Denied,
    #[error("this device has no lock to unlock with")]
    NoDeviceLock,
    /// Nothing is stored for this account, or the OS invalidated it.
    #[error("device unlock isn't set up for this account")]
    NotEnrolled,
    #[error("device unlock isn't available on this system")]
    Unavailable,
    /// An OS call failed. The message never contains secrets.
    #[error("device unlock failed: {0}")]
    Platform(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A new key in the device chip, for a local vault (plan 03, *Local mode keys*).
pub struct ChipKey {
    /// What the chip works from; the vault keeps it next to its file. Not a secret.
    pub context: Vec<u8>,
    /// `hw_secret`: 32 bytes only this chip can produce again from the context.
    pub secret: DeviceSecret,
}

/// `hw_secret` from what the chip returned, so its shape doesn't depend on the chip.
pub(crate) fn chip_secret_from(raw: &[u8]) -> DeviceSecret {
    use sha2::{Digest, Sha256};
    Zeroizing::new(Sha256::digest([b"octapass/v1/chip-secret|", raw].concat()).into())
}

/// One account's device unlock on this device. `account` is a stable, non-secret key for the
/// account (server URL and email); implementations hash it before using it as an OS identifier.
pub trait DeviceUnlock: Send + Sync {
    fn capabilities(&self) -> Result<Capabilities>;

    /// Creates (or replaces) the account's device secret behind the device lock and returns it.
    /// Fails with [`Error::NoDeviceLock`] on a device without a lock.
    fn enroll(&self, account: &str) -> Result<DeviceSecret>;

    /// Asks for the device lock (`reason` is shown in the prompt) and releases the secret.
    fn unlock(&self, account: &str, reason: &str) -> Result<DeviceSecret>;

    /// Asks for the device lock without releasing anything, to confirm a sensitive action.
    fn verify_user(&self, reason: &str) -> Result<()>;

    /// Forgets the account's device secret. Succeeds if there was none.
    fn remove(&self, account: &str) -> Result<()>;

    /// Stay unlocked (plan 18): keeps `secret` protected only by the OS user account (Keychain
    /// without user presence, DPAPI, Secret Service), so reading it needs no prompt.
    fn store_unprotected(&self, account: &str, secret: &[u8; SECRET_LEN]) -> Result<()>;

    fn load_unprotected(&self, account: &str) -> Result<Option<DeviceSecret>>;

    fn remove_unprotected(&self, account: &str) -> Result<()>;

    /// Whether [`create_chip_key`](Self::create_chip_key) can work here. Unsigned builds on a Mac
    /// can't reach the Secure Enclave, and most Linux machines have nothing to reach.
    fn chip_available(&self) -> bool {
        false
    }

    /// Makes a non-exportable key in the device chip (Secure Enclave, TPM) that binds a local
    /// vault to this computer. No prompt: it only ever works together with the master password.
    /// `None` when there's no usable chip. `name` is hashed for the OS, like account names.
    fn create_chip_key(&self, _name: &str) -> Result<Option<ChipKey>> {
        Ok(None)
    }

    /// `hw_secret` again, from the chip key and the context it gave. Fails with
    /// [`Error::NotEnrolled`] when the key is gone.
    fn chip_secret(&self, _name: &str, _context: &[u8]) -> Result<DeviceSecret> {
        Err(Error::NotEnrolled)
    }

    /// Succeeds if there was none.
    fn delete_chip_key(&self, _name: &str) -> Result<()> {
        Ok(())
    }
}

/// Whether the computer's screen is locked right now: the macOS lock screen, the Windows secure
/// desktop, logind's `LockedHint`. `None` when it can't tell (no GUI session, no logind). Stay
/// unlocked (plan 18) polls it, so a lock resets "revealing asked once".
pub fn screen_locked() -> Option<bool> {
    screen::locked()
}

/// The implementation for the platform this was compiled for.
pub fn platform() -> Box<dyn DeviceUnlock> {
    #[cfg(target_os = "macos")]
    return Box::new(macos::MacUnlock::new(macos::system::SystemApi));
    #[cfg(windows)]
    return Box::new(windows::HelloUnlock::new(windows::system::SystemApi::new()));
    #[cfg(target_os = "linux")]
    return Box::new(linux::PolkitUnlock::new(linux::system::SystemApi));
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    return Box::new(Unsupported);
}

/// Platforms with no device lock integration: the master password only.
pub struct Unsupported;

impl DeviceUnlock for Unsupported {
    fn capabilities(&self) -> Result<Capabilities> {
        Err(Error::Unavailable)
    }
    fn enroll(&self, _: &str) -> Result<DeviceSecret> {
        Err(Error::Unavailable)
    }
    fn unlock(&self, _: &str, _: &str) -> Result<DeviceSecret> {
        Err(Error::Unavailable)
    }
    fn verify_user(&self, _: &str) -> Result<()> {
        Err(Error::Unavailable)
    }
    fn remove(&self, _: &str) -> Result<()> {
        Ok(())
    }
    fn store_unprotected(&self, _: &str, _: &[u8; SECRET_LEN]) -> Result<()> {
        Err(Error::Unavailable)
    }
    fn load_unprotected(&self, _: &str) -> Result<Option<DeviceSecret>> {
        Ok(None)
    }
    fn remove_unprotected(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

/// The OS identifier for an account: a hash, so key names in the Keychain, the Windows key
/// store or the Secret Service don't reveal which email or server the user has.
pub fn account_tag(account: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest =
        Sha256::digest([b"octapass/v1/desktop-device-unlock|", account.as_bytes()].concat());
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn random_secret() -> DeviceSecret {
    use rand_core::{OsRng, RngCore};
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    OsRng.fill_bytes(secret.as_mut());
    secret
}

/// Copies OS-returned bytes into a [`DeviceSecret`], rejecting anything of the wrong length
/// (a corrupted or foreign item).
pub(crate) fn secret_from(bytes: &[u8]) -> Result<DeviceSecret> {
    let array: [u8; SECRET_LEN] = bytes.try_into().map_err(|_| Error::NotEnrolled)?;
    Ok(Zeroizing::new(array))
}

/// An OS status code with the call that returned it, for error messages.
pub(crate) fn platform_error(call: &str, status: impl fmt::Display) -> Error {
    Error::Platform(format!("{call} returned {status}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_tags_are_stable_and_distinct() {
        let a = account_tag("https://vault.octap.app|a@example.com");
        assert_eq!(a, account_tag("https://vault.octap.app|a@example.com"));
        assert_ne!(a, account_tag("https://vault.octap.app|b@example.com"));
        assert_eq!(a.len(), 32);
        assert!(!a.contains('@'));
    }

    #[test]
    fn chip_secrets_are_32_bytes_of_hash() {
        assert_eq!(*chip_secret_from(b"a"), *chip_secret_from(b"a"));
        assert_ne!(*chip_secret_from(b"a"), *chip_secret_from(b"b"));
    }

    #[test]
    fn a_platform_without_a_chip_says_so() {
        let unsupported = Unsupported;
        assert!(!unsupported.chip_available());
        assert!(unsupported.create_chip_key("v").unwrap().is_none());
        assert_eq!(
            unsupported.chip_secret("v", b"c").err(),
            Some(Error::NotEnrolled)
        );
        assert!(unsupported.delete_chip_key("v").is_ok());
    }

    #[test]
    fn secrets_must_be_32_bytes() {
        assert!(secret_from(&[1; 32]).is_ok());
        assert_eq!(secret_from(&[1; 31]).unwrap_err(), Error::NotEnrolled);
        assert_ne!(*random_secret(), *random_secret());
    }
}
