//! Staying unlocked between commands. `octapass unlock` turns on the desktop vault's device unlock
//! with a random 32-byte session secret kept in the OS keyring (macOS Keychain, Windows Credential
//! Manager, the Secret Service). The account key, wrapped by that secret, sits in the CLI's data
//! folder (`state.json`), so neither the file nor the keyring entry opens the vault alone.
//!
//! The keyring entry also holds when the session ends. Every command that uses it moves that time
//! forward (an idle timeout); once it has passed the entry is deleted and the vault is locked.
//! `octapass lock` deletes it straight away.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_device_unlock::{
    Capabilities, DeviceSecret, DeviceUnlock, Error, Result, SECRET_LEN, account_tag,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The keyring service name entries are stored under.
pub const SERVICE: &str = "Octa Pass CLI";
pub const DEFAULT_IDLE: Duration = Duration::from_secs(30 * 60);
pub const IDLE_RANGE: std::ops::RangeInclusive<Duration> =
    Duration::from_secs(60)..=Duration::from_secs(24 * 3600);

/// Where session secrets live. Names are non-secret hashes; values are secret.
pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String>;
    fn set(&self, name: &str, value: &[u8]) -> Result<(), String>;
    fn delete(&self, name: &str) -> Result<(), String>;
}

/// The operating system's keyring.
pub struct OsKeyring;

impl OsKeyring {
    /// The keyring, if this system has one the CLI can use.
    pub fn open() -> Option<Self> {
        keyring::Entry::store_status().is_ok().then_some(Self)
    }

    fn entry(name: &str) -> Result<keyring::Entry, String> {
        keyring::Entry::new(SERVICE, name).map_err(|error| error.to_string())
    }
}

impl SecretStore for OsKeyring {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        match Self::entry(name)?.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn set(&self, name: &str, value: &[u8]) -> Result<(), String> {
        Self::entry(name)?
            .set_secret(value)
            .map_err(|error| error.to_string())
    }

    fn delete(&self, name: &str) -> Result<(), String> {
        match Self::entry(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// What the keyring entry holds.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    secret: String,
    /// Unix seconds.
    expires_at: u64,
    idle_seconds: u64,
}

pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    })
}

/// The desktop vault's device unlock, answered from the keyring instead of Touch ID. There's no
/// prompt: typing the master password into `octapass unlock` is the user's presence.
pub struct KeyringUnlock {
    store: Option<Arc<dyn SecretStore>>,
    idle: Duration,
    clock: Clock,
    /// Octa Pass Connect reads under the session without keeping it alive, so a tool that polls
    /// can't hold the vault open past the idle timeout.
    keep_alive: bool,
}

impl KeyringUnlock {
    /// `store` is `None` on systems without a keyring: then nothing is kept and every command
    /// asks for the master password.
    pub fn new(store: Option<Arc<dyn SecretStore>>, idle: Duration, clock: Clock) -> Self {
        Self {
            store,
            idle,
            clock,
            keep_alive: true,
        }
    }

    /// Unlocking doesn't move the idle deadline forward.
    pub fn without_keep_alive(mut self) -> Self {
        self.keep_alive = false;
        self
    }

    pub fn available(&self) -> bool {
        self.store.is_some()
    }

    fn store(&self) -> Result<&dyn SecretStore> {
        self.store.as_deref().ok_or(Error::Unavailable)
    }

    fn load(&self, account: &str) -> Result<Option<Record>> {
        let Some(bytes) = self
            .store()?
            .get(&account_tag(account))
            .map_err(Error::Platform)?
        else {
            return Ok(None);
        };
        // An entry this version can't read is treated as no session.
        Ok(serde_json::from_slice(&bytes).ok())
    }

    fn save(&self, account: &str, record: &Record) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(record).expect("records serialize"));
        self.store()?
            .set(&account_tag(account), &bytes)
            .map_err(Error::Platform)
    }

    /// When the account's session ends, if there is one. Doesn't count as using it.
    pub fn expires_at(&self, account: &str) -> Option<u64> {
        let record = self.load(account).ok()??;
        (record.expires_at > (self.clock)()).then_some(record.expires_at)
    }
}

impl DeviceUnlock for KeyringUnlock {
    fn capabilities(&self) -> Result<Capabilities> {
        self.store()?;
        Ok(Capabilities {
            method: None,
            device_lock: true,
        })
    }

    fn enroll(&self, account: &str) -> Result<DeviceSecret> {
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        OsRng.fill_bytes(secret.as_mut());
        self.save(
            account,
            &Record {
                secret: b64_encode(secret.as_ref()),
                expires_at: (self.clock)() + self.idle.as_secs(),
                idle_seconds: self.idle.as_secs(),
            },
        )?;
        Ok(secret)
    }

    fn unlock(&self, account: &str, _reason: &str) -> Result<DeviceSecret> {
        let mut record = self.load(account)?.ok_or(Error::NotEnrolled)?;
        let now = (self.clock)();
        if record.expires_at <= now {
            self.remove(account)?;
            return Err(Error::NotEnrolled);
        }
        let bytes = Zeroizing::new(b64_decode(&record.secret).map_err(|_| Error::NotEnrolled)?);
        let secret: [u8; SECRET_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::NotEnrolled)?;
        if self.keep_alive {
            record.expires_at = now + record.idle_seconds;
            // Best effort: a keyring that can be read but not written still unlocks.
            let _ = self.save(account, &record);
        }
        Ok(Zeroizing::new(secret))
    }

    fn verify_user(&self, _reason: &str) -> Result<()> {
        self.store().map(drop)
    }

    fn remove(&self, account: &str) -> Result<()> {
        match &self.store {
            Some(store) => store.delete(&account_tag(account)).map_err(Error::Platform),
            None => Ok(()),
        }
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

/// Parses `90s`, `15m`, `2h` or a plain number of minutes.
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    let (number, unit) = match text.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((at, _)) => text.split_at(at),
        None => (text, "m"),
    };
    let number: u64 = number
        .parse()
        .map_err(|_| format!("`{text}` isn't a duration (try 15m or 2h)"))?;
    let seconds = match unit.trim() {
        "s" => number,
        "m" | "min" => number.saturating_mul(60),
        "h" => number.saturating_mul(3600),
        _ => return Err(format!("`{text}` isn't a duration (try 15m or 2h)")),
    };
    let duration = Duration::from_secs(seconds);
    if !IDLE_RANGE.contains(&duration) {
        return Err("the timeout must be between 1 minute and 24 hours".into());
    }
    Ok(duration)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    #[derive(Default)]
    struct Memory(Mutex<HashMap<String, Vec<u8>>>);

    impl SecretStore for Memory {
        fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .map(Zeroizing::new))
        }
        fn set(&self, name: &str, value: &[u8]) -> Result<(), String> {
            self.0.lock().unwrap().insert(name.into(), value.to_vec());
            Ok(())
        }
        fn delete(&self, name: &str) -> Result<(), String> {
            self.0.lock().unwrap().remove(name);
            Ok(())
        }
    }

    fn setup() -> (Arc<Memory>, Arc<AtomicU64>, KeyringUnlock) {
        let store = Arc::new(Memory::default());
        let time = Arc::new(AtomicU64::new(1_000));
        let clock = Arc::clone(&time);
        let unlock = KeyringUnlock::new(
            Some(store.clone()),
            Duration::from_secs(600),
            Arc::new(move || clock.load(Ordering::SeqCst)),
        );
        (store, time, unlock)
    }

    #[test]
    fn a_session_lasts_while_it_is_used() {
        let (store, time, unlock) = setup();
        let secret = unlock.enroll("server|a@example.com").unwrap();
        assert_eq!(unlock.expires_at("server|a@example.com"), Some(1_600));

        time.store(1_500, Ordering::SeqCst);
        assert_eq!(*unlock.unlock("server|a@example.com", "").unwrap(), *secret);
        assert_eq!(unlock.expires_at("server|a@example.com"), Some(2_100));

        time.store(2_100, Ordering::SeqCst);
        assert_eq!(unlock.expires_at("server|a@example.com"), None);
        assert_eq!(
            unlock.unlock("server|a@example.com", "").unwrap_err(),
            Error::NotEnrolled
        );
        assert!(store.0.lock().unwrap().is_empty(), "expired entries go");
    }

    #[test]
    fn reads_without_keep_alive_dont_extend_the_session() {
        let (store, time, unlock) = setup();
        unlock.enroll("server|a@example.com").unwrap();
        let clock = Arc::clone(&time);
        let reader = KeyringUnlock::new(
            Some(store),
            Duration::from_secs(600),
            Arc::new(move || clock.load(Ordering::SeqCst)),
        )
        .without_keep_alive();
        time.store(1_500, Ordering::SeqCst);
        reader.unlock("server|a@example.com", "").unwrap();
        assert_eq!(unlock.expires_at("server|a@example.com"), Some(1_600));
    }

    #[test]
    fn entries_are_per_account_and_named_by_hash() {
        let (store, _, unlock) = setup();
        unlock.enroll("server|a@example.com").unwrap();
        assert_eq!(
            unlock.unlock("server|b@example.com", "").unwrap_err(),
            Error::NotEnrolled
        );
        let names: Vec<String> = store.0.lock().unwrap().keys().cloned().collect();
        assert_eq!(names, [account_tag("server|a@example.com")]);
        assert!(!names[0].contains('@'));

        unlock.remove("server|a@example.com").unwrap();
        unlock.remove("server|a@example.com").unwrap();
        assert!(store.0.lock().unwrap().is_empty());
    }

    #[test]
    fn a_damaged_entry_is_no_session() {
        let (store, _, unlock) = setup();
        store
            .set(&account_tag("server|a@example.com"), b"not json")
            .unwrap();
        assert_eq!(unlock.expires_at("server|a@example.com"), None);
        assert_eq!(
            unlock.unlock("server|a@example.com", "").unwrap_err(),
            Error::NotEnrolled
        );
    }

    #[test]
    fn without_a_keyring_nothing_is_kept() {
        let unlock = KeyringUnlock::new(None, DEFAULT_IDLE, system_clock());
        assert!(!unlock.available());
        assert_eq!(unlock.enroll("a").unwrap_err(), Error::Unavailable);
        assert_eq!(unlock.verify_user("").unwrap_err(), Error::Unavailable);
        assert_eq!(unlock.unlock("a", "").unwrap_err(), Error::Unavailable);
        unlock.remove("a").unwrap();
    }

    /// Read-only, so it never changes this computer's keyring.
    #[test]
    fn the_os_keyring_reports_a_missing_entry_as_none() {
        if let Some(keyring) = OsKeyring::open() {
            assert_eq!(keyring.get("octapass-cli-test-missing-entry"), Ok(None));
        }
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("15").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        for bad in ["", "m", "10x", "30s", "25h", "-5m"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }
}
