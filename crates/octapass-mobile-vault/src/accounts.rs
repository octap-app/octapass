//! The accounts signed in on this phone, in `accounts.json` next to their stores in the shared
//! container. The AutoFill extension reads the same file to find the current account's store and
//! Keychain items, so its shape is a contract with `apps/ios/Packages/AutoFillKit`.
//!
//! Nothing here is secret: emails, server URLs and file names. The Secret Key, the refresh token,
//! the trusted-device token and the device-unlock secret are Keychain items named after the
//! account's tag.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, VaultError};

const FILE: &str = "accounts.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// Stable per server and email; names the store file and the Keychain items.
    pub tag: String,
    pub email: String,
    pub server_url: String,
    /// Set for a vault on this device only: `server_url` is `local:<vault id>`, `email` the
    /// vault's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<LocalAccount>,
}

/// What this phone remembers about a local vault, next to its store. Nothing here is secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalAccount {
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backup_at: Option<String>,
    /// The vault's last change the newest backup holds (Unix ms): automatic backups run when
    /// the vault has moved on from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backed_up_change: Option<u64>,
    /// Where automatic backups go: a platform reference (a security-scoped bookmark, a tree URI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_folder: Option<String>,
    /// What the user calls that folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_folder_name: Option<String>,
    /// What this vault's chip key works from, base64url; set when the vault is bound to the
    /// device chip. Not a secret. The extensions read it to unlock with the master password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chip_context: Option<String>,
}

impl Account {
    pub fn new(server_url: &str, email: &str) -> Self {
        let digest = Sha256::digest(format!("{server_url}|{email}").as_bytes());
        Self {
            tag: digest[..16]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            email: email.to_owned(),
            server_url: server_url.to_owned(),
            local: None,
        }
    }

    pub fn is_local(&self) -> bool {
        self.local.is_some()
    }

    /// A local vault's own file next to its store: see [`octapass_core::local::LocalVault::seed`].
    pub fn seed_file(&self) -> String {
        format!("{}.oplocal", self.tag)
    }

    /// The device chip key that binds a local vault to this phone.
    pub fn chip_key_name(&self) -> String {
        format!("chipKey.{}", self.tag)
    }

    pub fn store_file(&self) -> String {
        format!("{}.opstore", self.tag)
    }

    pub fn secret_key_name(&self) -> String {
        format!("secretKey.{}", self.tag)
    }

    pub fn refresh_token_name(&self) -> String {
        format!("refreshToken.{}", self.tag)
    }

    /// Skips two-step sign-in on this phone. It outlives an expired session, not a sign-out.
    pub fn trusted_device_name(&self) -> String {
        format!("trustedDevice.{}", self.tag)
    }

    pub fn device_secret_name(&self) -> String {
        format!("deviceSecret.{}", self.tag)
    }

    /// The stay-unlocked key (plan 18), kept where the phone's lock guards it with no prompt.
    pub fn stay_unlocked_name(&self) -> String {
        format!("stayUnlocked.{}", self.tag)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Accounts {
    #[serde(default)]
    pub accounts: Vec<Account>,
    /// The tag of the account the app opens on and the extension fills from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
}

impl Accounts {
    pub fn load(dir: &Path) -> Result<Self> {
        match fs::read(dir.join(FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| VaultError::unexpected(format!("{FILE}: {error}"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(io_error(error)),
        }
    }

    /// Written atomically: the extension may be reading it.
    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir).map_err(io_error)?;
        let temporary = dir.join(format!("{FILE}.tmp"));
        let mut file = fs::File::create(&temporary).map_err(io_error)?;
        file.write_all(&serde_json::to_vec_pretty(self).expect("accounts serialize"))
            .and_then(|()| file.sync_all())
            .map_err(io_error)?;
        fs::rename(&temporary, dir.join(FILE)).map_err(io_error)
    }

    pub fn current(&self) -> Option<&Account> {
        let tag = self.current.as_deref()?;
        self.accounts.iter().find(|account| account.tag == tag)
    }

    pub fn find(&self, server_url: &str, email: &str) -> Option<&Account> {
        self.accounts
            .iter()
            .find(|account| account.server_url == server_url && account.email == email)
    }

    pub fn upsert_current(&mut self, account: Account) {
        self.current = Some(account.tag.clone());
        self.accounts.retain(|existing| existing.tag != account.tag);
        self.accounts.push(account);
    }

    pub fn find_tag(&self, tag: &str) -> Option<&Account> {
        self.accounts.iter().find(|account| account.tag == tag)
    }

    pub fn find_tag_mut(&mut self, tag: &str) -> Option<&mut Account> {
        self.accounts.iter_mut().find(|account| account.tag == tag)
    }

    pub fn remove(&mut self, tag: &str) {
        self.accounts.retain(|account| account.tag != tag);
        if self.current.as_deref() == Some(tag) {
            self.current = None;
        }
    }
}

pub fn store_path(dir: &Path, account: &Account) -> PathBuf {
    dir.join(account.store_file())
}

fn io_error(error: std::io::Error) -> VaultError {
    VaultError::unexpected(format!("storage: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_stable_and_hide_the_email() {
        let a = Account::new("https://vault.octap.app/", "a@example.com");
        assert_eq!(a, Account::new("https://vault.octap.app/", "a@example.com"));
        assert_ne!(
            a.tag,
            Account::new("http://localhost:8080/", "a@example.com").tag
        );
        assert_eq!(a.tag.len(), 32);
        assert!(!a.store_file().contains('@'));
        assert_eq!(a.secret_key_name(), format!("secretKey.{}", a.tag));
    }

    #[test]
    fn the_file_round_trips_and_a_missing_one_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Accounts::load(dir.path()).unwrap(), Accounts::default());
        let mut accounts = Accounts::default();
        let account = Account::new("https://s/", "a@example.com");
        accounts.upsert_current(account.clone());
        accounts.upsert_current(account.clone());
        accounts.save(dir.path()).unwrap();
        let loaded = Accounts::load(dir.path()).unwrap();
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.current(), Some(&account));
        assert_eq!(loaded.find("https://s/", "a@example.com"), Some(&account));

        let mut loaded = loaded;
        loaded.remove(&account.tag);
        assert!(loaded.current().is_none() && loaded.accounts.is_empty());
    }
}
