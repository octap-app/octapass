//! The stay-unlocked key (plan 18): the account key wrapped exactly as for device unlock, under a
//! secret the app keeps where the phone's own lock guards it but nothing asks for it (iOS: a
//! Keychain item with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and no biometry flag;
//! Android: a Keystore key with `setUnlockedDeviceRequired(true)` and no user-authentication
//! requirement).
//!
//! The app and its autofill extensions only ever hold the opaque bytes [`LocalStore::stay_unlocked_key`]
//! returns, and hand them back to [`LocalStore::unlock_stay_unlocked`]. Nothing is written to the
//! store: the key lives in one platform item, so deleting that item ends it.
//!
//! ```text
//! key = 0x01 ‖ secret (32) ‖ device_salt (16) ‖ wrapped ASK (base64url, context "device-unlock")
//! ```
//!
//! The 14-day master password rule applies to it as to device unlock: when it's due,
//! `unlock_stay_unlocked` fails with `PasswordRequired` until the password unlocks once.
//!
//! **The fill key** (plan 03, *Two device-auth gates*, the autofill gate off): the same key with
//! the moment it stops working in front, which the app keeps in the same kind of platform item
//! while its own vault is unlocked, and deletes when it locks. The autofill extension or services
//! fill with it without a prompt until then ([`LocalStore::unlock_fill_key`]); the deadline is the
//! app's lock timer, so a suspended app that can't delete it in time still stops it.
//!
//! ```text
//! fill key = 0x02 ‖ expires at (u64 big-endian, ms since 1970) ‖ stay-unlocked key
//! ```

use std::sync::Arc;

use octapass_core::device::DEVICE_SALT_LEN;
use octapass_core::session::Session as CoreSession;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use super::{LocalStore, password_due};
use crate::error::{OctaPassError, Result};
use crate::session::Session;

const FORMAT: u8 = 1;
const FILL_FORMAT: u8 = 2;
const FILL_HEADER_LEN: usize = 1 + 8;
const SECRET_LEN: usize = 32;
const HEADER_LEN: usize = 1 + SECRET_LEN + DEVICE_SALT_LEN;

#[uniffi::export]
impl LocalStore {
    /// A new stay-unlocked key for the session's account: keep the bytes in the platform's
    /// stay-unlocked item, never anywhere readable without the device unlocked. Each call makes a
    /// new key; the old one keeps working until its item is deleted.
    pub fn stay_unlocked_key(&self, session: Arc<Session>) -> Result<Vec<u8>> {
        self.check_account(&session)?;
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        OsRng.fill_bytes(secret.as_mut());
        let wrapped =
            session.with(|core| Ok(core.enable_device_unlock(secret.as_ref(), &mut OsRng)?))?;
        let mut key = Vec::with_capacity(HEADER_LEN + wrapped.wrapped_ask.len());
        key.push(FORMAT);
        key.extend_from_slice(secret.as_ref());
        key.extend_from_slice(&wrapped.device_salt);
        key.extend_from_slice(wrapped.wrapped_ask.as_bytes());
        Ok(key)
    }

    /// Unlocks with what [`stay_unlocked_key`](Self::stay_unlocked_key) returned, without a
    /// prompt. Fails with `PasswordRequired` while the 14-day master password check is due, and
    /// `DeviceUnlockFailed` when the key doesn't open this account (delete it then).
    pub fn unlock_stay_unlocked(&self, key: Vec<u8>) -> Result<Arc<Session>> {
        let key = Zeroizing::new(key);
        let data = self.data().clone();
        if password_due(&data) {
            return Err(OctaPassError::PasswordRequired);
        }
        if key.len() <= HEADER_LEN || key[0] != FORMAT {
            return Err(OctaPassError::DeviceUnlockFailed);
        }
        let secret = &key[1..1 + SECRET_LEN];
        let salt = &key[1 + SECRET_LEN..HEADER_LEN];
        let wrapped_ask = std::str::from_utf8(&key[HEADER_LEN..])
            .map_err(|_| OctaPassError::DeviceUnlockFailed)?;
        let session = CoreSession::unlock_with_device_key(data.account, secret, salt, wrapped_ask)?;
        Ok(Session::new(session))
    }

    /// A fill key for the session's account that works until `expires_at_ms` (ms since 1970):
    /// keep it in the same kind of platform item as the stay-unlocked key, and delete it when the
    /// app's vault locks.
    pub fn fill_key(&self, session: Arc<Session>, expires_at_ms: u64) -> Result<Vec<u8>> {
        let inner = Zeroizing::new(self.stay_unlocked_key(session)?);
        let mut key = Vec::with_capacity(FILL_HEADER_LEN + inner.len());
        key.push(FILL_FORMAT);
        key.extend_from_slice(&expires_at_ms.to_be_bytes());
        key.extend_from_slice(&inner);
        Ok(key)
    }

    /// Unlocks with what [`fill_key`](Self::fill_key) returned, without a prompt. `None` once it
    /// has expired (the app's vault has locked by now): ask as before, and delete it. Fails like
    /// [`unlock_stay_unlocked`](Self::unlock_stay_unlocked) otherwise.
    pub fn unlock_fill_key(&self, key: Vec<u8>) -> Result<Option<Arc<Session>>> {
        let key = Zeroizing::new(key);
        if key.len() <= FILL_HEADER_LEN || key[0] != FILL_FORMAT {
            return Err(OctaPassError::DeviceUnlockFailed);
        }
        let mut expires = [0u8; 8];
        expires.copy_from_slice(&key[1..FILL_HEADER_LEN]);
        if crate::now_ms() >= u64::from_be_bytes(expires) {
            return Ok(None);
        }
        self.unlock_stay_unlocked(key[FILL_HEADER_LEN..].to_vec())
            .map(Some)
    }

    /// The 14-day master password check is due: the stay-unlocked key won't open the vault
    /// until the master password unlocks it once.
    pub fn password_required(&self) -> bool {
        password_due(&self.data())
    }
}

#[cfg(test)]
mod tests {
    use octapass_core::kdf::KdfParams;
    use octapass_core::local::{DeviceProtection, LocalVault};

    use super::*;
    use crate::now_ms;
    use crate::store::PASSWORD_INTERVAL_MS;

    const PASSWORD: &str = "vexed-kiwi-trumpet-galaxy-oboe";

    fn store(dir: &tempfile::TempDir) -> (Arc<LocalStore>, Arc<Session>) {
        let vault = LocalVault::create_with_backup_kdf(
            PASSWORD,
            DeviceProtection {
                kdf: KdfParams::DEFAULT,
                hardware_secret: None,
            },
            KdfParams::DEFAULT,
            now_ms(),
            &mut OsRng,
        )
        .unwrap();
        let path = dir.path().join("a.opstore").to_string_lossy().into_owned();
        let store = LocalStore::create_local(path, "local:v".into(), &vault).unwrap();
        let session = store.unlock_local(PASSWORD.into(), None).unwrap();
        (store, session)
    }

    #[test]
    fn the_key_opens_the_vault_without_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let (store, session) = store(&dir);
        let key = store.stay_unlocked_key(session).unwrap();
        assert_eq!(key[0], FORMAT);
        // The AutoFill extension opens the same file with the same bytes.
        let other =
            LocalStore::open(dir.path().join("a.opstore").to_string_lossy().into()).unwrap();
        assert!(other.unlock_stay_unlocked(key).is_ok());
    }

    #[test]
    fn the_14_day_check_stops_it() {
        let dir = tempfile::tempdir().unwrap();
        let (store, session) = store(&dir);
        let key = store.stay_unlocked_key(session).unwrap();
        store
            .mutate(|data| {
                data.password_unlocked_at = now_ms() - PASSWORD_INTERVAL_MS - 1;
                Ok(())
            })
            .unwrap();
        assert!(store.password_required());
        assert!(matches!(
            store.unlock_stay_unlocked(key.clone()),
            Err(OctaPassError::PasswordRequired)
        ));
        // Typing the master password once starts it again.
        store.unlock_local(PASSWORD.into(), None).unwrap();
        assert!(!store.password_required());
        assert!(store.unlock_stay_unlocked(key).is_ok());
    }

    #[test]
    fn the_fill_key_opens_the_vault_until_it_expires() {
        let dir = tempfile::tempdir().unwrap();
        let (store, session) = store(&dir);
        let later = now_ms() + 60_000;
        let key = store.fill_key(session.clone(), later).unwrap();
        assert_eq!(key[0], FILL_FORMAT);
        let other =
            LocalStore::open(dir.path().join("a.opstore").to_string_lossy().into()).unwrap();
        assert!(other.unlock_fill_key(key.clone()).unwrap().is_some());
        // Not a stay-unlocked key, and a stay-unlocked key isn't a fill key.
        assert!(matches!(
            other.unlock_stay_unlocked(key),
            Err(OctaPassError::DeviceUnlockFailed)
        ));
        let stay = store.stay_unlocked_key(session.clone()).unwrap();
        assert!(matches!(
            other.unlock_fill_key(stay),
            Err(OctaPassError::DeviceUnlockFailed)
        ));
        // Past its deadline it opens nothing.
        let expired = store.fill_key(session.clone(), now_ms() - 1).unwrap();
        assert!(other.unlock_fill_key(expired).unwrap().is_none());
        // The key under the deadline is checked as before.
        let mut damaged = store.fill_key(session, later).unwrap();
        damaged[FILL_HEADER_LEN + 1] ^= 1;
        assert!(matches!(
            other.unlock_fill_key(damaged),
            Err(OctaPassError::DeviceUnlockFailed)
        ));
        for bad in [vec![], vec![FILL_FORMAT; FILL_HEADER_LEN]] {
            assert!(matches!(
                other.unlock_fill_key(bad),
                Err(OctaPassError::DeviceUnlockFailed)
            ));
        }
    }

    #[test]
    fn the_14_day_check_stops_the_fill_key() {
        let dir = tempfile::tempdir().unwrap();
        let (store, session) = store(&dir);
        let key = store.fill_key(session, now_ms() + 60_000).unwrap();
        store
            .mutate(|data| {
                data.password_unlocked_at = now_ms() - PASSWORD_INTERVAL_MS - 1;
                Ok(())
            })
            .unwrap();
        assert!(matches!(
            store.unlock_fill_key(key),
            Err(OctaPassError::PasswordRequired)
        ));
    }

    #[test]
    fn a_damaged_or_foreign_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (store, session) = store(&dir);
        let mut key = store.stay_unlocked_key(session).unwrap();
        for bad in [vec![], vec![FORMAT; HEADER_LEN], vec![2; key.len()]] {
            assert!(matches!(
                store.unlock_stay_unlocked(bad),
                Err(OctaPassError::DeviceUnlockFailed)
            ));
        }
        key[1] ^= 1;
        assert!(matches!(
            store.unlock_stay_unlocked(key),
            Err(OctaPassError::DeviceUnlockFailed)
        ));

        let other_dir = tempfile::tempdir().unwrap();
        let (_, other_session) = self::store(&other_dir);
        assert!(matches!(
            store.stay_unlocked_key(other_session),
            Err(OctaPassError::InvalidStore)
        ));
    }
}
