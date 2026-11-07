//! An unlocked account: holds the ASK and open vault keys, and encrypts and decrypts items.
//!
//! Dropping the session zeroes every key it holds; that is what "lock" means.

use std::collections::HashMap;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::account::{AccountBundle, AccountKeyPairs, NewAccount, parse_id};
use crate::device::{self, DeviceUnlock};
use crate::envelope::{Context, open_b64, seal_b64, unwrap_key, wrap_key};
use crate::error::{Error, Result};
use crate::item::{Item, ItemOverview};
use crate::keys::SymmetricKey;
use crate::recovery::RecoveryCode;
use crate::sharing::pq::PqKeyPair;
use crate::sharing::seal::Opener;

/// The encrypted form of an item, as sent in `PUT /v1/vaults/{vaultId}/items/{itemId}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedItem {
    pub encrypted_item_key: String,
    pub overview: String,
    pub details: String,
}

pub struct Session {
    ask: SymmetricKey,
    key_pairs: AccountKeyPairs,
    pq_keys: Option<PqKeyPair>,
    bundle: AccountBundle,
    vault_keys: HashMap<String, SymmetricKey>,
}

impl Session {
    /// Unlocks with the AUK derived from password + Secret Key. Fails with
    /// [`Error::LoginFailed`] if they are wrong.
    pub fn unlock(bundle: AccountBundle, auk: &SymmetricKey) -> Result<Self> {
        let ask = bundle
            .unwrap_ask(auk)
            .map_err(|error| wrong_secret(error, Error::LoginFailed))?;
        Self::with_ask(bundle, ask)
    }

    /// Unlocks with the recovery code instead of password + Secret Key. Fails with
    /// [`Error::InvalidRecoveryCode`] if it is not this account's code.
    pub fn recover(bundle: AccountBundle, code: &RecoveryCode) -> Result<Self> {
        let ask = bundle
            .unwrap_ask_with_recovery(code)
            .map_err(|error| wrong_secret(error, Error::InvalidRecoveryCode))?;
        Self::with_ask(bundle, ask)
    }

    /// Unlocks with this device's key (see [`crate::device`]). Fails with
    /// [`Error::DeviceUnlockFailed`] if the PRF output or salt doesn't match the wrapped ASK.
    pub fn unlock_with_device_key(
        bundle: AccountBundle,
        prf_output: &[u8],
        device_salt: &[u8],
        wrapped_ask: &str,
    ) -> Result<Self> {
        let key = device::device_key(prf_output, device_salt)?;
        let ask = unwrap_key(&key, &Context::DeviceUnlock, wrapped_ask)
            .map_err(|error| wrong_secret(error, Error::DeviceUnlockFailed))?;
        // Opening the private keys proves this is the bundle's own ASK, not one for another account.
        Self::with_ask(bundle, ask).map_err(|error| wrong_secret(error, Error::DeviceUnlockFailed))
    }

    /// Wraps the ASK for device unlock with a fresh device salt. The result stays on the device.
    pub fn enable_device_unlock(
        &self,
        prf_output: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<DeviceUnlock> {
        let device_salt = device::generate_device_salt(rng);
        let key = device::device_key(prf_output, &device_salt)?;
        let wrapped_ask = wrap_key(&key, &Context::DeviceUnlock, &self.ask, rng)?;
        Ok(DeviceUnlock {
            device_salt,
            wrapped_ask,
        })
    }

    /// The session right after sign-up, with the personal vault already open.
    pub fn from_new_account(account: &NewAccount) -> Result<Self> {
        let mut session = Self::with_ask(account.bundle.clone(), account.ask.clone())?;
        session.vault_keys.insert(
            account.personal_vault.id.clone(),
            account.personal_vault_key.clone(),
        );
        Ok(session)
    }

    /// A session over an ASK that was unwrapped another way: a local vault's, whose bundle is the
    /// same key hierarchy without an account on a server.
    #[cfg(feature = "strength")] // only local vaults open a session from a bare ASK
    pub(crate) fn from_ask(bundle: AccountBundle, ask: SymmetricKey) -> Result<Self> {
        Self::with_ask(bundle, ask)
    }

    pub(crate) fn with_ask(bundle: AccountBundle, ask: SymmetricKey) -> Result<Self> {
        let key_pairs = bundle.open_key_pairs(&ask)?;
        let pq_keys = bundle.open_pq_keys(&ask)?;
        Ok(Self {
            ask,
            key_pairs,
            pq_keys,
            bundle,
            vault_keys: HashMap::new(),
        })
    }

    pub fn bundle(&self) -> &AccountBundle {
        &self.bundle
    }

    pub fn key_pairs(&self) -> &AccountKeyPairs {
        &self.key_pairs
    }

    /// The ML-KEM key pair, once the account has one.
    pub fn pq_keys(&self) -> Option<&PqKeyPair> {
        self.pq_keys.as_ref()
    }

    /// The private keys that open what is sealed to this account.
    pub(crate) fn opener(&self) -> Opener<'_> {
        Opener {
            x25519: self.key_pairs.encryption_key(),
            pq: self.pq_keys.as_ref(),
        }
    }

    pub(crate) fn set_pq_keys(&mut self, keys: PqKeyPair) {
        self.pq_keys = Some(keys);
    }

    /// The bundle after a change the server accepted, such as new credentials. The ASK and key
    /// pairs stay.
    pub(crate) fn set_bundle(&mut self, bundle: AccountBundle) {
        self.bundle = bundle;
    }

    pub(crate) fn ask(&self) -> &SymmetricKey {
        &self.ask
    }

    /// The account id from the bundle. Bundles from the server always have one.
    pub(crate) fn account_id(&self) -> Result<String> {
        let id = self.bundle.account_id.as_deref();
        parse_id(id.ok_or(Error::InvalidAccountBundle)?)
    }

    /// Keeps a vault key opened some other way than [`Session::open_vault`] (a shared vault's
    /// grant, an emergency release).
    pub(crate) fn insert_vault_key(&mut self, vault_id: String, key: SymmetricKey) {
        self.vault_keys.insert(vault_id, key);
    }

    /// Unwraps a personal vault's key (from a `VaultRecord`) and keeps it for this session.
    pub fn open_vault(&mut self, vault_id: &str, wrapped_vault_key: &str) -> Result<()> {
        let vault_id = parse_id(vault_id)?;
        let key = unwrap_key(
            &self.ask,
            &Context::VaultKey {
                vault_id: &vault_id,
            },
            wrapped_vault_key,
        )?;
        self.vault_keys.insert(vault_id, key);
        Ok(())
    }

    /// Forgets a vault's key: the vault is gone, or its key can no longer be trusted.
    pub fn close_vault(&mut self, vault_id: &str) {
        if let Ok(id) = parse_id(vault_id) {
            self.vault_keys.remove(&id);
        }
    }

    pub fn is_vault_open(&self, vault_id: &str) -> bool {
        parse_id(vault_id).is_ok_and(|id| self.vault_keys.contains_key(&id))
    }

    /// Encrypts an item. Pass the item's current `encryptedItemKey` when updating it, so the item
    /// keeps its key; otherwise a new random item key is generated.
    pub fn encrypt_item(
        &self,
        vault_id: &str,
        item_id: &str,
        item: &Item,
        existing_item_key: Option<&str>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<EncryptedItem> {
        let (vault_id, item_id) = (parse_id(vault_id)?, parse_id(item_id)?);
        let vault_key = self.vault_key(&vault_id)?;
        seal_item(vault_key, &vault_id, &item_id, item, existing_item_key, rng)
    }

    /// Decrypts only the overview: enough for lists and autofill matching.
    pub fn decrypt_overview(
        &self,
        vault_id: &str,
        item_id: &str,
        encrypted: &EncryptedItem,
    ) -> Result<ItemOverview> {
        let (vault_id, item_id) = (parse_id(vault_id)?, parse_id(item_id)?);
        open_overview(self.vault_key(&vault_id)?, &vault_id, &item_id, encrypted)
    }

    pub fn decrypt_item(
        &self,
        vault_id: &str,
        item_id: &str,
        encrypted: &EncryptedItem,
    ) -> Result<Item> {
        let (vault_id, item_id) = (parse_id(vault_id)?, parse_id(item_id)?);
        open_item(self.vault_key(&vault_id)?, &vault_id, &item_id, encrypted)
    }

    /// The key of an open vault, by its normalised id.
    pub(crate) fn vault_key(&self, vault_id: &str) -> Result<&SymmetricKey> {
        self.vault_keys.get(vault_id).ok_or(Error::VaultNotOpen)
    }
}

/// Encrypts an item under a vault key, for sessions and service accounts alike. Ids are normalised.
pub(crate) fn seal_item(
    vault_key: &SymmetricKey,
    vault_id: &str,
    item_id: &str,
    item: &Item,
    existing_item_key: Option<&str>,
    rng: &mut impl CryptoRngCore,
) -> Result<EncryptedItem> {
    let key_context = Context::ItemKey { vault_id, item_id };
    let item_key = match existing_item_key {
        Some(wrapped) => unwrap_key(vault_key, &key_context, wrapped)?,
        None => SymmetricKey::generate(rng),
    };
    let overview = zeroizing_json(&item.overview);
    let details = zeroizing_json(&item.details);
    Ok(EncryptedItem {
        encrypted_item_key: wrap_key(vault_key, &key_context, &item_key, rng)?,
        overview: seal_b64(
            &item_key,
            &Context::ItemOverview { vault_id, item_id },
            overview.as_bytes(),
            rng,
        )?,
        details: seal_b64(
            &item_key,
            &Context::ItemDetails { vault_id, item_id },
            details.as_bytes(),
            rng,
        )?,
    })
}

fn unwrap_item_key(
    vault_key: &SymmetricKey,
    vault_id: &str,
    item_id: &str,
    encrypted: &EncryptedItem,
) -> Result<SymmetricKey> {
    unwrap_key(
        vault_key,
        &Context::ItemKey { vault_id, item_id },
        &encrypted.encrypted_item_key,
    )
}

/// Decrypts only the overview under a vault key. Ids are normalised.
pub(crate) fn open_overview(
    vault_key: &SymmetricKey,
    vault_id: &str,
    item_id: &str,
    encrypted: &EncryptedItem,
) -> Result<ItemOverview> {
    let item_key = unwrap_item_key(vault_key, vault_id, item_id, encrypted)?;
    let overview = open_b64(
        &item_key,
        &Context::ItemOverview { vault_id, item_id },
        &encrypted.overview,
    )?;
    serde_json::from_slice(&overview).map_err(|_| Error::InvalidItem)
}

/// Decrypts an item under a vault key. Ids are normalised.
pub(crate) fn open_item(
    vault_key: &SymmetricKey,
    vault_id: &str,
    item_id: &str,
    encrypted: &EncryptedItem,
) -> Result<Item> {
    let item_key = unwrap_item_key(vault_key, vault_id, item_id, encrypted)?;
    let overview = open_b64(
        &item_key,
        &Context::ItemOverview { vault_id, item_id },
        &encrypted.overview,
    )?;
    let details = open_b64(
        &item_key,
        &Context::ItemDetails { vault_id, item_id },
        &encrypted.details,
    )?;
    Item::from_parts(
        serde_json::from_slice(&overview).map_err(|_| Error::InvalidItem)?,
        serde_json::from_slice(&details).map_err(|_| Error::InvalidItem)?,
    )
}

/// A key that doesn't open the ASK means the user typed the wrong secret; anything else (a
/// malformed bundle) is reported as it is.
fn wrong_secret(error: Error, instead: Error) -> Error {
    match error {
        Error::WrongKey | Error::DecryptionFailed => instead,
        other => other,
    }
}

fn zeroizing_json(value: &impl Serialize) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(serde_json::to_string(value).expect("items serialize infallibly"))
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::encoding::b64_encode;
    use crate::envelope::seal_b64;
    use crate::kdf::KdfParams;

    /// An account bundle built directly from keys, skipping Argon2id.
    fn account(rng: &mut ChaCha20Rng) -> (AccountBundle, SymmetricKey) {
        let auk = SymmetricKey::generate(rng);
        let ask = SymmetricKey::generate(rng);
        let pairs = AccountKeyPairs::generate(rng);
        let bundle = AccountBundle {
            account_id: None,
            email: "a@example.com".into(),
            kdf: KdfParams::DEFAULT,
            account_salt: b64_encode(&[0; 16]),
            wrapped_ask: wrap_key(&auk, &Context::Ask, &ask, rng).unwrap(),
            public_enc_key: b64_encode(&pairs.public_enc_key()),
            public_sign_key: b64_encode(&pairs.public_sign_key()),
            wrapped_private_keys: seal_b64(
                &ask,
                &Context::PrivateKeys,
                pairs.to_bytes().as_ref(),
                rng,
            )
            .unwrap(),
            recovery_wrapped_ask: String::new(),
            wrapped_pq_private_key: None,
            key_record: None,
        };
        (bundle, auk)
    }

    #[test]
    fn device_unlock_round_trip() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (bundle, auk) = account(&mut rng);
        let session = Session::unlock(bundle.clone(), &auk).unwrap();
        let prf = [7u8; 32];
        let device = session.enable_device_unlock(&prf, &mut rng).unwrap();

        let unlocked = Session::unlock_with_device_key(
            bundle.clone(),
            &prf,
            &device.device_salt,
            &device.wrapped_ask,
        )
        .unwrap();
        assert_eq!(unlocked.ask, session.ask);

        let again = session.enable_device_unlock(&prf, &mut rng).unwrap();
        assert_ne!(
            again.device_salt, device.device_salt,
            "each enable gets a fresh salt"
        );
    }

    #[test]
    fn device_unlock_rejects_the_wrong_device_or_account() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let (bundle, auk) = account(&mut rng);
        let device = Session::unlock(bundle.clone(), &auk)
            .unwrap()
            .enable_device_unlock(&[7; 32], &mut rng)
            .unwrap();
        let unlock = |bundle: &AccountBundle, prf: &[u8], salt: &[u8]| {
            Session::unlock_with_device_key(bundle.clone(), prf, salt, &device.wrapped_ask).err()
        };

        assert_eq!(
            unlock(&bundle, &[8; 32], &device.device_salt),
            Some(Error::DeviceUnlockFailed)
        );
        assert_eq!(
            unlock(&bundle, &[7; 32], &[0; 16]),
            Some(Error::DeviceUnlockFailed)
        );
        assert_eq!(
            unlock(&bundle, &[7; 16], &device.device_salt),
            Some(Error::InvalidKey)
        );
        let (other_account, _) = account(&mut rng);
        assert_eq!(
            unlock(&other_account, &[7; 32], &device.device_salt),
            Some(Error::DeviceUnlockFailed)
        );
    }

    #[test]
    fn wrong_password_is_login_failed() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let (bundle, _) = account(&mut rng);
        let wrong = SymmetricKey::generate(&mut rng);
        assert_eq!(
            Session::unlock(bundle, &wrong).err(),
            Some(Error::LoginFailed)
        );
    }
}
