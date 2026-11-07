//! Local mode: a vault on one device with no account and no server (plan 03, *Local mode keys*).
//!
//! The key hierarchy below the ASK is the one synced accounts use (ASK → vault key → item keys,
//! the same envelopes and associated data), so [turning on sync](LocalVault::upgrade_to_account)
//! only re-wraps the ASK. What differs is how the ASK is protected:
//!
//! ```text
//! LUK        = see `keys`: Argon2id of the master password (+ the device chip's secret, if any)
//! wrappedAsk = AEAD(LUK, ASK, context "local-ask")
//! body       = AEAD(ASK, vault JSON, context "local-vault")
//! ```
//!
//! The vault is one blob for the app to store (`to_bytes`), JSON:
//! `{ format: "octapass-local-vault", version: 1, kdf, salt, hardwareBound, wrappedAsk, body }`.
//! The body holds the account key pairs (sealed by the ASK), the personal vault's wrapped key,
//! every item as `{ id, encryptedItemKey, overview, details, createdAt, updatedAt, deletedAt? }`
//! (Unix milliseconds), the backup settings (the backup key and the backup recovery code) and the
//! vault's name, if it has one.
//!
//! Clients that keep the items somewhere else (the phones' shared store, which the AutoFill
//! extensions read) keep a [seed](LocalVault::seed) instead: the same blob with no items in it.

pub mod keys;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::account::{AccountBundle, AccountKeyPairs, NewAccount, NewVault, new_id, parse_id};
use crate::backup::{self, BACKUP_KDF, BackupKey};
use crate::device::{self, DeviceUnlock};
use crate::encoding::{b64_decode, b64_decode_array, b64_encode};
use crate::envelope::{Context, open_b64, seal_b64, unwrap_key, wrap_key};
use crate::error::{Error, Result};
use crate::item::{Item, ItemOverview};
use crate::kdf::{AccountKeys, KdfParams, generate_account_salt, normalize_email};
use crate::keys::SymmetricKey;
use crate::recovery::RecoveryCode;
use crate::secret_key::SecretKey;
use crate::session::{EncryptedItem, Session};
use keys::{SALT_LEN, check_strength, local_unlock_key};

const FORMAT: &str = "octapass-local-vault";
const VERSION: u32 = 1;

/// Trashed items are removed for good after this long, as the server does for accounts (plan 01).
pub const TRASH_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// The stored blob.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultFile {
    format: String,
    version: u32,
    kdf: KdfParams,
    salt: String,
    hardware_bound: bool,
    wrapped_ask: String,
    body: String,
}

/// The decrypted body. Also the plaintext of backups, next to the ASK.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Body {
    public_enc_key: String,
    public_sign_key: String,
    wrapped_private_keys: String,
    vault: NewVault,
    items: Vec<LocalItem>,
    backup: BackupSettings,
    /// What the user calls this vault, when a device keeps several. Older vaults have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupSettings {
    kdf: KdfParams,
    salt: String,
    key: Zeroizing<String>,
    recovery_code: Zeroizing<String>,
}

#[derive(Serialize, Deserialize)]
struct BackupPayload {
    ask: Zeroizing<String>,
    vault: Body,
}

/// One stored item: the same ciphertext a synced vault uploads, plus timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalItem {
    pub id: String,
    #[serde(flatten)]
    pub encrypted: EncryptedItem,
    pub created_at: u64,
    pub updated_at: u64,
    /// In the trash since then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<u64>,
}

/// What lists show: the decrypted overview and the timestamps.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalItemOverview {
    pub id: String,
    pub overview: ItemOverview,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<u64>,
}

/// What opens a backup.
#[derive(Clone, Copy)]
pub enum BackupSecret<'a> {
    /// The master password the backup was made with.
    Password(&'a str),
    /// The backup recovery code from the local Recovery Kit.
    RecoveryCode(&'a str),
}

/// How the vault is protected on this device.
#[derive(Debug, Clone, Copy)]
pub struct DeviceProtection<'a> {
    /// Argon2id for the master password: [`keys::LOCAL_KDF`] (256 MiB) where the device allows it,
    /// else [`keys::LOCAL_KDF_LOW_MEMORY`].
    pub kdf: KdfParams,
    /// 32 bytes from the device chip (Secure Enclave, Keystore, TPM), if there is one. Without it
    /// the master password must be strong ([`Error::WeakMasterPassword`]).
    pub hardware_secret: Option<&'a [u8]>,
}

/// An unlocked local vault. Dropping it locks: every key it holds is zeroed.
pub struct LocalVault {
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    hardware_bound: bool,
    wrapped_ask: String,
    ask: SymmetricKey,
    session: Session,
    body: Body,
}

impl LocalVault {
    /// Creates an empty vault. Runs Argon2id twice (the unlock key and the backup key), so it takes
    /// a few seconds: call it from a worker. Show [`backup_recovery_code`](Self::backup_recovery_code)
    /// in the local Recovery Kit.
    pub fn create(
        password: &str,
        protection: DeviceProtection<'_>,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        Self::create_with_backup_kdf(password, protection, BACKUP_KDF, now_ms, rng)
    }

    /// [`create`](Self::create) with other Argon2id parameters for the backup key: only for tests,
    /// where 256 MiB per vault adds up.
    #[doc(hidden)]
    pub fn create_with_backup_kdf(
        password: &str,
        protection: DeviceProtection<'_>,
        backup_kdf: KdfParams,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        check_strength(password, protection.hardware_secret.is_some())?;
        let ask = SymmetricKey::generate(rng);
        let key_pairs = AccountKeyPairs::generate(rng);
        let vault_key = SymmetricKey::generate(rng);
        let vault_id = new_id(now_ms, rng);
        let backup_key = BackupKey::derive(password, backup_kdf, rng)?;
        let body = Body {
            public_enc_key: b64_encode(&key_pairs.public_enc_key()),
            public_sign_key: b64_encode(&key_pairs.public_sign_key()),
            wrapped_private_keys: seal_b64(
                &ask,
                &Context::PrivateKeys,
                key_pairs.to_bytes().as_ref(),
                rng,
            )?,
            vault: NewVault {
                wrapped_vault_key: wrap_key(
                    &ask,
                    &Context::VaultKey {
                        vault_id: &vault_id,
                    },
                    &vault_key,
                    rng,
                )?,
                id: vault_id,
            },
            items: Vec::new(),
            backup: BackupSettings::new(&backup_key, &RecoveryCode::generate(rng)),
            name: None,
        };
        Self::protect(ask, body, password, protection, rng)
    }

    /// Wraps the ASK for this device and opens the vault.
    fn protect(
        ask: SymmetricKey,
        body: Body,
        password: &str,
        protection: DeviceProtection<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let luk = local_unlock_key(password, &salt, &protection.kdf, protection.hardware_secret)?;
        let wrapped_ask = wrap_key(&luk, &Context::LocalAsk, &ask, rng)?;
        Self::open(
            protection.kdf,
            salt,
            protection.hardware_secret.is_some(),
            wrapped_ask,
            ask,
            body,
        )
    }

    fn open(
        kdf: KdfParams,
        salt: [u8; SALT_LEN],
        hardware_bound: bool,
        wrapped_ask: String,
        ask: SymmetricKey,
        body: Body,
    ) -> Result<Self> {
        // A bundle without a server account, so items go through exactly the code synced vaults use.
        let bundle = AccountBundle {
            account_id: None,
            email: String::new(),
            kdf,
            account_salt: b64_encode(&salt),
            wrapped_ask: wrapped_ask.clone(),
            public_enc_key: body.public_enc_key.clone(),
            public_sign_key: body.public_sign_key.clone(),
            wrapped_private_keys: body.wrapped_private_keys.clone(),
            recovery_wrapped_ask: String::new(),
            wrapped_pq_private_key: None,
            key_record: None,
        };
        let mut session = Session::from_ask(bundle, ask.clone()).map_err(corrupt)?;
        session
            .open_vault(&body.vault.id, &body.vault.wrapped_vault_key)
            .map_err(corrupt)?;
        Ok(Self {
            kdf,
            salt,
            hardware_bound,
            wrapped_ask,
            ask,
            session,
            body,
        })
    }

    /// Unlocks a stored vault. Runs Argon2id. A wrong password (or chip secret) is
    /// [`Error::LoginFailed`]; a hardware-bound vault without its secret is
    /// [`Error::HardwareSecretRequired`].
    pub fn unlock(blob: &[u8], password: &str, hardware_secret: Option<&[u8]>) -> Result<Self> {
        let file = VaultFile::parse(blob)?;
        let hardware_secret = match (file.hardware_bound, hardware_secret) {
            (true, None) => return Err(Error::HardwareSecretRequired),
            (true, secret) => secret,
            (false, _) => None,
        };
        let salt: [u8; SALT_LEN] =
            b64_decode_array(&file.salt).map_err(|_| Error::InvalidLocalVault)?;
        let luk = local_unlock_key(password, &salt, &file.kdf, hardware_secret)?;
        let ask = unwrap_local_ask(&luk, &file.wrapped_ask)?;
        Self::open_file(file, ask)
    }

    /// Unlocks with the device's own lock: the secret it released, and what
    /// [`enable_device_unlock`](Self::enable_device_unlock) returned. Wrong ones are
    /// [`Error::DeviceUnlockFailed`].
    pub fn unlock_with_device_key(
        blob: &[u8],
        device_secret: &[u8],
        device_salt: &[u8],
        wrapped_ask: &str,
    ) -> Result<Self> {
        let file = VaultFile::parse(blob)?;
        let key = device::device_key(device_secret, device_salt)?;
        let ask = unwrap_key(&key, &Context::DeviceUnlock, wrapped_ask)
            .map_err(|_| Error::DeviceUnlockFailed)?;
        // The body only opens with this vault's own ASK.
        Self::open_file(file, ask).map_err(|_| Error::DeviceUnlockFailed)
    }

    /// Reopens a [seed](Self::seed) with a session that already holds its ASK. Add the items with
    /// [`set_items`](Self::set_items).
    pub fn from_seed(seed: &[u8], session: &Session) -> Result<Self> {
        Self::open_file(VaultFile::parse(seed)?, session.ask().clone())
    }

    fn open_file(file: VaultFile, ask: SymmetricKey) -> Result<Self> {
        let salt: [u8; SALT_LEN] =
            b64_decode_array(&file.salt).map_err(|_| Error::InvalidLocalVault)?;
        let body = open_b64(&ask, &Context::LocalVault, &file.body).map_err(corrupt)?;
        let body: Body = serde_json::from_slice(&body).map_err(|_| Error::InvalidLocalVault)?;
        Self::open(
            file.kdf,
            salt,
            file.hardware_bound,
            file.wrapped_ask,
            ask,
            body,
        )
    }

    /// Wraps the ASK for device unlock. The result stays on the device, next to the vault.
    pub fn enable_device_unlock(
        &self,
        device_secret: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<DeviceUnlock> {
        self.session.enable_device_unlock(device_secret, rng)
    }

    /// The encrypted blob to store. Call it after every change.
    pub fn to_bytes(&self, rng: &mut impl CryptoRngCore) -> Result<Vec<u8>> {
        self.sealed(&self.body, rng)
    }

    /// [`to_bytes`](Self::to_bytes) without the items: what a client whose items live in a store
    /// of their own keeps to make backups, change the password and turn on sync later.
    pub fn seed(&self, rng: &mut impl CryptoRngCore) -> Result<Vec<u8>> {
        self.sealed(
            &Body {
                items: Vec::new(),
                ..self.body.clone()
            },
            rng,
        )
    }

    fn sealed(&self, body: &Body, rng: &mut impl CryptoRngCore) -> Result<Vec<u8>> {
        let body = Zeroizing::new(serde_json::to_vec(body).expect("vaults serialize"));
        let file = VaultFile {
            format: FORMAT.into(),
            version: VERSION,
            kdf: self.kdf,
            salt: b64_encode(&self.salt),
            hardware_bound: self.hardware_bound,
            wrapped_ask: self.wrapped_ask.clone(),
            body: seal_b64(&self.ask, &Context::LocalVault, &body, rng)?,
        };
        Ok(serde_json::to_vec(&file).expect("vaults serialize"))
    }

    pub fn vault_id(&self) -> &str {
        &self.body.vault.id
    }

    pub fn is_hardware_bound(&self) -> bool {
        self.hardware_bound
    }

    pub fn name(&self) -> Option<&str> {
        self.body.name.as_deref()
    }

    /// Names the vault. The name travels with its backups.
    pub fn set_name(&mut self, name: Option<String>) {
        self.body.name = name;
    }

    /// A second session over this vault's keys, for code written against [`Session`]. Its bundle
    /// is the vault's, with no account id.
    pub fn session(&self) -> Result<Session> {
        let mut session =
            Session::from_ask(self.session.bundle().clone(), self.ask.clone()).map_err(corrupt)?;
        session
            .open_vault(&self.body.vault.id, &self.body.vault.wrapped_vault_key)
            .map_err(corrupt)?;
        Ok(session)
    }

    /// The personal vault's id and wrapped key.
    pub fn personal_vault(&self) -> &NewVault {
        &self.body.vault
    }

    /// The backup recovery code (11 groups of 5), for the local Recovery Kit. It can open every
    /// backup of this vault if the master password is forgotten.
    pub fn backup_recovery_code(&self) -> Zeroizing<String> {
        self.body.backup.recovery_code.clone()
    }

    /// Every item's overview, trash included.
    pub fn list(&self) -> Result<Vec<LocalItemOverview>> {
        self.body
            .items
            .iter()
            .map(|item| {
                Ok(LocalItemOverview {
                    id: item.id.clone(),
                    overview: self.session.decrypt_overview(
                        self.vault_id(),
                        &item.id,
                        &item.encrypted,
                    )?,
                    created_at: item.created_at,
                    updated_at: item.updated_at,
                    deleted_at: item.deleted_at,
                })
            })
            .collect()
    }

    pub fn get_item(&self, id: &str) -> Result<Item> {
        let item = self.find(id)?;
        self.session
            .decrypt_item(self.vault_id(), &item.id, &item.encrypted)
    }

    /// Adds an item with a new id (returned) and a new item key.
    pub fn add_item(
        &mut self,
        item: &Item,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<String> {
        let id = new_id(now_ms, rng);
        let encrypted = self
            .session
            .encrypt_item(self.vault_id(), &id, item, None, rng)?;
        self.body.items.push(LocalItem {
            id: id.clone(),
            encrypted,
            created_at: now_ms,
            updated_at: now_ms,
            deleted_at: None,
        });
        Ok(id)
    }

    /// Replaces an item's contents. It keeps its id and item key.
    pub fn update_item(
        &mut self,
        id: &str,
        item: &Item,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let index = self.index(id)?;
        let stored = &self.body.items[index];
        let encrypted = self.session.encrypt_item(
            &self.body.vault.id,
            &stored.id,
            item,
            Some(&stored.encrypted.encrypted_item_key),
            rng,
        )?;
        let stored = &mut self.body.items[index];
        stored.encrypted = encrypted;
        stored.updated_at = now_ms;
        Ok(())
    }

    /// Moves an item to the trash. Deleting a trashed item changes nothing.
    pub fn delete_item(&mut self, id: &str, now_ms: u64) -> Result<()> {
        let index = self.index(id)?;
        self.body.items[index].deleted_at.get_or_insert(now_ms);
        Ok(())
    }

    pub fn restore_item(&mut self, id: &str) -> Result<()> {
        let index = self.index(id)?;
        self.body.items[index].deleted_at = None;
        Ok(())
    }

    /// Removes an item for good.
    pub fn purge_item(&mut self, id: &str) -> Result<()> {
        let index = self.index(id)?;
        self.body.items.remove(index);
        Ok(())
    }

    /// Removes what has been in the trash for [`TRASH_RETENTION_MS`]. Returns how many went.
    pub fn purge_expired(&mut self, now_ms: u64) -> usize {
        let before = self.body.items.len();
        self.body.items.retain(|item| {
            item.deleted_at
                .is_none_or(|at| now_ms.saturating_sub(at) < TRASH_RETENTION_MS)
        });
        before - self.body.items.len()
    }

    /// Stores an item encrypted elsewhere with this vault's keys (by [`session`](Self::session)),
    /// replacing the one with its id.
    pub fn put_item(&mut self, item: LocalItem) {
        match self.body.items.iter_mut().find(|i| i.id == item.id) {
            Some(stored) => *stored = item,
            None => self.body.items.push(item),
        }
    }

    /// Replaces every item: the items of a store, for a backup or for turning on sync.
    pub fn set_items(&mut self, items: Vec<LocalItem>) {
        self.body.items = items;
    }

    /// Changes the master password (and optionally how the device protects it). The backup key is
    /// re-derived from the new password, so later backups need it; the backup recovery code stays.
    pub fn change_password(
        &mut self,
        new_password: &str,
        protection: DeviceProtection<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        check_strength(new_password, protection.hardware_secret.is_some())?;
        let backup_key = BackupKey::derive(new_password, self.body.backup.kdf, rng)?;
        let code = self.body.backup.recovery_code()?;
        let body = Body {
            backup: BackupSettings::new(&backup_key, &code),
            ..self.body.clone()
        };
        *self = Self::protect(self.ask.clone(), body, new_password, protection, rng)?;
        Ok(())
    }

    /// An encrypted `.octapass-backup` file of the whole vault. Needs no password: the backup key
    /// was derived when the vault was created or its password changed.
    pub fn create_backup(&self, rng: &mut impl CryptoRngCore) -> Result<Vec<u8>> {
        let payload = Zeroizing::new(
            serde_json::to_vec(&BackupPayload {
                ask: Zeroizing::new(b64_encode(self.ask.as_bytes())),
                vault: self.body.clone(),
            })
            .expect("vaults serialize"),
        );
        backup::seal(
            &payload,
            &self.body.backup.backup_key()?,
            &self.body.backup.recovery_code()?,
            rng,
        )
    }

    /// Restores a backup onto this device. `password` becomes the vault's master password here:
    /// usually the one the backup was made with, or a new one after opening it with the recovery
    /// code. Runs Argon2id two or three times. A wrong password is [`Error::LoginFailed`], a wrong
    /// code [`Error::InvalidRecoveryCode`].
    pub fn restore_backup(
        file: &[u8],
        secret: BackupSecret<'_>,
        password: &str,
        protection: DeviceProtection<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let (plaintext, same_password) = match secret {
            BackupSecret::Password(backup_password) => {
                let (plaintext, _) = backup::open_with_password(file, backup_password)?;
                (plaintext, backup_password == password)
            }
            BackupSecret::RecoveryCode(code) => {
                let code = RecoveryCode::parse(code)?;
                (backup::open_with_recovery_code(file, &code)?, false)
            }
        };
        // After opening it: a mistyped password is a wrong one, not a weak one.
        check_strength(password, protection.hardware_secret.is_some())?;
        let (ask, mut body) = BackupPayload::parse(&plaintext)?;
        if !same_password {
            let backup_key = BackupKey::derive(password, body.backup.kdf, rng)?;
            body.backup = BackupSettings::new(&backup_key, &body.backup.recovery_code()?);
        }
        Self::protect(ask, body, password, protection, rng)
    }

    /// **Turn on sync**: everything `register/finish` needs to create an account that keeps this
    /// vault's ASK, key pairs, personal vault and items. A new Secret Key and account recovery
    /// code are generated and the ASK is re-wrapped by the account's AUK; no item is decrypted.
    /// Runs Argon2id. Upload [`items`](Self::items) as they are after registering, then delete
    /// the local blob.
    pub fn upgrade_to_account(
        &self,
        email: &str,
        password: &str,
        kdf: KdfParams,
        rng: &mut impl CryptoRngCore,
    ) -> Result<NewAccount> {
        let email = normalize_email(email);
        let secret_key = SecretKey::generate(rng);
        let account_salt = generate_account_salt(rng);
        let keys = AccountKeys::derive(password, &secret_key, &email, &account_salt, &kdf)?;
        let recovery_code = RecoveryCode::generate(rng);
        let bundle = AccountBundle {
            account_id: None,
            email,
            kdf,
            account_salt: b64_encode(&account_salt),
            wrapped_ask: wrap_key(&keys.auk, &Context::Ask, &self.ask, rng)?,
            public_enc_key: self.body.public_enc_key.clone(),
            public_sign_key: self.body.public_sign_key.clone(),
            wrapped_private_keys: self.body.wrapped_private_keys.clone(),
            recovery_wrapped_ask: wrap_key(
                &recovery_code.wrapping_key(),
                &Context::Recovery,
                &self.ask,
                rng,
            )?,
            wrapped_pq_private_key: None,
            key_record: None,
        };
        let key_pairs = bundle.open_key_pairs(&self.ask)?;
        let personal_vault_key = unwrap_key(
            &self.ask,
            &Context::VaultKey {
                vault_id: &self.body.vault.id,
            },
            &self.body.vault.wrapped_vault_key,
        )?;
        Ok(NewAccount {
            secret_key,
            recovery_code,
            keys,
            ask: self.ask.clone(),
            key_pairs,
            bundle,
            personal_vault: self.body.vault.clone(),
            personal_vault_key,
        })
    }

    /// Every stored item, encrypted, as it would be uploaded.
    pub fn items(&self) -> &[LocalItem] {
        &self.body.items
    }

    fn index(&self, id: &str) -> Result<usize> {
        let id = parse_id(id)?;
        self.body
            .items
            .iter()
            .position(|item| item.id == id)
            .ok_or(Error::ItemNotFound)
    }

    fn find(&self, id: &str) -> Result<&LocalItem> {
        Ok(&self.body.items[self.index(id)?])
    }
}

impl VaultFile {
    fn parse(blob: &[u8]) -> Result<Self> {
        let file: VaultFile = serde_json::from_slice(blob).map_err(|_| Error::InvalidLocalVault)?;
        if file.format != FORMAT {
            return Err(Error::InvalidLocalVault);
        }
        if file.version != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        Ok(file)
    }
}

/// A wrong password (or chip secret) can't tell itself apart from a damaged wrapping.
fn unwrap_local_ask(luk: &SymmetricKey, wrapped_ask: &str) -> Result<SymmetricKey> {
    unwrap_key(luk, &Context::LocalAsk, wrapped_ask).map_err(|error| match error {
        Error::WrongKey | Error::DecryptionFailed => Error::LoginFailed,
        _ => Error::InvalidLocalVault,
    })
}

/// A session from the master password for a local vault's bundle, without its body: what the
/// phones' AutoFill extensions need, whose items are in the shared store. The bundle comes from
/// [`LocalVault::session`]. Runs Argon2id. A wrong password (or chip secret) is
/// [`Error::LoginFailed`].
pub fn unlock_session(
    bundle: AccountBundle,
    password: &str,
    hardware_secret: Option<&[u8]>,
) -> Result<Session> {
    let salt = bundle.account_salt_bytes()?;
    let luk = local_unlock_key(password, &salt, &bundle.kdf, hardware_secret)?;
    let ask = unwrap_local_ask(&luk, &bundle.wrapped_ask)?;
    Session::from_ask(bundle, ask).map_err(corrupt)
}

impl BackupSettings {
    fn new(key: &BackupKey, code: &RecoveryCode) -> Self {
        Self {
            kdf: key.kdf,
            salt: b64_encode(&key.salt),
            key: Zeroizing::new(b64_encode(key.key.as_bytes())),
            recovery_code: code.to_text(),
        }
    }

    fn backup_key(&self) -> Result<BackupKey> {
        Ok(BackupKey {
            key: SymmetricKey::from_slice(&Zeroizing::new(b64_decode(&self.key)?))
                .map_err(corrupt)?,
            salt: b64_decode_array(&self.salt).map_err(corrupt)?,
            kdf: self.kdf,
        })
    }

    fn recovery_code(&self) -> Result<RecoveryCode> {
        RecoveryCode::parse(&self.recovery_code).map_err(corrupt)
    }
}

impl BackupPayload {
    fn parse(plaintext: &[u8]) -> Result<(SymmetricKey, Body)> {
        let payload: BackupPayload =
            serde_json::from_slice(plaintext).map_err(|_| Error::InvalidBackup)?;
        let ask = SymmetricKey::from_slice(&Zeroizing::new(b64_decode(&payload.ask)?))
            .map_err(|_| Error::InvalidBackup)?;
        Ok((ask, payload.vault))
    }
}

/// Anything but a clean decryption inside an already-opened vault means the file is damaged.
fn corrupt(_: Error) -> Error {
    Error::InvalidLocalVault
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use serde_json::json;

    use super::*;
    use crate::item::ItemDetails;
    use crate::opaque::RegistrationClient;
    use crate::opaque::server::OpaqueServer;

    const PASSWORD: &str = "vexed-kiwi-trumpet-galaxy-oboe";
    const CHIP: [u8; 32] = [7; 32];
    const NOW: u64 = 1_792_713_600_000;

    fn rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    /// The fast KDF in tests; `create` itself always uses `BACKUP_KDF` for backups.
    fn protection(chip: Option<&[u8]>) -> DeviceProtection<'_> {
        DeviceProtection {
            kdf: KdfParams::DEFAULT,
            hardware_secret: chip,
        }
    }

    fn vault(chip: Option<&[u8]>, rng: &mut ChaCha20Rng) -> LocalVault {
        LocalVault::create_with_backup_kdf(PASSWORD, protection(chip), KdfParams::DEFAULT, NOW, rng)
            .unwrap()
    }

    fn item(title: &str, password: &str) -> Item {
        Item::from_json(
            &json!({
                "overview": { "title": title, "type": "login", "urls": ["https://example.com"] },
                "details": { "username": "alice", "password": password, "future": { "kept": true } }
            })
            .to_string(),
        )
        .unwrap()
    }

    fn password_of(item: &Item) -> &str {
        match &item.details {
            ItemDetails::Login(login) => login.password.as_deref().unwrap(),
            _ => panic!("not a login"),
        }
    }

    #[test]
    fn items_survive_storing_and_unlocking() {
        let mut rng = rng(1);
        let mut vault = vault(None, &mut rng);
        let a = vault.add_item(&item("A", "pw-a"), NOW, &mut rng).unwrap();
        let b = vault
            .add_item(&item("B", "pw-b"), NOW + 1, &mut rng)
            .unwrap();
        vault
            .update_item(&a, &item("Renamed title", "pw-a2"), NOW + 2, &mut rng)
            .unwrap();
        vault.delete_item(&b, NOW + 3).unwrap();
        let blob = vault.to_bytes(&mut rng).unwrap();
        let text = String::from_utf8(blob.clone()).unwrap();
        assert!(
            !text.contains("pw-a2") && !text.contains("Renamed"),
            "nothing is in the clear"
        );

        let again = LocalVault::unlock(&blob, PASSWORD, None).unwrap();
        let list = again.list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(
            (list[0].overview.title.as_str(), list[0].updated_at),
            ("Renamed title", NOW + 2)
        );
        assert_eq!(list[1].deleted_at, Some(NOW + 3));
        let a_item = again.get_item(&a).unwrap();
        assert_eq!(password_of(&a_item), "pw-a2");
        assert_eq!(
            a_item.to_json(),
            item("Renamed title", "pw-a2").to_json(),
            "unknown fields round-trip"
        );
        assert_eq!(again.backup_recovery_code(), vault.backup_recovery_code());

        let mut again = again;
        again.restore_item(&b).unwrap();
        again.purge_item(&a).unwrap();
        assert_eq!(again.list().unwrap().len(), 1);
        assert_eq!(again.get_item(&a).unwrap_err(), Error::ItemNotFound);
        assert_eq!(
            again.delete_item("not-an-id", NOW).unwrap_err(),
            Error::InvalidId
        );
    }

    #[test]
    fn unlock_failures() {
        let mut rng = rng(2);
        let blob = vault(Some(&CHIP), &mut rng).to_bytes(&mut rng).unwrap();
        assert!(
            LocalVault::unlock(&blob, PASSWORD, Some(&CHIP))
                .unwrap()
                .is_hardware_bound()
        );
        assert_eq!(
            LocalVault::unlock(&blob, "wrong", Some(&CHIP)).err(),
            Some(Error::LoginFailed)
        );
        assert_eq!(
            LocalVault::unlock(&blob, PASSWORD, Some(&[8; 32])).err(),
            Some(Error::LoginFailed)
        );
        assert_eq!(
            LocalVault::unlock(&blob, PASSWORD, None).err(),
            Some(Error::HardwareSecretRequired)
        );
        assert_eq!(
            LocalVault::unlock(b"{}", PASSWORD, None).err(),
            Some(Error::InvalidLocalVault)
        );

        let mut file: serde_json::Value = serde_json::from_slice(&blob).unwrap();
        file["version"] = json!(2);
        assert_eq!(
            LocalVault::unlock(file.to_string().as_bytes(), PASSWORD, Some(&CHIP)).err(),
            Some(Error::UnsupportedVersion)
        );
        file["version"] = json!(1);
        file["kdf"]["memoryKib"] = json!(1024);
        assert_eq!(
            LocalVault::unlock(file.to_string().as_bytes(), PASSWORD, Some(&CHIP)).err(),
            Some(Error::UnsupportedKdf)
        );
    }

    #[test]
    fn vaults_without_a_chip_need_a_strong_password() {
        let result = LocalVault::create_with_backup_kdf(
            "password123",
            protection(None),
            KdfParams::DEFAULT,
            NOW,
            &mut rng(3),
        );
        assert_eq!(result.err(), Some(Error::WeakMasterPassword));
        assert!(
            LocalVault::create_with_backup_kdf(
                "password123",
                protection(Some(&CHIP)),
                KdfParams::DEFAULT,
                NOW,
                &mut rng(3)
            )
            .is_ok()
        );
    }

    #[test]
    fn backups_restore_with_the_password_or_the_recovery_code() {
        let mut rng = rng(4);
        let mut vault = vault(Some(&CHIP), &mut rng);
        let id = vault.add_item(&item("A", "pw-a"), NOW, &mut rng).unwrap();
        let backup = vault.create_backup(&mut rng).unwrap();
        assert_eq!(&backup[..4], b"OPBK");

        // Another device without a chip, same password.
        let restored = LocalVault::restore_backup(
            &backup,
            BackupSecret::Password(PASSWORD),
            PASSWORD,
            protection(None),
            &mut rng,
        )
        .unwrap();
        assert!(!restored.is_hardware_bound());
        assert_eq!(password_of(&restored.get_item(&id).unwrap()), "pw-a");
        assert_eq!(restored.vault_id(), vault.vault_id());
        // It keeps backing up with the same key: the old password opens its new backups.
        let next = restored.create_backup(&mut rng).unwrap();
        LocalVault::restore_backup(
            &next,
            BackupSecret::Password(PASSWORD),
            PASSWORD,
            protection(Some(&CHIP)),
            &mut rng,
        )
        .unwrap();

        // Forgotten password: the recovery code opens it and sets a new one.
        let code = vault.backup_recovery_code();
        let new_password = "quartz-meadow-lantern-fjord-pixel";
        let recovered = LocalVault::restore_backup(
            &backup,
            BackupSecret::RecoveryCode(&code),
            new_password,
            protection(None),
            &mut rng,
        )
        .unwrap();
        assert_eq!(password_of(&recovered.get_item(&id).unwrap()), "pw-a");
        let blob = recovered.to_bytes(&mut rng).unwrap();
        assert!(LocalVault::unlock(&blob, new_password, None).is_ok());
        let after = recovered.create_backup(&mut rng).unwrap();
        assert_eq!(
            LocalVault::restore_backup(
                &after,
                BackupSecret::Password(PASSWORD),
                PASSWORD,
                protection(None),
                &mut rng
            )
            .err(),
            Some(Error::LoginFailed),
            "new backups use the new password"
        );
        assert!(
            LocalVault::restore_backup(
                &after,
                BackupSecret::RecoveryCode(&code),
                new_password,
                protection(None),
                &mut rng
            )
            .is_ok()
        );

        assert_eq!(
            LocalVault::restore_backup(
                &backup,
                BackupSecret::Password("wrong"),
                "wrong",
                protection(None),
                &mut rng
            )
            .err(),
            Some(Error::LoginFailed),
            "a mistyped password is wrong before it's weak"
        );
        assert_eq!(
            LocalVault::restore_backup(
                &backup,
                BackupSecret::RecoveryCode(&code),
                "password123",
                protection(None),
                &mut rng
            )
            .err(),
            Some(Error::WeakMasterPassword)
        );

        assert_eq!(
            LocalVault::restore_backup(
                &backup,
                BackupSecret::RecoveryCode("00000-00000"),
                PASSWORD,
                protection(None),
                &mut rng
            )
            .err(),
            Some(Error::InvalidRecoveryCode)
        );
    }

    #[test]
    fn changing_the_password() {
        let mut rng = rng(5);
        let mut vault = vault(None, &mut rng);
        let id = vault.add_item(&item("A", "pw-a"), NOW, &mut rng).unwrap();
        let code = vault.backup_recovery_code();
        vault
            .change_password("password123", protection(Some(&CHIP)), &mut rng)
            .unwrap();
        let blob = vault.to_bytes(&mut rng).unwrap();
        assert_eq!(
            LocalVault::unlock(&blob, PASSWORD, Some(&CHIP)).err(),
            Some(Error::LoginFailed)
        );
        let again = LocalVault::unlock(&blob, "password123", Some(&CHIP)).unwrap();
        assert_eq!(password_of(&again.get_item(&id).unwrap()), "pw-a");
        assert_eq!(again.backup_recovery_code(), code);
        assert_eq!(
            vault
                .change_password("password123", protection(None), &mut rng)
                .err(),
            Some(Error::WeakMasterPassword)
        );
    }

    #[test]
    fn device_unlock_opens_the_vault_without_the_password() {
        let mut rng = rng(7);
        let mut vault = vault(Some(&CHIP), &mut rng);
        let id = vault.add_item(&item("A", "pw-a"), NOW, &mut rng).unwrap();
        let secret = [9u8; 32];
        let wrapped = vault.enable_device_unlock(&secret, &mut rng).unwrap();
        let blob = vault.to_bytes(&mut rng).unwrap();

        let again = LocalVault::unlock_with_device_key(
            &blob,
            &secret,
            &wrapped.device_salt,
            &wrapped.wrapped_ask,
        )
        .unwrap();
        assert_eq!(password_of(&again.get_item(&id).unwrap()), "pw-a");
        assert_eq!(
            LocalVault::unlock_with_device_key(
                &blob,
                &[1u8; 32],
                &wrapped.device_salt,
                &wrapped.wrapped_ask
            )
            .err(),
            Some(Error::DeviceUnlockFailed)
        );

        // Another vault's wrapped ASK doesn't open this body.
        let other = self::vault(None, &mut self::rng(70));
        let foreign = other
            .enable_device_unlock(&secret, &mut self::rng(71))
            .unwrap();
        assert_eq!(
            LocalVault::unlock_with_device_key(
                &blob,
                &secret,
                &foreign.device_salt,
                &foreign.wrapped_ask
            )
            .err(),
            Some(Error::DeviceUnlockFailed)
        );
    }

    #[test]
    fn a_seed_holds_everything_but_the_items() {
        let mut rng = rng(8);
        let mut vault = vault(Some(&CHIP), &mut rng);
        vault.set_name(Some("Work".into()));
        let id = vault.add_item(&item("A", "pw-a"), NOW, &mut rng).unwrap();
        let seed = vault.seed(&mut rng).unwrap();

        // The store's side: a session from the bundle and the password alone.
        let bundle = vault.session().unwrap().bundle().clone();
        assert!(bundle.account_id.is_none());
        let mut session = unlock_session(bundle.clone(), PASSWORD, Some(&CHIP)).unwrap();
        assert_eq!(
            unlock_session(bundle.clone(), "wrong", Some(&CHIP)).err(),
            Some(Error::LoginFailed)
        );
        assert_eq!(
            unlock_session(bundle, PASSWORD, None).err(),
            Some(Error::LoginFailed)
        );
        session
            .open_vault(
                &vault.personal_vault().id,
                &vault.personal_vault().wrapped_vault_key,
            )
            .unwrap();
        let stored = vault.items()[0].clone();
        assert_eq!(
            password_of(
                &session
                    .decrypt_item(vault.vault_id(), &id, &stored.encrypted)
                    .unwrap()
            ),
            "pw-a"
        );

        // Put back together, it backs up like the vault it came from.
        let mut opened = LocalVault::from_seed(&seed, &session).unwrap();
        assert!(opened.items().is_empty());
        assert_eq!(opened.name(), Some("Work"));
        opened.set_items(vec![stored]);
        let backup = opened.create_backup(&mut rng).unwrap();
        let restored = LocalVault::restore_backup(
            &backup,
            BackupSecret::Password(PASSWORD),
            PASSWORD,
            protection(None),
            &mut rng,
        )
        .unwrap();
        assert_eq!(restored.name(), Some("Work"));
        assert_eq!(password_of(&restored.get_item(&id).unwrap()), "pw-a");

        let other = self::vault(None, &mut self::rng(80));
        assert!(LocalVault::from_seed(&seed, &other.session().unwrap()).is_err());
    }

    #[test]
    fn a_second_session_writes_items_the_vault_can_read() {
        let mut rng = rng(9);
        let mut vault = vault(None, &mut rng);
        let session = vault.session().unwrap();
        let id = new_id(NOW, &mut rng);
        let encrypted = session
            .encrypt_item(vault.vault_id(), &id, &item("A", "pw-a"), None, &mut rng)
            .unwrap();
        vault.put_item(LocalItem {
            id: id.clone(),
            encrypted: encrypted.clone(),
            created_at: NOW,
            updated_at: NOW,
            deleted_at: None,
        });
        assert_eq!(password_of(&vault.get_item(&id).unwrap()), "pw-a");
        vault.put_item(LocalItem {
            id: id.clone(),
            encrypted,
            created_at: NOW,
            updated_at: NOW + 1,
            deleted_at: None,
        });
        assert_eq!(vault.items().len(), 1);
        assert_eq!(vault.items()[0].updated_at, NOW + 1);
    }

    #[test]
    fn the_trash_empties_after_thirty_days() {
        let mut rng = rng(10);
        let mut vault = vault(None, &mut rng);
        let kept = vault.add_item(&item("A", "a"), NOW, &mut rng).unwrap();
        let old = vault.add_item(&item("B", "b"), NOW, &mut rng).unwrap();
        let recent = vault.add_item(&item("C", "c"), NOW, &mut rng).unwrap();
        vault.delete_item(&old, NOW).unwrap();
        vault
            .delete_item(&recent, NOW + TRASH_RETENTION_MS - 1)
            .unwrap();
        assert_eq!(vault.purge_expired(NOW + TRASH_RETENTION_MS - 1), 0);
        assert_eq!(vault.purge_expired(NOW + TRASH_RETENTION_MS), 1);
        assert_eq!(vault.get_item(&old).unwrap_err(), Error::ItemNotFound);
        assert!(vault.get_item(&kept).is_ok() && vault.get_item(&recent).is_ok());
    }

    #[test]
    fn a_backup_from_before_names_still_restores() {
        let mut rng = rng(11);
        let vault = vault(None, &mut rng);
        let mut body = serde_json::to_value(&vault.body).unwrap();
        assert!(
            body.get("name").is_none(),
            "an unnamed vault writes no name"
        );
        body.as_object_mut().unwrap().remove("name");
        let body: Body = serde_json::from_value(body).unwrap();
        assert_eq!(body.name, None);
    }

    #[test]
    fn turning_on_sync_rewraps_only_the_ask() {
        let mut rng = rng(6);
        let mut vault = vault(None, &mut rng);
        let id = vault.add_item(&item("A", "pw-a"), NOW, &mut rng).unwrap();
        let account = vault
            .upgrade_to_account(
                " Alice@Example.com ",
                "account password",
                KdfParams::DEFAULT,
                &mut rng,
            )
            .unwrap();
        assert_eq!(account.bundle.email, "alice@example.com");
        assert_eq!(account.personal_vault.id, vault.vault_id());

        // A new device signs in with password + Secret Key and reads the uploaded items as they are.
        let keys = AccountKeys::derive(
            "account password",
            &account.secret_key,
            "alice@example.com",
            &account.bundle.account_salt_bytes().unwrap(),
            &KdfParams::DEFAULT,
        )
        .unwrap();
        let mut session = Session::unlock(account.bundle.clone(), &keys.auk).unwrap();
        session
            .open_vault(
                &account.personal_vault.id,
                &account.personal_vault.wrapped_vault_key,
            )
            .unwrap();
        let stored = &vault.items()[0];
        assert_eq!(stored.id, id);
        assert_eq!(
            password_of(
                &session
                    .decrypt_item(vault.vault_id(), &id, &stored.encrypted)
                    .unwrap()
            ),
            "pw-a"
        );
        assert!(Session::recover(account.bundle.clone(), &account.recovery_code).is_ok());

        // And OPAQUE registration works with the new keys.
        let server = OpaqueServer::generate(&mut rng);
        let (client, request) =
            RegistrationClient::start(&account.keys.auth_secret, &mut rng).unwrap();
        let response = server
            .registration_start(&account.bundle.email, &request)
            .unwrap();
        client
            .finish(&account.keys.auth_secret, &response, &mut rng)
            .unwrap();
    }
}
