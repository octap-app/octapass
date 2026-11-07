//! Vaults on this computer only (plan 03, *Local mode keys*; plan 01, *Local mode*).
//!
//! A local vault is the core's `LocalVault` blob in a file of its own, opened behind the same
//! `Unlocked` state as an account: its items are mirrored into the cache and read by the same
//! code, and only what would reach a server differs (`put`, `trash` and `restore_item` come here;
//! `authed` refuses everything else with `needsSync`). Its session key looks like an account's,
//! with the server URL `local:<tag>`.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use octapass_api::{
    ItemRecord, LoginFinishResponse, NewPersonalVault, PutItemRequest, RegisterFinishRequest,
    RegisterStartRequest, VaultRecord, VaultRole, VaultType,
};
use octapass_core::account::{AccountBundle, NewAccount};
use octapass_core::backup::BACKUP_KDF;
use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_core::kdf::KdfParams;
use octapass_core::local::keys::LOCAL_KDF;
use octapass_core::local::{BackupSecret, DeviceProtection, LocalItem, LocalVault};
use octapass_core::opaque::RegistrationClient;
use octapass_core::session::Session;
use octapass_core::tools::strength;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use zeroize::Zeroizing;

use super::{
    Event, Login, Precondition, SIGNUP_TTL, Unlocked, Vault, blocking, convert, valid_email,
};
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{
    AccountSummary, ItemDraft, RecoveryKit, SignupStarted, now, parse_rfc3339, require, rfc3339,
    unix_ms,
};
use crate::store::{AccountKey, LOCAL_SCHEME, StoredAccount, StoredLocal, WrappedAsk};

/// A local vault without a backup for this long gets a reminder (plan 01).
const BACKUP_DUE: Duration = Duration::from_secs(30 * 86_400);
/// Automatic backups a folder keeps per vault; older ones are deleted.
const KEEP_BACKUPS: usize = 7;
/// A change waits this long for the next one, so a session of edits makes one backup.
const AUTO_BACKUP_QUIET: Duration = Duration::from_secs(60);
/// With a chip the password can't be attacked off this computer, but a backup can be: it's as
/// strong as the password. Without one, the core asks for zxcvbn's top score (plan 03).
const MIN_SCORE_WITH_CHIP: u8 = 3;
const BACKUP_EXTENSION: &str = ".octapass-backup";

/// One local vault on this computer, for the vault list and Settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalVaultInfo {
    /// What `switch_local_vault` takes.
    pub id: String,
    pub name: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_backup_at: Option<String>,
    /// 30 days since the last backup, or since creating it with none, and no folder is keeping
    /// up with the vault.
    pub backup_due: bool,
    /// Where automatic backups go. Missing: they're off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_folder: Option<String>,
    /// Bound to this computer's chip: a copied file is useless elsewhere.
    pub chip_bound: bool,
    /// The vault the app has open, or would open.
    pub current: bool,
}

/// What the setup screens need to know before asking for a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalCapabilities {
    /// New vaults are bound to this computer's chip.
    pub chip: bool,
    /// The lowest zxcvbn score a new master password may have here.
    pub min_score: u8,
}

/// What opens a backup file.
pub enum RestoreSecret {
    /// The master password it was made with, which stays the vault's.
    Password(Zeroizing<String>),
    /// The backup recovery code, and the new master password to set.
    RecoveryCode {
        code: Zeroizing<String>,
        new_password: Zeroizing<String>,
    },
}

/// An open local vault: the core's vault beside the mirror the rest of the app reads.
pub(crate) struct OpenLocal {
    vault: LocalVault,
}

/// Turning on sync between its steps. It survives a wrong code and a failed upload.
pub(super) struct PendingUpgrade {
    server_url: String,
    source: AccountKey,
    account: NewAccount,
    registration_upload: String,
    expires_at: Instant,
    registered: bool,
    /// Signed in: the account's session and key, kept for a retry of the upload.
    signed_in: Option<(AccountKey, Session)>,
}

fn new_tag() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn local_key(tag: &str) -> AccountKey {
    AccountKey {
        server_url: format!("{LOCAL_SCHEME}{tag}"),
        email: String::new(),
    }
}

fn chip_name(tag: &str) -> String {
    format!("local-vault|{tag}")
}

/// A name of its own for each vault's backups, so several vaults can share a folder. The
/// vault's name stays out of it: a folder may be a cloud drive.
fn backup_prefix(local: &StoredLocal) -> String {
    format!("octapass-{}-", &local.tag[..8])
}

fn backup_name(local: &StoredLocal, at: &str) -> String {
    let stamp: String = at
        .chars()
        .take(19)
        .map(|c| if c == ':' { '-' } else { c })
        .collect();
    format!("{}{stamp}{BACKUP_EXTENSION}", backup_prefix(local))
}

fn storage(error: std::io::Error) -> VaultError {
    VaultError::unexpected(format!("backup folder: {error}"))
}

/// The cache row for a stored item.
fn record(vault_id: &str, item: &LocalItem) -> ItemRecord {
    let at = |ms: u64| {
        rfc3339(
            time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
                .unwrap_or_else(|_| now()),
        )
    };
    ItemRecord {
        id: item.id.clone(),
        vault_id: vault_id.to_owned(),
        revision: item.updated_at,
        encrypted_item_key: item.encrypted.encrypted_item_key.clone(),
        overview: item.encrypted.overview.clone(),
        details: item.encrypted.details.clone(),
        updated_at: at(item.updated_at),
        deleted_at: item.deleted_at.map(at),
    }
}

/// The session, the cache's vault and its rows for an opened vault.
fn mirror(vault: &LocalVault) -> Result<(Session, Vec<VaultRecord>, Vec<ItemRecord>)> {
    let personal = vault.personal_vault();
    let record_of_vault = VaultRecord {
        id: personal.id.clone(),
        vault_type: VaultType::Personal,
        revision: 0,
        wrapped_vault_key: personal.wrapped_vault_key.clone(),
        role: VaultRole::Owner,
        key_id: None,
        grant: None,
        org_id: None,
    };
    let items = vault
        .items()
        .iter()
        .map(|item| record(&personal.id, item))
        .collect();
    Ok((vault.session()?, vec![record_of_vault], items))
}

impl Vault {
    /// The local vault the app has open or would open.
    pub(super) fn current_local(&self) -> Option<StoredLocal> {
        let state = self.state();
        let current = state.device.current.as_ref()?;
        state.device.local(current).cloned()
    }

    pub async fn local_capabilities(&self) -> LocalCapabilities {
        let device_unlock = Arc::clone(&self.device_unlock);
        let chip = blocking(move || Ok(device_unlock.chip_available()))
            .await
            .unwrap_or(false);
        LocalCapabilities {
            chip,
            min_score: if chip { MIN_SCORE_WITH_CHIP } else { 4 },
        }
    }

    pub fn local_vaults(&self) -> Vec<LocalVaultInfo> {
        let state = self.state();
        state
            .device
            .locals
            .iter()
            .map(|local| {
                let since = local.last_backup_at.as_deref().unwrap_or(&local.created_at);
                // A folder keeps an unchanged vault backed up for as long as it likes; one that
                // has stopped working still gets the reminder.
                let covered = local.backup_folder.is_some()
                    && local.last_backup_at.is_some()
                    && local.changed_at <= local.backed_up_at;
                LocalVaultInfo {
                    id: local.tag.clone(),
                    name: local.name.clone(),
                    created_at: local.created_at.clone(),
                    last_backup_at: local.last_backup_at.clone(),
                    backup_due: !covered
                        && parse_rfc3339(since).is_none_or(|at| now() - at >= BACKUP_DUE),
                    backup_folder: local.backup_folder.clone(),
                    chip_bound: local.chip_context.is_some(),
                    current: state.device.current.as_ref() == Some(&local.key),
                }
            })
            .collect()
    }

    /// A chip key for a new vault, where there's a chip.
    async fn new_chip(&self, tag: &str) -> Result<Option<(String, Zeroizing<Vec<u8>>)>> {
        let device_unlock = Arc::clone(&self.device_unlock);
        let name = chip_name(tag);
        blocking(move || Ok(device_unlock.create_chip_key(&name)?))
            .await
            .map(|key| {
                key.map(|key| {
                    (
                        b64_encode(&key.context),
                        Zeroizing::new(key.secret.to_vec()),
                    )
                })
            })
    }

    async fn stored_chip(&self, local: &StoredLocal) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let Some(context) = &local.chip_context else {
            return Ok(None);
        };
        let context = b64_decode(context)?;
        let device_unlock = Arc::clone(&self.device_unlock);
        let name = chip_name(&local.tag);
        blocking(move || Ok(device_unlock.chip_secret(&name, &context)?))
            .await
            .map(|secret| Some(Zeroizing::new(secret.to_vec())))
    }

    /// "Use on this device only": a new vault, unlocked and current. Runs Argon2id twice. Returns
    /// the backup recovery code, for the local Recovery Kit.
    pub async fn create_local_vault(
        &self,
        name: &str,
        password: Zeroizing<String>,
    ) -> Result<Zeroizing<String>> {
        self.create_local_vault_with(name, password, BACKUP_KDF)
            .await
    }

    /// `create_local_vault` with other backup key parameters: tests only.
    #[doc(hidden)]
    pub async fn create_local_vault_with(
        &self,
        name: &str,
        password: Zeroizing<String>,
        backup_kdf: KdfParams,
    ) -> Result<Zeroizing<String>> {
        let name = name.trim().to_owned();
        require(!name.is_empty(), ErrorCode::InvalidName)?;
        let tag = new_tag();
        check_password(&password, self.local_capabilities().await.chip)?;
        let chip = self.new_chip(&tag).await?;
        let secret = chip.as_ref().map(|(_, secret)| secret.clone());
        let created = {
            let name = name.clone();
            blocking(move || {
                let mut vault = LocalVault::create_with_backup_kdf(
                    &password,
                    DeviceProtection {
                        kdf: LOCAL_KDF,
                        hardware_secret: secret.as_ref().map(|secret| &secret[..]),
                    },
                    backup_kdf,
                    unix_ms(now()),
                    &mut OsRng,
                )?;
                vault.set_name(Some(name));
                Ok(vault)
            })
            .await
        };
        let vault = match created {
            Ok(vault) => vault,
            Err(error) => {
                let _ = self.device_unlock.delete_chip_key(&chip_name(&tag));
                return Err(error);
            }
        };
        let code = vault.backup_recovery_code();
        self.install_new_local(tag, name, chip.map(|(context, _)| context), vault, None)?;
        Ok(code)
    }

    /// Restores a `.octapass-backup` file as a new vault here, unlocked and current.
    pub async fn restore_local_vault(&self, file: Vec<u8>, secret: RestoreSecret) -> Result<()> {
        let tag = new_tag();
        let chip_here = self.local_capabilities().await.chip;
        let password = match &secret {
            RestoreSecret::Password(password) => password.clone(),
            RestoreSecret::RecoveryCode { new_password, .. } => new_password.clone(),
        };
        // The password a backup was made with is checked by opening it: a typo isn't "weak".
        if matches!(secret, RestoreSecret::RecoveryCode { .. }) {
            check_password(&password, chip_here)?;
        }
        let chip = self.new_chip(&tag).await?;
        let chip_secret = chip.as_ref().map(|(_, secret)| secret.clone());
        let opened_password = password.clone();
        let restored = blocking(move || {
            let secret = match &secret {
                RestoreSecret::Password(password) => BackupSecret::Password(password),
                RestoreSecret::RecoveryCode { code, .. } => BackupSecret::RecoveryCode(code),
            };
            LocalVault::restore_backup(
                &file,
                secret,
                &password,
                DeviceProtection {
                    kdf: LOCAL_KDF,
                    hardware_secret: chip_secret.as_ref().map(|secret| &secret[..]),
                },
                &mut OsRng,
            )
            .map_err(|error| match error {
                octapass_core::Error::LoginFailed
                | octapass_core::Error::InvalidRecoveryCode
                | octapass_core::Error::InvalidBackup
                | octapass_core::Error::UnsupportedVersion => ErrorCode::InvalidBackup.into(),
                other => VaultError::from(other),
            })
        })
        .await;
        let vault = match restored.and_then(|vault| {
            check_password(&opened_password, chip.is_some())?;
            Ok(vault)
        }) {
            Ok(vault) => vault,
            Err(error) => {
                let _ = self.device_unlock.delete_chip_key(&chip_name(&tag));
                return Err(error);
            }
        };
        let name = vault.name().unwrap_or("Restored").to_owned();
        // The file it came from is a backup of everything it holds.
        self.install_new_local(
            tag,
            name,
            chip.map(|(context, _)| context),
            vault,
            Some(rfc3339(now())),
        )
    }

    fn install_new_local(
        &self,
        tag: String,
        name: String,
        chip_context: Option<String>,
        vault: LocalVault,
        last_backup_at: Option<String>,
    ) -> Result<()> {
        let local = StoredLocal {
            key: local_key(&tag),
            tag,
            name,
            created_at: rfc3339(now()),
            last_backup_at,
            backed_up_at: None,
            changed_at: None,
            backup_folder: None,
            chip_context,
            last_password_unlock_at: rfc3339(now()),
            device_unlock: None,
        };
        self.store
            .write_local(&local.tag, &vault.to_bytes(&mut OsRng)?)?;
        {
            let mut state = self.state();
            state.device.upsert_local(local.clone());
            self.save_device(&state)?;
        }
        self.install_local(local, vault)
    }

    /// Opens a vault as the current one: its mirror goes where an account's cache would.
    fn install_local(&self, local: StoredLocal, vault: LocalVault) -> Result<()> {
        self.install_local_as(local, vault, true)
    }

    /// `confirmed`: the user opened it (false only for stay unlocked, plan 18).
    pub(super) fn install_local_as(
        &self,
        local: StoredLocal,
        mut vault: LocalVault,
        confirmed: bool,
    ) -> Result<()> {
        vault.purge_expired(unix_ms(now()));
        let (session, vaults, items) = mirror(&vault)?;
        let cache = crate::cache::VaultCache { vaults, items };
        let mut unlocked = Unlocked::new(local.key.clone(), session, cache);
        unlocked.local = Some(OpenLocal { vault });
        unlocked.confirmed = confirmed;
        let mut state = self.state();
        state.held = false;
        state.generation += 1;
        state.device.current = Some(local.key);
        state.unlocked = Some(unlocked);
        self.save_device(&state)?;
        drop(state);
        // Before the session event, so whoever hears it sees the key (plan 18).
        self.enroll_stay_unlocked();
        self.emit_session();
        self.emit(Event::ItemsChanged);
        Ok(())
    }

    /// The master password, and the chip's secret when the vault is bound to it.
    pub(super) async fn unlock_local(
        &self,
        local: StoredLocal,
        password: Zeroizing<String>,
    ) -> Result<()> {
        require(self.state().unlocked.is_none(), ErrorCode::Locked)?;
        let blob = self.store.read_local(&local.tag)?;
        let chip = self.stored_chip(&local).await?;
        let vault = blocking(move || {
            Ok(LocalVault::unlock(
                &blob,
                &password,
                chip.as_ref().map(|secret| &secret[..]),
            )?)
        })
        .await?;
        {
            let mut state = self.state();
            if state.unlocked.is_some() {
                return Ok(());
            }
            if let Some(stored) = state.device.local_mut(&local.key) {
                stored.last_password_unlock_at = rfc3339(now());
            }
            self.save_device(&state)?;
        }
        self.install_local(local, vault)
    }

    /// Unlocks with Touch ID / the Mac password, Windows Hello or polkit.
    pub(super) async fn unlock_local_with_device(&self, local: StoredLocal) -> Result<()> {
        if self.state().unlocked.is_some() {
            return Ok(());
        }
        let record = local
            .device_unlock
            .clone()
            .ok_or(ErrorCode::DeviceUnlockFailed)?;
        require(
            !super::password_due(&local.last_password_unlock_at),
            ErrorCode::PasswordRequired,
        )?;
        let device_unlock = Arc::clone(&self.device_unlock);
        let account_id = local.key.id();
        let secret =
            match blocking(move || Ok(device_unlock.unlock(&account_id, "unlock your vault")?))
                .await
            {
                Err(error) if error.code == ErrorCode::DeviceUnlockFailed => {
                    // The OS no longer has the secret (or refuses it for good): start over.
                    self.remove_device_unlock(&local.key)?;
                    return Err(error);
                }
                other => other?,
            };
        let blob = self.store.read_local(&local.tag)?;
        let vault = match LocalVault::unlock_with_device_key(
            &blob,
            secret.as_ref(),
            &b64_decode(&record.device_salt)?,
            &record.wrapped_ask,
        ) {
            Ok(vault) => vault,
            Err(error) => {
                self.remove_device_unlock(&local.key)?;
                return Err(error.into());
            }
        };
        if self.state().unlocked.is_some() {
            return Ok(());
        }
        self.install_local(local, vault)?;
        self.note_device_unlock();
        Ok(())
    }

    /// Wraps the vault's key for device unlock, as for accounts.
    pub(super) fn set_local_device_unlock(
        &self,
        key: &AccountKey,
        record: WrappedAsk,
    ) -> Result<()> {
        let mut state = self.state();
        state
            .device
            .local_mut(key)
            .ok_or(ErrorCode::Locked)?
            .device_unlock = Some(record);
        self.save_device(&state)
    }

    /// Checks the master password against the stored vault: reveal, copy, export.
    pub(super) async fn confirm_local_password(
        &self,
        local: StoredLocal,
        password: Zeroizing<String>,
    ) -> Result<()> {
        self.with_unlocked(|_| Ok(()))?;
        let blob = self.store.read_local(&local.tag)?;
        let chip = self.stored_chip(&local).await?;
        blocking(move || {
            LocalVault::unlock(&blob, &password, chip.as_ref().map(|secret| &secret[..]))?;
            Ok(())
        })
        .await
    }

    /// A new master password. The backup key follows it; the recovery code stays, and device
    /// unlock has to be turned on again.
    pub(super) async fn change_local_password(
        &self,
        local: StoredLocal,
        current: Zeroizing<String>,
        new_password: Zeroizing<String>,
    ) -> Result<()> {
        let chip = self.stored_chip(&local).await?;
        check_password(&new_password, chip.is_some())?;
        self.confirm_local_password(local.clone(), current).await?;
        let (seed, session) =
            self.with_local(|open| Ok((open.vault.to_bytes(&mut OsRng)?, open.vault.session()?)))?;
        let kdf = session.bundle().kdf;
        let changed = blocking(move || {
            let mut vault = LocalVault::from_seed(&seed, &session)?;
            vault.change_password(
                &new_password,
                DeviceProtection {
                    kdf,
                    hardware_secret: chip.as_ref().map(|secret| &secret[..]),
                },
                &mut OsRng,
            )?;
            Ok(vault)
        })
        .await?;
        self.store
            .write_local(&local.tag, &changed.to_bytes(&mut OsRng)?)?;
        self.with_unlocked(|unlocked| {
            unlocked.local = Some(OpenLocal { vault: changed });
            Ok(())
        })?;
        self.remove_device_unlock(&local.key)?;
        self.forget_stay_unlocked(&local.key)?;
        let mut state = self.state();
        if let Some(stored) = state.device.local_mut(&local.key) {
            stored.last_password_unlock_at = rfc3339(now());
        }
        self.save_device(&state)
    }

    fn with_local<T>(&self, run: impl FnOnce(&mut OpenLocal) -> Result<T>) -> Result<T> {
        self.with_unlocked(|unlocked| run(unlocked.local.as_mut().ok_or(ErrorCode::NotFound)?))
    }

    pub(super) fn local_account_summary(&self) -> Result<AccountSummary> {
        let name = self.snapshot().session.email.unwrap_or_default();
        self.with_unlocked(|unlocked| {
            Ok(AccountSummary {
                email: name,
                item_count: unlocked
                    .cache
                    .items
                    .iter()
                    .filter(|item| item.deleted_at.is_none())
                    .count(),
                vault_count: 1,
                device_count: 1,
                shared_vaults_owned: Vec::new(),
            })
        })
    }

    /// Encrypts and stores one item, in place of an upload.
    pub(super) fn put_local(
        &self,
        draft: &ItemDraft,
        item_id: &str,
        item_key: Option<&str>,
    ) -> Result<()> {
        let key = self.with_unlocked(|unlocked| {
            let encrypted = unlocked.session.encrypt_item(
                &draft.vault_id,
                item_id,
                &draft.to_core()?,
                item_key,
                &mut OsRng,
            )?;
            let at = unix_ms(now());
            let previous = unlocked.cache.item(item_id).map(|record| record.revision);
            let stored = LocalItem {
                id: item_id.to_owned(),
                encrypted,
                created_at: previous.map_or(at, |_| {
                    unlocked
                        .local
                        .as_ref()
                        .and_then(|open| open.vault.items().iter().find(|item| item.id == item_id))
                        .map_or(at, |item| item.created_at)
                }),
                // Revisions follow it, and two saves in a millisecond must still differ.
                updated_at: previous.map_or(at, |revision| at.max(revision + 1)),
                deleted_at: None,
            };
            unlocked.cache.upsert(record(&draft.vault_id, &stored));
            unlocked
                .local
                .as_mut()
                .ok_or(ErrorCode::NotFound)?
                .vault
                .put_item(stored);
            Ok(unlocked.key.clone())
        })?;
        self.persist_local(&key)
    }

    /// Moves an item to the trash, or out of it.
    pub(super) fn trash_local(&self, item_id: &str, trashed: bool) -> Result<()> {
        let key = self.with_unlocked(|unlocked| {
            let open = unlocked.local.as_mut().ok_or(ErrorCode::NotFound)?;
            let at = unix_ms(now());
            if trashed {
                open.vault.delete_item(item_id, at)?;
            } else {
                open.vault.restore_item(item_id)?;
            }
            let row = unlocked
                .cache
                .items
                .iter_mut()
                .find(|item| item.id == item_id)
                .ok_or(ErrorCode::NotFound)?;
            row.revision += 1;
            row.deleted_at = trashed.then(|| rfc3339(now()));
            Ok(unlocked.key.clone())
        })?;
        self.persist_local(&key)
    }

    /// Writes the vault after a change, and notes it for the next automatic backup.
    fn persist_local(&self, key: &AccountKey) -> Result<()> {
        let bytes = self.with_local(|open| Ok(open.vault.to_bytes(&mut OsRng)?))?;
        let tag = key.server_url.trim_start_matches(LOCAL_SCHEME).to_owned();
        self.store.write_local(&tag, &bytes)?;
        let mut state = self.state();
        if let Some(local) = state.device.local_mut(key) {
            local.changed_at = Some(unix_ms(now()));
        }
        self.save_device(&state)?;
        drop(state);
        self.emit(Event::ItemsChanged);
        Ok(())
    }

    /// A backup file of the open vault, counted as a backup: the app saves it where the user
    /// says. Needs no password: the backup key is in the vault.
    pub fn create_local_backup(&self) -> Result<Vec<u8>> {
        let key = self.account_key()?;
        let bytes = self.with_local(|open| Ok(open.vault.create_backup(&mut OsRng)?))?;
        self.mark_backed_up(&key)?;
        Ok(bytes)
    }

    /// What the save dialog suggests for a backup of the open vault.
    pub fn local_backup_file_name(&self) -> Result<String> {
        let local = self.current_local().ok_or(ErrorCode::NotFound)?;
        Ok(backup_name(&local, &rfc3339(now())))
    }

    fn mark_backed_up(&self, key: &AccountKey) -> Result<()> {
        let mut state = self.state();
        if let Some(local) = state.device.local_mut(key) {
            local.last_backup_at = Some(rfc3339(now()));
            local.backed_up_at = local.changed_at;
        }
        self.save_device(&state)
    }

    pub fn local_recovery_code(&self) -> Result<Zeroizing<String>> {
        self.with_local(|open| Ok(open.vault.backup_recovery_code()))
    }

    /// Turns automatic backups on, into `folder`, and writes the first one now; `None` turns
    /// them off. A folder that can't take that backup isn't kept, and the one before it stays.
    pub fn set_backup_folder(&self, folder: Option<String>) -> Result<()> {
        let key = self.account_key()?;
        let before = {
            let mut state = self.state();
            let local = state.device.local_mut(&key).ok_or(ErrorCode::NotFound)?;
            let before = (local.backup_folder.clone(), local.backed_up_at);
            local.backup_folder = folder.clone();
            // Whatever the newest backup holds, a new folder has none.
            local.backed_up_at = None;
            self.save_device(&state)?;
            before
        };
        if folder.is_none() {
            return Ok(());
        }
        let written = self.back_up_to_folder();
        if written.is_err() {
            let mut state = self.state();
            if let Some(local) = state.device.local_mut(&key) {
                (local.backup_folder, local.backed_up_at) = before;
            }
            self.save_device(&state)?;
        }
        written
    }

    /// A backup to the vault's folder when it changed and has been quiet for a minute. The app
    /// calls this on a timer, and locking does too (with `force`). Failing doesn't stop
    /// anything: it's reported, and the next try is the next timer.
    pub fn auto_backup(&self, force: bool) {
        // On its own line: the state's lock must be free again for `current_local`.
        let open = self
            .state()
            .unlocked
            .as_ref()
            .is_some_and(|unlocked| unlocked.local.is_some());
        let due = open
            && self.current_local().is_some_and(|local| {
                let changed = local
                    .changed_at
                    .is_some_and(|at| local.backed_up_at.is_none_or(|done| done < at));
                let quiet = local.changed_at.is_some_and(|at| {
                    unix_ms(now()).saturating_sub(at) >= AUTO_BACKUP_QUIET.as_millis() as u64
                });
                local.backup_folder.is_some() && changed && (force || quiet)
            });
        if due && let Err(error) = self.back_up_to_folder() {
            self.emit(Event::BackupFailed {
                message: error.message,
            });
        }
    }

    fn back_up_to_folder(&self) -> Result<()> {
        let local = self.current_local().ok_or(ErrorCode::NotFound)?;
        let Some(folder) = &local.backup_folder else {
            return Ok(());
        };
        let bytes = self.with_local(|open| Ok(open.vault.create_backup(&mut OsRng)?))?;
        let folder = Path::new(folder);
        let name = backup_name(&local, &rfc3339(now()));
        let temporary = folder.join(format!(".{name}.tmp"));
        std::fs::write(&temporary, bytes)
            .and_then(|()| std::fs::rename(&temporary, folder.join(&name)))
            .map_err(|error| {
                let _ = std::fs::remove_file(&temporary);
                storage(error)
            })?;
        self.mark_backed_up(&local.key)?;

        // Only this vault's own automatic files, and only the oldest.
        let prefix = backup_prefix(&local);
        let mut files: Vec<_> = std::fs::read_dir(folder)
            .map_err(storage)?
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|file| file.starts_with(&prefix) && file.ends_with(BACKUP_EXTENSION))
            .collect();
        files.sort();
        for file in &files[..files.len().saturating_sub(KEEP_BACKUPS)] {
            std::fs::remove_file(folder.join(file)).map_err(storage)?;
        }
        Ok(())
    }

    /// Opens another local vault, locked, as the current one.
    pub fn switch_local_vault(&self, id: &str) -> Result<()> {
        self.lock();
        let mut state = self.state();
        let key = local_key(id);
        require(state.device.local(&key).is_some(), ErrorCode::NotFound)?;
        state.device.current = Some(key);
        self.save_device(&state)?;
        drop(state);
        self.emit_session();
        Ok(())
    }

    /// Back to the first screen, to add a vault or sign in. Nothing is deleted.
    pub fn leave_local_vault(&self) -> Result<()> {
        self.lock();
        let mut state = self.state();
        state.device.current = None;
        self.save_device(&state)?;
        drop(state);
        self.emit_session();
        Ok(())
    }

    pub fn rename_local_vault(&self, name: &str) -> Result<()> {
        let key = self.account_key()?;
        let name = name.trim().to_owned();
        require(!name.is_empty(), ErrorCode::InvalidName)?;
        self.with_local(|open| {
            open.vault.set_name(Some(name.clone()));
            Ok(())
        })?;
        {
            let mut state = self.state();
            state
                .device
                .local_mut(&key)
                .ok_or(ErrorCode::NotFound)?
                .name = name;
            self.save_device(&state)?;
        }
        self.persist_local(&key)?;
        self.emit_session();
        Ok(())
    }

    /// Deletes the open vault from this computer for good, after the master password. Backups
    /// stay where they are. Another local vault becomes current, if there is one.
    pub async fn delete_local_vault(&self, password: Zeroizing<String>) -> Result<()> {
        let local = self.current_local().ok_or(ErrorCode::NotFound)?;
        self.confirm_local_password(local.clone(), password).await?;
        self.forget_local(&local.key)?;
        self.emit_session();
        Ok(())
    }

    /// Removes a local vault's file and keys. The vault must not be needed: when it's open, it
    /// closes.
    fn forget_local(&self, key: &AccountKey) -> Result<()> {
        let local = {
            let mut state = self.state();
            let local = state
                .device
                .local(key)
                .cloned()
                .ok_or(ErrorCode::NotFound)?;
            if state
                .unlocked
                .as_ref()
                .is_some_and(|unlocked| &unlocked.key == key)
            {
                state.unlocked = None;
                state.generation += 1;
            }
            state.device.locals.retain(|other| &other.key != key);
            if state.device.current.as_ref() == Some(key) {
                state.device.current = state.device.locals.first().map(|other| other.key.clone());
            }
            self.save_device(&state)?;
            local
        };
        self.store.delete_local(&local.tag)?;
        let _ = self.device_unlock.remove(&key.id());
        let _ = self.forget_stay_unlocked(key);
        let _ = self.device_unlock.delete_chip_key(&chip_name(&local.tag));
        Ok(())
    }

    /// **Turn on sync**, first half: the sign-up steps, keeping this vault's keys (only the
    /// ASK is wrapped again). The server emails a code; `finish_turn_on_sync` takes it.
    pub async fn start_turn_on_sync(
        &self,
        server_url: &str,
        email: &str,
        password: Zeroizing<String>,
    ) -> Result<SignupStarted> {
        let local = self.current_local().ok_or(ErrorCode::NotFound)?;
        let server_url = super::normalize_server_url(server_url)?;
        let email = valid_email(email)?;
        let (seed, session) =
            self.with_local(|open| Ok((open.vault.seed(&mut OsRng)?, open.vault.session()?)))?;
        let account = blocking(move || {
            let vault = LocalVault::from_seed(&seed, &session)?;
            Ok(vault.upgrade_to_account(&email, &password, KdfParams::DEFAULT, &mut OsRng)?)
        })
        .await?;
        let (registration, registration_request) =
            RegistrationClient::start(&account.keys.auth_secret, &mut OsRng)?;
        let api = self.api(&server_url);
        let started = api
            .register_start(&RegisterStartRequest {
                email: account.bundle.email.clone(),
                registration_request,
            })
            .await?;
        let registration_upload = registration.finish(
            &account.keys.auth_secret,
            &started.registration_response,
            &mut OsRng,
        )?;
        let signup_id = new_tag();
        self.state().upgrades.insert(
            signup_id.clone(),
            PendingUpgrade {
                server_url,
                source: local.key,
                account,
                registration_upload,
                expires_at: Instant::now() + SIGNUP_TTL,
                registered: false,
                signed_in: None,
            },
        );
        Ok(SignupStarted {
            signup_id,
            dev_verification_code: started.dev_verification_code,
        })
    }

    /// **Turn on sync**, second half: registers the account, uploads the items as they are, and
    /// only then removes the local vault and opens the account. A wrong code, or an upload that
    /// fails, can be tried again with the same call: the local vault stays until every item is
    /// on the server.
    pub async fn finish_turn_on_sync(
        &self,
        signup_id: &str,
        verification_code: &str,
    ) -> Result<RecoveryKit> {
        let mut pending = self
            .state()
            .upgrades
            .remove(signup_id)
            .filter(|pending| pending.expires_at > Instant::now())
            .ok_or(ErrorCode::SignupExpired)?;
        let result = self.run_upgrade(&mut pending, verification_code).await;
        if result.is_err() {
            self.state().upgrades.insert(signup_id.to_owned(), pending);
        }
        result
    }

    async fn run_upgrade(
        &self,
        pending: &mut PendingUpgrade,
        verification_code: &str,
    ) -> Result<RecoveryKit> {
        let (items, vault_id) = self.with_unlocked(|unlocked| {
            require(unlocked.key == pending.source, ErrorCode::SignupExpired)?;
            let open = unlocked.local.as_ref().ok_or(ErrorCode::NotFound)?;
            Ok((
                open.vault.items().to_vec(),
                open.vault.vault_id().to_owned(),
            ))
        })?;
        let api = self.api(&pending.server_url);
        if !pending.registered {
            let account = &pending.account;
            api.register_finish(&RegisterFinishRequest {
                email: account.bundle.email.clone(),
                verification_code: verification_code.split_whitespace().collect(),
                registration_upload: pending.registration_upload.clone(),
                account: convert(&account.bundle)?,
                personal_vault: NewPersonalVault {
                    id: account.personal_vault.id.clone(),
                    wrapped_vault_key: account.personal_vault.wrapped_vault_key.clone(),
                },
            })
            .await?;
            pending.registered = true;
        }

        let _io = self.io.lock().await;
        if pending.signed_in.is_none() {
            let account = &pending.account;
            let Login::Finished(login) = self
                .login(&api, &account.bundle.email, &account.keys, None)
                .await?
            else {
                return Err(VaultError::unexpected(
                    "a new account asked for a second step",
                ));
            };
            pending.signed_in = Some(self.remember_upgraded(pending, login)?);
        }
        let (key, _) = pending.signed_in.as_ref().expect("signed in above");

        // Everything goes up before anything local goes away. Items sent by a first try are
        // already there.
        let mut trashed = Vec::new();
        for item in &items {
            let body = PutItemRequest {
                encrypted_item_key: item.encrypted.encrypted_item_key.clone(),
                overview: item.encrypted.overview.clone(),
                details: item.encrypted.details.clone(),
                skip_history: false,
            };
            let (vault, id) = (vault_id.clone(), item.id.clone());
            let saved = self
                .authed(key, |api, token| {
                    let (body, vault, id) = (body.clone(), vault.clone(), id.clone());
                    async move {
                        api.put_item(&token, &vault, &id, Precondition::Create, &body)
                            .await
                    }
                })
                .await?;
            match saved {
                Ok(saved) if item.deleted_at.is_some() => {
                    trashed.push((item.id.clone(), saved.revision));
                }
                Ok(_) => {}
                Err(error) if error.is(octapass_api::problem::types::CONFLICT) => {}
                Err(error) => return Err(error.into()),
            }
        }
        // An upload can't say an item is in the trash.
        for (id, revision) in trashed {
            let (vault, id) = (vault_id.clone(), id);
            self.authed(key, |api, token| {
                let (vault, id) = (vault.clone(), id.clone());
                async move { api.delete_item(&token, &vault, &id, revision).await }
            })
            .await??;
        }

        let source = pending.source.clone();
        let (key, session) = pending.signed_in.take().expect("signed in above");
        self.forget_local(&source)?;
        self.install(key.clone(), session)?;
        self.report(self.sync_locked().await);
        Ok(RecoveryKit {
            email: key.email,
            server_url: key.server_url,
            secret_key: pending.account.secret_key.to_text().to_string(),
            recovery_code: pending.account.recovery_code.to_text().to_string(),
            created_at: rfc3339(now()),
        })
    }

    fn remember_upgraded(
        &self,
        pending: &PendingUpgrade,
        login: LoginFinishResponse,
    ) -> Result<(AccountKey, Session)> {
        let bundle: AccountBundle = convert(&login.account)?;
        let session = Session::unlock(bundle.clone(), &pending.account.keys.auk)?;
        let key = AccountKey {
            server_url: pending.server_url.clone(),
            email: bundle.email.clone(),
        };
        self.remember(
            StoredAccount {
                key: key.clone(),
                secret_key: pending.account.secret_key.to_text().to_string(),
                bundle,
                refresh_token: Some(login.refresh_token),
                trusted_device_token: login.trusted_device_token,
                last_password_unlock_at: rfc3339(now()),
                device_unlock: None,
            },
            login.access_token,
        )?;
        Ok((key, session))
    }

    /// The chip's secret for the browser extension's own local vault (plan 05): the extension
    /// has no chip of its own, so one is kept for it here. Without the app the vault can't open,
    /// and without the master password this secret is useless.
    pub(crate) async fn extension_chip_secret(
        &self,
        vault_id: &str,
        context: Option<&str>,
    ) -> Result<Option<(String, Zeroizing<Vec<u8>>)>> {
        let name = format!("extension-vault|{vault_id}");
        let device_unlock = Arc::clone(&self.device_unlock);
        match context {
            Some(context) => {
                let context = b64_decode(context)?;
                let encoded = b64_encode(&context);
                blocking(move || Ok(device_unlock.chip_secret(&name, &context)?))
                    .await
                    .map(|secret| Some((encoded, Zeroizing::new(secret.to_vec()))))
            }
            None => blocking(move || Ok(device_unlock.create_chip_key(&name)?))
                .await
                .map(|key| {
                    key.map(|key| {
                        (
                            b64_encode(&key.context),
                            Zeroizing::new(key.secret.to_vec()),
                        )
                    })
                }),
        }
    }
}

fn check_password(password: &str, chip: bool) -> Result<()> {
    let enough = !chip || strength::estimate(password, &[]).score >= MIN_SCORE_WITH_CHIP;
    require(enough, ErrorCode::WeakMasterPassword)
}
