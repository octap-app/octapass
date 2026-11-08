//! Vaults on this phone only (plan 03, *Local mode keys*; plan 01, *Local mode*).
//!
//! A local vault is an entry in `accounts.json` with `local` set, and a `LocalStore` like any
//! other: the app's screens and the AutoFill extensions work unchanged, and only what would reach
//! a server differs. Next to the store is the vault's seed, which holds the backup key and the
//! backup recovery code, sealed by the account key.

use std::path::Path;

use octapass_core::backup::BACKUP_KDF;
use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_core::kdf::KdfParams;
use octapass_core::local::keys::{LOCAL_KDF, LOCAL_KDF_LOW_MEMORY};
use octapass_core::local::{BackupSecret, DeviceProtection, LocalVault};
use octapass_core::tools::strength;
use octapass_ffi::{LOCAL_SERVER_PREFIX, LocalStore, Session};
use rand_core::{OsRng, RngCore};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use super::{Event, PendingSignup, SIGNUP_TTL, Unlocked, Vault, new_signup_id};
use crate::accounts::{Account, LocalAccount, store_path};
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{RecoveryKit, SignupStarted, now, require};

/// A new chip key: its context (base64url) and `hw_secret`.
type NewChip = (String, Zeroizing<Vec<u8>>);

/// A local vault without a backup for this long gets a reminder (plan 01).
const BACKUP_DUE_MS: i128 = 30 * 86_400_000;
/// Automatic backups a folder keeps per vault; older ones are deleted.
const KEEP_BACKUPS: usize = 7;
/// With a chip the password can't be attacked off this phone, but a backup can be: it's as
/// strong as the password. Without one, the core asks for zxcvbn's top score (plan 03).
const MIN_SCORE_WITH_CHIP: u8 = 3;
const BACKUP_EXTENSION: &str = ".octapass-backup";

/// One local vault on this phone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVaultInfo {
    /// Stable: how the app names it to `switch_local_vault`.
    pub tag: String,
    pub name: String,
    pub created_at: String,
    pub last_backup_at: Option<String>,
    /// It's been 30 days since the last backup (or since creating it, with none), and no folder
    /// is keeping up with the vault.
    pub backup_due: bool,
    /// The platform's reference to the folder, to let go of it when it changes.
    pub backup_folder: Option<String>,
    pub backup_folder_name: Option<String>,
    /// Bound to this phone's chip: a copied file is useless elsewhere.
    pub chip_bound: bool,
    /// The vault the app has open, or would open.
    pub current: bool,
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

/// What the setup screens need to know before asking for a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalCapabilities {
    /// New vaults are bound to this device's chip.
    pub chip: bool,
    /// The lowest zxcvbn score a new master password may have here.
    pub min_score: u8,
}

fn new_tag() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A name of its own for each vault's backups, so several vaults can share a folder. The vault's
/// name stays out of it: a folder may be a cloud drive.
fn backup_prefix(account: &Account) -> String {
    format!("octapass-{}-", &account.tag[..8])
}

fn backup_name(account: &Account, at: &str) -> String {
    let stamp: String = at
        .chars()
        .take(19)
        .map(|c| if c == ':' { '-' } else { c })
        .collect();
    format!("{}{stamp}{BACKUP_EXTENSION}", backup_prefix(account))
}

/// Whether 30 days have passed since an RFC 3339 time. One that can't be read counts as due.
fn backup_due(since: &str) -> bool {
    OffsetDateTime::parse(since, &Rfc3339).map_or(true, |at| {
        (OffsetDateTime::now_utc() - at).whole_milliseconds() >= BACKUP_DUE_MS
    })
}

fn storage(error: impl std::fmt::Display) -> VaultError {
    VaultError::unexpected(format!("storage: {error}"))
}

impl Vault {
    pub(super) fn is_local_unlocked(&self) -> bool {
        self.state()
            .unlocked
            .as_ref()
            .is_some_and(|unlocked| unlocked.account.is_local())
    }

    pub fn local_capabilities(&self) -> LocalCapabilities {
        let chip = self.native.chip_available();
        LocalCapabilities {
            chip,
            min_score: if chip { MIN_SCORE_WITH_CHIP } else { 4 },
        }
    }

    /// Every local vault on this phone, with the one the app has open marked.
    pub fn local_vaults(&self) -> Vec<LocalVaultInfo> {
        let state = self.state();
        let current = state.accounts.current.as_deref();
        state
            .accounts
            .accounts
            .iter()
            .filter_map(|account| {
                let local = account.local.as_ref()?;
                let last = local.last_backup_at.as_deref().unwrap_or(&local.created_at);
                // A folder keeps an unchanged vault backed up for as long as it likes; one that
                // has stopped working still gets the reminder.
                let covered = local.backup_folder.is_some()
                    && local.backed_up_change.is_some()
                    && state
                        .unlocked
                        .as_ref()
                        .filter(|open| open.account.tag == account.tag)
                        .is_some_and(|open| {
                            local.backed_up_change >= Some(open.store.last_changed_at())
                        });
                Some(LocalVaultInfo {
                    tag: account.tag.clone(),
                    name: account.email.clone(),
                    created_at: local.created_at.clone(),
                    last_backup_at: local.last_backup_at.clone(),
                    backup_due: !covered && backup_due(last),
                    backup_folder: local.backup_folder.clone(),
                    backup_folder_name: local.backup_folder_name.clone(),
                    chip_bound: local.chip_context.is_some(),
                    current: current == Some(account.tag.as_str()),
                })
            })
            .collect()
    }

    /// How a new vault is protected here. The KDF follows the device, and the chip key is new.
    fn protect_new(&self, account: &Account) -> Result<(KdfParams, Option<NewChip>)> {
        let kdf = if self.native.low_memory() {
            LOCAL_KDF_LOW_MEMORY
        } else {
            LOCAL_KDF
        };
        let chip = self.native.create_chip_key(&account.chip_key_name())?;
        Ok((
            kdf,
            chip.map(|chip| (b64_encode(&chip.context), chip.secret)),
        ))
    }

    fn check_password(&self, password: &str, chip: bool) -> Result<()> {
        if chip {
            require(
                strength::estimate(password, &[]).score >= MIN_SCORE_WITH_CHIP,
                ErrorCode::WeakMasterPassword,
            )?;
        }
        Ok(())
    }

    /// "Use on this device only": a new vault, unlocked and current. Runs Argon2id twice. Returns
    /// the backup recovery code, for the local Recovery Kit.
    pub fn create_local_vault(
        &self,
        name: &str,
        password: Zeroizing<String>,
    ) -> Result<Zeroizing<String>> {
        self.create_local_vault_with(name, password, BACKUP_KDF)
    }

    /// `create_local_vault` with other backup key parameters: tests only.
    #[doc(hidden)]
    pub fn create_local_vault_with(
        &self,
        name: &str,
        password: Zeroizing<String>,
        backup_kdf: KdfParams,
    ) -> Result<Zeroizing<String>> {
        let mut account = self.new_local_account(name)?;
        self.check_password(&password, self.native.chip_available())?;
        let (kdf, chip) = self.protect_new(&account)?;
        let created = LocalVault::create_with_backup_kdf(
            &password,
            DeviceProtection {
                kdf,
                hardware_secret: chip.as_ref().map(|(_, secret)| &secret[..]),
            },
            backup_kdf,
            unix_ms(),
            &mut OsRng,
        );
        let mut vault = match created {
            Ok(vault) => vault,
            Err(error) => {
                let _ = self.native.delete_chip_key(&account.chip_key_name());
                return Err(VaultError::from(octapass_ffi::OctaPassError::from(error)));
            }
        };
        vault.set_name(Some(account.email.clone()));
        let code = vault.backup_recovery_code();
        if let Some(local) = &mut account.local {
            local.chip_context = chip.map(|(context, _)| context);
        }
        self.install_local(account, &vault)?;
        Ok(code)
    }

    fn new_local_account(&self, name: &str) -> Result<Account> {
        let name = name.trim();
        require(!name.is_empty(), ErrorCode::InvalidName)?;
        Ok(Account {
            tag: new_tag(),
            email: name.to_owned(),
            server_url: String::new(),
            local: Some(LocalAccount {
                created_at: now(),
                ..LocalAccount::default()
            }),
        })
    }

    /// Writes a vault's store and seed, and opens it as the current vault.
    fn install_local(&self, mut account: Account, vault: &LocalVault) -> Result<()> {
        account.server_url = format!("{LOCAL_SERVER_PREFIX}{}", vault.vault_id());
        std::fs::create_dir_all(&self.config.data_dir).map_err(storage)?;
        self.write_seed(&account, vault)?;
        let path = store_path(&self.config.data_dir, &account);
        let store = LocalStore::create_local(
            path.to_string_lossy().into_owned(),
            account.server_url.clone(),
            vault,
        )?;
        let session = Session::from_local_vault(vault)?;
        let previous = {
            let mut state = self.state();
            let previous = state.unlocked.take();
            if let Some(previous) = &previous {
                previous.session.lock();
            }
            state.access_token = None;
            state.accounts.upsert_current(account.clone());
            state.accounts.save(&self.config.data_dir)?;
            previous
        };
        if let Some(previous) = previous {
            self.drop_fill_key(&previous.account);
        }
        self.clear_plaintext();
        self.set_unlocked(account, store, session)?;
        (self.listener)(Event::ItemsChanged);
        self.publish_identities();
        Ok(())
    }

    fn write_seed(&self, account: &Account, vault: &LocalVault) -> Result<()> {
        let path = self.config.data_dir.join(account.seed_file());
        let temporary = path.with_extension("oplocal.tmp");
        std::fs::write(&temporary, vault.seed(&mut OsRng).map_err(core_error)?)
            .and_then(|()| std::fs::rename(&temporary, &path))
            .map_err(storage)
    }

    fn read_seed(&self, account: &Account) -> Result<Vec<u8>> {
        std::fs::read(self.config.data_dir.join(account.seed_file())).map_err(storage)
    }

    /// `hw_secret`, for a vault bound to the chip.
    pub(super) fn chip_secret(&self, account: &Account) -> Result<Option<Vec<u8>>> {
        let context = account
            .local
            .as_ref()
            .and_then(|local| local.chip_context.as_ref());
        let Some(context) = context else {
            return Ok(None);
        };
        let context =
            b64_decode(context).map_err(|error| VaultError::unexpected(error.to_string()))?;
        let secret = self
            .native
            .chip_secret(&account.chip_key_name(), &context)?;
        Ok(Some(secret.to_vec()))
    }

    pub(super) fn unlock_local(&self, account: Account, password: Zeroizing<String>) -> Result<()> {
        let store = self.open_store(&account)?;
        let session = store.unlock_local(password.to_string(), self.chip_secret(&account)?)?;
        store.purge_local_trash(unix_ms())?;
        self.set_unlocked(account, store, session)?;
        self.publish_identities();
        Ok(())
    }

    /// Restores a `.octapass-backup` file as a new vault here, unlocked and current.
    pub fn restore_local_vault(&self, path: &Path, secret: RestoreSecret) -> Result<()> {
        let file = std::fs::read(path).map_err(storage)?;
        let mut account = self.new_local_account("Restored")?;
        let (password, core_secret) = match &secret {
            RestoreSecret::Password(password) => {
                (password.clone(), BackupSecret::Password(password))
            }
            RestoreSecret::RecoveryCode { code, new_password } => {
                (new_password.clone(), BackupSecret::RecoveryCode(code))
            }
        };
        // The password a backup was made with is checked by opening it: a typo isn't "weak".
        if matches!(secret, RestoreSecret::RecoveryCode { .. }) {
            self.check_password(&password, self.native.chip_available())?;
        }
        let (kdf, chip) = self.protect_new(&account)?;
        let restored = LocalVault::restore_backup(
            &file,
            core_secret,
            &password,
            DeviceProtection {
                kdf,
                hardware_secret: chip.as_ref().map(|(_, secret)| &secret[..]),
            },
            &mut OsRng,
        );
        let vault = match restored {
            Ok(vault) => vault,
            Err(error) => {
                let _ = self.native.delete_chip_key(&account.chip_key_name());
                return Err(match error {
                    octapass_core::Error::LoginFailed
                    | octapass_core::Error::InvalidRecoveryCode
                    | octapass_core::Error::InvalidBackup
                    | octapass_core::Error::UnsupportedVersion => ErrorCode::InvalidBackup.into(),
                    other => core_error(other),
                });
            }
        };
        if let Err(error) = self.check_password(&password, chip.is_some()) {
            let _ = self.native.delete_chip_key(&account.chip_key_name());
            return Err(error);
        }
        if let Some(name) = vault.name() {
            account.email = name.to_owned();
        }
        if let Some(local) = &mut account.local {
            local.chip_context = chip.map(|(context, _)| context);
            // The file it came from is a backup of everything it holds.
            local.last_backup_at = Some(now());
        }
        self.install_local(account, &vault)
    }

    /// Opens another local vault, locked, as the current one.
    pub fn switch_local_vault(&self, tag: &str) -> Result<()> {
        self.lock();
        {
            let mut state = self.state();
            require(
                state.accounts.find_tag(tag).is_some_and(Account::is_local),
                ErrorCode::NotFound,
            )?;
            state.accounts.current = Some(tag.to_owned());
            state.accounts.save(&self.config.data_dir)?;
        }
        self.native.set_credential_identities(&[])?;
        self.emit_session();
        Ok(())
    }

    /// Back to the first screen, for adding another vault or an account. Nothing is deleted.
    pub fn leave_local_vault(&self) -> Result<()> {
        self.lock();
        {
            let mut state = self.state();
            state.accounts.current = None;
            state.accounts.save(&self.config.data_dir)?;
        }
        self.native.set_credential_identities(&[])?;
        self.emit_session();
        Ok(())
    }

    pub fn rename_local_vault(&self, name: &str) -> Result<()> {
        let unlocked = self.local()?;
        let name = name.trim();
        require(!name.is_empty(), ErrorCode::InvalidName)?;
        let seed = self.read_seed(&unlocked.account)?;
        let mut vault = unlocked.session.local_vault(&unlocked.store, &seed)?;
        vault.set_name(Some(name.to_owned()));
        self.write_seed(&unlocked.account, &vault)?;
        {
            let mut state = self.state();
            if let Some(account) = state.accounts.find_tag_mut(&unlocked.account.tag) {
                account.email = name.to_owned();
            }
            if let Some(open) = &mut state.unlocked {
                open.account.email = name.to_owned();
            }
            state.accounts.save(&self.config.data_dir)?;
        }
        self.emit_session();
        Ok(())
    }

    /// Deletes the open vault from this phone for good, after the master password. Backups stay
    /// where they are. Another local vault becomes current, if there is one.
    pub fn delete_local_vault(&self, password: Zeroizing<String>) -> Result<()> {
        let unlocked = self.local()?;
        self.confirm_user(Some(password))?;
        self.forget_local(&unlocked.account)?;
        self.emit_session();
        Ok(())
    }

    /// Removes a local vault's files and keys.
    fn forget_local(&self, account: &Account) -> Result<()> {
        {
            let mut state = self.state();
            if state
                .unlocked
                .as_ref()
                .is_some_and(|unlocked| unlocked.account.tag == account.tag)
                && let Some(unlocked) = state.unlocked.take()
            {
                unlocked.session.lock();
            }
            let current = state.accounts.current.as_deref() == Some(account.tag.as_str());
            state.accounts.remove(&account.tag);
            if current {
                state.accounts.current = state
                    .accounts
                    .accounts
                    .iter()
                    .find(|other| other.is_local())
                    .map(|other| other.tag.clone());
            }
            state.accounts.save(&self.config.data_dir)?;
        }
        self.clear_plaintext();
        let store = store_path(&self.config.data_dir, account);
        for file in [
            store.clone(),
            store.with_extension("opstore.lock"),
            store.with_extension("opstore.inbox"),
            self.config.data_dir.join(account.seed_file()),
        ] {
            match std::fs::remove_file(file) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(storage(error));
                }
                _ => {}
            }
        }
        self.delete_device_keys(account)?;
        self.native.delete_chip_key(&account.chip_key_name())?;
        Ok(())
    }

    /// The open vault's backup recovery code, for the local Recovery Kit.
    pub fn local_recovery_code(&self) -> Result<Zeroizing<String>> {
        Ok(self.open_local()?.1.backup_recovery_code())
    }

    fn local(&self) -> Result<Unlocked> {
        let unlocked = self.unlocked()?;
        require(unlocked.account.is_local(), ErrorCode::NotFound)?;
        Ok(unlocked)
    }

    fn open_local(&self) -> Result<(Unlocked, LocalVault)> {
        let unlocked = self.local()?;
        unlocked.store.reload()?;
        let seed = self.read_seed(&unlocked.account)?;
        let vault = unlocked.session.local_vault(&unlocked.store, &seed)?;
        Ok((unlocked, vault))
    }

    /// Writes a backup of the open vault to a file in the app's private storage, for the share
    /// sheet or the system's save dialog. `delete_opened` removes it afterwards. It counts as a
    /// backup only with `local_backup_saved`: the user can still cancel.
    pub fn export_local_backup(&self) -> Result<String> {
        let (unlocked, vault) = self.open_local()?;
        let bytes = vault.create_backup(&mut OsRng).map_err(core_error)?;
        let path = self
            .backup_temp()?
            .join(backup_name(&unlocked.account, &now()));
        std::fs::write(&path, bytes).map_err(storage)?;
        Ok(path.to_string_lossy().into_owned())
    }

    /// The file `export_local_backup` made reached the user's chosen place.
    pub fn local_backup_saved(&self) -> Result<()> {
        let unlocked = self.local()?;
        self.mark_backed_up(&unlocked, &now())
    }

    pub(super) fn backup_temp_dir(&self) -> std::path::PathBuf {
        self.config.temp_dir.join("backups")
    }

    fn backup_temp(&self) -> Result<std::path::PathBuf> {
        let folder = self.backup_temp_dir();
        std::fs::create_dir_all(&folder).map_err(storage)?;
        Ok(folder)
    }

    fn mark_backed_up(&self, unlocked: &Unlocked, at: &str) -> Result<()> {
        let change = unlocked.store.last_changed_at();
        let mut state = self.state();
        if let Some(local) = state
            .accounts
            .find_tag_mut(&unlocked.account.tag)
            .and_then(|account| account.local.as_mut())
        {
            local.last_backup_at = Some(at.to_owned());
            local.backed_up_change = Some(change);
        }
        state.accounts.save(&self.config.data_dir)
    }

    /// Where automatic backups go: a platform reference to a folder the user picked and what
    /// they call it. `None` turns them off. A folder that's just been picked gets a backup now;
    /// one that can't take it isn't kept, and the folder before it stays.
    pub fn set_backup_folder(&self, folder: Option<(String, String)>) -> Result<()> {
        let unlocked = self.local()?;
        let tag = &unlocked.account.tag;
        let change = |state: &mut super::State, apply: &dyn Fn(&mut LocalAccount)| {
            if let Some(local) = state
                .accounts
                .find_tag_mut(tag)
                .and_then(|account| account.local.as_mut())
            {
                apply(local);
            }
            state.accounts.save(&self.config.data_dir)
        };
        let before = {
            let mut state = self.state();
            let before = state
                .accounts
                .find_tag(tag)
                .and_then(|account| account.local.clone());
            let (reference, name) = folder.clone().unzip();
            change(&mut state, &|local| {
                local.backup_folder = reference.clone();
                local.backup_folder_name = name.clone();
                // Whatever the newest backup holds, the new folder has none.
                local.backed_up_change = None;
            })?;
            before.unwrap_or_default()
        };
        if folder.is_none() {
            return Ok(());
        }
        let written = self.back_up_to_folder();
        if written.is_err() {
            change(&mut self.state(), &|local| {
                local.backup_folder = before.backup_folder.clone();
                local.backup_folder_name = before.backup_folder_name.clone();
                local.backed_up_change = before.backed_up_change;
            })?;
        }
        written.map(drop)
    }

    /// Writes a backup to the vault's folder when the vault changed since the last one, and
    /// reports a failure without stopping anything: the phone keeps the vault either way. The
    /// app calls this when it leaves the screen; locking does too.
    pub fn auto_backup(&self) {
        if !self.is_local_unlocked() {
            return;
        }
        match self.back_up_to_folder() {
            // "Last backup" moved: the screens read it again on a session event.
            Ok(true) => self.emit_session(),
            Ok(false) => {}
            Err(error) => (self.listener)(Event::SyncFailed {
                message: format!("Automatic backup: {}", error.message),
            }),
        }
    }

    /// Whether a backup was written.
    fn back_up_to_folder(&self) -> Result<bool> {
        let (unlocked, vault) = self.open_local()?;
        let account = self
            .state()
            .accounts
            .find_tag(&unlocked.account.tag)
            .cloned()
            .ok_or(ErrorCode::NotFound)?;
        let local = account.local.clone().unwrap_or_default();
        let Some(folder) = local.backup_folder else {
            return Ok(false);
        };
        if local
            .backed_up_change
            .is_some_and(|at| at >= unlocked.store.last_changed_at())
        {
            return Ok(false);
        }
        let bytes = vault.create_backup(&mut OsRng).map_err(core_error)?;
        let at = now();
        let name = backup_name(&account, &at);
        let temporary = self.backup_temp()?.join(&name);
        std::fs::write(&temporary, bytes).map_err(storage)?;
        let written = self.native.write_backup_file(&folder, &name, &temporary);
        let _ = std::fs::remove_file(&temporary);
        written?;
        self.mark_backed_up(&unlocked, &at)?;

        // Only this vault's own automatic files, and only the oldest.
        let prefix = backup_prefix(&account);
        let mut files: Vec<String> = self
            .native
            .backup_folder_files(&folder)?
            .into_iter()
            .filter(|file| file.starts_with(&prefix) && file.ends_with(BACKUP_EXTENSION))
            .collect();
        files.sort();
        let extra = files.len().saturating_sub(KEEP_BACKUPS);
        for file in &files[..extra] {
            self.native.delete_backup_file(&folder, file)?;
        }
        Ok(true)
    }

    /// Trash here, not on a server. Autofill loses a trashed login at once, as for accounts.
    pub(super) fn trash_local(&self, id: &str, trashed: bool) -> Result<()> {
        let unlocked = self.local()?;
        unlocked
            .store
            .set_local_trashed(id, trashed.then(unix_ms))?;
        (self.listener)(Event::ItemsChanged);
        self.publish_identities();
        Ok(())
    }

    pub(super) fn change_local_password(
        &self,
        unlocked: &Unlocked,
        current: &str,
        new_password: Zeroizing<String>,
    ) -> Result<()> {
        let chip = self.chip_secret(&unlocked.account)?;
        self.check_password(&new_password, chip.is_some())?;
        // A wrong password stops here, before anything changes.
        unlocked
            .store
            .unlock_local(current.to_owned(), chip.clone())?
            .lock();
        let (_, mut vault) = self.open_local()?;
        let kdf = vault.session().map_err(core_error)?.bundle().kdf;
        vault
            .change_password(
                &new_password,
                DeviceProtection {
                    kdf,
                    hardware_secret: chip.as_deref(),
                },
                &mut OsRng,
            )
            .map_err(core_error)?;
        self.write_seed(&unlocked.account, &vault)?;
        unlocked
            .store
            .set_local_account(vault.session().map_err(core_error)?.bundle().clone())?;
        unlocked.store.disable_device_unlock()?;
        self.delete_device_keys(&unlocked.account)
    }

    /// **Turn on sync**, first half: the sign-up steps, keeping this vault's keys. The server
    /// emails a code; `finish_turn_on_sync` takes it.
    pub fn start_turn_on_sync(
        &self,
        server_url: &str,
        email: &str,
        password: Zeroizing<String>,
    ) -> Result<SignupStarted> {
        let (unlocked, vault) = self.open_local()?;
        let server = self.server(server_url)?;
        let account = vault
            .upgrade_to_account(email, &password, KdfParams::DEFAULT, &mut OsRng)
            .map_err(core_error)?;
        let signup = server.start_signup_for(account)?;
        let signup_id = new_signup_id();
        let started = SignupStarted {
            signup_id: signup_id.clone(),
            dev_verification_code: signup.dev_verification_code(),
        };
        self.state().signups.insert(
            signup_id,
            PendingSignup {
                server,
                signup,
                expires_at: std::time::Instant::now() + SIGNUP_TTL,
                upgrades: Some(unlocked.account.tag.clone()),
            },
        );
        Ok(started)
    }

    /// **Turn on sync**, second half: registers the account, moves the items into its new store
    /// (encrypted as they are), uploads them, and removes the local vault. From the moment the
    /// new store exists the items are safe in it: an upload that fails here goes on at the next
    /// sync, as for any change made offline.
    pub fn finish_turn_on_sync(
        &self,
        signup_id: &str,
        verification_code: &str,
    ) -> Result<RecoveryKit> {
        let (server, signup, tag) = {
            let state = self.state();
            let pending = state
                .signups
                .get(signup_id)
                .filter(|pending| pending.expires_at > std::time::Instant::now())
                .ok_or(ErrorCode::SignupExpired)?;
            (
                pending.server.clone(),
                pending.signup.clone(),
                pending.upgrades.clone().ok_or(ErrorCode::SignupExpired)?,
            )
        };
        let local = self.local()?;
        require(local.account.tag == tag, ErrorCode::SignupExpired)?;
        local.store.reload()?;
        let signed_in = signup.finish(verification_code.to_owned(), self.config.device.clone())?;
        self.state().signups.remove(signup_id);
        let trashed = local.store.trashed_item_ids();
        let secret_key = Zeroizing::new(signup.secret_key());
        let account = self.adopt_with(
            &server,
            &signup.email(),
            &secret_key,
            signed_in,
            Some(&local.store),
        )?;
        self.forget_local(&local.account)?;
        // `adopt` made the account current; forgetting only tidied what the vault left. The app
        // still has to hear that the vault's gone.
        self.emit_session();
        let unlocked = self.unlocked()?;
        {
            let _io = self.io();
            if let Err(error) = self.push_changes(&unlocked) {
                (self.listener)(Event::SyncFailed {
                    message: error.message,
                });
            }
        }
        // An upload doesn't say an item is in the trash. Best effort: one that stays out of the
        // trash isn't lost.
        for id in trashed {
            let _ = self.delete_item(&id);
        }
        (self.listener)(Event::ItemsChanged);
        self.publish_identities();
        Ok(RecoveryKit {
            email: account.email,
            server_url: account.server_url,
            secret_key: secret_key.to_string(),
            recovery_code: signup.recovery_code(),
            created_at: now(),
        })
    }
}

fn core_error(error: octapass_core::Error) -> VaultError {
    VaultError::from(octapass_ffi::OctaPassError::from(error))
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}
