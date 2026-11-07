//! Vaults on this device only (plan 01, *Local mode*): "Use on this device only", encrypted
//! backups, several vaults on one phone, and Turn on sync.

use std::path::Path;
use std::sync::Arc;

use octapass_mobile_vault::vault::{
    LocalCapabilities as VaultCapabilities, LocalVaultInfo as VaultInfo, RestoreSecret,
};
use zeroize::Zeroizing;

use crate::error::Result;
use crate::vault::{OctaPassVault, RecoveryKit, SignupStarted, recovery_kit};

/// What the setup screens need to know before asking for a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct LocalCapabilities {
    /// New vaults are bound to this phone's chip, so a copied file is useless elsewhere.
    pub chip: bool,
    /// The lowest `estimateStrength` score a new master password may have here.
    pub min_score: u8,
}

impl From<VaultCapabilities> for LocalCapabilities {
    fn from(capabilities: VaultCapabilities) -> Self {
        Self {
            chip: capabilities.chip,
            min_score: capabilities.min_score,
        }
    }
}

/// One vault on this phone only.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LocalVaultInfo {
    /// What `switchLocalVault` takes.
    pub tag: String,
    pub name: String,
    pub created_at: String,
    pub last_backup_at: Option<String>,
    /// 30 days since the last backup, or since creating it with none, and no folder keeping up:
    /// remind the user.
    pub backup_due: bool,
    /// What the app gave `setBackupFolder`, to let go of it when it changes.
    pub backup_folder: Option<String>,
    /// The folder automatic backups go to, as the user knows it. `None`: they're off.
    pub backup_folder_name: Option<String>,
    pub chip_bound: bool,
    /// The vault the app has open, or would open.
    pub current: bool,
}

impl From<VaultInfo> for LocalVaultInfo {
    fn from(info: VaultInfo) -> Self {
        Self {
            tag: info.tag,
            name: info.name,
            created_at: info.created_at,
            last_backup_at: info.last_backup_at,
            backup_due: info.backup_due,
            backup_folder: info.backup_folder,
            backup_folder_name: info.backup_folder_name,
            chip_bound: info.chip_bound,
            current: info.current,
        }
    }
}

/// What opens a backup file.
#[derive(uniffi::Enum)]
pub enum BackupKey {
    /// The master password it was made with, which stays the vault's.
    Password { password: String },
    /// The backup recovery code, and the master password to set instead.
    RecoveryCode { code: String, new_password: String },
}

#[uniffi::export]
impl OctaPassVault {
    /// Fast: call it anywhere.
    pub fn local_capabilities(&self) -> LocalCapabilities {
        self.vault.local_capabilities().into()
    }

    /// Every vault on this phone only. Fast: call it anywhere, signed out too.
    pub fn local_vaults(&self) -> Vec<LocalVaultInfo> {
        self.vault
            .local_vaults()
            .into_iter()
            .map(LocalVaultInfo::from)
            .collect()
    }

    /// "Use on this device only": a new vault with no account, unlocked and current. Runs
    /// Argon2id twice. Returns the backup recovery code, for the local Recovery Kit.
    pub async fn create_local_vault(
        self: Arc<Self>,
        name: String,
        password: String,
    ) -> Result<String> {
        let password = Zeroizing::new(password);
        self.run(move |this| {
            let code = this.vault.create_local_vault(&name, password)?;
            this.touch();
            Ok(code.to_string())
        })
        .await
    }

    /// Restores a `.octapass-backup` file as a new vault here, unlocked and current. Fails with
    /// `invalidBackup` when the file is damaged or the password or code doesn't open it.
    pub async fn restore_local_vault(self: Arc<Self>, path: String, key: BackupKey) -> Result<()> {
        let secret = match key {
            BackupKey::Password { password } => RestoreSecret::Password(Zeroizing::new(password)),
            BackupKey::RecoveryCode { code, new_password } => RestoreSecret::RecoveryCode {
                code: Zeroizing::new(code),
                new_password: Zeroizing::new(new_password),
            },
        };
        self.run(move |this| {
            this.vault.restore_local_vault(Path::new(&path), secret)?;
            this.touch();
            Ok(())
        })
        .await
    }

    /// Makes another local vault current. It opens locked.
    pub async fn switch_local_vault(self: Arc<Self>, tag: String) -> Result<()> {
        self.run(move |this| Ok(this.vault.switch_local_vault(&tag)?))
            .await
    }

    /// Back to the first screen, to add a vault or sign in. Nothing is deleted, and the vault
    /// stays in `localVaults`.
    pub async fn leave_local_vault(self: Arc<Self>) -> Result<()> {
        self.run(move |this| Ok(this.vault.leave_local_vault()?))
            .await
    }

    pub async fn rename_local_vault(self: Arc<Self>, name: String) -> Result<()> {
        self.run(move |this| Ok(this.vault.rename_local_vault(&name)?))
            .await
    }

    /// Deletes the open vault from this phone for good, after the master password. Backups
    /// stay where they are. Another local vault becomes current, if there is one.
    pub async fn delete_local_vault(self: Arc<Self>, password: String) -> Result<()> {
        let password = Zeroizing::new(password);
        self.run(move |this| Ok(this.vault.delete_local_vault(password)?))
            .await
    }

    /// The open vault's backup recovery code. Ask for the device lock or the master password
    /// first (`confirmUser`).
    pub async fn local_recovery_code(self: Arc<Self>) -> Result<String> {
        self.run(move |this| Ok(this.vault.local_recovery_code()?.to_string()))
            .await
    }

    /// A backup of the open vault in the app's private storage, for the share sheet or the
    /// save dialog. `closeAttachment(path)` deletes it afterwards. Call `localBackupSaved` when
    /// the user really saved it: cancelling doesn't count.
    pub async fn export_local_backup(self: Arc<Self>) -> Result<String> {
        self.run(move |this| Ok(this.vault.export_local_backup()?))
            .await
    }

    /// The file from `exportLocalBackup` reached where the user chose.
    pub async fn local_backup_saved(self: Arc<Self>) -> Result<()> {
        self.run(move |this| Ok(this.vault.local_backup_saved()?))
            .await
    }

    /// Turns automatic backups on for the open vault, into `folder` (the platform's reference)
    /// that the user calls `name`, and writes the first one now; both `None` turns them off. A
    /// folder that can't take that backup isn't kept: the error says so and the old one stays.
    pub async fn set_backup_folder(
        self: Arc<Self>,
        folder: Option<String>,
        name: Option<String>,
    ) -> Result<()> {
        self.run(move |this| Ok(this.vault.set_backup_folder(folder.zip(name))?))
            .await
    }

    /// **Turn on sync**, first half: makes an account that keeps this vault's keys and items,
    /// and asks the server for an email code.
    pub async fn start_turn_on_sync(
        self: Arc<Self>,
        server_url: String,
        email: String,
        password: String,
    ) -> Result<SignupStarted> {
        let password = Zeroizing::new(password);
        self.run(move |this| {
            let started = this
                .vault
                .start_turn_on_sync(&server_url, &email, password)?;
            Ok(SignupStarted {
                signup_id: started.signup_id,
                dev_verification_code: started.dev_verification_code,
            })
        })
        .await
    }

    /// **Turn on sync**, second half: the items move into the new account as they are and the
    /// local vault is removed. Show the Recovery Kit next. A wrong code can be tried again.
    pub async fn finish_turn_on_sync(
        self: Arc<Self>,
        signup_id: String,
        verification_code: String,
    ) -> Result<RecoveryKit> {
        self.run(move |this| {
            let kit = this
                .vault
                .finish_turn_on_sync(&signup_id, &verification_code)?;
            this.touch();
            Ok(recovery_kit(kit))
        })
        .await
    }
}
