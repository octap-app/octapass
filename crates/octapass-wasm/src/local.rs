//! Local mode: a vault on this device only, with no account (plan 03, *Local mode keys*).

use octapass_core::kdf::KdfParams;
use octapass_core::local::{self, BackupSecret, DeviceProtection, keys::LOCAL_KDF};
use rand_core::OsRng;
use serde::Deserialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::account::{Signup, item_from_js};
use crate::{from_js, js_error, now_ms, options_from_js, to_js};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
export type LocalVaultOptions = {
  /** Argon2id memory: 262144 (256 MiB, the default) where the device allows it, else 65536 (64 MiB). */
  memoryKib?: number;
  /** 32 bytes from the device chip (Secure Enclave, Keystore, TPM via the desktop app). Without it the master password must be very strong (`weak_master_password`). */
  hardwareSecret?: Uint8Array;
};
export type LocalItemOverview = { id: string; overview: ItemOverview; createdAt: number; updatedAt: number; deletedAt?: number };
/** An item exactly as stored and as uploaded when turning on sync (Unix milliseconds). */
export type LocalItem = EncryptedItem & { id: string; createdAt: number; updatedAt: number; deletedAt?: number };
/** What opens a backup: the master password it was made with, or the backup recovery code. */
export type BackupSecret = { password: string } | { recoveryCode: string };
"#;

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Options {
    memory_kib: Option<u32>,
    hardware_secret: Option<Zeroizing<Vec<u8>>>,
}

impl Options {
    fn protection(&self) -> DeviceProtection<'_> {
        DeviceProtection {
            kdf: KdfParams {
                memory_kib: self.memory_kib.unwrap_or(LOCAL_KDF.memory_kib),
                ..LOCAL_KDF
            },
            hardware_secret: self
                .hardware_secret
                .as_ref()
                .map(|secret| secret.as_slice()),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Secret {
    Password(Zeroizing<String>),
    RecoveryCode(Zeroizing<String>),
}

/// An unlocked local vault. Store `toBytes()` after every change; `free()` it to lock.
/// Opens the device chip's secret the desktop app sealed for this extension (`local-chip-secret`
/// over native messaging), with the key both sides derived. Pass it as `hardwareSecret`.
#[wasm_bindgen(js_name = openChipSecret)]
pub fn open_chip_secret(key: &[u8], sealed: &str) -> Result<Vec<u8>, JsValue> {
    let key = octapass_core::keys::SymmetricKey::from_slice(key).map_err(js_error)?;
    let secret = local::keys::open_chip_secret(&key, sealed).map_err(js_error)?;
    Ok(secret.to_vec())
}

#[wasm_bindgen]
pub struct LocalVault {
    inner: local::LocalVault,
}

#[wasm_bindgen]
impl LocalVault {
    /// Creates an empty vault. Runs Argon2id twice (a few seconds): call it from a worker. Show
    /// `backupRecoveryCode` in the local Recovery Kit.
    pub fn create(
        password: String,
        #[wasm_bindgen(unchecked_param_type = "LocalVaultOptions | undefined")] options: JsValue,
    ) -> Result<LocalVault, JsValue> {
        let password = Zeroizing::new(password);
        let options: Options = options_from_js(options, "local vault options")?;
        let inner =
            local::LocalVault::create(&password, options.protection(), now_ms(), &mut OsRng)
                .map_err(js_error)?;
        Ok(LocalVault { inner })
    }

    /// Unlocks a stored vault. Throws `login_failed` for a wrong password and
    /// `hardware_secret_required` when the vault is bound to the device chip.
    pub fn unlock(
        blob: Vec<u8>,
        password: String,
        #[wasm_bindgen(js_name = hardwareSecret)] hardware_secret: Option<Vec<u8>>,
    ) -> Result<LocalVault, JsValue> {
        let password = Zeroizing::new(password);
        let hardware_secret = hardware_secret.map(Zeroizing::new);
        let inner = local::LocalVault::unlock(
            &blob,
            &password,
            hardware_secret.as_ref().map(|s| s.as_slice()),
        )
        .map_err(js_error)?;
        Ok(LocalVault { inner })
    }

    /// Restores a `.octapass-backup` file onto this device. `password` becomes the vault's master
    /// password here: the backup's own, or a new one when opening it with the recovery code.
    #[wasm_bindgen(js_name = restoreBackup)]
    pub fn restore_backup(
        file: Vec<u8>,
        #[wasm_bindgen(unchecked_param_type = "BackupSecret")] secret: JsValue,
        password: String,
        #[wasm_bindgen(unchecked_param_type = "LocalVaultOptions | undefined")] options: JsValue,
    ) -> Result<LocalVault, JsValue> {
        let password = Zeroizing::new(password);
        let secret: Secret = from_js(secret, "backup secret")?;
        let secret = match &secret {
            Secret::Password(password) => BackupSecret::Password(password),
            Secret::RecoveryCode(code) => BackupSecret::RecoveryCode(code),
        };
        let options: Options = options_from_js(options, "local vault options")?;
        let inner = local::LocalVault::restore_backup(
            &file,
            secret,
            &password,
            options.protection(),
            &mut OsRng,
        )
        .map_err(js_error)?;
        Ok(LocalVault { inner })
    }

    /// The encrypted vault to store (IndexedDB, a file).
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.to_bytes(&mut OsRng).map_err(js_error)
    }

    #[wasm_bindgen(getter, js_name = vaultId)]
    pub fn vault_id(&self) -> String {
        self.inner.vault_id().to_string()
    }

    #[wasm_bindgen(getter, js_name = hardwareBound)]
    pub fn hardware_bound(&self) -> bool {
        self.inner.is_hardware_bound()
    }

    /// The backup recovery code (11 groups of 5) for the local Recovery Kit.
    #[wasm_bindgen(getter, js_name = backupRecoveryCode)]
    pub fn backup_recovery_code(&self) -> String {
        self.inner.backup_recovery_code().to_string()
    }

    /// Every item's overview, trash included.
    #[wasm_bindgen(unchecked_return_type = "LocalItemOverview[]")]
    pub fn list(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.list().map_err(js_error)?)
    }

    #[wasm_bindgen(js_name = getItem, unchecked_return_type = "ItemPlaintext")]
    pub fn get_item(&self, id: String) -> Result<JsValue, JsValue> {
        to_js(&self.inner.get_item(&id).map_err(js_error)?)
    }

    /// Adds an item and returns its new id.
    #[wasm_bindgen(js_name = addItem)]
    pub fn add_item(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "ItemPlaintext")] item: JsValue,
    ) -> Result<String, JsValue> {
        let item = item_from_js(item)?;
        self.inner
            .add_item(&item, now_ms(), &mut OsRng)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = updateItem)]
    pub fn update_item(
        &mut self,
        id: String,
        #[wasm_bindgen(unchecked_param_type = "ItemPlaintext")] item: JsValue,
    ) -> Result<(), JsValue> {
        let item = item_from_js(item)?;
        self.inner
            .update_item(&id, &item, now_ms(), &mut OsRng)
            .map_err(js_error)
    }

    /// Moves an item to the trash.
    #[wasm_bindgen(js_name = deleteItem)]
    pub fn delete_item(&mut self, id: String) -> Result<(), JsValue> {
        self.inner.delete_item(&id, now_ms()).map_err(js_error)
    }

    #[wasm_bindgen(js_name = restoreItem)]
    pub fn restore_item(&mut self, id: String) -> Result<(), JsValue> {
        self.inner.restore_item(&id).map_err(js_error)
    }

    /// Removes an item for good.
    #[wasm_bindgen(js_name = purgeItem)]
    pub fn purge_item(&mut self, id: String) -> Result<(), JsValue> {
        self.inner.purge_item(&id).map_err(js_error)
    }

    /// Changes the master password. Later backups need the new one; the recovery code stays.
    #[wasm_bindgen(js_name = changePassword)]
    pub fn change_password(
        &mut self,
        #[wasm_bindgen(js_name = newPassword)] new_password: String,
        #[wasm_bindgen(unchecked_param_type = "LocalVaultOptions | undefined")] options: JsValue,
    ) -> Result<(), JsValue> {
        let new_password = Zeroizing::new(new_password);
        let options: Options = options_from_js(options, "local vault options")?;
        self.inner
            .change_password(&new_password, options.protection(), &mut OsRng)
            .map_err(js_error)
    }

    /// An encrypted `.octapass-backup` file of the whole vault (no password needed).
    #[wasm_bindgen(js_name = createBackup)]
    pub fn create_backup(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.create_backup(&mut OsRng).map_err(js_error)
    }

    /// Every item as stored: the body for `/v1/batch` `put` operations when turning on sync.
    #[wasm_bindgen(unchecked_return_type = "LocalItem[]")]
    pub fn items(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.items())
    }

    /// Pins this vault's own public keys as its inbox key (plan 03, *Saving while locked*), at every
    /// unlock. The owner is the vault's id. Returns the inbox JSON.
    #[wasm_bindgen(js_name = inboxPin)]
    pub fn inbox_pin(&self, inbox: &str) -> Result<String, JsValue> {
        let session = self.inner.session().map_err(js_error)?;
        crate::inbox::pin(&session, inbox, self.inner.vault_id())
    }

    /// Opens every inbox entry, oldest first.
    #[wasm_bindgen(js_name = inboxOpen, unchecked_return_type = "OpenedInbox")]
    pub fn inbox_open(&self, inbox: &str) -> Result<JsValue, JsValue> {
        let session = self.inner.session().map_err(js_error)?;
        crate::inbox::open(&session, inbox, self.inner.vault_id())
    }

    /// **Turn on sync**: a `Signup` for a new account that keeps this vault's keys and items. Use
    /// it like `Signup.create` (register/start, finish, Recovery Kit), upload `items()` unchanged
    /// into `signup.finish(...).personalVault.id`, then delete the local blob. Runs Argon2id.
    #[wasm_bindgen(js_name = upgradeToAccount)]
    pub fn upgrade_to_account(&self, email: String, password: String) -> Result<Signup, JsValue> {
        let password = Zeroizing::new(password);
        let account = self
            .inner
            .upgrade_to_account(&email, &password, KdfParams::DEFAULT, &mut OsRng)
            .map_err(js_error)?;
        Signup::from_account(account)
    }
}
