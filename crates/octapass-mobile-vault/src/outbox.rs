//! Attachment changes on their way to the server, per account, in `<tag>.files/` next to the
//! store: each new file's ciphertext, exactly as it will be uploaded, and `changes.json` with what
//! to do. The item's file list changes at once, like any edit saved here; the outbox is how the
//! files themselves follow, after their item, whenever the app syncs.
//!
//! For an item whose only change here is its files, `bases.json` keeps the version the change
//! started from, encrypted as stored, so a conflict can tell file changes from other edits.
//!
//! Nothing here is secret: ciphertext, and ids the server knows anyway. Names, types and keys are
//! only in the item's encrypted details.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use octapass_api::ItemRecord;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::accounts::Account;
use crate::error::{Result, VaultError};

const CHANGES: &str = "changes.json";
const BASES: &str = "bases.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChangeKind {
    /// Upload the file in the outbox.
    Upload,
    /// Delete the file from the server.
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub kind: ChangeKind,
    pub vault_id: String,
    pub item_id: String,
    pub attachment_id: String,
    /// Done on the server. Kept until the item's file list is uploaded too, so a conflict with
    /// another device's edit still knows what changed here.
    #[serde(default)]
    pub sent: bool,
}

impl Change {
    pub fn new(kind: ChangeKind, vault_id: &str, item_id: &str, attachment_id: &str) -> Self {
        Self {
            kind,
            vault_id: vault_id.to_owned(),
            item_id: item_id.to_owned(),
            attachment_id: attachment_id.to_owned(),
            sent: false,
        }
    }

    pub fn is(&self, kind: ChangeKind, item_id: &str, attachment_id: &str) -> bool {
        self.kind == kind && self.item_id == item_id && self.attachment_id == attachment_id
    }
}

pub struct Outbox {
    dir: PathBuf,
}

impl Outbox {
    pub fn new(data_dir: &Path, account: &Account) -> Self {
        Self {
            dir: data_dir.join(format!("{}.files", account.tag)),
        }
    }

    pub fn changes(&self) -> Result<Vec<Change>> {
        self.read(CHANGES)
    }

    pub fn save(&self, changes: &[Change]) -> Result<()> {
        self.write(CHANGES, &changes)
    }

    /// Each item's stored record from before its file changes, by item id.
    pub fn bases(&self) -> Result<BTreeMap<String, ItemRecord>> {
        self.read(BASES)
    }

    pub fn save_bases(&self, bases: &BTreeMap<String, ItemRecord>) -> Result<()> {
        self.write(BASES, bases)
    }

    fn read<T: DeserializeOwned + Default>(&self, name: &str) -> Result<T> {
        match fs::read(self.dir.join(name)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| VaultError::unexpected(format!("{name}: {error}"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
            Err(error) => Err(io_error(error)),
        }
    }

    /// Replaces the file atomically.
    fn write(&self, name: &str, value: &impl Serialize) -> Result<()> {
        fs::create_dir_all(&self.dir).map_err(io_error)?;
        let bytes = serde_json::to_vec_pretty(value).expect("the outbox serializes");
        let temp = self.dir.join(format!("{name}.tmp"));
        let mut file = fs::File::create(&temp).map_err(io_error)?;
        file.write_all(&bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        fs::rename(&temp, self.dir.join(name)).map_err(io_error)
    }

    /// Where a new file's ciphertext waits. `None` for an id that isn't one of ours.
    pub fn file(&self, attachment_id: &str) -> Option<PathBuf> {
        is_id(attachment_id).then(|| self.dir.join(format!("{attachment_id}.upload")))
    }

    /// Where a file is written before it's complete.
    pub fn partial(&self, attachment_id: &str) -> Option<PathBuf> {
        is_id(attachment_id).then(|| self.dir.join(format!("{attachment_id}.part")))
    }

    pub fn create_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.dir).map_err(io_error)
    }

    pub fn remove_file(&self, attachment_id: &str) {
        for path in [self.file(attachment_id), self.partial(attachment_id)]
            .into_iter()
            .flatten()
        {
            let _ = fs::remove_file(path);
        }
    }

    /// Bytes waiting to upload.
    pub fn pending_bytes(&self, changes: &[Change]) -> u64 {
        changes
            .iter()
            .filter(|change| change.kind == ChangeKind::Upload && !change.sent)
            .filter_map(|change| self.file(&change.attachment_id))
            .filter_map(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .sum()
    }

    /// Everything, on sign-out.
    pub fn delete(&self) -> Result<()> {
        match fs::remove_dir_all(&self.dir) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(io_error(error)),
            _ => Ok(()),
        }
    }
}

/// Attachment ids are UUIDs; anything else never becomes part of a path.
fn is_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

fn io_error(error: std::io::Error) -> VaultError {
    VaultError::unexpected(format!("outbox: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0192f0c8-1c2d-7a00-8000-0000000000cc";

    #[test]
    fn changes_round_trip_and_files_live_under_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let account = Account::new("https://octapass.test/", "ada@example.com");
        let outbox = Outbox::new(dir.path(), &account);
        assert!(outbox.changes().unwrap().is_empty());

        let mut change = Change::new(ChangeKind::Upload, "v", "i", ID);
        outbox.save(std::slice::from_ref(&change)).unwrap();
        change.sent = true;
        outbox.save(&[change.clone()]).unwrap();
        assert_eq!(outbox.changes().unwrap(), [change.clone()]);
        assert!(change.is(ChangeKind::Upload, "i", ID));
        assert!(!change.is(ChangeKind::Delete, "i", ID));

        let file = outbox.file(ID).unwrap();
        assert_eq!(
            file.parent().unwrap(),
            dir.path().join(format!("{}.files", account.tag))
        );
        fs::write(&file, [0u8; 52]).unwrap();
        change.sent = false;
        assert_eq!(outbox.pending_bytes(&[change]), 52);
        outbox.remove_file(ID);
        assert!(!file.exists());

        assert!(outbox.bases().unwrap().is_empty());
        let record: ItemRecord = serde_json::from_value(serde_json::json!({
            "id": "i", "vaultId": "v", "revision": 3, "encryptedItemKey": "k", "overview": "o",
            "details": "d", "updatedAt": "2026-10-23T00:00:00.000Z",
        }))
        .unwrap();
        outbox
            .save_bases(&BTreeMap::from([("i".to_owned(), record.clone())]))
            .unwrap();
        assert_eq!(outbox.bases().unwrap()["i"], record);

        outbox.delete().unwrap();
        assert!(!dir.path().join(format!("{}.files", account.tag)).exists());
        outbox.delete().unwrap();
    }

    #[test]
    fn only_ids_become_paths() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::new(dir.path(), &Account::new("https://a.test/", "a@b.c"));
        assert!(outbox.file("../accounts").is_none());
        assert!(outbox.file("").is_none());
        assert!(outbox.partial(ID).is_some());
    }
}
