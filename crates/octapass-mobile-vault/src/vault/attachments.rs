//! Attachments: files encrypted here under a key of their own, which the item key wraps
//! (`octapass_core::attachment`), as in the desktop app. The phone saves first and uploads later:
//! a new file is encrypted into the account's outbox and listed in the item at once, and the
//! outbox sends it once the item is on the server, retrying on every sync. Opening decrypts into
//! the app's private storage for the system viewer, and the file is deleted when it closes.
//!
//! Plaintext never passes through the web view: pickers copy into private storage, the vault
//! reads from there, and the viewer reads what the vault decrypted.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use octapass_api::{UsageResponse, VaultRole};
use octapass_core::account::new_id;
use octapass_core::attachment;
use octapass_core::item::Item as CoreItem;
use octapass_ffi::{
    HttpMethod, OctaPassError, Resolution, attachments_of, with_attachments, without_attachments,
};
use rand_core::OsRng;
use serde_json::{Value, json};

use super::{Unlocked, Vault};
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{FileSource, Item, PickedFile, StorageUsage, require};
use crate::outbox::{Change, ChangeKind, Outbox};

/// Plaintext encrypted or decrypted per step.
const SLICE: usize = 1024 * 1024;
/// Folders in the app's private storage, emptied on lock and when the app starts.
pub(super) const PICKED: &str = "picked";
const OPENED: &str = "opened";

/// A file the system picker copied here, until it's attached or discarded.
#[derive(Debug, Clone)]
pub(crate) struct Picked {
    path: PathBuf,
    name: String,
    media_type: String,
}

fn attachment_id(entry: &Value) -> Option<&str> {
    entry.get("id").and_then(Value::as_str)
}

fn entry<'a>(item: &'a Item, id: &str) -> Option<&'a Value> {
    item.details
        .get("attachments")
        .and_then(Value::as_array)?
        .iter()
        .find(|entry| attachment_id(entry) == Some(id))
}

/// A random folder or file name.
pub(super) fn random_name() -> String {
    let mut bytes = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// The file's name as the viewer shows it: no folders, no control characters, not too long, and
/// the extension kept so the system knows the kind of file.
pub(super) fn safe_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    let cleaned = cleaned.trim().trim_start_matches('.');
    if cleaned.is_empty() {
        return "file".into();
    }
    if cleaned.len() <= 120 {
        return cleaned.into();
    }
    let (stem, extension) = match cleaned.rsplit_once('.') {
        Some((stem, extension)) if extension.len() <= 10 => (stem, Some(extension)),
        _ => (cleaned, None),
    };
    let mut end = 100;
    while !stem.is_char_boundary(end) {
        end -= 1;
    }
    match extension {
        Some(extension) => format!("{}.{extension}", &stem[..end]),
        None => stem[..end].into(),
    }
}

pub(super) fn io_error(error: std::io::Error) -> VaultError {
    VaultError::unexpected(format!("files: {error}"))
}

pub(super) fn remove_dir(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

/// How an upload settles an item changed both here and elsewhere: the server's version wins, the
/// file changes made here go on top of it (they're bound to this item, so a copy couldn't open
/// them), and other edits made here become a conflicting copy as usual. `base` is the version
/// the file changes started from, when nothing else had changed here: if the rest still matches
/// it, there are no other edits to keep.
pub(crate) fn resolve(
    changes: &[Change],
    base: Option<&CoreItem>,
    item_id: &str,
    local: &CoreItem,
    server: Option<&CoreItem>,
) -> Resolution {
    let Some(server) = server else {
        return Resolution::copy(local);
    };
    let ours = |kind: ChangeKind| -> HashSet<&str> {
        changes
            .iter()
            .filter(|change| change.kind == kind && change.item_id == item_id)
            .map(|change| change.attachment_id.as_str())
            .collect()
    };
    let (added, removed) = (ours(ChangeKind::Upload), ours(ChangeKind::Delete));
    let theirs = attachments_of(server);
    let mut list: Vec<Value> = theirs
        .iter()
        .filter(|entry| !attachment_id(entry).is_some_and(|id| removed.contains(id)))
        .cloned()
        .collect();
    for entry in attachments_of(local) {
        let Some(id) = attachment_id(&entry) else {
            continue;
        };
        if added.contains(id) && !list.iter().any(|kept| attachment_id(kept) == Some(id)) {
            list.push(entry);
        }
    }
    let (local_rest, server_rest) = (without_attachments(local), without_attachments(server));
    let edited_here = base.is_none_or(|base| without_attachments(base) != local_rest);
    Resolution {
        merged: (list != theirs)
            .then(|| with_attachments(server, list).ok())
            .flatten(),
        copy: (edited_here && local_rest != server_rest).then_some(local_rest),
    }
}

impl Vault {
    fn outbox(&self, unlocked: &Unlocked) -> Outbox {
        Outbox::new(&self.config.data_dir, &unlocked.account)
    }

    pub(super) fn opened_dir(&self) -> PathBuf {
        self.config.temp_dir.join(OPENED)
    }

    /// Deletes every plaintext file (picked ones not attached yet, and ones shown in the viewer)
    /// and items another app handed over that weren't imported.
    pub(crate) fn clear_plaintext(&self) {
        let mut state = self.state();
        state.picked.clear();
        state.received = None;
        drop(state);
        for folder in [PICKED, OPENED] {
            remove_dir(&self.config.temp_dir.join(folder));
        }
    }

    /// The stored item with the files still waiting to upload marked `pending`, for the UI.
    pub(crate) fn with_pending_marks(&self, unlocked: &Unlocked, mut item: Item) -> Item {
        let changes = self.outbox(unlocked).changes().unwrap_or_default();
        let waiting: HashSet<&str> = changes
            .iter()
            .filter(|change| {
                change.kind == ChangeKind::Upload && !change.sent && change.item_id == item.id
            })
            .map(|change| change.attachment_id.as_str())
            .collect();
        if let Some(list) = item
            .details
            .get_mut("attachments")
            .and_then(Value::as_array_mut)
        {
            for entry in list {
                if attachment_id(entry).is_some_and(|id| waiting.contains(id))
                    && let Some(fields) = entry.as_object_mut()
                {
                    fields.insert("pending".into(), Value::Bool(true));
                }
            }
        }
        item
    }

    // ---------- Picking ----------

    pub fn file_sources(&self) -> Vec<FileSource> {
        self.native.file_sources()
    }

    /// Opens the system picker. The chosen files wait in private storage for `attach_picked`.
    pub fn pick_files(&self, source: FileSource) -> Result<Vec<PickedFile>> {
        self.unlocked()?;
        let into = self.config.temp_dir.join(PICKED).join(random_name());
        fs::create_dir_all(&into).map_err(io_error)?;
        let files = match self.native.pick_files(source, &into) {
            Ok(files) => files,
            Err(error) => {
                remove_dir(&into);
                return Err(error);
            }
        };
        let mut picked = Vec::new();
        let mut state = self.state();
        for file in files {
            // Only what the picker copied where it was asked to.
            let inside = file.path.parent() == Some(into.as_path());
            let Ok(metadata) = fs::metadata(&file.path) else {
                continue;
            };
            if !inside || !metadata.is_file() {
                continue;
            }
            let id = random_name();
            picked.push(PickedFile {
                id: id.clone(),
                name: file.name.clone(),
                media_type: file.media_type.clone(),
                size: metadata.len(),
            });
            state.picked.insert(
                id,
                Picked {
                    path: file.path,
                    name: file.name,
                    media_type: file.media_type,
                },
            );
        }
        drop(state);
        if picked.is_empty() {
            remove_dir(&into);
        }
        Ok(picked)
    }

    /// Attaches a file `pick_files` returned, then deletes the plaintext copy, whatever happens.
    pub fn attach_picked(&self, item_id: &str, picked_id: &str) -> Result<Item> {
        require(!self.is_local_unlocked(), ErrorCode::NeedsSync)?;
        let picked = self
            .state()
            .picked
            .remove(picked_id)
            .ok_or(ErrorCode::NotFound)?;
        let attached = fs::File::open(&picked.path)
            .and_then(|file| Ok((file.metadata()?.len(), file)))
            .map_err(io_error)
            .and_then(|(len, mut file)| {
                self.attach(item_id, &picked.name, &picked.media_type, &mut file, len)
            });
        Self::delete_picked(&picked);
        attached
    }

    /// Forgets picked files that won't be attached (the editor was closed without saving).
    pub fn discard_picked(&self, picked_ids: &[String]) {
        let mut state = self.state();
        let removed: Vec<Picked> = picked_ids
            .iter()
            .filter_map(|id| state.picked.remove(id))
            .collect();
        drop(state);
        removed.iter().for_each(Self::delete_picked);
    }

    fn delete_picked(picked: &Picked) {
        let _ = fs::remove_file(&picked.path);
        // The pick's own folder, once its last file is gone.
        if let Some(folder) = picked.path.parent() {
            let _ = fs::remove_dir(folder);
        }
    }

    // ---------- Adding, opening and removing ----------

    /// Encrypts a file in memory and attaches it (the dev hook and tests; the app attaches
    /// picked files).
    pub fn add_attachment(
        &self,
        item_id: &str,
        name: &str,
        media_type: &str,
        file: &[u8],
    ) -> Result<Item> {
        require(!self.is_local_unlocked(), ErrorCode::NeedsSync)?;
        let mut reader = file;
        self.attach(item_id, name, media_type, &mut reader, file.len() as u64)
    }

    /// Encrypts `source` into the outbox under a fresh file key, lists it in the item (saved
    /// here at once) and uploads what it can. Checks the server's limits first when it's
    /// reachable; offline, the upload finds out.
    fn attach(
        &self,
        item_id: &str,
        name: &str,
        media_type: &str,
        source: &mut dyn Read,
        len: u64,
    ) -> Result<Item> {
        let unlocked = self.unlocked()?;
        let item = self.stored_item(&unlocked, item_id)?;
        require(item.deleted_at.is_none(), ErrorCode::NotFound)?;
        let role = self.vault_role(&unlocked, &item.vault_id)?;
        require(role != VaultRole::Read, ErrorCode::ReadOnlyVault)?;
        let outbox = self.outbox(&unlocked);
        let stored = attachment::encrypted_len(len);
        if let Some(usage) = self.usage_if_online(&unlocked) {
            require(stored <= usage.max_file_bytes, ErrorCode::FileTooLarge)?;
            // The quota is the vault owner's, so only our own vaults can be checked here.
            let queued = outbox.pending_bytes(&outbox.changes()?);
            require(
                role != VaultRole::Owner
                    || usage.attachment_bytes + queued + stored <= usage.max_attachment_bytes,
                ErrorCode::QuotaExceeded,
            )?;
        }

        let id = new_id(unix_ms(), &mut OsRng);
        let (wrapped_key, encryptor) =
            unlocked
                .session
                .new_attachment(&unlocked.store, item_id, &id)?;
        outbox.create_dir()?;
        let (partial, file) = (
            outbox.partial(&id).expect("our own id"),
            outbox.file(&id).expect("our own id"),
        );
        if let Err(error) = encrypt_to(encryptor, source, len, &partial)
            .and_then(|()| fs::rename(&partial, &file).map_err(io_error))
        {
            outbox.remove_file(&id);
            return Err(error);
        }

        let entry =
            json!({ "id": id, "name": name, "type": media_type, "size": len, "key": wrapped_key });
        {
            let _io = self.io();
            // Queued before it's listed: an upload whose file isn't listed is dropped, so a
            // crash in between leaves nothing behind.
            let mut changes = outbox.changes()?;
            changes.push(Change::new(
                ChangeKind::Upload,
                &item.vault_id,
                item_id,
                &id,
            ));
            outbox.save(&changes)?;
            if let Err(error) = self.change_attachments(&unlocked, item_id, |list| list.push(entry))
            {
                changes.retain(|change| change.attachment_id != id);
                outbox.save(&changes)?;
                outbox.remove_file(&id);
                return Err(error);
            }
            self.push_quietly(&unlocked);
        }
        (self.listener)(super::Event::ItemsChanged);
        self.get_item(item_id)
    }

    /// Decrypts a file into private storage and shows it in the system viewer, then deletes it.
    /// A file not uploaded yet opens from the outbox, offline too.
    pub fn open_attachment(&self, item_id: &str, attachment_id: &str) -> Result<()> {
        let unlocked = self.unlocked()?;
        let item = self.stored_item(&unlocked, item_id)?;
        let entry = entry(&item, attachment_id).ok_or(ErrorCode::NotFound)?;
        let text = |field: &str| {
            entry
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let (name, media_type) = (text("name"), text("type"));
        let folder = self.config.temp_dir.join(OPENED).join(random_name());
        fs::create_dir_all(&folder).map_err(io_error)?;
        let path = folder.join(safe_file_name(&name));
        let decrypted = fs::File::create(folder.join(".partial"))
            .map_err(io_error)
            .and_then(|mut file| {
                self.decrypt_into(&unlocked, &item, attachment_id, &mut file)?;
                file.sync_all().map_err(io_error)
            })
            // Only a whole, verified file gets its name and reaches the viewer.
            .and_then(|()| fs::rename(folder.join(".partial"), &path).map_err(io_error))
            .and_then(|()| self.native.open_file(&path, &name, &media_type));
        remove_dir(&folder);
        decrypted
    }

    /// Encrypts a file the native app's own picker copied to `path` and attaches it, as
    /// `attach_picked` does. The app deletes its copy afterwards.
    pub fn attach_file(
        &self,
        item_id: &str,
        path: &Path,
        name: &str,
        media_type: &str,
    ) -> Result<Item> {
        require(!self.is_local_unlocked(), ErrorCode::NeedsSync)?;
        let mut file = fs::File::open(path).map_err(io_error)?;
        let len = file.metadata().map_err(io_error)?.len();
        self.attach(item_id, name, media_type, &mut file, len)
    }

    /// Decrypts a file into private storage for the native app's own viewer and returns its
    /// path, named like the file. The app deletes it with `delete_opened` when the viewer closes;
    /// locking deletes every one left.
    pub fn open_attachment_file(&self, item_id: &str, attachment_id: &str) -> Result<PathBuf> {
        let unlocked = self.unlocked()?;
        let item = self.stored_item(&unlocked, item_id)?;
        let entry = entry(&item, attachment_id).ok_or(ErrorCode::NotFound)?;
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let path = self.new_opened_path(name)?;
        let folder = path.parent().expect("a file in a folder").to_owned();
        let decrypted = fs::File::create(folder.join(".partial"))
            .map_err(io_error)
            .and_then(|mut file| {
                self.decrypt_into(&unlocked, &item, attachment_id, &mut file)?;
                file.sync_all().map_err(io_error)
            })
            .and_then(|()| fs::rename(folder.join(".partial"), &path).map_err(io_error));
        match decrypted {
            Ok(()) => Ok(path),
            Err(error) => {
                remove_dir(&folder);
                Err(error)
            }
        }
    }

    /// Deletes a file `open_attachment_file` returned. Only paths it made are touched.
    pub fn delete_opened(&self, path: &Path) {
        if let Some(folder) = path.parent()
            && folder.parent() == Some(self.opened_dir().as_path())
        {
            remove_dir(folder);
        } else if path.parent() == Some(self.backup_temp_dir().as_path()) {
            let _ = fs::remove_file(path);
        }
    }

    /// Downloads (or reads from the outbox) and decrypts a file into memory. Nothing is returned
    /// unless the whole file checks out.
    pub fn get_attachment(&self, item_id: &str, attachment_id: &str) -> Result<Vec<u8>> {
        let unlocked = self.unlocked()?;
        let item = self.stored_item(&unlocked, item_id)?;
        let mut file = Vec::new();
        self.decrypt_into(&unlocked, &item, attachment_id, &mut file)?;
        Ok(file)
    }

    fn decrypt_into(
        &self,
        unlocked: &Unlocked,
        item: &Item,
        attachment_id: &str,
        sink: &mut dyn Write,
    ) -> Result<()> {
        let entry = entry(item, attachment_id).ok_or(ErrorCode::NotFound)?;
        let wrapped_key = entry.get("key").and_then(Value::as_str).unwrap_or_default();
        let mut decryptor = unlocked.session.open_attachment(
            &unlocked.store,
            &item.id,
            attachment_id,
            wrapped_key,
        )?;
        let queued = self
            .outbox(unlocked)
            .file(attachment_id)
            .filter(|path| path.is_file());
        let mut source: Box<dyn Read> = match queued {
            Some(path) => Box::new(fs::File::open(path).map_err(io_error)?),
            None => {
                let url = self.attachment_url(unlocked, &item.vault_id, &item.id, attachment_id);
                let _io = self.io();
                Box::new(self.with_token(unlocked, |token| self.http.download(url.clone(), token))?)
            }
        };
        let network = |error: std::io::Error| {
            VaultError::new(ErrorCode::ServerUnreachable, error.to_string())
        };
        let damaged =
            |_| VaultError::new(ErrorCode::ServerError, "the file could not be decrypted");
        let mut buffer = vec![0u8; SLICE];
        loop {
            let read = source.read(&mut buffer).map_err(network)?;
            if read == 0 {
                break;
            }
            let plain = decryptor.push(&buffer[..read]).map_err(damaged)?;
            sink.write_all(&plain).map_err(io_error)?;
        }
        let plain = decryptor.finish().map_err(damaged)?;
        sink.write_all(&plain).map_err(io_error)
    }

    /// Takes a file off the item (saved here at once), then deletes it from the server, or from
    /// the outbox if it never got there.
    pub fn remove_attachment(&self, item_id: &str, attachment_id: &str) -> Result<Item> {
        let unlocked = self.unlocked()?;
        let item = self.stored_item(&unlocked, item_id)?;
        require(
            self.vault_role(&unlocked, &item.vault_id)? != VaultRole::Read,
            ErrorCode::ReadOnlyVault,
        )?;
        {
            let _io = self.io();
            let outbox = self.outbox(&unlocked);
            let mut changes = outbox.changes()?;
            let unsent = changes.iter().any(|change| {
                change.is(ChangeKind::Upload, item_id, attachment_id) && !change.sent
            });
            changes.retain(|change| !change.is(ChangeKind::Upload, item_id, attachment_id));
            if !unsent {
                changes.push(Change::new(
                    ChangeKind::Delete,
                    &item.vault_id,
                    item_id,
                    attachment_id,
                ));
            }
            outbox.save(&changes)?;
            outbox.remove_file(attachment_id);
            self.change_attachments(&unlocked, item_id, |list| {
                list.retain(|entry| self::attachment_id(entry) != Some(attachment_id));
            })?;
            self.push_quietly(&unlocked);
        }
        (self.listener)(super::Event::ItemsChanged);
        self.get_item(item_id)
    }

    pub fn storage_usage(&self) -> Result<StorageUsage> {
        let unlocked = self.unlocked()?;
        let _io = self.io();
        let usage = self.usage(&unlocked)?;
        Ok(StorageUsage {
            attachment_bytes: usage.attachment_bytes,
            max_attachment_bytes: usage.max_attachment_bytes,
            max_file_bytes: usage.max_file_bytes,
        })
    }

    /// The caller holds `io`.
    fn usage(&self, unlocked: &Unlocked) -> Result<UsageResponse> {
        let url = format!("{}v1/account/usage", unlocked.server.base_url());
        self.with_token(unlocked, |token| {
            self.http.json(HttpMethod::Get, url.clone(), token, &[])
        })
    }

    fn usage_if_online(&self, unlocked: &Unlocked) -> Option<UsageResponse> {
        let _io = self.io();
        self.usage(unlocked).ok()
    }

    fn vault_role(&self, unlocked: &Unlocked, vault_id: &str) -> Result<VaultRole> {
        unlocked
            .store
            .vaults()
            .into_iter()
            .find(|vault| vault.id == vault_id)
            .map(|vault| vault.role)
            .ok_or_else(|| ErrorCode::NotFound.into())
    }

    fn attachment_url(
        &self,
        unlocked: &Unlocked,
        vault_id: &str,
        item_id: &str,
        attachment_id: &str,
    ) -> String {
        format!(
            "{}v1/vaults/{vault_id}/items/{item_id}/attachments/{attachment_id}",
            unlocked.server.base_url()
        )
    }

    /// Rewrites the item's file list in the store, to upload with the next push. An item with
    /// nothing else waiting to upload keeps its version from before, for `resolve`.
    fn change_attachments(
        &self,
        unlocked: &Unlocked,
        item_id: &str,
        change: impl FnOnce(&mut Vec<Value>),
    ) -> Result<()> {
        let stored = unlocked.session.decrypt_item(&unlocked.store, item_id)?;
        if !stored.pending {
            let outbox = self.outbox(unlocked);
            let mut bases = outbox.bases()?;
            bases.insert(item_id.to_owned(), stored.record.clone());
            outbox.save_bases(&bases)?;
        }
        let mut list = attachments_of(&stored.item);
        change(&mut list);
        let item = with_attachments(&stored.item, list)?;
        unlocked.session.save_item(
            &unlocked.store,
            &stored.record.vault_id,
            Some(item_id),
            &item,
        )?;
        Ok(())
    }

    // ---------- Uploading ----------

    /// Sends everything saved here: files for items the server already has (before their new
    /// file lists, so a list never names a file the server lacks), then the items, then the
    /// remaining files and deletions. The caller holds `io`.
    pub(crate) fn push_changes(&self, unlocked: &Unlocked) -> Result<()> {
        let outbox = self.outbox(unlocked);
        let mut changes = outbox.changes()?;
        let sent = self.send_changes(unlocked, &outbox, &mut changes, false);
        outbox.save(&changes)?;
        sent?;
        let snapshot = changes.clone();
        let mut bases = outbox.bases()?;
        let decrypted: HashMap<&str, CoreItem> = bases
            .iter()
            .filter_map(|(id, record)| {
                let item = unlocked
                    .session
                    .decrypt_record(&unlocked.store, record)
                    .ok()?;
                Some((id.as_str(), item))
            })
            .collect();
        self.with_token(unlocked, |token| {
            unlocked.server.upload_pending_resolving(
                token.into(),
                unlocked.session.clone(),
                unlocked.store.clone(),
                &|item_id, local, server| {
                    resolve(&snapshot, decrypted.get(item_id), item_id, local, server)
                },
            )
        })?;
        drop(decrypted);
        let sent = self.send_changes(unlocked, &outbox, &mut changes, true);
        // Done once the server has both the file change and the item's list.
        let items = unlocked.session.decrypt_items(&unlocked.store)?;
        changes.retain(|change| {
            items
                .iter()
                .find(|item| item.record.id == change.item_id)
                .is_some_and(|item| !change.sent || item.pending)
        });
        let kept: HashSet<&str> = changes
            .iter()
            .map(|change| change.attachment_id.as_str())
            .collect();
        for change in snapshot
            .iter()
            .filter(|change| !kept.contains(change.attachment_id.as_str()))
        {
            outbox.remove_file(&change.attachment_id);
        }
        outbox.save(&changes)?;
        bases.retain(|id, _| changes.iter().any(|change| change.item_id == *id));
        outbox.save_bases(&bases)?;
        sent
    }

    /// `push_changes`, telling the UI instead of failing (offline, everything waits for the next
    /// sync). The caller holds `io`.
    pub(crate) fn push_quietly(&self, unlocked: &Unlocked) {
        match self.push_changes(unlocked) {
            Ok(()) => self.publish_identities(),
            Err(error) => (self.listener)(super::Event::SyncFailed {
                message: error.message,
            }),
        }
    }

    /// Sends the outbox's file changes: `after_items` is false before the items are uploaded
    /// (only files for items the server has), true after. Stops at the first failure that
    /// isn't the file's own fault.
    fn send_changes(
        &self,
        unlocked: &Unlocked,
        outbox: &Outbox,
        changes: &mut Vec<Change>,
        after_items: bool,
    ) -> Result<()> {
        let mut dropped = Vec::new();
        for (index, change) in changes.iter_mut().enumerate() {
            if change.sent || (change.kind == ChangeKind::Delete && !after_items) {
                continue;
            }
            let Ok(item) = self.stored_item(unlocked, &change.item_id) else {
                dropped.push(index);
                continue;
            };
            let url = self.attachment_url(
                unlocked,
                &change.vault_id,
                &change.item_id,
                &change.attachment_id,
            );
            let result = match change.kind {
                ChangeKind::Delete => self.with_token(unlocked, |token| {
                    match self.http.call(HttpMethod::Delete, url.clone(), token) {
                        Err(OctaPassError::Server { problem_type, .. })
                            if problem_type == "not-found" =>
                        {
                            Ok(())
                        }
                        other => other,
                    }
                }),
                ChangeKind::Upload => {
                    let Some(entry) = entry(&item, &change.attachment_id) else {
                        // Removed, or never listed (a crash before the list was saved).
                        dropped.push(index);
                        continue;
                    };
                    // Not on the server yet, or in the trash until it's restored.
                    if (item.revision == 0 && !after_items) || item.deleted_at.is_some() {
                        continue;
                    }
                    let Some(path) = outbox.file(&change.attachment_id).filter(|p| p.is_file())
                    else {
                        dropped.push(index);
                        continue;
                    };
                    let uploaded = self.with_token(unlocked, |token| {
                        match self.http.upload_file(url.clone(), token, &path) {
                            Ok(()) => Ok(Upload::Sent),
                            Err(OctaPassError::Server { problem_type, .. }) => {
                                Ok(match problem_type.as_str() {
                                    // Sent before, and the answer got lost.
                                    "already-exists" => Upload::Sent,
                                    // The item isn't on the server (yet).
                                    "not-found" => Upload::NotYet,
                                    "quota-exceeded" => Upload::Refused(ErrorCode::QuotaExceeded),
                                    "payload-too-large" => Upload::Refused(ErrorCode::FileTooLarge),
                                    "invalid-request" => Upload::Refused(ErrorCode::Unexpected),
                                    _ => Upload::Failed(problem_type),
                                })
                            }
                            Err(error) => Err(error),
                        }
                    })?;
                    match uploaded {
                        Upload::Sent => Ok(()),
                        Upload::NotYet => continue,
                        Upload::Refused(code) => {
                            // It can never go up: take it off the item rather than list a file
                            // nobody can open.
                            let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
                            (self.listener)(super::Event::SyncFailed {
                                message: format!("“{name}” couldn't be uploaded: {code:?}"),
                            });
                            let id = change.attachment_id.clone();
                            self.change_attachments(unlocked, &change.item_id, |list| {
                                list.retain(|entry| attachment_id(entry) != Some(id.as_str()));
                            })?;
                            dropped.push(index);
                            continue;
                        }
                        Upload::Failed(problem) => Err(VaultError::new(
                            ErrorCode::ServerError,
                            format!("attachment upload: {problem}"),
                        )),
                    }
                }
            };
            result?;
            change.sent = true;
            if change.kind == ChangeKind::Upload {
                outbox.remove_file(&change.attachment_id);
            }
        }
        for index in dropped.into_iter().rev() {
            let change = changes.remove(index);
            if change.kind == ChangeKind::Upload {
                outbox.remove_file(&change.attachment_id);
            }
        }
        Ok(())
    }
}

/// How the server took one file.
enum Upload {
    Sent,
    NotYet,
    /// Never: too large, over the quota, or not an attachment.
    Refused(ErrorCode),
    Failed(String),
}

/// Writes the ciphertext of `len` bytes from `source` to `path`.
fn encrypt_to(
    mut encryptor: attachment::Encryptor,
    source: &mut dyn Read,
    len: u64,
    path: &Path,
) -> Result<()> {
    let mut file = fs::File::create(path).map_err(io_error)?;
    let mut buffer = zeroize::Zeroizing::new(vec![0u8; SLICE]);
    let mut total = 0u64;
    loop {
        let read = source.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        let sealed = encryptor
            .push(&buffer[..read])
            .map_err(|error| VaultError::unexpected(error.to_string()))?;
        file.write_all(&sealed).map_err(io_error)?;
    }
    // The size goes in the item's details, so it must be what was encrypted.
    require(total == len, ErrorCode::Unexpected)?;
    let sealed = encryptor
        .finish()
        .map_err(|error| VaultError::unexpected(error.to_string()))?;
    file.write_all(&sealed).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(title: &str, files: &[&str]) -> CoreItem {
        let files = files
            .iter()
            .map(|id| json!({ "id": id, "name": format!("{id}.pdf"), "type": "", "size": 1, "key": "AQ" }))
            .collect();
        let overview = serde_json::from_value(
            json!({ "schemaVersion": 1, "type": "document", "title": title }),
        )
        .unwrap();
        with_attachments(
            &CoreItem::from_parts(overview, json!({ "schemaVersion": 1 })).unwrap(),
            files,
        )
        .unwrap()
    }

    fn ids(item: &CoreItem) -> Vec<String> {
        attachments_of(item)
            .iter()
            .map(|entry| attachment_id(entry).unwrap().to_owned())
            .collect()
    }

    fn change(kind: ChangeKind, id: &str) -> Change {
        Change::new(kind, "v", "i", id)
    }

    #[test]
    fn conflicts_keep_file_changes_made_here_on_the_server_version() {
        // Here: added "c", removed "a". There: added "b", renamed it.
        let changes = [
            change(ChangeKind::Upload, "c"),
            change(ChangeKind::Delete, "a"),
        ];
        let local = item("Lease", &["c"]);
        let server = item("Lease 2026", &["a", "b"]);
        let resolution = resolve(&changes, None, "i", &local, Some(&server));
        let merged = resolution.merged.unwrap();
        assert_eq!(merged.overview.title, "Lease 2026");
        assert_eq!(ids(&merged), ["b", "c"]);
        // The old title was this device's version of the other fields: it becomes the copy,
        // without files.
        let copy = resolution.copy.unwrap();
        assert_eq!(copy.overview.title, "Lease");
        assert!(ids(&copy).is_empty());
    }

    #[test]
    fn only_file_changes_need_no_copy() {
        let changes = [change(ChangeKind::Upload, "c")];
        let resolution = resolve(
            &changes,
            None,
            "i",
            &item("Lease", &["a", "c"]),
            Some(&item("Lease", &["a", "b"])),
        );
        assert_eq!(ids(&resolution.merged.unwrap()), ["a", "b", "c"]);
        assert!(resolution.copy.is_none());

        // Renamed elsewhere, files added here: the rename stands and nothing is copied, because
        // the rest is still what the file change started from.
        let base = item("Lease", &["a"]);
        let (local, server) = (item("Lease", &["a", "c"]), item("Lease 2026", &["a"]));
        let resolution = resolve(&changes, Some(&base), "i", &local, Some(&server));
        assert_eq!(resolution.merged.unwrap().overview.title, "Lease 2026");
        assert!(resolution.copy.is_none());
        // Renamed here too: that edit is kept as a copy.
        let local = item("Lease (mine)", &["a", "c"]);
        let resolution = resolve(&changes, Some(&base), "i", &local, Some(&server));
        assert_eq!(resolution.copy.unwrap().overview.title, "Lease (mine)");

        // A file another device removed stays removed; only files added here come back.
        let resolution = resolve(
            &[],
            None,
            "i",
            &item("Lease", &["a"]),
            Some(&item("Lease", &[])),
        );
        assert!(resolution.merged.is_none());
        assert!(resolution.copy.is_none());

        // Other items' changes don't count.
        let other = [Change::new(ChangeKind::Upload, "v", "j", "c")];
        let resolution = resolve(
            &other,
            None,
            "i",
            &item("Lease", &["c"]),
            Some(&item("Lease", &[])),
        );
        assert!(resolution.merged.is_none());
    }

    #[test]
    fn without_the_server_version_this_one_is_a_copy() {
        let resolution = resolve(&[], None, "i", &item("Lease", &["a"]), None);
        assert!(resolution.merged.is_none());
        assert!(ids(&resolution.copy.unwrap()).is_empty());
    }

    #[test]
    fn file_names_stay_files() {
        assert_eq!(safe_file_name("lease.pdf"), "lease.pdf");
        assert_eq!(safe_file_name("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(safe_file_name("..hidden"), "hidden");
        assert_eq!(safe_file_name(" \u{0} "), "_");
        assert_eq!(safe_file_name(""), "file");
        let long = format!("{}.pdf", "é".repeat(100));
        let safe = safe_file_name(&long);
        assert!(safe.ends_with(".pdf") && safe.len() <= 104, "{safe}");
    }
}
