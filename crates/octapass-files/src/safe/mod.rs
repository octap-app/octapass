//! The Octa Pass Safe engine: a [`Safe`] is a folder of encrypted blobs (see
//! `octapass_core::safe` for the format) that behaves as a file tree while it's unlocked.
//! Every way of showing a Safe (FUSE, File Provider, Cloud Files, DocumentsProvider, the CLI) is a
//! thin layer over this type.
//!
//! **Writes never touch a blob.** A file being written lives in a [`staged`] file, encrypted under
//! a throwaway key, and is sealed as a new content blob, under a new file key, when it's flushed.
//! So nothing readable reaches the disk, and a crash loses only what wasn't flushed.
//!
//! **Locking** ([`Safe::lock`]) flushes what's open, then drops every key. After that every call
//! returns [`SafeError::Locked`].

pub mod cloud_files;
#[cfg(feature = "fuse")]
pub mod fuse;
mod staged;
pub mod sync;
mod tree;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use octapass_core::Error as CoreError;
use octapass_core::keys::SymmetricKey;
use octapass_core::safe::{
    self as format, BlobKind, CONTENT_CHUNK_LEN, CONTENT_HEADER_LEN, ContentReader, ObjectKind,
    ObjectRecord, ROOT, SafeKeys, blob_kind, chunk_count, chunk_span, encode_file_key, new_blob_id,
    new_object_id,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::safe::staged::Staged;

pub use format::ROOT as ROOT_ID;

const MANIFEST: &str = "safe.json";
const BLOBS: &str = "blobs";
const TEMPORARY: &str = "tmp";
const NOTES: &str = "device-state.sealed";
const FORMAT: u32 = 1;

#[derive(Debug, Error)]
pub enum SafeError {
    /// The vault locked, so this Safe has no keys.
    #[error("the Safe is locked")]
    Locked,
    #[error("nothing by that name")]
    NotFound,
    #[error("something by that name already exists")]
    Exists,
    #[error("this is a folder")]
    IsFolder,
    #[error("this isn't a folder")]
    NotFolder,
    #[error("the folder isn't empty")]
    NotEmpty,
    #[error("a name can't be empty, be . or .., hold a slash, or pass 255 bytes")]
    InvalidName,
    #[error("a folder can't move into itself")]
    InvalidMove,
    #[error("this folder isn't a Safe")]
    NotASafe,
    #[error("this Safe was made by a newer Octa Pass")]
    UnsupportedFormat,
    #[error("this isn't the key of this Safe, or the Safe is damaged")]
    WrongKey,
    #[error("the Safe's data is damaged: {0}")]
    Damaged(CoreError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("sync failed: {0}")]
    Remote(String),
}

pub type Result<T> = std::result::Result<T, SafeError>;

impl From<CoreError> for SafeError {
    fn from(error: CoreError) -> Self {
        SafeError::Damaged(error)
    }
}

/// What the rest of the world sees of a file or folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub parent: String,
    pub name: String,
    pub folder: bool,
    pub size: u64,
    /// Milliseconds since 1970.
    pub modified: u64,
}

/// Something about a Safe the user should hear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Warning {
    /// A blob that doesn't open: changed on disk or on the server.
    DamagedBlob { blob: String },
    /// This device saw a newer revision of the object than the one that's here now.
    RolledBack { object: String },
    /// This device saw an object that's gone, with no record of its deletion.
    Missing { object: String },
    /// A file's folder is gone, so it was moved to the top of the Safe.
    Orphaned { name: String },
}

/// `safe.json`: not secret. Tells a Safe's folder from any other.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    format: u32,
    safe_id: String,
}

/// What this device remembers about a Safe between runs. Sealed; never synced.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Notes {
    /// The highest revision seen of each object.
    #[serde(default)]
    pub seen: HashMap<String, u64>,
    /// Blobs that were on the server at the end of the last sync.
    #[serde(default)]
    pub synced: HashSet<String>,
}

pub(crate) struct Node {
    pub blob: String,
    pub record: ObjectRecord,
    pub display_name: String,
}

pub(crate) struct Open {
    pub keys: SafeKeys,
    pub nodes: HashMap<String, Node>,
    /// Deleted objects: kept so their deletion syncs and a later revision builds on them.
    pub deleted: HashMap<String, (String, ObjectRecord)>,
    pub children: HashMap<String, BTreeMap<String, String>>,
    pub staged: HashMap<String, Staged>,
    pub notes: Notes,
    pub notes_dirty: bool,
    pub warnings: Vec<Warning>,
}

/// One Safe's folder, unlocked until [`Safe::lock`].
pub struct Safe {
    root: PathBuf,
    open: Mutex<Option<Open>>,
    clock: fn() -> u64,
}

fn system_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}

pub(crate) fn blob_path(root: &Path, blob: &str) -> PathBuf {
    root.join(BLOBS).join(&blob[..2]).join(blob)
}

/// Writes `bytes` under a temporary name, syncs them to disk, then moves them into place, so a
/// blob is either whole or absent.
pub(crate) fn install_blob(root: &Path, blob: &str, bytes: &[u8]) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(root.join(TEMPORARY))?;
    file.write_all(bytes)?;
    finish_blob(root, blob, file)
}

fn finish_blob(root: &Path, blob: &str, file: tempfile::NamedTempFile) -> Result<()> {
    file.as_file().sync_all()?;
    let path = blob_path(root, blob);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    file.persist(&path).map_err(|error| error.error)?;
    Ok(())
}

pub(crate) fn remove_blob(root: &Path, blob: &str) -> Result<()> {
    match fs::remove_file(blob_path(root, blob)) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

pub(crate) fn local_blobs(root: &Path) -> Result<Vec<String>> {
    let mut found = Vec::new();
    for shard in fs::read_dir(root.join(BLOBS))? {
        let shard = shard?;
        if !shard.file_type()?.is_dir() {
            continue;
        }
        for blob in fs::read_dir(shard.path())? {
            if let Some(name) = blob?.file_name().to_str()
                && blob_kind(name).is_some()
            {
                found.push(name.to_owned());
            }
        }
    }
    Ok(found)
}

fn read_notes(root: &Path, keys: &SafeKeys) -> Notes {
    // Lost or damaged notes only cost a fuller next sync and the rollback check of this run.
    fs::read(root.join(NOTES))
        .ok()
        .and_then(|sealed| keys.open_state(&sealed).ok())
        .and_then(|json| serde_json::from_slice(&json).ok())
        .unwrap_or_default()
}

impl Safe {
    /// Makes an empty Safe in `root`, which must be empty or missing.
    pub fn create(root: &Path, safe_id: &str, key: &SymmetricKey) -> Result<Self> {
        fs::create_dir_all(root)?;
        if fs::read_dir(root)?.next().is_some() {
            return Err(SafeError::Exists);
        }
        fs::create_dir_all(root.join(BLOBS))?;
        fs::create_dir_all(root.join(TEMPORARY))?;
        let manifest = Manifest {
            format: FORMAT,
            safe_id: safe_id.to_owned(),
        };
        let json = serde_json::to_vec_pretty(&manifest).map_err(io::Error::other)?;
        fs::write(root.join(MANIFEST), json)?;
        Self::open(root, key)
    }

    /// The Safe id written in a folder, if it's a Safe.
    pub fn id_of(root: &Path) -> Result<String> {
        let bytes = match fs::read(root.join(MANIFEST)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(SafeError::NotASafe);
            }
            Err(error) => return Err(error.into()),
        };
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| SafeError::NotASafe)?;
        if manifest.format > FORMAT {
            return Err(SafeError::UnsupportedFormat);
        }
        Ok(manifest.safe_id)
    }

    /// Unlocks a Safe with its key and reads its tree.
    pub fn open(root: &Path, key: &SymmetricKey) -> Result<Self> {
        let safe_id = Self::id_of(root)?;
        let keys = SafeKeys::derive(key, &safe_id)?;
        fs::create_dir_all(root.join(BLOBS))?;
        fs::create_dir_all(root.join(TEMPORARY))?;
        // Whatever was left here by a crash can't be finished, and is ciphertext anyway.
        for leftover in fs::read_dir(root.join(TEMPORARY))? {
            let _ = fs::remove_file(leftover?.path());
        }
        let notes = read_notes(root, &keys);
        let mut open = Open {
            keys,
            nodes: HashMap::new(),
            deleted: HashMap::new(),
            children: HashMap::new(),
            staged: HashMap::new(),
            notes,
            notes_dirty: false,
            warnings: Vec::new(),
        };
        open.scan(root)?;
        let safe = Self {
            root: root.to_owned(),
            open: Mutex::new(Some(open)),
            clock: system_ms,
        };
        Ok(safe)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, Option<Open>> {
        self.open.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn with<T>(&self, run: impl FnOnce(&mut Open) -> Result<T>) -> Result<T> {
        let mut state = self.state();
        run(state.as_mut().ok_or(SafeError::Locked)?)
    }

    pub fn is_locked(&self) -> bool {
        self.state().is_none()
    }

    /// Flushes open files, then forgets every key. The blobs on disk stay, and are all there is.
    pub fn lock(&self) -> Result<()> {
        let mut state = self.state();
        let Some(open) = state.as_mut() else {
            return Ok(());
        };
        let flushed = open.flush_all(&self.root, (self.clock)());
        let saved = open.save_notes(&self.root);
        *state = None;
        flushed.and(saved)
    }

    pub fn safe_id(&self) -> Result<String> {
        self.with(|open| Ok(open.keys.safe_id().to_owned()))
    }

    /// What's wrong with this Safe, if anything, since it was opened.
    pub fn warnings(&self) -> Result<Vec<Warning>> {
        self.with(|open| Ok(open.warnings.clone()))
    }

    // ---------- Reading the tree ----------

    pub fn entry(&self, id: &str) -> Result<Entry> {
        self.with(|open| open.entry(id))
    }

    pub fn list(&self, folder: &str) -> Result<Vec<Entry>> {
        self.with(|open| {
            open.require_folder(folder)?;
            open.children
                .get(folder)
                .into_iter()
                .flat_map(BTreeMap::values)
                .map(|id| open.entry(id))
                .collect()
        })
    }

    pub fn lookup(&self, folder: &str, name: &str) -> Result<Entry> {
        self.with(|open| {
            open.require_folder(folder)?;
            let id = open
                .children
                .get(folder)
                .and_then(|names| names.get(name))
                .ok_or(SafeError::NotFound)?;
            open.entry(id)
        })
    }

    /// Follows `a/b/c` from the top of the Safe. An empty path is the top.
    pub fn resolve(&self, path: &str) -> Result<Entry> {
        let mut current = self.root_entry();
        for name in path.split('/').filter(|part| !part.is_empty()) {
            current = self.lookup(&current.id, name)?;
        }
        Ok(current)
    }

    /// The top of the Safe.
    pub fn root_entry(&self) -> Entry {
        Entry {
            id: ROOT.to_owned(),
            parent: ROOT.to_owned(),
            name: String::new(),
            folder: true,
            size: 0,
            modified: 0,
        }
    }

    /// Everything in the Safe.
    pub fn all(&self) -> Result<Vec<Entry>> {
        self.with(|open| open.nodes.keys().map(|id| open.entry(id)).collect())
    }

    pub fn read(&self, id: &str, offset: u64, size: usize) -> Result<Zeroizing<Vec<u8>>> {
        self.with(|open| open.read(&self.root, id, offset, size))
    }

    /// Writes a whole file to `out`.
    pub fn export(&self, id: &str, out: &mut impl Write) -> Result<u64> {
        let size = self.entry(id)?;
        if size.folder {
            return Err(SafeError::IsFolder);
        }
        let mut offset = 0;
        loop {
            let piece = self.read(id, offset, CONTENT_CHUNK_LEN)?;
            if piece.is_empty() {
                return Ok(offset);
            }
            out.write_all(&piece)?;
            offset += piece.len() as u64;
        }
    }

    // ---------- Changing the tree ----------

    pub fn create_file(&self, folder: &str, name: &str) -> Result<Entry> {
        let now = (self.clock)();
        self.with(|open| open.create(&self.root, folder, name, ObjectKind::File, now))
    }

    pub fn create_folder(&self, folder: &str, name: &str) -> Result<Entry> {
        let now = (self.clock)();
        self.with(|open| open.create(&self.root, folder, name, ObjectKind::Folder, now))
    }

    pub fn write(&self, id: &str, offset: u64, data: &[u8]) -> Result<()> {
        self.with(|open| open.write(&self.root, id, offset, data))
    }

    pub fn truncate(&self, id: &str, size: u64) -> Result<()> {
        self.with(|open| open.truncate(&self.root, id, size))
    }

    /// Seals what was written to `id` as a new revision.
    pub fn flush(&self, id: &str) -> Result<()> {
        let now = (self.clock)();
        self.with(|open| open.flush(&self.root, id, now))
    }

    /// Flushes every open file.
    pub fn flush_all(&self) -> Result<()> {
        let now = (self.clock)();
        self.with(|open| {
            open.flush_all(&self.root, now)?;
            open.save_notes(&self.root)
        })
    }

    /// Reads `input` into a file, replacing what's there, as one new revision. It's all or nothing:
    /// the new contents are staged on their own, outside the files open for writing, so a lock
    /// while `input` is still being read (which seals open files) can't put half of it over the
    /// file. They join the Safe in one step at the end, or not at all.
    pub fn import(&self, id: &str, input: &mut impl Read) -> Result<u64> {
        let mut staged = Staged::new(&std::env::temp_dir(), 0)?;
        let mut piece = Zeroizing::new(vec![0u8; CONTENT_CHUNK_LEN]);
        let mut total = 0u64;
        for index in 0.. {
            let filled = fill(input, &mut piece)?;
            if filled == 0 && index > 0 {
                break;
            }
            staged.write_chunk(index, &piece[..filled])?;
            total += filled as u64;
            staged.grow_to(total);
            if filled < CONTENT_CHUNK_LEN {
                break;
            }
        }
        let now = (self.clock)();
        self.with(|open| {
            let record = open.record(id)?.clone();
            if record.kind != ObjectKind::File {
                return Err(SafeError::IsFolder);
            }
            // Writes in progress to this file are replaced whole.
            open.staged.remove(id);
            open.seal_staged(&self.root, &record, &mut staged, now)
        })?;
        Ok(total)
    }

    pub fn rename(&self, id: &str, folder: &str, name: &str) -> Result<()> {
        let now = (self.clock)();
        self.with(|open| open.rename(&self.root, id, folder, name, now))
    }

    /// Deletes a file, or an empty folder.
    pub fn remove(&self, id: &str) -> Result<()> {
        let now = (self.clock)();
        self.with(|open| open.remove(&self.root, id, now))
    }

    /// Deletes a file, or a folder and everything in it.
    pub fn remove_all(&self, id: &str) -> Result<()> {
        for child in self.list_if_folder(id)? {
            self.remove_all(&child.id)?;
        }
        self.remove(id)
    }

    fn list_if_folder(&self, id: &str) -> Result<Vec<Entry>> {
        if self.entry(id)?.folder {
            self.list(id)
        } else {
            Ok(Vec::new())
        }
    }

    /// Sets a file or folder's modified time (for `touch`, and copying with times kept).
    pub fn set_modified(&self, id: &str, modified: u64) -> Result<()> {
        self.with(|open| {
            let mut record = open.record(id)?.clone();
            record.modified = modified;
            open.commit_record(&self.root, record, None)
        })
    }
}

impl Drop for Safe {
    fn drop(&mut self) {
        let _ = self.lock();
    }
}

impl Open {
    pub(crate) fn record(&self, id: &str) -> Result<&ObjectRecord> {
        self.nodes
            .get(id)
            .map(|node| &node.record)
            .ok_or(SafeError::NotFound)
    }

    fn entry(&self, id: &str) -> Result<Entry> {
        if id == ROOT {
            return Ok(Entry {
                id: ROOT.to_owned(),
                parent: ROOT.to_owned(),
                name: String::new(),
                folder: true,
                size: 0,
                modified: 0,
            });
        }
        let node = self.nodes.get(id).ok_or(SafeError::NotFound)?;
        let size = self
            .staged
            .get(id)
            .map_or(node.record.size, |staged| staged.len());
        Ok(Entry {
            id: id.to_owned(),
            parent: node.record.parent.clone(),
            name: node.display_name.clone(),
            folder: node.record.kind == ObjectKind::Folder,
            size,
            modified: node.record.modified,
        })
    }

    fn require_folder(&self, id: &str) -> Result<()> {
        if id == ROOT {
            return Ok(());
        }
        match self.record(id)?.kind {
            ObjectKind::Folder => Ok(()),
            _ => Err(SafeError::NotFolder),
        }
    }

    fn taken(&self, folder: &str, name: &str) -> bool {
        self.children
            .get(folder)
            .is_some_and(|names| names.contains_key(name))
    }

    pub(crate) fn seal_blob(&self, record: &ObjectRecord) -> Result<(String, Vec<u8>)> {
        let blob = new_blob_id(BlobKind::Record, &mut OsRng);
        let sealed = self.keys.seal_record(&blob, record, &mut OsRng)?;
        Ok((blob, sealed))
    }

    /// Writes `record` as the object's next revision, then removes the old record, and the old
    /// content if `old_content` names one. The order means a crash at any step leaves a working
    /// Safe: the next open keeps the newest record and clears what it left behind.
    pub(crate) fn commit_record(
        &mut self,
        root: &Path,
        mut record: ObjectRecord,
        old_content: Option<String>,
    ) -> Result<()> {
        let id = record.object.clone();
        let previous = self
            .nodes
            .get(&id)
            .map(|node| (node.blob.clone(), node.record.rev))
            .or_else(|| {
                self.deleted
                    .get(&id)
                    .map(|(blob, record)| (blob.clone(), record.rev))
            });
        record.rev = previous.as_ref().map_or(1, |(_, rev)| rev + 1);
        record.prev = previous.as_ref().map(|(blob, _)| blob.clone());
        let (blob, sealed) = self.seal_blob(&record)?;
        install_blob(root, &blob, &sealed)?;
        self.notes.seen.insert(id.clone(), record.rev);
        self.notes_dirty = true;
        if let Some((old, _)) = previous {
            remove_blob(root, &old)?;
        }
        if let Some(content) = old_content {
            remove_blob(root, &content)?;
        }
        self.place(blob, record);
        self.rebuild();
        Ok(())
    }

    fn create(
        &mut self,
        root: &Path,
        folder: &str,
        name: &str,
        kind: ObjectKind,
        now: u64,
    ) -> Result<Entry> {
        if !format::valid_name(name) {
            return Err(SafeError::InvalidName);
        }
        self.require_folder(folder)?;
        if self.taken(folder, name) {
            return Err(SafeError::Exists);
        }
        let record = ObjectRecord {
            object: new_object_id(&mut OsRng),
            rev: 0,
            prev: None,
            parent: folder.to_owned(),
            name: name.to_owned(),
            kind,
            size: 0,
            modified: now,
            content: None,
            file_key: None,
        };
        let id = record.object.clone();
        self.commit_record(root, record, None)?;
        self.entry(&id)
    }

    fn content_reader(&self, root: &Path, record: &ObjectRecord) -> Result<(File, ContentReader)> {
        let blob = record
            .content
            .as_deref()
            .ok_or(SafeError::Damaged(CoreError::MalformedCiphertext))?;
        let mut file = File::open(blob_path(root, blob))?;
        let blob_len = file.metadata()?.len();
        let mut header = [0u8; CONTENT_HEADER_LEN];
        file.read_exact(&mut header)?;
        let reader = self.keys.open_content(record, &header, blob_len)?;
        Ok((file, reader))
    }

    /// One chunk of a file's sealed content; empty past the end.
    fn base_chunk(
        record: &ObjectRecord,
        file: &mut File,
        reader: &mut ContentReader,
        index: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let Some((start, len, _)) = chunk_span(record.size, index) else {
            return Ok(Zeroizing::new(Vec::new()));
        };
        file.seek(SeekFrom::Start(start))?;
        let mut sealed = vec![0u8; len];
        file.read_exact(&mut sealed)?;
        Ok(reader.open_chunk(index, &sealed)?)
    }

    fn read(&mut self, root: &Path, id: &str, offset: u64, size: usize) -> Result<Zeroizing<Vec<u8>>> {
        let record = self.record(id)?.clone();
        if record.kind != ObjectKind::File {
            return Err(SafeError::IsFolder);
        }
        let len = self.staged.get(id).map_or(record.size, Staged::len);
        let chunk = CONTENT_CHUNK_LEN as u64;
        let end = offset.saturating_add(size as u64).min(len);
        let mut out = Zeroizing::new(Vec::with_capacity(end.saturating_sub(offset) as usize));
        if offset >= end {
            return Ok(out);
        }
        let mut base = match record.content {
            Some(_) => Some(self.content_reader(root, &record)?),
            None => None,
        };
        let mut position = offset;
        while position < end {
            let index = position / chunk;
            let start = (position % chunk) as usize;
            let staged = self.staged.get_mut(id);
            let plain = match staged {
                Some(staged) if staged.holds(index) => staged.read_chunk(index)?,
                Some(staged) if !staged.from_base(index) => Zeroizing::new(Vec::new()),
                _ => match base.as_mut() {
                    Some((file, reader)) => Self::base_chunk(&record, file, reader, index)?,
                    None => Zeroizing::new(Vec::new()),
                },
            };
            // Past what was stored but inside the file: a hole, which reads as zeros.
            let take = ((end - position) as usize).min(CONTENT_CHUNK_LEN - start);
            let have = plain.len().saturating_sub(start).min(take);
            if have > 0 {
                out.extend_from_slice(&plain[start..start + have]);
            }
            let filled = out.len() + take - have;
            out.resize(filled, 0);
            position += take as u64;
        }
        Ok(out)
    }

    fn staged_for(&mut self, id: &str) -> Result<&mut Staged> {
        if !self.staged.contains_key(id) {
            let size = {
                let record = self.record(id)?;
                if record.kind != ObjectKind::File {
                    return Err(SafeError::IsFolder);
                }
                record.size
            };
            self.staged
                .insert(id.to_owned(), Staged::new(&self.staging_folder(), size)?);
        }
        Ok(self.staged.get_mut(id).expect("just added"))
    }

    fn staging_folder(&self) -> PathBuf {
        std::env::temp_dir()
    }

    /// Copies the chunk into staging before part of it changes.
    fn stage_chunk(&mut self, root: &Path, id: &str, index: u64) -> Result<()> {
        if self.staged_for(id)?.holds(index) {
            return Ok(());
        }
        let record = self.record(id)?.clone();
        let from_base = self.staged_for(id)?.from_base(index);
        let plain = if record.content.is_some() && from_base {
            let (mut file, mut reader) = self.content_reader(root, &record)?;
            Self::base_chunk(&record, &mut file, &mut reader, index)?
        } else {
            Zeroizing::new(Vec::new())
        };
        self.staged_for(id)?.write_chunk(index, &plain)
    }

    fn write(&mut self, root: &Path, id: &str, offset: u64, data: &[u8]) -> Result<()> {
        let chunk = CONTENT_CHUNK_LEN as u64;
        let mut position = offset;
        let mut rest = data;
        while !rest.is_empty() {
            let index = position / chunk;
            let start = (position % chunk) as usize;
            let take = rest.len().min(CONTENT_CHUNK_LEN - start);
            let whole = start == 0 && take == CONTENT_CHUNK_LEN;
            if !whole {
                self.stage_chunk(root, id, index)?;
            }
            let staged = self.staged_for(id)?;
            let mut plain = if whole {
                Zeroizing::new(Vec::new())
            } else {
                staged.read_chunk(index)?
            };
            if plain.len() < start + take {
                plain.resize(start + take, 0);
            }
            plain[start..start + take].copy_from_slice(&rest[..take]);
            staged.write_chunk(index, &plain)?;
            staged.grow_to(position + take as u64);
            position += take as u64;
            rest = &rest[take..];
        }
        if data.is_empty() {
            self.staged_for(id)?;
        }
        Ok(())
    }

    fn truncate(&mut self, root: &Path, id: &str, size: u64) -> Result<()> {
        let chunk = CONTENT_CHUNK_LEN as u64;
        let current = self.entry(id)?.size;
        if size < current && size % chunk != 0 {
            // The chunk that's cut keeps its head, in staging.
            self.stage_chunk(root, id, size / chunk)?;
        }
        self.staged_for(id)?.set_len(size)
    }

    fn flush(&mut self, root: &Path, id: &str, now: u64) -> Result<()> {
        let Some(mut staged) = self.staged.remove(id) else {
            return Ok(());
        };
        if !staged.dirty() {
            return Ok(());
        }
        let record = self.record(id)?.clone();
        let sealed = self.seal_staged(root, &record, &mut staged, now);
        match sealed {
            Ok(()) => Ok(()),
            Err(error) => {
                // Keep it, so a retry or the next flush has the data.
                self.staged.insert(id.to_owned(), staged);
                Err(error)
            }
        }
    }

    fn seal_staged(
        &mut self,
        root: &Path,
        record: &ObjectRecord,
        staged: &mut Staged,
        now: u64,
    ) -> Result<()> {
        let id = &record.object;
        let blob = new_blob_id(BlobKind::Content, &mut OsRng);
        let (file_key, mut encryptor) = self.keys.new_content(id, &blob, &mut OsRng)?;
        let mut output = tempfile::NamedTempFile::new_in(root.join(TEMPORARY))?;
        let mut base = match record.content {
            Some(_) => Some(self.content_reader(root, record)?),
            None => None,
        };
        let len = staged.len();
        for index in 0..chunk_count(len) {
            let wanted = (len - (index * CONTENT_CHUNK_LEN as u64).min(len))
                .min(CONTENT_CHUNK_LEN as u64) as usize;
            let mut plain = match base.as_mut() {
                _ if staged.holds(index) => staged.read_chunk(index)?,
                Some((file, reader)) if staged.from_base(index) => {
                    Self::base_chunk(record, file, reader, index)?
                }
                _ => Zeroizing::new(Vec::new()),
            };
            plain.resize(wanted, 0);
            output.write_all(&encryptor.push(&plain)?)?;
        }
        output.write_all(&encryptor.finish()?)?;
        finish_blob(root, &blob, output)?;

        let mut next = record.clone();
        next.size = len;
        next.modified = now;
        next.content = Some(blob);
        next.file_key = Some(encode_file_key(&file_key));
        self.commit_record(root, next, record.content.clone())
    }

    pub(crate) fn flush_all(&mut self, root: &Path, now: u64) -> Result<()> {
        let ids: Vec<String> = self.staged.keys().cloned().collect();
        let mut first_error = Ok(());
        for id in ids {
            if let Err(error) = self.flush(root, &id, now)
                && first_error.is_ok()
            {
                first_error = Err(error);
            }
        }
        first_error
    }

    fn rename(&mut self, root: &Path, id: &str, folder: &str, name: &str, now: u64) -> Result<()> {
        if id == ROOT {
            return Err(SafeError::InvalidMove);
        }
        if !format::valid_name(name) {
            return Err(SafeError::InvalidName);
        }
        self.require_folder(folder)?;
        let mut record = self.record(id)?.clone();
        let mut ancestor = folder.to_owned();
        while ancestor != ROOT {
            if ancestor == id {
                return Err(SafeError::InvalidMove);
            }
            ancestor = self.record(&ancestor)?.parent.clone();
        }
        if let Some(existing) = self
            .children
            .get(folder)
            .and_then(|names| names.get(name))
            .cloned()
        {
            if existing == id {
                return Ok(());
            }
            let target = self.entry(&existing)?;
            if target.folder != (record.kind == ObjectKind::Folder) {
                return Err(if target.folder {
                    SafeError::IsFolder
                } else {
                    SafeError::NotFolder
                });
            }
            if target.folder && self.children.get(&existing).is_some_and(|c| !c.is_empty()) {
                return Err(SafeError::NotEmpty);
            }
            self.remove(root, &existing, now)?;
        }
        record.parent = folder.to_owned();
        record.name = name.to_owned();
        record.modified = record.modified.max(now);
        self.commit_record(root, record, None)
    }

    fn remove(&mut self, root: &Path, id: &str, now: u64) -> Result<()> {
        if id == ROOT {
            return Err(SafeError::InvalidMove);
        }
        let record = self.record(id)?.clone();
        if self.children.get(id).is_some_and(|names| !names.is_empty()) {
            return Err(SafeError::NotEmpty);
        }
        self.staged.remove(id);
        let tombstone = ObjectRecord {
            object: record.object.clone(),
            rev: record.rev,
            prev: None,
            parent: ROOT.to_owned(),
            name: String::new(),
            kind: ObjectKind::Deleted,
            size: 0,
            modified: now,
            content: None,
            file_key: None,
        };
        self.commit_record(root, tombstone, record.content.clone())
    }

    pub(crate) fn save_notes(&mut self, root: &Path) -> Result<()> {
        if !self.notes_dirty {
            return Ok(());
        }
        let json = Zeroizing::new(serde_json::to_vec(&self.notes).map_err(io::Error::other)?);
        let sealed = self.keys.seal_state(&json, &mut OsRng)?;
        let mut file = tempfile::NamedTempFile::new_in(root.join(TEMPORARY))?;
        file.write_all(&sealed)?;
        file.as_file().sync_all()?;
        file.persist(root.join(NOTES)).map_err(|error| error.error)?;
        self.notes_dirty = false;
        Ok(())
    }
}

/// Reads until `buffer` is full or the input ends. Returns how much was read.
fn fill(input: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match input.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// `report (2).pdf` from `report.pdf`.
pub(crate) fn numbered_name(name: &str, number: u32) -> String {
    match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => format!("{stem} ({number}).{extension}"),
        _ => format!("{name} ({number})"),
    }
}

#[cfg(test)]
mod tests;
