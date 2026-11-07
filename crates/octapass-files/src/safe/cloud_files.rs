//! Shows a Safe in File Explorer through the Windows Cloud Files API: an unlocked Safe is a sync
//! root, every file in it a placeholder, and Windows asks for a file's bytes when something reads
//! it. No kernel driver is installed, which is why this and not WinFsp.
//!
//! **This is weaker than FUSE, and here's how.** FUSE serves every read from memory, so nothing
//! decrypted reaches a disk. Cloud Files can't: a file that was opened is *hydrated*, which means
//! its plaintext sits on NTFS until the Safe locks.
//!
//! - **While unlocked**, every opened file is plaintext on the disk, readable by anything running
//!   as this user, like any other file in the profile.
//! - **On lock**, [`CloudFilesMount`] removes the placeholders and the hydrated files, overwriting
//!   the hydrated ones first (see [`crate::shred`]). That's as far as it can go. An SSD keeps old
//!   copies, and NTFS keeps file names in its journal and master file table after a delete. Only
//!   full-disk encryption covers those.
//! - **A file an app holds open can't be removed.** Lock reports it and keeps trying in the
//!   background for an hour, and the next start tries again.
//! - **A crash leaves plaintext behind** until [`clean_leftovers`] runs at the next start.
//!   Anything edited there but not yet imported is lost with it: nothing can read the Safe then.
//! - **Copies are out of reach**: what an app saved to `%TEMP%`, its recent-files list, thumbnails.
//!   The folder is marked as not to be indexed, but that's a request to Windows Search.
//!
//! **Moving a file out of the Safe is refused**, because it would leave as plaintext. That includes
//! the Recycle Bin, so Explorer offers a permanent delete instead. Copying out still works, and
//! that's the user's choice.
//!
//! How it fits together. Placeholders are created eagerly from [`Safe::list`], so the population
//! policy is always-full and listing a folder never needs this app, which matters when one is
//! emptied after a crash. A placeholder's file identity is its object id. All changes
//! that aren't callbacks go through one idempotent pass, [`plan`], which compares the disk with the
//! Safe and is run by the watcher thread: `ReadDirectoryChangesW` only says when to run it, so a
//! lost notification costs a few seconds and a failed step is simply tried again.
//!
//! If a file changed both here and in the Safe, the local edit wins. There's no conflict copy.
//!
//! The pure part (names, paths, the plan, cutting a hydration into transfers) has no `cfg(windows)`
//! and is tested on every platform. **The part that calls Windows only type-checks from a Mac or
//! Linux machine**; see the tests at the end for what's covered.

#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use octapass_core::safe::MAX_NAME_LEN;

use super::{ROOT_ID, Result, Safe, SafeError, numbered_name};

#[cfg(windows)]
pub use platform::{CloudFilesMount, clean_leftovers, mount};

/// Says a folder is one of ours. Lock and [`clean_leftovers`] empty a folder without asking, so
/// they only touch one that holds this. It's hidden, and never part of the Safe.
const MARKER: &str = ".octapass-safe-mount";
const MARKER_TEXT: &[u8] = b"Octa Pass Safe mount. Emptied when the Safe locks.\n";

/// UTF-16 units in an NTFS name.
const MAX_LOCAL_NAME: usize = 255;
/// `CfExecute` wants transfers on this boundary, except one that ends at the end of the file.
const TRANSFER_ALIGN: u64 = 4096;
/// The most handed over in one transfer. A multiple of [`TRANSFER_ALIGN`].
const TRANSFER_LEN: u64 = 1024 * 1024;
const REPLACEMENT: char = '_';
/// ` (4294967295)`: what [`numbered_name`] can add.
const NUMBER_ROOM: usize = 13;

// ---------- Names ----------

fn forbidden(c: char) -> bool {
    matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || c < ' '
}

/// `CON`, `nul.txt`, `COM1.tar.gz`: Windows opens a device for these, whatever the extension.
fn reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let stem = stem.to_ascii_uppercase();
    match stem.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        _ => {
            let (device, number) = stem.split_at(stem.char_indices().nth(3).map_or(0, |at| at.0));
            matches!(device, "COM" | "LPT")
                && number.chars().count() == 1
                && number
                    .chars()
                    .all(|c| c.is_ascii_digit() || "¹²³".contains(c))
        }
    }
}

/// Whether Windows takes this as a name, as it stands.
pub fn windows_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.encode_utf16().count() <= MAX_LOCAL_NAME
        && !name.ends_with(['.', ' '])
        && !name.chars().any(forbidden)
        && !reserved(name)
}

fn fits_locally(name: &str) -> bool {
    name.encode_utf16().count() <= MAX_LOCAL_NAME
}

/// Cuts `name` until it `fits`, from the end of the stem so that the extension survives.
fn shorten(name: &str, fits: impl Fn(&str) -> bool) -> String {
    if fits(name) {
        return name.to_owned();
    }
    if let Some((stem, extension)) = name.rsplit_once('.') {
        let mut stem = stem.to_owned();
        while !stem.is_empty() {
            let candidate = format!("{stem}.{extension}");
            if fits(&candidate) {
                return candidate;
            }
            stem.pop();
        }
    }
    let mut whole = name.to_owned();
    while !fits(&whole) {
        whole.pop();
    }
    whole
}

/// The name a Safe's entry goes by on Windows. A Safe takes names Windows doesn't (`a:b`, `CON`,
/// `end.`), so those get a stand-in on this device and keep their real name in the Safe.
pub fn local_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if forbidden(c) { REPLACEMENT } else { c })
        .collect();
    let cleaned = cleaned.trim_end_matches(['.', ' ']);
    let cleaned = shorten(cleaned, fits_locally);
    let cleaned = cleaned.trim_end_matches(['.', ' ']);
    if cleaned.is_empty() {
        return REPLACEMENT.to_string();
    }
    if reserved(cleaned) {
        // The first letter goes, rather than adding one, so that it still fits.
        return format!("{REPLACEMENT}{}", cleaned.split_at(1).1);
    }
    cleaned.to_owned()
}

/// What a name made on Windows is called in the Safe, which counts bytes and not UTF-16 units.
fn safe_name(local: &str) -> String {
    shorten(local, |name| name.len() <= MAX_NAME_LEN)
}

/// Files Windows and Office make on their own, which aren't the user's and shouldn't be in a Safe.
/// Lock removes them with the rest.
fn is_noise(name: &str) -> bool {
    let name = name.to_lowercase();
    name == "desktop.ini" || name == "thumbs.db" || name.starts_with("~$")
}

/// NTFS doesn't tell `A` from `a` by default; a Safe does.
fn folded(name: &str) -> String {
    name.to_lowercase()
}

// ---------- The tree as this device shows it ----------

/// One file or folder of the Safe, and where it sits here.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Placed {
    id: String,
    parent: String,
    /// The name in the Safe.
    name: String,
    /// The name here: [`local_name`], and numbered if a neighbour took it first.
    local: String,
    folder: bool,
    size: u64,
    modified: u64,
}

/// The Safe's tree with Windows names. Names are unique within a folder, ignoring case.
#[derive(Debug, Clone, Default)]
struct PlaceholderTree {
    placed: HashMap<String, Placed>,
    by_name: HashMap<(String, String), String>,
    /// Folders before what's in them.
    order: Vec<String>,
}

impl PlaceholderTree {
    /// Reads the whole Safe. A name that's in use here stays, so that something new in a folder
    /// doesn't renumber its neighbours.
    fn read(safe: &Safe, before: &PlaceholderTree) -> Result<Self> {
        let mut tree = Self::default();
        let mut folders = vec![ROOT_ID.to_owned()];
        while let Some(folder) = folders.pop() {
            let entries = safe.list(&folder)?;
            let mut taken = HashSet::new();
            if folder == ROOT_ID {
                taken.insert(folded(MARKER));
            }
            let mut names: Vec<Option<String>> = entries
                .iter()
                .map(|entry| {
                    before
                        .placed
                        .get(&entry.id)
                        .filter(|old| old.parent == entry.parent && old.name == entry.name)
                        .filter(|old| taken.insert(folded(&old.local)))
                        .map(|old| old.local.clone())
                })
                .collect();
            for (entry, name) in entries.iter().zip(&mut names) {
                if name.is_none() {
                    *name = Some(free_name(&entry.name, &mut taken));
                }
            }
            for (entry, local) in entries.into_iter().zip(names.into_iter().flatten()) {
                if entry.folder {
                    folders.push(entry.id.clone());
                }
                tree.by_name
                    .insert((entry.parent.clone(), folded(&local)), entry.id.clone());
                tree.order.push(entry.id.clone());
                tree.placed.insert(
                    entry.id.clone(),
                    Placed {
                        id: entry.id,
                        parent: entry.parent,
                        name: entry.name,
                        local,
                        folder: entry.folder,
                        size: entry.size,
                        modified: entry.modified,
                    },
                );
            }
        }
        Ok(tree)
    }

    fn get(&self, id: &str) -> Option<&Placed> {
        self.placed.get(id)
    }

    /// Who's at `path` under the root. An empty path is nobody: the root isn't an entry.
    fn id_at(&self, path: &[String]) -> Option<&str> {
        let mut current: Option<&str> = None;
        for name in path {
            let key = (current.unwrap_or(ROOT_ID).to_owned(), folded(name));
            current = Some(self.by_name.get(&key)?);
        }
        current
    }

    /// Where `id` sits under the root.
    fn path_of(&self, id: &str) -> Option<Vec<String>> {
        let mut path = Vec::new();
        let mut current = self.placed.get(id)?;
        loop {
            path.push(current.local.clone());
            if current.parent == ROOT_ID {
                path.reverse();
                return Some(path);
            }
            current = self.placed.get(&current.parent)?;
        }
    }

    /// `entry`'s new size and time, after this device wrote it.
    fn note(&mut self, id: &str, size: u64, modified: u64) {
        if let Some(placed) = self.placed.get_mut(id) {
            placed.size = size;
            placed.modified = modified;
        }
    }

    /// Makes the next [`plan`] refresh `id`, because this one couldn't.
    fn mark_stale(&mut self, id: &str) {
        if let Some(placed) = self.placed.get_mut(id) {
            placed.modified = u64::MAX;
        }
    }
}

fn free_name(name: &str, taken: &mut HashSet<String>) -> String {
    let base = local_name(name);
    let mut candidate = base.clone();
    // With room left for the number: cutting one off again would make the same name forever.
    let room = shorten(&base, |name| {
        name.encode_utf16().count() <= MAX_LOCAL_NAME - NUMBER_ROOM
    });
    let mut number = 2;
    while !taken.insert(folded(&candidate)) {
        candidate = numbered_name(&room, number);
        number += 1;
    }
    candidate
}

// ---------- Paths ----------

/// A path's names, without `\\?\` or a drive. Cloud Files gives paths from the top of the volume.
fn path_names(path: &str) -> Vec<&str> {
    let mut names: Vec<&str> = path
        .split(['\\', '/'])
        .filter(|name| !name.is_empty() && *name != "?" && *name != ".")
        .collect();
    if names
        .first()
        .is_some_and(|first| first.len() == 2 && first.ends_with(':'))
    {
        names.remove(0);
    }
    names
}

/// `path` relative to `root`, as names, or nothing if it isn't under `root`.
fn under_root(root: &str, path: &str) -> Option<Vec<String>> {
    let root = path_names(root);
    let path = path_names(path);
    if path.len() < root.len() || !root.iter().zip(&path).all(|(a, b)| folded(a) == folded(b)) {
        return None;
    }
    Some(
        path[root.len()..]
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
    )
}

/// `\\?\C:\Users` as `C:\Users`: Cloud Files wants the plain form, and `canonicalize` gives the
/// other. A UNC path stays as it is, and registering it fails, since sync roots are local.
fn plain_path(path: &str) -> &str {
    match path.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest,
        _ => path,
    }
}

/// 100 ns units since 1601, from milliseconds since 1970.
fn file_time(milliseconds: u64) -> i64 {
    const FROM_1601: i64 = 116_444_736_000_000_000;
    FROM_1601.saturating_add(i64::try_from(milliseconds).unwrap_or(i64::MAX / 10_000) * 10_000)
}

// ---------- Hydration ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    offset: u64,
    len: usize,
}

/// The transfers that answer a request for `length` bytes at `offset` of a file of `size` bytes:
/// on 4 KiB boundaries, widened to cover the request, and ending exactly at the end of the file.
fn transfer_spans(offset: u64, length: u64, size: u64) -> Vec<Span> {
    let wanted_end = offset.saturating_add(length).min(size);
    if offset >= wanted_end {
        return Vec::new();
    }
    let mut position = offset - offset % TRANSFER_ALIGN;
    let end = wanted_end
        .div_ceil(TRANSFER_ALIGN)
        .saturating_mul(TRANSFER_ALIGN)
        .min(size);
    let mut spans = Vec::new();
    while position < end {
        let len = (end - position).min(TRANSFER_LEN);
        spans.push(Span {
            offset: position,
            len: len as usize,
        });
        position += len;
    }
    spans
}

// ---------- What's on the disk, and what to do about it ----------

#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalState {
    /// Not a placeholder: something new from an app or from Explorer.
    Plain,
    Placeholder {
        id: String,
        in_sync: bool,
        /// Its bytes are on the disk.
        hydrated: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalRow {
    path: Vec<String>,
    folder: bool,
    state: LocalState,
}

/// Whether locking now would lose this row's content.
fn holds_edits(row: &LocalRow) -> bool {
    match &row.state {
        LocalState::Plain => !row.folder && row.path.last().is_some_and(|name| !is_noise(name)),
        LocalState::Placeholder {
            in_sync, hydrated, ..
        } => !row.folder && !in_sync && *hydrated,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// Something new goes into the Safe, as `into` if the Safe has it at that path already.
    Adopt {
        path: Vec<String>,
        folder: bool,
        into: Option<String>,
    },
    /// An edited placeholder goes into the Safe.
    Import {
        path: Vec<String>,
        id: String,
    },
    /// Only its metadata changed, so there's nothing to import.
    MarkInSync {
        path: Vec<String>,
    },
    /// The Safe has newer content, so the bytes here go and come back on the next read.
    Refresh {
        path: Vec<String>,
        placed: Placed,
    },
    Move {
        from: Vec<String>,
        to: Vec<String>,
    },
    /// It's gone from the Safe.
    Remove {
        path: Vec<String>,
        folder: bool,
    },
    /// New placeholders in one folder.
    Create {
        folder: Vec<String>,
        items: Vec<Placed>,
    },
}

/// Compares the disk with the Safe. `rows` has folders before what's in them, and `before` is the
/// tree of the last pass, which shows what changed in the Safe since.
///
/// Local steps come first, so a Safe-side step never overwrites what the user just did. Removes and
/// moves run from the deepest up, which keeps the paths of those still to come valid. A step that
/// fails, or that an earlier step made stale, is put right by the next pass.
fn plan(before: &PlaceholderTree, now: &PlaceholderTree, rows: &[LocalRow]) -> Vec<Step> {
    let mut local = Vec::new();
    let mut removes = Vec::new();
    let mut moves = Vec::new();
    let mut refreshes = Vec::new();
    let mut seen = HashSet::new();
    let mut ids: HashMap<&[String], &str> = HashMap::new();

    for row in rows {
        let Some((name, folders)) = row.path.split_last() else {
            continue;
        };
        match &row.state {
            LocalState::Plain => {
                if is_noise(name) {
                    continue;
                }
                let into = now.id_at(&row.path).filter(|id| {
                    now.get(id)
                        .is_some_and(|placed| placed.folder == row.folder)
                });
                if let Some(id) = into {
                    seen.insert(id.to_owned());
                    ids.insert(&row.path, id);
                }
                local.push(Step::Adopt {
                    path: row.path.clone(),
                    folder: row.folder,
                    into: into.map(str::to_owned),
                });
            }
            LocalState::Placeholder {
                id,
                in_sync,
                hydrated,
            } => {
                ids.insert(&row.path, id);
                let Some(placed) = now.get(id) else {
                    if !row.folder && !in_sync && *hydrated {
                        // Deleted from the Safe but edited here: the edit stays, as something new.
                        local.push(Step::Adopt {
                            path: row.path.clone(),
                            folder: false,
                            into: None,
                        });
                    } else {
                        removes.push(Step::Remove {
                            path: row.path.clone(),
                            folder: row.folder,
                        });
                    }
                    continue;
                };
                seen.insert(id.clone());
                if !in_sync {
                    local.push(if !row.folder && *hydrated {
                        Step::Import {
                            path: row.path.clone(),
                            id: id.clone(),
                        }
                    } else {
                        Step::MarkInSync {
                            path: row.path.clone(),
                        }
                    });
                } else if !row.folder
                    && before.get(id).is_some_and(|old| {
                        (old.size, old.modified) != (placed.size, placed.modified)
                    })
                {
                    refreshes.push(Step::Refresh {
                        path: row.path.clone(),
                        placed: placed.clone(),
                    });
                }
                let parent = if folders.is_empty() {
                    Some(ROOT_ID)
                } else {
                    ids.get(folders).copied()
                };
                if (parent != Some(placed.parent.as_str()) || *name != placed.local)
                    && let Some(to) = now.path_of(id)
                {
                    moves.push(Step::Move {
                        from: row.path.clone(),
                        to,
                    });
                }
            }
        }
    }

    let mut creates: BTreeMap<Vec<String>, Vec<Placed>> = BTreeMap::new();
    for id in &now.order {
        if !seen.contains(id)
            && let (Some(placed), Some(mut folder)) = (now.get(id), now.path_of(id))
        {
            folder.pop();
            creates.entry(folder).or_default().push(placed.clone());
        }
    }

    removes.reverse();
    moves.reverse();
    let mut steps = local;
    steps.append(&mut removes);
    steps.append(&mut moves);
    steps.append(&mut refreshes);
    // The map's order puts a folder before what's in it.
    steps.extend(
        creates
            .into_iter()
            .map(|(folder, items)| Step::Create { folder, items }),
    );
    steps
}

// ---------- Emptying a folder ----------

fn has_marker(root: &Path) -> bool {
    fs::read(root.join(MARKER)).is_ok_and(|text| text == MARKER_TEXT)
}

/// A folder that isn't empty is the user's, and lock would delete what's in it.
fn check_empty(root: &Path) -> Result<()> {
    if fs::read_dir(root)?.next().is_some() {
        return Err(SafeError::NotEmpty);
    }
    Ok(())
}

fn empty_folder(
    folder: &Path,
    top: bool,
    erase: &dyn Fn(&Path) -> io::Result<()>,
    left: &mut Vec<PathBuf>,
) {
    let Ok(entries) = fs::read_dir(folder) else {
        left.push(folder.to_owned());
        return;
    };
    for entry in entries.flatten() {
        if top && entry.file_name() == MARKER {
            continue;
        }
        let path = entry.path();
        let removed = match entry.file_type() {
            Ok(kind) if kind.is_dir() => {
                empty_folder(&path, false, erase, left);
                fs::remove_dir(&path)
            }
            // A link goes, and what it points at is left alone, here or as a folder on Windows.
            Ok(kind) if kind.is_symlink() => {
                fs::remove_file(&path).or_else(|_| fs::remove_dir(&path))
            }
            _ => erase(&path),
        };
        if removed.is_err() {
            left.push(path);
        }
    }
}

/// Removes everything but the marker, and says what wouldn't go.
fn remove_tree(root: &Path, erase: &dyn Fn(&Path) -> io::Result<()>) -> Vec<PathBuf> {
    let mut left = Vec::new();
    empty_folder(root, true, erase, &mut left);
    left
}

#[cfg(windows)]
mod platform {
    use std::collections::BTreeSet;
    use std::ffi::{OsStr, c_void};
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{
        CloseHandle, ERROR_CLOUD_FILE_ALREADY_CONNECTED, HANDLE, NTSTATUS, STATUS_ACCESS_DENIED,
        STATUS_CLOUD_FILE_UNSUCCESSFUL, STATUS_SUCCESS, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::Storage::CloudFilters::{
        CF_CALLBACK_DELETE_FLAG_IS_UNDELETE, CF_CALLBACK_INFO, CF_CALLBACK_PARAMETERS,
        CF_CALLBACK_REGISTRATION, CF_CALLBACK_TYPE_FETCH_DATA, CF_CALLBACK_TYPE_NONE,
        CF_CALLBACK_TYPE_NOTIFY_DELETE, CF_CALLBACK_TYPE_NOTIFY_RENAME,
        CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION, CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH,
        CF_CONNECTION_KEY, CF_CONVERT_FLAG_MARK_IN_SYNC, CF_CREATE_FLAG_NONE, CF_FS_METADATA,
        CF_HARDLINK_POLICY_NONE, CF_HYDRATION_POLICY, CF_HYDRATION_POLICY_FULL,
        CF_HYDRATION_POLICY_MODIFIER_NONE, CF_IN_SYNC_STATE_IN_SYNC, CF_INSYNC_POLICY_TRACK_ALL,
        CF_OPERATION_ACK_DELETE_FLAG_NONE, CF_OPERATION_ACK_RENAME_FLAG_NONE, CF_OPERATION_INFO,
        CF_OPERATION_PARAMETERS, CF_OPERATION_PARAMETERS_0, CF_OPERATION_PARAMETERS_0_0,
        CF_OPERATION_PARAMETERS_0_6, CF_OPERATION_PARAMETERS_0_7,
        CF_OPERATION_TRANSFER_DATA_FLAG_NONE, CF_OPERATION_TYPE, CF_OPERATION_TYPE_ACK_DELETE,
        CF_OPERATION_TYPE_ACK_RENAME, CF_OPERATION_TYPE_TRANSFER_DATA,
        CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION,
        CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC, CF_PLACEHOLDER_CREATE_INFO,
        CF_PLACEHOLDER_INFO_STANDARD, CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
        CF_PLACEHOLDER_STANDARD_INFO, CF_POPULATION_POLICY, CF_POPULATION_POLICY_ALWAYS_FULL,
        CF_POPULATION_POLICY_MODIFIER_NONE, CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT,
        CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT, CF_REQUEST_KEY_DEFAULT, CF_SET_IN_SYNC_FLAG_NONE,
        CF_SYNC_POLICIES, CF_SYNC_REGISTRATION, CF_UPDATE_FLAG_DEHYDRATE,
        CF_UPDATE_FLAG_MARK_IN_SYNC, CfConnectSyncRoot, CfConvertToPlaceholder,
        CfCreatePlaceholders, CfDisconnectSyncRoot, CfExecute, CfGetPlaceholderInfo,
        CfRegisterSyncRoot, CfSetInSyncState, CfUnregisterSyncRoot, CfUpdatePlaceholder,
    };
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_SYSTEM, FILE_BASIC_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED,
        FILE_GENERIC_READ, FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_DIR_NAME,
        FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_WRITE_ATTRIBUTES, MOVE_FILE_FLAGS, MoveFileExW, ReadDirectoryChangesW,
        SetFileAttributesW, WRITE_DAC,
    };
    use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows::Win32::System::Threading::{
        CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects,
    };
    use windows::core::{GUID, HRESULT, PCWSTR};

    use super::*;
    use crate::shred;

    /// Ours, for the life of the format: Windows uses it to tell sync engines apart.
    const PROVIDER: GUID = GUID::from_u128(0xe1a567dc_fbd6_46f3_90f0_ab9193c0f095);
    const PROVIDER_NAME: &str = "Octa Pass";
    const PROVIDER_VERSION: &str = "1";
    /// How often the Safe is compared with the disk when nothing's happening: sync can change it.
    const TICK: Duration = Duration::from_secs(5);
    /// How long after a change the pass runs, so that a burst of changes makes one pass.
    const SETTLE: Duration = Duration::from_millis(500);
    /// How often a file that wouldn't go on lock is tried again, and for how long.
    const SWEEP_EVERY: Duration = Duration::from_secs(5);
    const SWEEP_TRIES: u32 = 720;
    const WATCH_BUFFER: usize = 64 * 1024;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
    const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    const DEHYDRATED: u32 = FILE_ATTRIBUTE_OFFLINE
        | FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
    const SHARE_ALL: u32 = FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0;
    const METADATA_FLAGS: u32 = FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_BACKUP_SEMANTICS.0;

    /// Folders in use in this process. Emptying a live mount's folder would reach the Safe through
    /// its delete callbacks, so nothing empties a folder without claiming it.
    static CLAIMED: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

    struct Claim(PathBuf);

    impl Claim {
        fn take(root: &Path) -> Result<Self> {
            if !CLAIMED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(root.to_owned())
            {
                return Err(SafeError::Exists);
            }
            Ok(Self(root.to_owned()))
        }
    }

    impl Drop for Claim {
        fn drop(&mut self) {
            CLAIMED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&self.0);
        }
    }

    fn wide(text: &OsStr) -> Vec<u16> {
        text.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn cf_failure(error: windows::core::Error) -> SafeError {
        SafeError::Io(io::Error::other(error))
    }

    fn handle_of(file: &File) -> HANDLE {
        HANDLE(file.as_raw_handle())
    }

    fn on_disk(root: &Path, path: &[String]) -> PathBuf {
        path.iter()
            .fold(root.to_owned(), |all, name| all.join(name))
    }

    fn identity_ptr(id: &str) -> Option<*const c_void> {
        Some(id.as_ptr().cast())
    }

    /// For looking at a file. Never brings its bytes back.
    fn open_metadata(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES.0)
            .share_mode(SHARE_ALL)
            .custom_flags(METADATA_FLAGS)
            .open(path)
    }

    /// For changing a placeholder's state, with no access to its data. Cloud Files takes `WRITE_DAC`
    /// in place of write access, which would bring a dehydrated file's bytes back.
    fn open_placeholder(path: &Path, share: u32) -> io::Result<File> {
        OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES.0 | FILE_WRITE_ATTRIBUTES.0 | WRITE_DAC.0)
            .share_mode(share)
            .custom_flags(METADATA_FLAGS)
            .open(path)
    }

    /// For taking a file into the Safe. It fails while anything has it open to write, which is how
    /// a half-saved file waits for the next pass. Keeping this one handle from the first read to
    /// marking it in sync means no write can land in between and be taken for imported.
    fn open_to_import(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .access_mode(FILE_GENERIC_READ.0 | FILE_WRITE_ATTRIBUTES.0 | WRITE_DAC.0)
            .share_mode(FILE_SHARE_READ.0)
            .open(path)
    }

    fn local_state(path: &Path, size: u64, folder: bool) -> io::Result<LocalState> {
        let file = open_metadata(path)?;
        // Aligned for the struct. Identities are object ids, which fit with plenty of room.
        let mut buffer = [0u64; 64];
        let bytes = size_of::<[u64; 64]>();
        let info = unsafe {
            // SAFETY: the buffer is writable for the length given and outlives the call.
            CfGetPlaceholderInfo(
                handle_of(&file),
                CF_PLACEHOLDER_INFO_STANDARD,
                buffer.as_mut_ptr().cast(),
                bytes as u32,
                None,
            )
        };
        // Not a placeholder, normally. Whatever the reason, taking it for a new file is the safe
        // way to be wrong: that imports it, into the same object if the Safe has it at this path.
        if info.is_err() {
            return Ok(LocalState::Plain);
        }
        // SAFETY: the call succeeded, so the buffer starts with the struct.
        let info = unsafe { &*buffer.as_ptr().cast::<CF_PLACEHOLDER_STANDARD_INFO>() };
        let start = offset_of!(CF_PLACEHOLDER_STANDARD_INFO, FileIdentity);
        let length = (info.FileIdentityLength as usize).min(bytes - start);
        // SAFETY: `start + length` is inside the buffer, by the line above.
        let identity =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>().add(start), length) };
        let Ok(id) = std::str::from_utf8(identity) else {
            return Ok(LocalState::Plain);
        };
        if id.is_empty() {
            return Ok(LocalState::Plain);
        }
        Ok(LocalState::Placeholder {
            id: id.to_owned(),
            in_sync: info.InSyncState == CF_IN_SYNC_STATE_IN_SYNC,
            hydrated: folder || info.OnDiskDataSize >= i64::try_from(size).unwrap_or(i64::MAX),
        })
    }

    /// Everything under `root`, folders before what's in them, breadth first. Links aren't followed
    /// or taken in, and a name Windows holds that isn't valid UTF-16 can't be, so it's left out.
    fn local_rows(root: &Path) -> io::Result<Vec<LocalRow>> {
        let mut rows = Vec::new();
        let mut folders = vec![Vec::new()];
        let mut next = 0;
        while next < folders.len() {
            let parent: Vec<String> = folders[next].clone();
            next += 1;
            for entry in fs::read_dir(on_disk(root, &parent))? {
                let entry = entry?;
                let kind = entry.file_type()?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if kind.is_symlink() || (parent.is_empty() && name == MARKER) {
                    continue;
                }
                let size = entry.metadata()?.len();
                // Gone since it was listed, or busy: the next pass sees it.
                let Ok(state) = local_state(&entry.path(), size, kind.is_dir()) else {
                    continue;
                };
                let mut path = parent.clone();
                path.push(name.to_owned());
                if kind.is_dir() {
                    folders.push(path.clone());
                }
                rows.push(LocalRow {
                    path,
                    folder: kind.is_dir(),
                    state,
                });
            }
        }
        Ok(rows)
    }

    fn fs_metadata(placed: &Placed) -> CF_FS_METADATA {
        let time = file_time(placed.modified);
        CF_FS_METADATA {
            BasicInfo: FILE_BASIC_INFO {
                CreationTime: time,
                LastAccessTime: time,
                LastWriteTime: time,
                ChangeTime: time,
                FileAttributes: if placed.folder {
                    FILE_ATTRIBUTE_DIRECTORY.0
                } else {
                    FILE_ATTRIBUTE_NORMAL.0
                },
            },
            FileSize: if placed.folder {
                0
            } else {
                i64::try_from(placed.size).unwrap_or(i64::MAX)
            },
        }
    }

    fn create_placeholders(base: &Path, items: &[Placed]) -> Result<()> {
        let names: Vec<Vec<u16>> = items.iter().map(|item| wide(item.local.as_ref())).collect();
        let mut infos: Vec<CF_PLACEHOLDER_CREATE_INFO> = items
            .iter()
            .zip(&names)
            .map(|(item, name)| CF_PLACEHOLDER_CREATE_INFO {
                RelativeFileName: PCWSTR(name.as_ptr()),
                FsMetadata: fs_metadata(item),
                FileIdentity: item.id.as_ptr().cast(),
                FileIdentityLength: item.id.len() as u32,
                Flags: if item.folder {
                    CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
                        | CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION
                } else {
                    CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
                },
                Result: HRESULT(0),
                CreateUsn: 0,
            })
            .collect();
        let base = wide(base.as_os_str());
        let mut processed = 0u32;
        // SAFETY: `names`, `items` and `base` outlive the call, and every string ends in a NUL.
        unsafe {
            CfCreatePlaceholders(
                PCWSTR(base.as_ptr()),
                &mut infos,
                CF_CREATE_FLAG_NONE,
                Some(&mut processed),
            )
        }
        .map_err(cf_failure)?;
        for info in &infos {
            info.Result.ok().map_err(cf_failure)?;
        }
        Ok(())
    }

    fn convert_to_placeholder(file: &File, id: &str) -> Result<()> {
        // SAFETY: the handle is open and `id` outlives the call. The rest is optional output.
        unsafe {
            CfConvertToPlaceholder(
                handle_of(file),
                identity_ptr(id),
                id.len() as u32,
                CF_CONVERT_FLAG_MARK_IN_SYNC,
                None,
                None,
            )
        }
        .map_err(cf_failure)
    }

    /// For a file that's a placeholder already, whose object is gone from the Safe.
    fn give_identity(file: &File, id: &str) -> Result<()> {
        // SAFETY: as in `convert_to_placeholder`.
        unsafe {
            CfUpdatePlaceholder(
                handle_of(file),
                None,
                identity_ptr(id),
                id.len() as u32,
                None,
                CF_UPDATE_FLAG_MARK_IN_SYNC,
                None,
                None,
            )
        }
        .map_err(cf_failure)
    }

    fn set_in_sync(file: &File) -> Result<()> {
        // SAFETY: the handle is open.
        unsafe {
            CfSetInSyncState(
                handle_of(file),
                CF_IN_SYNC_STATE_IN_SYNC,
                CF_SET_IN_SYNC_FLAG_NONE,
                None,
            )
        }
        .map_err(cf_failure)
    }

    fn refresh_placeholder(path: &Path, placed: &Placed) -> Result<()> {
        // Nothing else may hold it: dehydrating under an open file isn't allowed.
        let file = open_placeholder(path, 0)?;
        let metadata = fs_metadata(placed);
        // SAFETY: the handle is open, and `metadata` outlives the call.
        unsafe {
            CfUpdatePlaceholder(
                handle_of(&file),
                Some(&metadata),
                None,
                0,
                None,
                CF_UPDATE_FLAG_MARK_IN_SYNC | CF_UPDATE_FLAG_DEHYDRATE,
                None,
                None,
            )
        }
        .map_err(cf_failure)
    }

    /// Unlike `fs::rename` this doesn't replace what's at `to`, which would delete it from the Safe
    /// through its callback.
    fn move_without_replacing(from: &Path, to: &Path) -> Result<()> {
        let (from, to) = (wide(from.as_os_str()), wide(to.as_os_str()));
        // SAFETY: both strings end in a NUL and outlive the call.
        unsafe {
            MoveFileExW(
                PCWSTR(from.as_ptr()),
                PCWSTR(to.as_ptr()),
                MOVE_FILE_FLAGS(0),
            )
        }
        .map_err(cf_failure)
    }

    /// What the callbacks and the watcher share. It's leaked on purpose: Windows doesn't promise
    /// that no callback is still running once `CfDisconnectSyncRoot` returns, and a callback
    /// reading freed memory is worse than a few words per mount. The keys aren't in here: the Safe
    /// is dropped from it on lock.
    struct Bridge {
        root: PathBuf,
        root_text: String,
        /// `None` once locking started: callbacks then answer without touching anything.
        safe: Mutex<Option<Arc<Safe>>>,
        tree: Mutex<PlaceholderTree>,
    }

    impl Bridge {
        fn safe(&self) -> Option<Arc<Safe>> {
            self.safe
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// Held for moments only, and never across a file operation: those run callbacks, which
        /// want this too.
        fn tree(&self) -> MutexGuard<'_, PlaceholderTree> {
            self.tree.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn close(&self) {
            *self.safe.lock().unwrap_or_else(PoisonError::into_inner) = None;
        }

        /// The Safe's folder at `path`, made if it isn't there yet.
        fn ensure_folder(&self, safe: &Safe, path: &[String]) -> Result<String> {
            let mut folder = ROOT_ID.to_owned();
            for (depth, name) in path.iter().enumerate() {
                let known = self.tree().id_at(&path[..=depth]).map(str::to_owned);
                folder = match known {
                    Some(id) => id,
                    None => {
                        let name = safe_name(name);
                        match safe.lookup(&folder, &name) {
                            Ok(entry) if entry.folder => entry.id,
                            Ok(_) => return Err(SafeError::NotFolder),
                            Err(SafeError::NotFound) => safe.create_folder(&folder, &name)?.id,
                            Err(error) => return Err(error),
                        }
                    }
                };
            }
            Ok(folder)
        }

        fn note(&self, safe: &Safe, id: &str) {
            if let Ok(entry) = safe.entry(id) {
                self.tree().note(id, entry.size, entry.modified);
            }
        }

        fn new_file(&self, safe: &Safe, path: &[String]) -> Result<String> {
            let Some((name, folders)) = path.split_last() else {
                return Err(SafeError::InvalidName);
            };
            let folder = self.ensure_folder(safe, folders)?;
            let name = safe_name(name);
            match safe.create_file(&folder, &name) {
                Ok(entry) => Ok(entry.id),
                // A pass that failed halfway got this far.
                Err(SafeError::Exists) => Ok(safe.lookup(&folder, &name)?.id),
                Err(error) => Err(error),
            }
        }

        fn adopt_file(&self, safe: &Safe, path: &[String], into: Option<&str>) -> Result<()> {
            let mut file = open_to_import(&on_disk(&self.root, path))?;
            let id = match into {
                Some(id) => id.to_owned(),
                None => self.new_file(safe, path)?,
            };
            safe.import(&id, &mut file)?;
            self.note(safe, &id);
            convert_to_placeholder(&file, &id).or_else(|_| give_identity(&file, &id))
        }

        fn adopt_folder(&self, safe: &Safe, path: &[String], into: Option<&str>) -> Result<()> {
            let id = match into {
                Some(id) => id.to_owned(),
                None => self.ensure_folder(safe, path)?,
            };
            let file = open_placeholder(&on_disk(&self.root, path), SHARE_ALL)?;
            convert_to_placeholder(&file, &id)
        }

        fn apply(&self, safe: &Safe, step: &Step) -> Result<()> {
            match step {
                Step::Adopt {
                    path,
                    folder: true,
                    into,
                } => self.adopt_folder(safe, path, into.as_deref()),
                Step::Adopt {
                    path,
                    folder: false,
                    into,
                } => self.adopt_file(safe, path, into.as_deref()),
                Step::Import { path, id } => {
                    let mut file = open_to_import(&on_disk(&self.root, path))?;
                    safe.import(id, &mut file)?;
                    self.note(safe, id);
                    set_in_sync(&file)
                }
                Step::MarkInSync { path } => {
                    set_in_sync(&open_placeholder(&on_disk(&self.root, path), SHARE_ALL)?)
                }
                Step::Refresh { path, placed } => {
                    let refreshed = refresh_placeholder(&on_disk(&self.root, path), placed);
                    if refreshed.is_err() {
                        self.tree().mark_stale(&placed.id);
                    }
                    refreshed
                }
                Step::Move { from, to } => {
                    move_without_replacing(&on_disk(&self.root, from), &on_disk(&self.root, to))
                }
                Step::Remove { path, folder } => {
                    let disk = on_disk(&self.root, path);
                    if *folder {
                        fs::remove_dir(&disk)?;
                    } else {
                        erase(&disk)?;
                    }
                    Ok(())
                }
                Step::Create { folder, items } => {
                    create_placeholders(&on_disk(&self.root, folder), items)
                }
            }
        }

        /// One pass. Runs on the watcher thread, or on the locking thread once that's gone, so
        /// never twice at once. The disk is read first: what changes after that is seen next time.
        fn reconcile(&self) -> Result<()> {
            let safe = self.safe().ok_or(SafeError::Locked)?;
            let rows = local_rows(&self.root)?;
            let steps = {
                let mut tree = self.tree();
                let now = PlaceholderTree::read(&safe, &tree)?;
                let steps = plan(&tree, &now, &rows);
                *tree = now;
                steps
            };
            let mut outcome = Ok(());
            for step in &steps {
                if let Err(error) = self.apply(&safe, step)
                    && outcome.is_ok()
                {
                    outcome = Err(error);
                }
            }
            outcome
        }

        fn delete_from_safe(&self, id: &str, undelete: bool) -> NTSTATUS {
            let Some(safe) = self.safe() else {
                return STATUS_SUCCESS;
            };
            if undelete {
                return STATUS_SUCCESS;
            }
            match safe.remove_all(id) {
                // A pass removing what's already gone from the Safe comes through here too.
                Ok(()) | Err(SafeError::NotFound) => STATUS_SUCCESS,
                Err(_) => STATUS_CLOUD_FILE_UNSUCCESSFUL,
            }
        }

        fn rename_in_safe(&self, id: &str, target: &str) -> NTSTATUS {
            let Some(safe) = self.safe() else {
                return STATUS_SUCCESS;
            };
            // Out of the sync root, the Recycle Bin included, it would be plaintext outside.
            let Some(path) = under_root(&self.root_text, target) else {
                return STATUS_ACCESS_DENIED;
            };
            let Some((name, folders)) = path.split_last() else {
                return STATUS_ACCESS_DENIED;
            };
            let name = {
                let tree = self.tree();
                // A pass moved it, because the Safe already says so.
                if tree.path_of(id).as_deref() == Some(&path) {
                    return STATUS_SUCCESS;
                }
                // A stand-in name that's only moving keeps the real name in the Safe.
                match tree.get(id) {
                    Some(placed) if placed.local == *name => placed.name.clone(),
                    _ => safe_name(name),
                }
            };
            let renamed = self
                .ensure_folder(&safe, folders)
                .and_then(|folder| safe.rename(id, &folder, &name));
            match renamed {
                Ok(()) => STATUS_SUCCESS,
                Err(_) => STATUS_CLOUD_FILE_UNSUCCESSFUL,
            }
        }
    }

    /// The bridge of a callback. A connection made only to clean up has none, and that's treated
    /// like a mount that's locking.
    ///
    /// # Safety
    ///
    /// `info` must come from a callback of a connection whose context is a leaked [`Bridge`] or
    /// null.
    unsafe fn bridge_of(info: &CF_CALLBACK_INFO) -> Option<&'static Bridge> {
        // SAFETY: by the contract above, and it's never freed.
        unsafe { info.CallbackContext.cast::<Bridge>().cast_const().as_ref() }
    }

    /// The object id a placeholder was given.
    ///
    /// # Safety
    ///
    /// `info` must come from a callback, which keeps the identity valid while it runs.
    unsafe fn identity_of(info: &CF_CALLBACK_INFO) -> Option<&str> {
        if info.FileIdentity.is_null() {
            return None;
        }
        // SAFETY: by the contract above, for the length the platform gave.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                info.FileIdentity.cast::<u8>(),
                info.FileIdentityLength as usize,
            )
        };
        std::str::from_utf8(bytes).ok()
    }

    fn execute(
        info: &CF_CALLBACK_INFO,
        kind: CF_OPERATION_TYPE,
        mut parameters: CF_OPERATION_PARAMETERS,
    ) -> windows::core::Result<()> {
        let request = CF_OPERATION_INFO {
            StructSize: size_of::<CF_OPERATION_INFO>() as u32,
            Type: kind,
            ConnectionKey: info.ConnectionKey,
            TransferKey: info.TransferKey,
            CorrelationVector: ptr::null(),
            SyncStatus: ptr::null(),
            RequestKey: CF_REQUEST_KEY_DEFAULT as i64,
        };
        // SAFETY: both structs are complete and outlive the call. Any buffer in `parameters` is
        // kept alive by the caller until this returns.
        unsafe { CfExecute(&request, &mut parameters) }
    }

    fn operation<T>(anonymous: CF_OPERATION_PARAMETERS_0) -> CF_OPERATION_PARAMETERS {
        CF_OPERATION_PARAMETERS {
            // What the `CF_SIZE_OF_OP_PARAM` macro of the C headers works out.
            ParamSize: (offset_of!(CF_OPERATION_PARAMETERS, Anonymous) + size_of::<T>()) as u32,
            Anonymous: anonymous,
        }
    }

    fn transfer(
        info: &CF_CALLBACK_INFO,
        status: NTSTATUS,
        buffer: *const c_void,
        offset: i64,
        length: i64,
    ) -> windows::core::Result<()> {
        let data = CF_OPERATION_PARAMETERS_0_0 {
            Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
            CompletionStatus: status,
            Buffer: buffer,
            Offset: offset,
            Length: length,
        };
        execute(
            info,
            CF_OPERATION_TYPE_TRANSFER_DATA,
            operation::<CF_OPERATION_PARAMETERS_0_0>(CF_OPERATION_PARAMETERS_0 {
                TransferData: data,
            }),
        )
    }

    fn hydrate(info: &CF_CALLBACK_INFO, bridge: &Bridge, offset: u64, length: u64) -> Result<()> {
        let size = u64::try_from(info.FileSize).unwrap_or(0);
        // SAFETY: called from a callback, with its `info`.
        let id = unsafe { identity_of(info) }.ok_or(SafeError::NotFound)?;
        for span in transfer_spans(offset, length, size) {
            // Lock doesn't wait for a big file. Asked again each time, so it stops here.
            let safe = bridge.safe().ok_or(SafeError::Locked)?;
            let bytes = safe.read(id, span.offset, span.len)?;
            if bytes.len() != span.len {
                // The Safe's copy is shorter than the placeholder says. A pass will refresh it.
                return Err(SafeError::NotFound);
            }
            transfer(
                info,
                STATUS_SUCCESS,
                bytes.as_ptr().cast(),
                span.offset as i64,
                span.len as i64,
            )
            .map_err(cf_failure)?;
        }
        Ok(())
    }

    unsafe extern "system" fn on_fetch_data(
        info: *const CF_CALLBACK_INFO,
        parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        // SAFETY: Windows passes valid pointers for the length of the callback, and this union
        // member is the one for a FETCH_DATA callback.
        let (info, fetch) = unsafe { (&*info, (*parameters).Anonymous.FetchData) };
        let offset = u64::try_from(fetch.RequiredFileOffset).unwrap_or(0);
        let length = u64::try_from(fetch.RequiredLength).unwrap_or(0);
        // SAFETY: `info` is from this callback.
        let hydrated = match unsafe { bridge_of(info) } {
            Some(bridge) => hydrate(info, bridge, offset, length),
            None => Err(SafeError::Locked),
        };
        if hydrated.is_err() {
            let _ = transfer(
                info,
                STATUS_CLOUD_FILE_UNSUCCESSFUL,
                ptr::null(),
                fetch.RequiredFileOffset,
                fetch.RequiredLength,
            );
        }
    }

    unsafe extern "system" fn on_delete(
        info: *const CF_CALLBACK_INFO,
        parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        // SAFETY: as in `on_fetch_data`, for a NOTIFY_DELETE callback.
        let (info, delete) = unsafe { (&*info, (*parameters).Anonymous.Delete) };
        let undelete = delete.Flags.contains(CF_CALLBACK_DELETE_FLAG_IS_UNDELETE);
        // SAFETY: `info` is from this callback, here and below.
        let status = match (unsafe { bridge_of(info) }, unsafe { identity_of(info) }) {
            (Some(bridge), Some(id)) => bridge.delete_from_safe(id, undelete),
            _ => STATUS_SUCCESS,
        };
        let ack = CF_OPERATION_PARAMETERS_0_7 {
            Flags: CF_OPERATION_ACK_DELETE_FLAG_NONE,
            CompletionStatus: status,
        };
        let _ = execute(
            info,
            CF_OPERATION_TYPE_ACK_DELETE,
            operation::<CF_OPERATION_PARAMETERS_0_7>(CF_OPERATION_PARAMETERS_0 { AckDelete: ack }),
        );
    }

    unsafe extern "system" fn on_rename(
        info: *const CF_CALLBACK_INFO,
        parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        // SAFETY: as in `on_fetch_data`, for a NOTIFY_RENAME callback.
        let (info, rename) = unsafe { (&*info, (*parameters).Anonymous.Rename) };
        // SAFETY: the platform's string, valid and NUL-terminated while the callback runs.
        let target = unsafe { rename.TargetPath.to_string() }.unwrap_or_default();
        // SAFETY: `info` is from this callback, here and below.
        let status = match (unsafe { bridge_of(info) }, unsafe { identity_of(info) }) {
            (Some(bridge), Some(id)) => bridge.rename_in_safe(id, &target),
            _ => STATUS_SUCCESS,
        };
        let ack = CF_OPERATION_PARAMETERS_0_6 {
            Flags: CF_OPERATION_ACK_RENAME_FLAG_NONE,
            CompletionStatus: status,
        };
        let _ = execute(
            info,
            CF_OPERATION_TYPE_ACK_RENAME,
            operation::<CF_OPERATION_PARAMETERS_0_6>(CF_OPERATION_PARAMETERS_0 { AckRename: ack }),
        );
    }

    static CALLBACKS: [CF_CALLBACK_REGISTRATION; 4] = [
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_FETCH_DATA,
            Callback: Some(on_fetch_data),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_DELETE,
            Callback: Some(on_delete),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_RENAME,
            Callback: Some(on_rename),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NONE,
            Callback: None,
        },
    ];

    fn register(root: &Path, safe_id: &str) -> Result<()> {
        let path = wide(root.as_os_str());
        let name = wide(PROVIDER_NAME.as_ref());
        let version = wide(PROVIDER_VERSION.as_ref());
        let registration = CF_SYNC_REGISTRATION {
            StructSize: size_of::<CF_SYNC_REGISTRATION>() as u32,
            ProviderName: PCWSTR(name.as_ptr()),
            ProviderVersion: PCWSTR(version.as_ptr()),
            SyncRootIdentity: safe_id.as_ptr().cast(),
            SyncRootIdentityLength: safe_id.len() as u32,
            FileIdentity: ROOT_ID.as_ptr().cast(),
            FileIdentityLength: ROOT_ID.len() as u32,
            ProviderId: PROVIDER,
        };
        let policies = CF_SYNC_POLICIES {
            StructSize: size_of::<CF_SYNC_POLICIES>() as u32,
            Hydration: CF_HYDRATION_POLICY {
                Primary: CF_HYDRATION_POLICY_FULL,
                Modifier: CF_HYDRATION_POLICY_MODIFIER_NONE,
            },
            Population: CF_POPULATION_POLICY {
                Primary: CF_POPULATION_POLICY_ALWAYS_FULL,
                Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
            },
            InSync: CF_INSYNC_POLICY_TRACK_ALL,
            HardLink: CF_HARDLINK_POLICY_NONE,
            PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
        };
        // SAFETY: every string ends in a NUL, and it all outlives the call, which copies it.
        unsafe {
            CfRegisterSyncRoot(
                PCWSTR(path.as_ptr()),
                &registration,
                &policies,
                CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT
                    | CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT,
            )
        }
        .map_err(cf_failure)
    }

    fn connect(
        root: &Path,
        bridge: Option<&'static Bridge>,
    ) -> windows::core::Result<CF_CONNECTION_KEY> {
        let path = wide(root.as_os_str());
        let context = bridge.map(|bridge| ptr::from_ref(bridge).cast::<c_void>());
        // SAFETY: the table is static and ends in a `CF_CALLBACK_TYPE_NONE` entry, the string ends
        // in a NUL, and the context is leaked or absent, as `bridge_of` expects.
        unsafe {
            CfConnectSyncRoot(
                PCWSTR(path.as_ptr()),
                CALLBACKS.as_ptr(),
                context,
                CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH
                    | CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION,
            )
        }
    }

    fn disconnect(connection: CF_CONNECTION_KEY) -> Result<()> {
        // SAFETY: the key came from `connect` and is used once.
        unsafe { CfDisconnectSyncRoot(connection) }.map_err(cf_failure)
    }

    fn unregister(root: &Path) -> Result<()> {
        let path = wide(root.as_os_str());
        // SAFETY: the string ends in a NUL and outlives the call.
        unsafe { CfUnregisterSyncRoot(PCWSTR(path.as_ptr())) }.map_err(cf_failure)
    }

    /// Overwrites a file with bytes on the disk, then removes it. A dehydrated one has nothing to
    /// overwrite, and opening it to write would ask for its bytes.
    fn erase(path: &Path) -> io::Result<()> {
        let dehydrated = fs::symlink_metadata(path)
            .is_ok_and(|metadata| metadata.file_attributes() & DEHYDRATED != 0);
        if !dehydrated && shred::shred(path).is_ok() {
            return Ok(());
        }
        match fs::remove_file(path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }

    /// Takes away a folder that's been emptied. If something's left it stays, marker and all, for
    /// [`clean_leftovers`] to come back to.
    fn finish(root: &Path, left: &[PathBuf]) -> Result<()> {
        if !left.is_empty() {
            return Err(SafeError::Io(io::Error::other(format!(
                "{} files or folders couldn't be removed from the Safe's folder",
                left.len()
            ))));
        }
        fs::remove_file(root.join(MARKER))?;
        // Windows may hold it for a moment after unregistering. It's empty, so that does no harm.
        let _ = fs::remove_dir(root);
        Ok(())
    }

    fn clean(root: &Path) -> Result<bool> {
        if !has_marker(root) {
            return Ok(false);
        }
        // A provider has to be there for placeholders to be deleted without an error. If this was
        // never a sync root, or isn't any more, it's a plain folder and needs none.
        let connection = match connect(root, None) {
            Ok(connection) => Some(connection),
            Err(error) if error.code() == ERROR_CLOUD_FILE_ALREADY_CONNECTED.to_hresult() => {
                // Another copy of the app has it mounted.
                return Err(SafeError::Exists);
            }
            Err(_) => None,
        };
        let mut left = remove_tree(root, &erase);
        if let Some(connection) = connection {
            let _ = disconnect(connection);
        }
        let _ = unregister(root);
        if !left.is_empty() {
            left = remove_tree(root, &erase);
        }
        finish(root, &left)?;
        Ok(true)
    }

    /// Empties a folder a crash left behind, and unregisters it. Run this at start-up for every
    /// folder a mount may have used. Returns whether there was anything to clean. A folder that
    /// has no marker is left alone, whatever's in it, and so is one that's mounted right now.
    pub fn clean_leftovers(folder: &Path) -> Result<bool> {
        let Ok(root) = canonical(folder) else {
            return Ok(false);
        };
        let _claim = Claim::take(&root)?;
        clean(&root)
    }

    fn canonical(folder: &Path) -> io::Result<PathBuf> {
        let path = fs::canonicalize(folder)?;
        Ok(path
            .to_str()
            .map_or_else(|| path.clone(), |text| PathBuf::from(plain_path(text))))
    }

    /// Keeps trying for files that wouldn't go on lock, because an app has them open.
    fn sweep(root: PathBuf) {
        thread::spawn(move || {
            for _ in 0..SWEEP_TRIES {
                thread::sleep(SWEEP_EVERY);
                match clean_leftovers(&root) {
                    Ok(_) if !has_marker(&root) => return,
                    _ => {}
                }
            }
        });
    }

    struct Event(HANDLE);

    // SAFETY: an event handle is a kernel object, usable from any thread.
    unsafe impl Send for Event {}
    // SAFETY: as above, and the calls made on it are synchronised by the kernel.
    unsafe impl Sync for Event {}

    impl Event {
        fn new() -> Result<Self> {
            // SAFETY: no security attributes and no name, so nothing to keep alive.
            let handle = unsafe { CreateEventW(None, true, false, None) }.map_err(cf_failure)?;
            Ok(Self(handle))
        }

        fn set(&self) {
            // SAFETY: the handle is open for as long as `self`.
            let _ = unsafe { SetEvent(self.0) };
        }
    }

    impl Drop for Event {
        fn drop(&mut self) {
            // SAFETY: the handle is open, and this is the last use of it.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    /// Runs a pass when the folder changes, and every [`TICK`]. Only *when* matters: a pass looks
    /// at everything, so the notifications themselves aren't read, and if they overflow the buffer
    /// nothing is lost.
    fn watch(bridge: &'static Bridge, stop: &Event) {
        let folder = OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY.0)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OVERLAPPED.0)
            .open(&bridge.root);
        let done = Event::new();
        let (Ok(folder), Ok(done)) = (folder, done) else {
            // Passes still run, every tick.
            while !wait_for(stop, TICK) {
                let _ = bridge.reconcile();
            }
            return;
        };
        let handle = handle_of(&folder);
        let mut buffer = vec![0u32; WATCH_BUFFER / size_of::<u32>()];
        let mut overlapped = OVERLAPPED {
            hEvent: done.0,
            ..Default::default()
        };
        let mut reading = false;
        let mut next = Instant::now() + TICK;
        let filter = FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE;
        loop {
            if !reading {
                // SAFETY: the event is open. The buffer and `overlapped` stay in place until the
                // read has finished: the code after this loop waits for that.
                reading = unsafe {
                    let _ = ResetEvent(done.0);
                    ReadDirectoryChangesW(
                        handle,
                        buffer.as_mut_ptr().cast(),
                        WATCH_BUFFER as u32,
                        true,
                        filter,
                        None,
                        Some(&raw mut overlapped),
                        None,
                    )
                }
                .is_ok();
            }
            let now = Instant::now();
            let wait = next.saturating_duration_since(now).as_millis() as u32;
            // SAFETY: both handles are open.
            let woken = unsafe { WaitForMultipleObjects(&[stop.0, done.0], false, wait) };
            if woken == WAIT_OBJECT_0 {
                break;
            }
            if woken == WAIT_TIMEOUT {
                let _ = bridge.reconcile();
                next = Instant::now() + TICK;
            } else if woken.0 == WAIT_OBJECT_0.0 + 1 {
                let mut ignored = 0;
                // SAFETY: the read that signalled the event used this `overlapped`.
                let _ = unsafe { GetOverlappedResult(handle, &overlapped, &mut ignored, false) };
                reading = false;
                // Sooner, but never later, or a file that never stops changing starves the pass.
                next = next.min(now + SETTLE);
            } else {
                // The wait itself failed. Not a reason to spin.
                thread::sleep(SETTLE);
            }
        }
        if reading {
            let mut ignored = 0;
            // SAFETY: the read is pending on this handle, and this waits until the kernel has let
            // go of the buffer.
            unsafe {
                let _ = CancelIoEx(handle, Some(&overlapped));
                let _ = GetOverlappedResult(handle, &overlapped, &mut ignored, true);
            }
        }
    }

    /// Waits for `stop`, and says whether it came.
    fn wait_for(stop: &Event, time: Duration) -> bool {
        // SAFETY: the handle is open.
        unsafe {
            WaitForMultipleObjects(&[stop.0], false, time.as_millis() as u32) == WAIT_OBJECT_0
        }
    }

    /// A Safe in File Explorer. Locking it, or dropping it, disconnects and removes everything.
    pub struct CloudFilesMount {
        bridge: &'static Bridge,
        root: PathBuf,
        connection: Option<CF_CONNECTION_KEY>,
        stop: Arc<Event>,
        watcher: Option<JoinHandle<()>>,
        claim: Option<Claim>,
        locked: bool,
    }

    /// Shows `safe` in `folder`, which is made if it's missing. Takes an empty folder only, or
    /// what's left of an earlier mount: locking deletes everything in it.
    pub fn mount(safe: Arc<Safe>, folder: &Path) -> Result<CloudFilesMount> {
        fs::create_dir_all(folder)?;
        let root = canonical(folder)?;
        let claim = Claim::take(&root)?;
        clean(&root)?;
        fs::create_dir_all(&root)?;
        check_empty(&root)?;
        let safe_id = safe.safe_id()?;
        let stop = Arc::new(Event::new()?);
        let marker = root.join(MARKER);
        fs::write(&marker, MARKER_TEXT)?;
        let marker = wide(marker.as_os_str());
        let path = wide(root.as_os_str());
        // SAFETY: the strings end in a NUL and outlive the calls. Both are only requests: the
        // marker needn't be hidden to work, and the folder needn't be left out of the index.
        unsafe {
            let hidden = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
            let _ = SetFileAttributesW(PCWSTR(marker.as_ptr()), hidden);
            let _ = SetFileAttributesW(PCWSTR(path.as_ptr()), FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
        }
        if let Err(error) = register(&root, &safe_id) {
            let _ = finish(&root, &[]);
            return Err(error);
        }
        let bridge: &'static Bridge = Box::leak(Box::new(Bridge {
            root: root.clone(),
            root_text: root.to_string_lossy().into_owned(),
            safe: Mutex::new(Some(safe)),
            tree: Mutex::new(PlaceholderTree::default()),
        }));
        let connection = match connect(&root, Some(bridge)) {
            Ok(connection) => connection,
            Err(error) => {
                bridge.close();
                let _ = unregister(&root);
                let _ = finish(&root, &[]);
                return Err(cf_failure(error));
            }
        };
        // From here on, dropping it undoes all of the above.
        let mut mount = CloudFilesMount {
            bridge,
            root,
            connection: Some(connection),
            stop: Arc::clone(&stop),
            watcher: None,
            claim: Some(claim),
            locked: false,
        };
        bridge.reconcile()?;
        mount.watcher = Some(thread::spawn(move || watch(bridge, &stop)));
        Ok(mount)
    }

    impl CloudFilesMount {
        /// The folder Explorer shows.
        pub fn folder(&self) -> &Path {
            &self.root
        }

        /// Takes in what's still waiting, then removes everything from the folder and unregisters
        /// it. Nothing here touches the Safe: callbacks stop reaching it before the first delete.
        ///
        /// An error means something's wrong in a way the user should hear: edits that couldn't be
        /// taken in are gone, or an app holds a file open. Those files are tried again in the
        /// background, and [`clean_leftovers`] gets them at the next start if not.
        pub fn lock(&mut self) -> Result<()> {
            if self.locked {
                return Ok(());
            }
            self.locked = true;
            self.stop.set();
            if let Some(watcher) = self.watcher.take() {
                let _ = watcher.join();
            }
            let bridge = self.bridge;
            let _ = bridge.reconcile();
            let lost = local_rows(&self.root)
                .map_or(0, |rows| rows.iter().filter(|row| holds_edits(row)).count());
            bridge.close();

            // While still connected: without a provider, Windows can refuse to delete placeholders.
            let mut left = remove_tree(&self.root, &erase);
            if let Some(connection) = self.connection.take() {
                let _ = disconnect(connection);
            }
            let unregistered = unregister(&self.root);
            if !left.is_empty() {
                left = remove_tree(&self.root, &erase);
            }
            let finished = finish(&self.root, &left);
            let claim = self.claim.take();
            drop(claim);
            if finished.is_err() {
                sweep(self.root.clone());
            }
            finished?;
            unregistered?;
            if lost > 0 {
                return Err(SafeError::Io(io::Error::other(format!(
                    "{lost} edited files couldn't be saved to the Safe before it locked"
                ))));
            }
            Ok(())
        }
    }

    impl Drop for CloudFilesMount {
        fn drop(&mut self) {
            let _ = self.lock();
        }
    }
}

#[cfg(test)]
mod tests {
    use octapass_core::keys::SymmetricKey;
    use proptest::prelude::*;

    use super::*;

    const SAFE_ID: &str = "11111111-1111-4111-8111-111111111111";

    fn new_safe() -> (tempfile::TempDir, Safe) {
        let dir = tempfile::tempdir().unwrap();
        let key = SymmetricKey::from_bytes([7; 32]);
        let safe = Safe::create(&dir.path().join("safe"), SAFE_ID, &key).unwrap();
        (dir, safe)
    }

    fn tree_of(safe: &Safe) -> PlaceholderTree {
        PlaceholderTree::read(safe, &PlaceholderTree::default()).unwrap()
    }

    fn names(path: &[&str]) -> Vec<String> {
        path.iter().map(|name| (*name).to_owned()).collect()
    }

    fn placeholder(path: &[&str], id: &str, in_sync: bool, hydrated: bool) -> LocalRow {
        LocalRow {
            path: names(path),
            folder: false,
            state: LocalState::Placeholder {
                id: id.to_owned(),
                in_sync,
                hydrated,
            },
        }
    }

    fn folder_row(path: &[&str], id: &str) -> LocalRow {
        LocalRow {
            folder: true,
            ..placeholder(path, id, true, true)
        }
    }

    fn plain(path: &[&str], folder: bool) -> LocalRow {
        LocalRow {
            path: names(path),
            folder,
            state: LocalState::Plain,
        }
    }

    /// Every row a tree would have, as if the disk agreed with it.
    fn rows_of(tree: &PlaceholderTree) -> Vec<LocalRow> {
        let mut rows: Vec<LocalRow> = tree
            .order
            .iter()
            .map(|id| {
                let placed = tree.get(id).unwrap();
                let path = tree.path_of(id).unwrap();
                let path: Vec<&str> = path.iter().map(String::as_str).collect();
                if placed.folder {
                    folder_row(&path, id)
                } else {
                    placeholder(&path, id, true, false)
                }
            })
            .collect();
        rows.sort_by_key(|row| row.path.len());
        rows
    }

    #[test]
    fn names_windows_refuses_are_told_apart() {
        for bad in [
            "a:b",
            "a<b",
            "a>b",
            "a\"b",
            "a|b",
            "a?b",
            "a*b",
            "a/b",
            "a\\b",
            "a\u{1}b",
            "end.",
            "end ",
            "CON",
            "con",
            "nul.txt",
            "COM1",
            "lpt9.tar.gz",
            "CON .txt",
            "COM¹",
            "CONIN$",
            "",
        ] {
            assert!(!windows_name_ok(bad), "{bad:?}");
        }
        for good in [
            "a.txt",
            "CONSOLE",
            "COM10",
            "COM",
            "LPT",
            "console.log",
            ".hidden",
            "ملف.txt",
            "a b",
            "COMA",
            "NULL",
        ] {
            assert!(windows_name_ok(good), "{good:?}");
        }
        assert!(!windows_name_ok(&"a".repeat(256)));
        assert!(windows_name_ok(&"a".repeat(255)));
    }

    #[test]
    fn a_name_windows_refuses_gets_a_stand_in() {
        assert_eq!(local_name("report.pdf"), "report.pdf");
        assert_eq!(local_name("a:b?.txt"), "a_b_.txt");
        assert_eq!(local_name("end. "), "end");
        assert_eq!(local_name("..."), "_");
        assert_eq!(local_name(&format!("{}x", " ".repeat(300))), "_");
        assert_eq!(local_name("CON"), "_ON");
        assert_eq!(local_name("nul.txt"), "_ul.txt");
    }

    #[test]
    fn a_long_name_is_cut_from_the_stem() {
        let long = format!("{}.pdf", "a".repeat(300));
        let local = local_name(&long);
        assert_eq!(local.encode_utf16().count(), 255);
        assert!(local.ends_with(".pdf"));
        // Under the Safe's limit in UTF-16, over it in bytes.
        let arabic = format!("{}.txt", "م".repeat(200));
        assert_eq!(local_name(&arabic), arabic);
        let cut = safe_name(&arabic);
        assert!(cut.len() <= MAX_NAME_LEN);
        assert!(cut.ends_with(".txt"));
    }

    proptest! {
        #[test]
        fn every_name_has_a_usable_stand_in(name in "\\PC{0,300}") {
            let local = local_name(&name);
            prop_assert!(windows_name_ok(&local), "{:?} became {:?}", name, local);
        }

        #[test]
        fn a_usable_name_is_kept(name in "[a-zA-Z0-9_-]{1,40}(\\.[a-z]{1,5})?") {
            prop_assume!(!reserved(&name));
            prop_assert_eq!(local_name(&name), name);
        }

        #[test]
        fn spans_cover_the_request_and_obey_the_rules(
            offset in 0u64..50_000_000,
            length in 0u64..50_000_000,
            size in 0u64..50_000_000,
        ) {
            let spans = transfer_spans(offset, length, size);
            let wanted_end = offset.saturating_add(length).min(size);
            if offset >= wanted_end {
                prop_assert!(spans.is_empty());
            } else {
                prop_assert!(spans[0].offset <= offset);
                let last = spans[spans.len() - 1];
                let end = last.offset + last.len as u64;
                prop_assert!(end >= wanted_end);
                prop_assert!(end <= size);
                for pair in spans.windows(2) {
                    prop_assert_eq!(pair[0].offset + pair[0].len as u64, pair[1].offset);
                }
                for span in &spans {
                    prop_assert_eq!(span.offset % TRANSFER_ALIGN, 0);
                    prop_assert!(span.len as u64 <= TRANSFER_LEN);
                    let span_end = span.offset + span.len as u64;
                    prop_assert!(span_end % TRANSFER_ALIGN == 0 || span_end == size);
                }
            }
        }
    }

    #[test]
    fn a_small_file_is_one_transfer_to_its_end() {
        assert_eq!(transfer_spans(0, 10, 10), [Span { offset: 0, len: 10 }]);
        assert_eq!(
            transfer_spans(5000, 1, 6000),
            [Span {
                offset: 4096,
                len: 1904
            }]
        );
        assert!(transfer_spans(0, 0, 10).is_empty());
        assert!(transfer_spans(10, 5, 10).is_empty());
    }

    #[test]
    fn the_tree_gives_clashing_names_their_own_place() {
        let (_dir, safe) = new_safe();
        let upper = safe.create_file(ROOT_ID, "Report.pdf").unwrap();
        let lower = safe.create_file(ROOT_ID, "report.pdf").unwrap();
        let colon = safe.create_file(ROOT_ID, "a:b").unwrap();
        let under = safe.create_file(ROOT_ID, "a_b").unwrap();
        let marker = safe.create_file(ROOT_ID, MARKER).unwrap();

        let tree = tree_of(&safe);
        assert_eq!(tree.get(&upper.id).unwrap().local, "Report.pdf");
        assert_eq!(tree.get(&lower.id).unwrap().local, "report (2).pdf");
        assert_eq!(tree.get(&colon.id).unwrap().local, "a_b");
        assert_eq!(tree.get(&under.id).unwrap().local, "a_b (2)");
        assert_eq!(tree.get(&colon.id).unwrap().name, "a:b");
        // The marker's name belongs to the mount.
        assert_ne!(tree.get(&marker.id).unwrap().local, MARKER);
    }

    #[test]
    fn the_longest_names_can_still_clash() {
        let (_dir, safe) = new_safe();
        let upper = safe.create_file(ROOT_ID, &"A".repeat(255)).unwrap();
        let lower = safe.create_file(ROOT_ID, &"a".repeat(255)).unwrap();
        let tree = tree_of(&safe);
        let (upper, lower) = (tree.get(&upper.id).unwrap(), tree.get(&lower.id).unwrap());
        assert_ne!(folded(&upper.local), folded(&lower.local));
        assert!(windows_name_ok(&upper.local));
        assert!(windows_name_ok(&lower.local));
    }

    #[test]
    fn a_new_neighbour_leaves_a_name_alone() {
        let (_dir, safe) = new_safe();
        let first = safe.create_file(ROOT_ID, "a_b").unwrap();
        let before = tree_of(&safe);
        // Sorts first, and would otherwise take `a_b` from what's already on the disk.
        let second = safe.create_file(ROOT_ID, "A_b").unwrap();

        let tree = PlaceholderTree::read(&safe, &before).unwrap();
        assert_eq!(tree.get(&first.id).unwrap().local, "a_b");
        assert_eq!(tree.get(&second.id).unwrap().local, "A_b (2)");
    }

    #[test]
    fn paths_are_looked_up_in_both_directions_ignoring_case() {
        let (_dir, safe) = new_safe();
        let folder = safe.create_folder(ROOT_ID, "Docs").unwrap();
        let inner = safe.create_folder(&folder.id, "a:b").unwrap();
        let file = safe.create_file(&inner.id, "note.txt").unwrap();

        let tree = tree_of(&safe);
        assert_eq!(tree.path_of(&file.id).unwrap(), ["Docs", "a_b", "note.txt"]);
        assert_eq!(
            tree.id_at(&names(&["docs", "A_B", "NOTE.TXT"])),
            Some(file.id.as_str())
        );
        assert_eq!(tree.id_at(&names(&["Docs", "missing"])), None);
        assert_eq!(tree.id_at(&[]), None);
    }

    #[test]
    fn a_folder_comes_before_what_is_in_it() {
        let (_dir, safe) = new_safe();
        let folder = safe.create_folder(ROOT_ID, "z").unwrap();
        let inner = safe.create_folder(&folder.id, "y").unwrap();
        let file = safe.create_file(&inner.id, "x").unwrap();
        let tree = tree_of(&safe);
        let at = |id: &str| tree.order.iter().position(|one| one == id).unwrap();
        assert!(at(&folder.id) < at(&inner.id));
        assert!(at(&inner.id) < at(&file.id));
    }

    #[test]
    fn paths_from_cloud_files_are_found_under_the_root() {
        let root = r"C:\Users\Sam\Octa Pass Safe\Taxes";
        assert_eq!(
            under_root(root, r"\Users\sam\OCTA PASS SAFE\taxes\2024\a.pdf").unwrap(),
            ["2024", "a.pdf"]
        );
        assert_eq!(
            under_root(root, r"C:\Users\Sam\Octa Pass Safe\Taxes\a.pdf").unwrap(),
            ["a.pdf"]
        );
        assert_eq!(under_root(root, root).unwrap(), Vec::<String>::new());
        assert_eq!(under_root(root, r"\$Recycle.Bin\S-1-5\$R123.pdf"), None);
        assert_eq!(
            under_root(root, r"\Users\Sam\Octa Pass Safe\Taxes2\a"),
            None
        );
        assert_eq!(under_root(root, r"\Users\Sam"), None);
    }

    #[test]
    fn verbatim_paths_become_plain_ones() {
        assert_eq!(plain_path(r"\\?\C:\Users\Sam"), r"C:\Users\Sam");
        assert_eq!(plain_path(r"C:\Users\Sam"), r"C:\Users\Sam");
        assert_eq!(plain_path(r"\\?\UNC\server\share"), r"\\?\UNC\server\share");
    }

    #[test]
    fn times_count_from_1601() {
        assert_eq!(file_time(0), 116_444_736_000_000_000);
        assert_eq!(file_time(1), 116_444_736_000_010_000);
        assert!(file_time(u64::MAX) > 0);
    }

    #[test]
    fn a_disk_that_agrees_needs_nothing() {
        let (_dir, safe) = new_safe();
        let folder = safe.create_folder(ROOT_ID, "Docs").unwrap();
        safe.create_file(&folder.id, "a.txt").unwrap();
        let tree = tree_of(&safe);
        assert!(plan(&tree, &tree, &rows_of(&tree)).is_empty());
    }

    #[test]
    fn a_first_pass_creates_everything_folders_first() {
        let (_dir, safe) = new_safe();
        let folder = safe.create_folder(ROOT_ID, "Docs").unwrap();
        let file = safe.create_file(&folder.id, "a.txt").unwrap();
        let top = safe.create_file(ROOT_ID, "b.txt").unwrap();

        let tree = tree_of(&safe);
        let steps = plan(&PlaceholderTree::default(), &tree, &[]);
        let [
            Step::Create {
                folder: first,
                items: at_top,
            },
            Step::Create {
                folder: second,
                items: in_docs,
            },
        ] = steps.as_slice()
        else {
            panic!("{steps:?}");
        };
        assert!(first.is_empty());
        let mut ids: Vec<&str> = at_top.iter().map(|item| item.id.as_str()).collect();
        ids.sort_unstable();
        let mut expected = [folder.id.as_str(), top.id.as_str()];
        expected.sort_unstable();
        assert_eq!(ids, expected);
        assert_eq!(second, &["Docs"]);
        assert_eq!(in_docs[0].id, file.id);
    }

    #[test]
    fn something_new_goes_into_the_safe_and_noise_does_not() {
        let tree = PlaceholderTree::default();
        let rows = [
            plain(&["new"], true),
            plain(&["new", "a.txt"], false),
            plain(&["desktop.ini"], false),
            plain(&["~$report.docx"], false),
        ];
        assert_eq!(
            plan(&tree, &tree, &rows),
            [
                Step::Adopt {
                    path: names(&["new"]),
                    folder: true,
                    into: None
                },
                Step::Adopt {
                    path: names(&["new", "a.txt"]),
                    folder: false,
                    into: None
                },
            ]
        );
    }

    #[test]
    fn a_save_that_replaced_a_placeholder_goes_into_the_same_object() {
        let (_dir, safe) = new_safe();
        let file = safe.create_file(ROOT_ID, "a.txt").unwrap();
        let tree = tree_of(&safe);
        assert_eq!(
            plan(&tree, &tree, &[plain(&["A.TXT"], false)]),
            [Step::Adopt {
                path: names(&["A.TXT"]),
                folder: false,
                into: Some(file.id)
            }]
        );
    }

    #[test]
    fn an_edit_is_imported_and_a_metadata_change_is_not() {
        let (_dir, safe) = new_safe();
        let edited = safe.create_file(ROOT_ID, "edited").unwrap();
        let touched = safe.create_file(ROOT_ID, "touched").unwrap();
        let tree = tree_of(&safe);
        let rows = [
            placeholder(&["edited"], &edited.id, false, true),
            placeholder(&["touched"], &touched.id, false, false),
        ];
        assert_eq!(
            plan(&tree, &tree, &rows),
            [
                Step::Import {
                    path: names(&["edited"]),
                    id: edited.id
                },
                Step::MarkInSync {
                    path: names(&["touched"])
                },
            ]
        );
    }

    #[test]
    fn newer_content_in_the_safe_refreshes_the_placeholder() {
        let (_dir, safe) = new_safe();
        let file = safe.create_file(ROOT_ID, "a.txt").unwrap();
        let before = tree_of(&safe);
        safe.write(&file.id, 0, b"changed elsewhere").unwrap();
        safe.flush(&file.id).unwrap();
        let now = PlaceholderTree::read(&safe, &before).unwrap();

        let steps = plan(
            &before,
            &now,
            &[placeholder(&["a.txt"], &file.id, true, true)],
        );
        let [Step::Refresh { path, placed }] = steps.as_slice() else {
            panic!("{steps:?}");
        };
        assert_eq!(path, &["a.txt"]);
        assert_eq!(placed.size, 17);
        // An edit here wins over it.
        let steps = plan(
            &before,
            &now,
            &[placeholder(&["a.txt"], &file.id, false, true)],
        );
        assert!(matches!(steps.as_slice(), [Step::Import { .. }]));
    }

    #[test]
    fn a_refresh_that_failed_comes_back() {
        let (_dir, safe) = new_safe();
        let file = safe.create_file(ROOT_ID, "a.txt").unwrap();
        let mut before = tree_of(&safe);
        before.mark_stale(&file.id);
        let now = PlaceholderTree::read(&safe, &before).unwrap();
        let steps = plan(
            &before,
            &now,
            &[placeholder(&["a.txt"], &file.id, true, true)],
        );
        assert!(matches!(steps.as_slice(), [Step::Refresh { .. }]));
    }

    #[test]
    fn what_this_device_wrote_is_not_refreshed() {
        let (_dir, safe) = new_safe();
        let file = safe.create_file(ROOT_ID, "a.txt").unwrap();
        let mut before = tree_of(&safe);
        safe.write(&file.id, 0, b"from this device").unwrap();
        safe.flush(&file.id).unwrap();
        let entry = safe.entry(&file.id).unwrap();
        before.note(&file.id, entry.size, entry.modified);
        let now = PlaceholderTree::read(&safe, &before).unwrap();
        assert!(
            plan(
                &before,
                &now,
                &[placeholder(&["a.txt"], &file.id, true, true)]
            )
            .is_empty()
        );
    }

    #[test]
    fn what_left_the_safe_leaves_the_disk_deepest_first() {
        let tree = PlaceholderTree::default();
        let rows = [
            folder_row(&["gone"], "1"),
            placeholder(&["gone", "a.txt"], "2", true, true),
        ];
        assert_eq!(
            plan(&tree, &tree, &rows),
            [
                Step::Remove {
                    path: names(&["gone", "a.txt"]),
                    folder: false
                },
                Step::Remove {
                    path: names(&["gone"]),
                    folder: true
                },
            ]
        );
    }

    #[test]
    fn an_edit_of_something_deleted_elsewhere_survives() {
        let tree = PlaceholderTree::default();
        let rows = [placeholder(&["a.txt"], "gone", false, true)];
        assert_eq!(
            plan(&tree, &tree, &rows),
            [Step::Adopt {
                path: names(&["a.txt"]),
                folder: false,
                into: None
            }]
        );
    }

    #[test]
    fn a_rename_in_the_safe_moves_the_placeholder_and_its_folder_keeps_its_children() {
        let (_dir, safe) = new_safe();
        let folder = safe.create_folder(ROOT_ID, "old").unwrap();
        let file = safe.create_file(&folder.id, "a.txt").unwrap();
        let before = tree_of(&safe);
        safe.rename(&folder.id, ROOT_ID, "new").unwrap();
        let now = PlaceholderTree::read(&safe, &before).unwrap();
        let rows = [
            folder_row(&["old"], &folder.id),
            placeholder(&["old", "a.txt"], &file.id, true, true),
        ];
        assert_eq!(
            plan(&before, &now, &rows),
            [Step::Move {
                from: names(&["old"]),
                to: names(&["new"])
            }]
        );
    }

    #[test]
    fn a_case_only_rename_counts_as_a_move() {
        let (_dir, safe) = new_safe();
        let file = safe.create_file(ROOT_ID, "A.txt").unwrap();
        let tree = tree_of(&safe);
        assert_eq!(
            plan(
                &tree,
                &tree,
                &[placeholder(&["a.txt"], &file.id, true, true)]
            ),
            [Step::Move {
                from: names(&["a.txt"]),
                to: names(&["A.txt"])
            }]
        );
    }

    #[test]
    fn what_vanished_from_the_disk_comes_back() {
        let (_dir, safe) = new_safe();
        let file = safe.create_file(ROOT_ID, "a.txt").unwrap();
        let tree = tree_of(&safe);
        let steps = plan(&tree, &tree, &[]);
        let [Step::Create { items, .. }] = steps.as_slice() else {
            panic!("{steps:?}");
        };
        assert_eq!(items[0].id, file.id);
    }

    #[test]
    fn local_steps_come_before_what_could_undo_them() {
        let (_dir, safe) = new_safe();
        let gone = safe.create_file(ROOT_ID, "edited").unwrap();
        let tree = tree_of(&safe);
        let empty = PlaceholderTree::default();
        let rows = [
            placeholder(&["stale"], "missing", true, true),
            plain(&["new.txt"], false),
            placeholder(&["edited"], &gone.id, false, true),
        ];
        let steps = plan(&tree, &tree, &rows);
        assert!(matches!(steps[0], Step::Adopt { .. }));
        assert!(matches!(steps[1], Step::Import { .. }));
        assert!(matches!(steps[2], Step::Remove { .. }));
        // An empty Safe with nothing edited removes, and never adopts.
        let steps = plan(&empty, &empty, &[placeholder(&["a"], "x", true, false)]);
        assert!(matches!(steps.as_slice(), [Step::Remove { .. }]));
    }

    #[test]
    fn only_what_would_be_lost_counts_as_edits() {
        assert!(holds_edits(&plain(&["new.txt"], false)));
        assert!(holds_edits(&placeholder(&["a"], "1", false, true)));
        assert!(!holds_edits(&placeholder(&["a"], "1", true, true)));
        assert!(!holds_edits(&placeholder(&["a"], "1", false, false)));
        assert!(!holds_edits(&plain(&["folder"], true)));
        assert!(!holds_edits(&plain(&["~$lock.docx"], false)));
    }

    fn plain_remove(path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    #[test]
    fn the_marker_must_be_ours() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!has_marker(dir.path()));
        fs::write(dir.path().join(MARKER), b"something else").unwrap();
        assert!(!has_marker(dir.path()));
        fs::write(dir.path().join(MARKER), MARKER_TEXT).unwrap();
        assert!(has_marker(dir.path()));
    }

    #[test]
    fn a_folder_with_anything_in_it_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        check_empty(dir.path()).unwrap();
        fs::write(dir.path().join("thesis.docx"), b"years of work").unwrap();
        assert!(matches!(check_empty(dir.path()), Err(SafeError::NotEmpty)));
    }

    #[test]
    fn emptying_removes_everything_but_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join(MARKER), MARKER_TEXT).unwrap();
        fs::create_dir_all(root.join("a/b/c")).unwrap();
        fs::write(root.join("a/b/c/secret.txt"), b"plaintext").unwrap();
        fs::write(root.join("a/top.txt"), b"plaintext").unwrap();
        // Only at the top: a file of that name further down is just a file.
        fs::write(root.join("a").join(MARKER), b"not this one").unwrap();

        assert!(remove_tree(root, &plain_remove).is_empty());
        let left: Vec<_> = fs::read_dir(root).unwrap().flatten().collect();
        assert_eq!(left.len(), 1);
        assert!(has_marker(root));
    }

    #[test]
    fn what_will_not_go_is_reported_and_the_rest_still_goes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("in-use")).unwrap();
        fs::write(root.join("in-use/held.docx"), b"plaintext").unwrap();
        fs::write(root.join("free.txt"), b"plaintext").unwrap();

        let erase = |path: &Path| {
            if path.ends_with("held.docx") {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                fs::remove_file(path)
            }
        };
        let left = remove_tree(root, &erase);
        assert!(!root.join("free.txt").exists());
        assert!(left.iter().any(|path| path.ends_with("held.docx")));
        assert!(left.iter().any(|path| path.ends_with("in-use")));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_goes_and_what_it_points_at_stays() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep.txt"), b"not ours").unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        assert!(remove_tree(&root, &plain_remove).is_empty());
        assert!(!root.join("link").exists());
        assert!(outside.join("keep.txt").exists());
    }
}
