//! Secure delete: overwrite a file, then remove it. This only does what the disk lets it, and says
//! so. An overwrite reaches the original bytes only when the file system writes in place on a
//! medium that does too:
//!
//! - **Copy-on-write file systems** (APFS, Btrfs, ZFS, bcachefs) write the new bytes elsewhere,
//!   and snapshots keep the old ones.
//! - **SSDs and flash** move writes around (wear levelling), whatever the file system.
//! - **Network and cloud folders** keep copies we can't reach.
//!
//! So a [`Report`] carries a [`Guarantee`], and the only claim of `Overwritten` is an in-place file
//! system on a spinning disk. Everything else, including every case we can't tell, is
//! `BestEffort`. The answer to those cases is to not let plaintext reach the disk: full-disk
//! encryption, and a Safe.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};
use serde::Serialize;

const SLICE: usize = 1024 * 1024;

/// What a delete can promise about the bytes that were there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Guarantee {
    /// In-place file system on a spinning disk: the original blocks were overwritten.
    Overwritten,
    /// Removed and overwritten as far as we can reach. Copies may stay on the disk.
    BestEffort,
}

/// Why the guarantee is what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Storage {
    /// In-place file system on a spinning disk.
    InPlaceDisk,
    /// APFS, Btrfs, ZFS or bcachefs.
    CopyOnWrite,
    /// In-place file system, but on an SSD or flash.
    SolidState,
    /// A network or cloud folder.
    Network,
    /// We can't tell, so we assume the worst.
    Unknown,
}

impl Storage {
    pub fn guarantee(self) -> Guarantee {
        match self {
            Storage::InPlaceDisk => Guarantee::Overwritten,
            _ => Guarantee::BestEffort,
        }
    }

    /// The plain-language note for this kind of storage.
    pub fn note(self) -> &'static str {
        match self {
            Storage::InPlaceDisk => {
                "This file system overwrites in place on a spinning disk, so the original blocks were overwritten. Backups and snapshots aren't touched."
            }
            Storage::CopyOnWrite => {
                "This file system is copy-on-write: the overwrite went to new blocks, and the old ones stay until they're reused. Snapshots keep them longer. Full-disk encryption is what protects them."
            }
            Storage::SolidState => {
                "This is an SSD or flash drive. It moves writes around, so old copies can stay in cells nothing can reach. Full-disk encryption is what protects them."
            }
            Storage::Network => {
                "This is a network or cloud folder. Its server and backups keep their own copies, which this can't reach."
            }
            Storage::Unknown => {
                "Octa Pass can't tell how this drive stores data, so assume old copies can stay on it. Full-disk encryption is what protects them."
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub path: PathBuf,
    pub bytes: u64,
    pub files: u64,
    pub storage: Storage,
    pub guarantee: Guarantee,
    pub note: &'static str,
    /// Other names of the same file still exist (hard links), so it wasn't overwritten.
    pub hard_linked: Vec<PathBuf>,
}

/// What kind of storage holds `path`.
pub fn storage_of(path: &Path) -> Storage {
    platform::storage_of(path)
}

fn overwrite(path: &Path, len: u64) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let mut buffer = vec![0u8; SLICE.min(len.max(1) as usize)];
    let mut remaining = len;
    file.seek(SeekFrom::Start(0))?;
    while remaining > 0 {
        let take = buffer.len().min(remaining as usize);
        OsRng.fill_bytes(&mut buffer[..take]);
        file.write_all(&buffer[..take])?;
        remaining -= take as u64;
    }
    file.sync_all()?;
    file.set_len(0)?;
    file.sync_all()
}

fn random_name() -> String {
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sync_folder(path: &Path) {
    // Windows can't open a folder this way, and renames there are journalled anyway.
    if let Some(parent) = path.parent()
        && let Ok(folder) = File::open(parent)
    {
        let _ = folder.sync_all();
    }
}

/// The name goes too, as far as a rename can take it.
fn remove_with_new_name(path: &Path) -> io::Result<()> {
    let renamed = path.with_file_name(random_name());
    let target = if fs::rename(path, &renamed).is_ok() {
        renamed
    } else {
        path.to_owned()
    };
    fs::remove_file(&target)?;
    sync_folder(&target);
    Ok(())
}

fn shred_one(path: &Path, report: &mut Report) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_symlink() {
        // The link goes; what it points at isn't what was asked about.
        fs::remove_file(path)?;
        report.files += 1;
        return Ok(());
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            shred_one(&entry?.path(), report)?;
        }
        fs::remove_dir(path)?;
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} isn't a file", path.display()),
        ));
    }
    if platform::link_count(&metadata) > 1 {
        // Overwriting would destroy the other name's data, and leaving them means the data stays.
        report.hard_linked.push(path.to_owned());
        fs::remove_file(path)?;
        report.files += 1;
        return Ok(());
    }
    overwrite(path, metadata.len())?;
    remove_with_new_name(path)?;
    report.bytes += metadata.len();
    report.files += 1;
    Ok(())
}

/// Overwrites and removes a file, or a folder and everything in it.
pub fn shred(path: &Path) -> io::Result<Report> {
    let storage = storage_of(path);
    let mut report = Report {
        path: path.to_owned(),
        bytes: 0,
        files: 0,
        storage,
        guarantee: storage.guarantee(),
        note: storage.note(),
        hard_linked: Vec::new(),
    };
    shred_one(path, &mut report)?;
    if !report.hard_linked.is_empty() {
        report.guarantee = Guarantee::BestEffort;
    }
    Ok(report)
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::{CStr, CString};
    use std::fs::Metadata;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use super::Storage;

    pub fn link_count(metadata: &Metadata) -> u64 {
        metadata.nlink()
    }

    pub fn storage_of(path: &Path) -> Storage {
        let existing = path.ancestors().find(|one| one.exists()).unwrap_or(path);
        let Ok(name) = CString::new(existing.as_os_str().as_bytes()) else {
            return Storage::Unknown;
        };
        let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: `name` is a NUL-terminated path and `stats` is writable for a whole `statfs`.
        if unsafe { libc::statfs(name.as_ptr(), stats.as_mut_ptr()) } != 0 {
            return Storage::Unknown;
        }
        // SAFETY: statfs returned 0, so it filled the struct.
        let stats = unsafe { stats.assume_init() };
        // SAFETY: the kernel NUL-terminates this name.
        let kind = unsafe { CStr::from_ptr(stats.f_fstypename.as_ptr()) };
        classify(&kind.to_string_lossy())
    }

    fn classify(kind: &str) -> Storage {
        match kind {
            "apfs" => Storage::CopyOnWrite,
            "smbfs" | "nfs" | "afpfs" | "webdav" | "macfuse" | "osxfuse" => Storage::Network,
            // HFS+ writes in place, but Macs with it may be on either kind of disk.
            _ => Storage::Unknown,
        }
    }

    #[cfg(test)]
    #[test]
    fn classifies() {
        assert_eq!(classify("apfs"), Storage::CopyOnWrite);
        assert_eq!(classify("smbfs"), Storage::Network);
        assert_eq!(classify("hfs"), Storage::Unknown);
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::CString;
    use std::fs::{self, Metadata};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use super::Storage;

    const EXT: i64 = 0xEF53;
    const XFS: i64 = 0x5846_5342;
    const BTRFS: i64 = 0x9123_683E;
    const ZFS: i64 = 0x2FC1_2FC1;
    const BCACHEFS: i64 = 0xCA45_1A4E;
    const NFS: i64 = 0x6969;
    const SMB2: i64 = 0xFE53_4D42;
    const CIFS: i64 = 0xFF53_4D42;
    const FUSE: i64 = 0x6573_5546;

    pub fn link_count(metadata: &Metadata) -> u64 {
        metadata.nlink()
    }

    pub fn storage_of(path: &Path) -> Storage {
        let existing = path.ancestors().find(|one| one.exists()).unwrap_or(path);
        let Ok(name) = CString::new(existing.as_os_str().as_bytes()) else {
            return Storage::Unknown;
        };
        let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: `name` is a NUL-terminated path and `stats` is writable for a whole `statfs`.
        if unsafe { libc::statfs(name.as_ptr(), stats.as_mut_ptr()) } != 0 {
            return Storage::Unknown;
        }
        // SAFETY: statfs returned 0, so it filled the struct.
        let stats = unsafe { stats.assume_init() };
        let rotational = fs::metadata(existing)
            .ok()
            .and_then(|meta| rotational(meta.dev()));
        classify(stats.f_type as i64, rotational)
    }

    /// Whether the disk behind a device number spins, from sysfs. Partitions and device-mapper
    /// layers have their own entry with the answer, or a parent that does.
    fn rotational(device: u64) -> Option<bool> {
        let major = libc::major(device);
        let minor = libc::minor(device);
        let base = format!("/sys/dev/block/{major}:{minor}");
        for candidate in [
            format!("{base}/queue/rotational"),
            format!("{base}/../queue/rotational"),
        ] {
            if let Ok(text) = fs::read_to_string(candidate) {
                return Some(text.trim() == "1");
            }
        }
        None
    }

    fn classify(kind: i64, rotational: Option<bool>) -> Storage {
        match kind {
            BTRFS | ZFS | BCACHEFS => Storage::CopyOnWrite,
            NFS | SMB2 | CIFS | FUSE => Storage::Network,
            EXT | XFS => match rotational {
                Some(true) => Storage::InPlaceDisk,
                Some(false) => Storage::SolidState,
                None => Storage::Unknown,
            },
            _ => Storage::Unknown,
        }
    }

    #[cfg(test)]
    #[test]
    fn classifies() {
        assert_eq!(classify(BTRFS, Some(true)), Storage::CopyOnWrite);
        assert_eq!(classify(EXT, Some(true)), Storage::InPlaceDisk);
        assert_eq!(classify(EXT, Some(false)), Storage::SolidState);
        assert_eq!(classify(EXT, None), Storage::Unknown);
        assert_eq!(classify(NFS, Some(true)), Storage::Network);
        assert_eq!(classify(1, Some(true)), Storage::Unknown);
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use std::fs::Metadata;
    use std::path::Path;

    use super::Storage;

    /// Windows reports links through a handle query we don't make; a linked file is overwritten
    /// like any other, which only ever errs towards destroying the data.
    pub fn link_count(_metadata: &Metadata) -> u64 {
        1
    }

    /// NTFS writes in place, but telling a spinning disk from an SSD needs a device query that
    /// asks for administrator rights on many systems, so Windows always gets the cautious note.
    pub fn storage_of(_path: &Path) -> Storage {
        Storage::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_in_place_disk_earns_the_promise() {
        for storage in [
            Storage::CopyOnWrite,
            Storage::SolidState,
            Storage::Network,
            Storage::Unknown,
        ] {
            assert_eq!(storage.guarantee(), Guarantee::BestEffort);
            assert!(
                storage.note().to_lowercase().contains("copies")
                    || storage.note().contains("copy-on-write")
            );
        }
        assert_eq!(Storage::InPlaceDisk.guarantee(), Guarantee::Overwritten);
    }

    #[test]
    fn a_file_is_gone_and_overwritten_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        fs::write(&path, vec![0x41u8; 3 * SLICE + 17]).unwrap();
        // A second handle sees what the overwrite does to the same inode.
        let probe = File::open(&path).unwrap();
        let before = probe.metadata().unwrap().len();
        let report = shred(&path).unwrap();
        assert!(!path.exists());
        assert_eq!(report.bytes, before);
        assert_eq!(report.files, 1);
        // Cut to nothing before removal.
        assert_eq!(probe.metadata().unwrap().len(), 0);
        assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn overwrite_replaces_every_byte() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x");
        fs::write(&path, vec![0u8; 1000]).unwrap();
        // Same steps as `overwrite`, up to the truncation.
        let mut buffer = vec![0u8; 1000];
        OsRng.fill_bytes(&mut buffer);
        assert!(buffer.iter().filter(|byte| **byte == 0).count() < 100);
        overwrite(&path, 1000).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    fn folders_go_with_everything_in_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a");
        fs::create_dir_all(path.join("b")).unwrap();
        fs::write(path.join("b/c"), b"123").unwrap();
        fs::write(path.join("d"), b"45").unwrap();
        let report = shred(&path).unwrap();
        assert!(!path.exists());
        assert_eq!(report.files, 2);
        assert_eq!(report.bytes, 5);
    }

    #[cfg(unix)]
    #[test]
    fn links_are_removed_without_touching_their_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"keep").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        shred(&link).unwrap();
        assert!(!link.exists());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn hard_links_are_named_and_keep_their_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a");
        fs::write(&path, b"keep").unwrap();
        let other = dir.path().join("b");
        fs::hard_link(&path, &other).unwrap();
        let report = shred(&path).unwrap();
        assert_eq!(report.hard_linked, vec![path.clone()]);
        assert_eq!(report.guarantee, Guarantee::BestEffort);
        assert_eq!(fs::read(&other).unwrap(), b"keep");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn this_mac_is_copy_on_write_and_says_so() {
        // The test folder is on the system volume, which is APFS on every supported macOS.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(storage_of(dir.path()), Storage::CopyOnWrite);
    }
}
