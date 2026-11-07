//! Shows a Safe as a folder through FUSE: Linux, and macOS with macFUSE. Everything below goes
//! through [`Safe`], so nothing decrypted is ever written to a disk by this layer. The kernel's
//! page cache holds what was read until the mount goes, which is why unmounting comes first when
//! the vault locks.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    BackgroundSession, FileAttr, FileType, Filesystem, KernelConfig, MountOption, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
    ReplyWrite, Request, TimeOrNow,
};

use super::{Entry, ROOT_ID, Result, Safe, SafeError};

/// How long the kernel may trust an answer. Short, because sync can change the tree underneath.
const TTL: Duration = Duration::from_secs(1);
const ROOT_INODE: u64 = fuser::FUSE_ROOT_ID;
const BLOCK: u32 = 4096;

const EINVAL: i32 = 22;
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
#[cfg(target_os = "linux")]
const ENOTEMPTY: i32 = 39;
#[cfg(not(target_os = "linux"))]
const ENOTEMPTY: i32 = 66;

fn errno(error: &SafeError) -> i32 {
    match error {
        SafeError::NotFound => ENOENT,
        SafeError::Exists => EEXIST,
        SafeError::IsFolder => EISDIR,
        SafeError::NotFolder => ENOTDIR,
        SafeError::NotEmpty => ENOTEMPTY,
        SafeError::InvalidName | SafeError::InvalidMove => EINVAL,
        SafeError::Locked => EACCES,
        _ => EIO,
    }
}

/// Object ids and inode numbers, which only live as long as the mount.
struct Inodes {
    by_id: HashMap<String, u64>,
    by_inode: HashMap<u64, String>,
    next: u64,
}

impl Inodes {
    fn new() -> Self {
        Self {
            by_id: HashMap::from([(ROOT_ID.to_owned(), ROOT_INODE)]),
            by_inode: HashMap::from([(ROOT_INODE, ROOT_ID.to_owned())]),
            next: ROOT_INODE + 1,
        }
    }

    fn inode(&mut self, id: &str) -> u64 {
        if let Some(inode) = self.by_id.get(id) {
            return *inode;
        }
        let inode = self.next;
        self.next += 1;
        self.by_id.insert(id.to_owned(), inode);
        self.by_inode.insert(inode, id.to_owned());
        inode
    }

    fn id(&self, inode: u64) -> Option<String> {
        self.by_inode.get(&inode).cloned()
    }
}

struct SafeFs {
    safe: Arc<Safe>,
    inodes: Inodes,
}

fn name_of(name: &OsStr) -> Option<&str> {
    name.to_str()
}

impl SafeFs {
    fn attr(&mut self, req: &Request<'_>, entry: &Entry) -> FileAttr {
        let time = UNIX_EPOCH + Duration::from_millis(entry.modified);
        FileAttr {
            ino: self.inodes.inode(&entry.id),
            size: entry.size,
            blocks: entry.size.div_ceil(u64::from(BLOCK)),
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: if entry.folder {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            // For this user alone, whatever the umask: the mount isn't shared with other users.
            perm: if entry.folder { 0o700 } else { 0o600 },
            nlink: if entry.folder { 2 } else { 1 },
            uid: req.uid(),
            gid: req.gid(),
            rdev: 0,
            blksize: BLOCK,
            flags: 0,
        }
    }

    fn id(&self, inode: u64) -> std::result::Result<String, i32> {
        self.inodes.id(inode).ok_or(ENOENT)
    }

    fn named(
        &self,
        parent: u64,
        name: &OsStr,
    ) -> std::result::Result<(String, String), i32> {
        let folder = self.id(parent)?;
        let name = name_of(name).ok_or(EINVAL)?;
        Ok((folder, name.to_owned()))
    }
}

impl Filesystem for SafeFs {
    fn init(
        &mut self,
        _req: &Request<'_>,
        _config: &mut KernelConfig,
    ) -> std::result::Result<(), i32> {
        Ok(())
    }

    fn destroy(&mut self) {
        let _ = self.safe.flush_all();
    }

    fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let found = self
            .named(parent, name)
            .and_then(|(folder, name)| {
                self.safe.lookup(&folder, &name).map_err(|error| errno(&error))
            });
        match found {
            Ok(entry) => reply.entry(&TTL, &self.attr(req, &entry), 0),
            Err(code) => reply.error(code),
        }
    }

    fn getattr(&mut self, req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let found = self
            .id(ino)
            .and_then(|id| self.safe.entry(&id).map_err(|error| errno(&error)));
        match found {
            Ok(entry) => reply.attr(&TTL, &self.attr(req, &entry)),
            Err(code) => reply.error(code),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let run = || -> std::result::Result<Entry, i32> {
            let id = self.id(ino)?;
            let fail = |error: SafeError| errno(&error);
            if let Some(size) = size {
                self.safe.truncate(&id, size).map_err(fail)?;
            }
            if let Some(mtime) = mtime {
                let time = match mtime {
                    TimeOrNow::SpecificTime(time) => time,
                    TimeOrNow::Now => SystemTime::now(),
                };
                let ms = time
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |since| since.as_millis() as u64);
                // A file with writes waiting takes its time from the flush that follows.
                if id != ROOT_ID {
                    self.safe.set_modified(&id, ms).map_err(fail)?;
                }
            }
            self.safe.entry(&id).map_err(fail)
        };
        match run() {
            Ok(entry) => reply.attr(&TTL, &self.attr(req, &entry)),
            Err(code) => reply.error(code),
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        match self.id(ino) {
            Ok(_) => reply.opened(0, 0),
            Err(code) => reply.error(code),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let found = self.id(ino).and_then(|id| {
            self.safe
                .read(&id, offset.max(0) as u64, size as usize)
                .map_err(|error| errno(&error))
        });
        match found {
            Ok(bytes) => reply.data(&bytes),
            Err(code) => reply.error(code),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let done = self.id(ino).and_then(|id| {
            self.safe
                .write(&id, offset.max(0) as u64, data)
                .map_err(|error| errno(&error))
        });
        match done {
            Ok(()) => reply.written(data.len() as u32),
            Err(code) => reply.error(code),
        }
    }

    fn flush(&mut self, _req: &Request<'_>, ino: u64, _fh: u64, _owner: u64, reply: ReplyEmpty) {
        self.seal(ino, reply);
    }

    fn fsync(&mut self, _req: &Request<'_>, ino: u64, _fh: u64, _data: bool, reply: ReplyEmpty) {
        self.seal(ino, reply);
    }

    #[allow(clippy::too_many_arguments)]
    fn release(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _flags: i32,
        _owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.seal(ino, reply);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let listed = self
            .id(ino)
            .and_then(|id| {
                let entry = self.safe.entry(&id).map_err(|error| errno(&error))?;
                let list = self.safe.list(&id).map_err(|error| errno(&error))?;
                Ok((entry, list))
            });
        let (folder, entries) = match listed {
            Ok(listed) => listed,
            Err(code) => return reply.error(code),
        };
        let parent = self.inodes.inode(&folder.parent);
        let mut rows = vec![
            (ino, FileType::Directory, ".".to_owned()),
            (parent, FileType::Directory, "..".to_owned()),
        ];
        for entry in entries {
            let kind = if entry.folder {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            rows.push((self.inodes.inode(&entry.id), kind, entry.name));
        }
        for (index, (inode, kind, name)) in rows.into_iter().enumerate().skip(offset as usize) {
            if reply.add(inode, (index + 1) as i64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let made = self.named(parent, name).and_then(|(folder, name)| {
            self.safe
                .create_folder(&folder, &name)
                .map_err(|error| errno(&error))
        });
        match made {
            Ok(entry) => reply.entry(&TTL, &self.attr(req, &entry), 0),
            Err(code) => reply.error(code),
        }
    }

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let made = self.named(parent, name).and_then(|(folder, name)| {
            self.safe
                .create_file(&folder, &name)
                .map_err(|error| errno(&error))
        });
        match made {
            Ok(entry) => reply.created(&TTL, &self.attr(req, &entry), 0, 0, 0),
            Err(code) => reply.error(code),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.delete(parent, name, reply);
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.delete(parent, name, reply);
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let moved = (|| {
            let (from, from_name) = self.named(parent, name)?;
            let (to, to_name) = self.named(new_parent, new_name)?;
            let fail = |error: SafeError| errno(&error);
            let entry = self.safe.lookup(&from, &from_name).map_err(fail)?;
            self.safe.rename(&entry.id, &to, &to_name).map_err(fail)
        })();
        match moved {
            Ok(()) => reply.ok(),
            Err(code) => reply.error(code),
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        // A Safe grows with the disk under it; these only need to look roomy.
        reply.statfs(1 << 40, 1 << 39, 1 << 39, 1 << 32, 1 << 31, BLOCK, 255, BLOCK);
    }
}

impl SafeFs {
    fn seal(&mut self, ino: u64, reply: ReplyEmpty) {
        let done = self.id(ino).and_then(|id| {
            match self.safe.flush(&id) {
                // Deleted while open: nothing left to seal.
                Err(SafeError::NotFound) => Ok(()),
                other => other.map_err(|error| errno(&error)),
            }
        });
        match done {
            Ok(()) => reply.ok(),
            Err(code) => reply.error(code),
        }
    }

    fn delete(&mut self, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let gone = self.named(parent, name).and_then(|(folder, name)| {
            let fail = |error: SafeError| errno(&error);
            let entry = self.safe.lookup(&folder, &name).map_err(fail)?;
            self.safe.remove(&entry.id).map_err(fail)
        });
        match gone {
            Ok(()) => reply.ok(),
            Err(code) => reply.error(code),
        }
    }
}

/// A Safe showing at a folder. Dropping this unmounts it.
pub struct Mount {
    session: BackgroundSession,
}

impl Mount {
    /// Whether it was unmounted from outside (`fusermount -u`, the file manager).
    pub fn finished(&self) -> bool {
        self.session.guard.is_finished()
    }
}

/// Shows `safe` at `target`, an existing empty folder, for this user alone.
pub fn mount(safe: Arc<Safe>, target: &Path, name: &str) -> Result<Mount> {
    let options = [
        MountOption::FSName("octapass-safe".to_owned()),
        MountOption::Subtype(name.chars().filter(char::is_ascii_alphanumeric).collect()),
        MountOption::NoDev,
        MountOption::NoSuid,
        MountOption::RW,
    ];
    let session = fuser::spawn_mount2(
        SafeFs {
            safe,
            inodes: Inodes::new(),
        },
        target,
        &options,
    )?;
    Ok(Mount { session })
}
