//! `octapass encrypt` and `decrypt` on the file system: one file, or a folder as a tar archive
//! inside age, so `age -d folder.tar.age | tar x` works without Octa Pass.
//!
//! Output appears only when it's whole. It's written under a temporary name beside the target and
//! moved into place at the end, so an interrupted run or a damaged file leaves nothing that could
//! be mistaken for the real thing. Existing files are never replaced unless asked.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use octapass_core::tools::age::{AgeError, DecryptReader, EncryptWriter, Keys, Opening, Target};
use thiserror::Error;
use zeroize::Zeroizing;

pub const AGE_EXTENSION: &str = "age";
pub const ARCHIVE_SUFFIX: &str = ".tar.age";
/// The largest piece copied at once.
const BUFFER: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum FilesError {
    #[error("{0} already exists")]
    Exists(PathBuf),
    #[error("{0} isn't a file or folder")]
    NotFound(PathBuf),
    #[error("{0} doesn't end in .age, so give the output name")]
    NoOutputName(PathBuf),
    #[error("this archive holds something unsafe to unpack: {0}")]
    UnsafeArchive(String),
    #[error(transparent)]
    Age(#[from] AgeError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, FilesError>;

/// Where a file or folder is encrypted to by default: next to it.
pub fn encrypted_name(source: &Path, folder: bool) -> PathBuf {
    let mut name = source
        .file_name()
        .map_or_else(|| "folder".into(), |name| name.to_os_string());
    name.push(if folder { ARCHIVE_SUFFIX } else { ".age" });
    source.with_file_name(name)
}

/// Where a `.age` file decrypts to by default, and whether it unpacks as a folder.
pub fn decrypted_name(source: &Path) -> Option<(PathBuf, bool)> {
    let name = source.file_name()?.to_str()?;
    if let Some(stem) = name.strip_suffix(ARCHIVE_SUFFIX).filter(|s| !s.is_empty()) {
        return Some((source.with_file_name(stem), true));
    }
    let stem = name.strip_suffix(".age").filter(|s| !s.is_empty())?;
    Some((source.with_file_name(stem), false))
}

fn check_free(output: &Path, overwrite: bool) -> Result<()> {
    if !overwrite && fs::symlink_metadata(output).is_ok() {
        return Err(FilesError::Exists(output.to_owned()));
    }
    Ok(())
}

fn folder_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// A file being written, readable by this user only, that takes its real name in [`finish`].
fn temporary_beside(output: &Path) -> Result<tempfile::NamedTempFile> {
    Ok(tempfile::Builder::new()
        .prefix(".octapass-")
        .suffix(".part")
        .tempfile_in(folder_of(output))?)
}

fn finish(file: tempfile::NamedTempFile, output: &Path, overwrite: bool) -> Result<()> {
    file.as_file().sync_all()?;
    if overwrite {
        file.persist(output).map_err(|error| error.error)?;
    } else {
        file.persist_noclobber(output).map_err(|error| {
            if error.error.kind() == io::ErrorKind::AlreadyExists {
                FilesError::Exists(output.to_owned())
            } else {
                error.error.into()
            }
        })?;
    }
    Ok(())
}

/// What encrypting did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    pub output: PathBuf,
    pub folder: bool,
    /// Plaintext bytes read.
    pub bytes: u64,
    /// Links, sockets and the like inside a folder, which aren't files and weren't included.
    pub skipped: Vec<PathBuf>,
}

/// Encrypts a stream. Returns the plaintext bytes.
pub fn encrypt_stream(
    target: &Target<'_>,
    armor: bool,
    input: &mut impl Read,
    output: impl Write,
) -> Result<u64> {
    let mut writer = EncryptWriter::new(target, armor, output)?;
    let bytes = copy(input, &mut writer)?;
    writer.finish()?;
    Ok(bytes)
}

fn copy(input: &mut impl Read, output: &mut impl Write) -> io::Result<u64> {
    let mut buffer = Zeroizing::new(vec![0u8; BUFFER]);
    let mut total = 0;
    loop {
        match input.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(read) => {
                output.write_all(&buffer[..read])?;
                total += read as u64;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Counts what passes through, for the folder case.
struct Counting<W> {
    inner: W,
    bytes: u64,
}

impl<W: Write> Write for Counting<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Adds a folder's files to an archive. Only real files and folders go in: following a link could
/// pull in anything on the disk.
fn add_folder<W: Write>(
    archive: &mut tar::Builder<W>,
    source: &Path,
    name: &Path,
    skipped: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut entries = fs::read_dir(source)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    archive.append_dir(name, source)?;
    for entry in entries {
        let kind = entry.file_type()?;
        let path = entry.path();
        let inner = name.join(entry.file_name());
        if kind.is_dir() {
            add_folder(archive, &path, &inner, skipped)?;
        } else if kind.is_file() {
            archive.append_path_with_name(&path, &inner)?;
        } else {
            skipped.push(path);
        }
    }
    Ok(())
}

/// Encrypts a file, or a folder as a tar archive, to `output`.
pub fn encrypt_path(
    source: &Path,
    target: &Target<'_>,
    armor: bool,
    output: &Path,
    overwrite: bool,
) -> Result<Encrypted> {
    let metadata = fs::metadata(source).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => FilesError::NotFound(source.to_owned()),
        _ => error.into(),
    })?;
    check_free(output, overwrite)?;
    let mut temporary = temporary_beside(output)?;
    let mut skipped = Vec::new();
    let bytes = if metadata.is_dir() {
        let name = source
            .canonicalize()?
            .file_name()
            .map_or_else(|| PathBuf::from("folder"), PathBuf::from);
        let writer = EncryptWriter::new(target, armor, temporary.as_file_mut())?;
        let mut archive = tar::Builder::new(Counting {
            inner: writer,
            bytes: 0,
        });
        archive.follow_symlinks(false);
        add_folder(&mut archive, source, &name, &mut skipped)?;
        let counted = archive.into_inner()?;
        counted.inner.finish()?;
        counted.bytes
    } else if metadata.is_file() {
        let mut input = File::open(source)?;
        encrypt_stream(target, armor, &mut input, temporary.as_file_mut())?
    } else {
        return Err(FilesError::NotFound(source.to_owned()));
    };
    finish(temporary, output, overwrite)?;
    Ok(Encrypted {
        output: output.to_owned(),
        folder: metadata.is_dir(),
        bytes,
        skipped,
    })
}

/// Reads an age file's header, to learn what it needs before asking for anything.
pub fn needs_passphrase(source: &Path) -> Result<bool> {
    Ok(Opening::new(File::open(source)?)?.needs_passphrase())
}

/// What decrypting did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decrypted {
    pub output: PathBuf,
    pub folder: bool,
    pub bytes: u64,
}

fn reader(source: &Path, keys: &Keys) -> Result<DecryptReader<File>> {
    let input = File::open(source).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => FilesError::NotFound(source.to_owned()),
        _ => error.into(),
    })?;
    Ok(Opening::new(input)?.decrypt(keys)?)
}

/// Decrypts a stream. `output` holds plaintext from chunks that checked out, but it's only the
/// whole file if this returns `Ok`.
pub fn decrypt_stream(keys: &Keys, input: impl Read, output: &mut impl Write) -> Result<u64> {
    let mut reader = Opening::new(input)?.decrypt(keys)?;
    Ok(copy(&mut reader, output)?)
}

/// Decrypts a file to `output`.
pub fn decrypt_file(
    source: &Path,
    keys: &Keys,
    output: &Path,
    overwrite: bool,
) -> Result<Decrypted> {
    check_free(output, overwrite)?;
    let mut reader = reader(source, keys)?;
    let mut temporary = temporary_beside(output)?;
    let bytes = copy(&mut reader, temporary.as_file_mut())?;
    finish(temporary, output, overwrite)?;
    Ok(Decrypted {
        output: output.to_owned(),
        folder: false,
        bytes,
    })
}

/// Why a name in an archive can't be unpacked, if it can't.
fn safe_entry_path(path: &Path) -> bool {
    path.components()
        .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
}

/// Unpacks a `.tar.age` so that `output` is the folder inside it. Only plain files and folders
/// are unpacked, inside `output`; anything else (links, devices, a path that climbs out) stops
/// the whole thing, because a file from someone else must not be able to write outside it.
pub fn decrypt_folder(source: &Path, keys: &Keys, output: &Path) -> Result<Decrypted> {
    check_free(output, false)?;
    let reader = reader(source, keys)?;
    let unpacking = tempfile::Builder::new()
        .prefix(".octapass-")
        .suffix(".part")
        .tempdir_in(folder_of(output))?;
    let mut archive = tar::Archive::new(reader);
    let mut bytes = 0;
    let mut tops: Vec<std::ffi::OsString> = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if !safe_entry_path(&path) {
            return Err(FilesError::UnsafeArchive(path.display().to_string()));
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err(FilesError::UnsafeArchive(path.display().to_string()));
        }
        if let Some(Component::Normal(top)) = path.components().next()
            && !tops.iter().any(|known| known == top)
        {
            tops.push(top.to_owned());
        }
        bytes += entry.size();
        entry.set_preserve_permissions(false);
        if !entry.unpack_in(unpacking.path())? {
            return Err(FilesError::UnsafeArchive(path.display().to_string()));
        }
    }
    // One folder inside, as Octa Pass and `tar -c folder` make: that's the result. Otherwise the
    // unpacking folder itself is.
    if let [top] = tops.as_slice()
        && unpacking.path().join(top).is_dir()
    {
        fs::rename(unpacking.path().join(top), output)?;
    } else {
        fs::rename(unpacking.keep(), output)?;
    }
    Ok(Decrypted {
        output: output.to_owned(),
        folder: true,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use octapass_core::tools::age::{identity_string, recipient_of};

    use super::*;

    fn keys() -> (Vec<String>, Keys) {
        let identity = identity_string(&[4; 32]);
        let recipient = recipient_of(&identity).unwrap();
        (
            vec![recipient],
            Keys {
                identities: vec![identity],
                passphrase: None,
            },
        )
    }

    #[test]
    fn output_names() {
        assert_eq!(
            encrypted_name(Path::new("/a/b.txt"), false),
            Path::new("/a/b.txt.age")
        );
        assert_eq!(
            encrypted_name(Path::new("/a/b"), true),
            Path::new("/a/b.tar.age")
        );
        assert_eq!(
            decrypted_name(Path::new("/a/b.txt.age")).unwrap(),
            (PathBuf::from("/a/b.txt"), false)
        );
        assert_eq!(
            decrypted_name(Path::new("/a/b.tar.age")).unwrap(),
            (PathBuf::from("/a/b"), true)
        );
        assert!(decrypted_name(Path::new("/a/b.txt")).is_none());
        assert!(decrypted_name(Path::new("/a/.age")).is_none());
    }

    #[test]
    fn a_file_round_trips_and_keeps_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let (recipients, keys) = keys();
        let source = dir.path().join("note.txt");
        fs::write(&source, b"hello").unwrap();
        let output = encrypted_name(&source, false);
        let target = Target::Recipients(&recipients);
        encrypt_path(&source, &target, false, &output, false).unwrap();
        assert!(matches!(
            encrypt_path(&source, &target, false, &output, false),
            Err(FilesError::Exists(_))
        ));
        encrypt_path(&source, &target, false, &output, true).unwrap();

        let back = dir.path().join("back.txt");
        decrypt_file(&output, &keys, &back, false).unwrap();
        assert_eq!(fs::read(&back).unwrap(), b"hello");
        assert!(matches!(
            decrypt_file(&output, &keys, &back, false),
            Err(FilesError::Exists(_))
        ));
    }

    #[test]
    fn a_damaged_file_leaves_no_output() {
        let dir = tempfile::tempdir().unwrap();
        let (recipients, keys) = keys();
        let source = dir.path().join("a");
        fs::write(&source, vec![1u8; 200_000]).unwrap();
        let output = dir.path().join("a.age");
        encrypt_path(
            &source,
            &Target::Recipients(&recipients),
            false,
            &output,
            false,
        )
        .unwrap();
        let mut bytes = fs::read(&output).unwrap();
        let end = bytes.len() - 100;
        bytes[end] ^= 1;
        fs::write(&output, bytes).unwrap();

        let back = dir.path().join("back");
        assert!(decrypt_file(&output, &keys, &back, false).is_err());
        let left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(left.len(), 2, "{left:?}");
    }

    #[cfg(unix)]
    #[test]
    fn output_is_for_this_user_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (recipients, keys) = keys();
        let source = dir.path().join("a");
        fs::write(&source, b"x").unwrap();
        let output = dir.path().join("a.age");
        encrypt_path(
            &source,
            &Target::Recipients(&recipients),
            false,
            &output,
            false,
        )
        .unwrap();
        let back = dir.path().join("back");
        decrypt_file(&output, &keys, &back, false).unwrap();
        assert_eq!(
            fs::metadata(&back).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_folder_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let (recipients, keys) = keys();
        let source = dir.path().join("photos");
        fs::create_dir_all(source.join("2026/empty")).unwrap();
        fs::write(source.join("2026/a.jpg"), b"aaa").unwrap();
        fs::write(source.join("b.jpg"), b"bb").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/hosts", source.join("link")).unwrap();

        let output = encrypted_name(&source, true);
        let done = encrypt_path(
            &source,
            &Target::Recipients(&recipients),
            false,
            &output,
            false,
        )
        .unwrap();
        assert!(done.folder);
        #[cfg(unix)]
        assert_eq!(done.skipped, vec![source.join("link")]);

        let back = dir.path().join("restored");
        decrypt_folder(&output, &keys, &back).unwrap();
        assert_eq!(fs::read(back.join("2026/a.jpg")).unwrap(), b"aaa");
        assert_eq!(fs::read(back.join("b.jpg")).unwrap(), b"bb");
        assert!(back.join("2026/empty").is_dir());
        assert!(!back.join("link").exists());
    }

    fn sealed_tar(
        build: impl FnOnce(&mut tar::Builder<Vec<u8>>),
        recipients: &[String],
    ) -> Vec<u8> {
        let mut archive = tar::Builder::new(Vec::new());
        build(&mut archive);
        let tar = archive.into_inner().unwrap();
        let mut out = Vec::new();
        encrypt_stream(
            &Target::Recipients(recipients),
            false,
            &mut &tar[..],
            &mut out,
        )
        .unwrap();
        out
    }

    fn raw_path_header(path: &str, kind: tar::EntryType, size: u64) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
        header.set_entry_type(kind);
        header.set_size(size);
        header.set_mode(0o644);
        header.set_cksum();
        header
    }

    #[test]
    fn a_hostile_archive_can_not_climb_out_or_leave_links() {
        let dir = tempfile::tempdir().unwrap();
        let (recipients, keys) = keys();
        let climb = sealed_tar(
            |archive| {
                let header = raw_path_header("../evil", tar::EntryType::Regular, 1);
                archive.append(&header, &b"x"[..]).unwrap();
            },
            &recipients,
        );
        let link = sealed_tar(
            |archive| {
                let mut header = raw_path_header("top/link", tar::EntryType::Symlink, 0);
                header.set_link_name("/etc").unwrap();
                header.set_cksum();
                archive.append(&header, io::empty()).unwrap();
            },
            &recipients,
        );
        for (name, file) in [("climb.tar.age", climb), ("link.tar.age", link)] {
            let path = dir.path().join(name);
            fs::write(&path, file).unwrap();
            let output = dir.path().join("out");
            assert!(
                matches!(
                    decrypt_folder(&path, &keys, &output),
                    Err(FilesError::UnsafeArchive(_))
                ),
                "{name}"
            );
            assert!(!output.exists());
        }
        assert!(!dir.path().parent().unwrap().join("evil").exists());
    }
}
