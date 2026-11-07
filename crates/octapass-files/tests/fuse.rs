//! A Safe mounted for real: every file operation below goes through the kernel and FUSE. Needs
//! `/dev/fuse` and `fusermount3` (a Linux machine, or a container run with `--device /dev/fuse
//! --cap-add SYS_ADMIN`). See `scripts/test-fuse.sh`.
#![cfg(all(feature = "fuse", target_os = "linux"))]

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use octapass_core::keys::SymmetricKey;
use octapass_files::safe::{ROOT_ID, Safe, fuse};

const SAFE_ID: &str = "11111111-1111-4111-8111-111111111111";

fn key() -> SymmetricKey {
    SymmetricKey::from_bytes([7; 32])
}

struct Mounted {
    safe: Arc<Safe>,
    mount: Option<fuse::Mount>,
    folder: tempfile::TempDir,
    point: std::path::PathBuf,
    store: std::path::PathBuf,
}

fn mounted() -> Mounted {
    let folder = tempfile::tempdir().unwrap();
    let store = folder.path().join("store");
    let point = folder.path().join("drive");
    fs::create_dir(&point).unwrap();
    let safe = Arc::new(Safe::create(&store, SAFE_ID, &key()).unwrap());
    let mount = fuse::mount(Arc::clone(&safe), &point, "Test").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    Mounted {
        safe,
        mount: Some(mount),
        folder,
        point,
        store,
    }
}

fn everything_under(folder: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for entry in fs::read_dir(folder).unwrap() {
        let entry = entry.unwrap();
        all.extend_from_slice(entry.file_name().as_encoded_bytes());
        if entry.path().is_dir() {
            all.extend(everything_under(&entry.path()));
        } else {
            all.extend(fs::read(entry.path()).unwrap());
        }
    }
    all
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn it_behaves_like_a_folder() {
    let drive = mounted();
    let point = &drive.point;

    fs::create_dir(point.join("Taxes")).unwrap();
    fs::write(point.join("Taxes/SECRETNAME.txt"), b"SECRETBODY one").unwrap();
    assert_eq!(fs::read(point.join("Taxes/SECRETNAME.txt")).unwrap(), b"SECRETBODY one");

    // Listing, sizes, permissions for this user alone.
    let names: Vec<String> = fs::read_dir(point.join("Taxes"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["SECRETNAME.txt"]);
    let metadata = fs::metadata(point.join("Taxes/SECRETNAME.txt")).unwrap();
    assert_eq!(metadata.len(), 14);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    // A big file, written in pieces, read with seeks.
    let body: Vec<u8> = (0..2_000_000u32).map(|i| (i % 253) as u8).collect();
    let mut file = fs::File::create(point.join("big.bin")).unwrap();
    for piece in body.chunks(7_001) {
        file.write_all(piece).unwrap();
    }
    drop(file);
    let mut file = fs::File::open(point.join("big.bin")).unwrap();
    file.seek(SeekFrom::Start(1_234_567)).unwrap();
    let mut part = [0u8; 100_000];
    file.read_exact(&mut part).unwrap();
    assert_eq!(part, body[1_234_567..1_334_567]);
    drop(file);

    // Patch the middle in place, then cut.
    let mut file = fs::OpenOptions::new().write(true).open(point.join("big.bin")).unwrap();
    file.seek(SeekFrom::Start(500_000)).unwrap();
    file.write_all(b"PATCHED").unwrap();
    file.set_len(600_000).unwrap();
    drop(file);
    let back = fs::read(point.join("big.bin")).unwrap();
    assert_eq!(back.len(), 600_000);
    assert_eq!(&back[500_000..500_007], b"PATCHED");
    assert_eq!(back[..500_000], body[..500_000]);

    // The way editors save: write beside, rename over.
    fs::write(point.join("note.tmp"), b"new").unwrap();
    fs::write(point.join("note.txt"), b"old").unwrap();
    fs::rename(point.join("note.tmp"), point.join("note.txt")).unwrap();
    assert_eq!(fs::read(point.join("note.txt")).unwrap(), b"new");

    // Tools that aren't us.
    let status = Command::new("cp")
        .args(["-r"])
        .arg(point.join("Taxes"))
        .arg(point.join("Copy"))
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(fs::read(point.join("Copy/SECRETNAME.txt")).unwrap(), b"SECRETBODY one");
    fs::remove_dir_all(point.join("Copy")).unwrap();
    assert!(!point.join("Copy").exists());

    // Refusals the right way.
    assert_eq!(
        fs::remove_dir(point.join("Taxes")).unwrap_err().raw_os_error(),
        Some(39) // ENOTEMPTY
    );
    assert_eq!(
        fs::read(point.join("missing")).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );

    // The store holds nothing readable, even while mounted.
    let disk = everything_under(&drive.store);
    for needle in [b"SECRETNAME".as_slice(), b"SECRETBODY", b"PATCHED", b"Taxes"] {
        assert!(!contains(&disk, needle));
    }
}

#[test]
fn locking_takes_it_away_and_it_comes_back() {
    let mut drive = mounted();
    fs::write(drive.point.join("a.txt"), b"kept").unwrap();

    // What the apps do when the vault locks: unmount, then drop the keys.
    drive.mount.take();
    drive.safe.lock().unwrap();
    assert!(fs::read_dir(&drive.point).unwrap().next().is_none());
    assert!(!drive.point.join("a.txt").exists());

    let safe = Safe::open(&drive.store, &key()).unwrap();
    let entry = safe.resolve("a.txt").unwrap();
    assert_eq!(*safe.read(&entry.id, 0, 10).unwrap(), *b"kept");
    assert_eq!(safe.list(ROOT_ID).unwrap().len(), 1);
    let _ = &drive.folder;
}

#[test]
fn an_outside_unmount_is_noticed() {
    let mut drive = mounted();
    let status = Command::new("fusermount3")
        .arg("-u")
        .arg(&drive.point)
        .status()
        .or_else(|_| Command::new("fusermount").arg("-u").arg(&drive.point).status())
        .unwrap();
    assert!(status.success());
    std::thread::sleep(Duration::from_millis(500));
    assert!(drive.mount.as_ref().unwrap().finished());
    drive.mount.take();
}
