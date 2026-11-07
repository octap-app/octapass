use std::fs;
use std::io::{self, Read};

use proptest::prelude::*;
use tempfile::TempDir;

use super::*;

const SAFE_ID: &str = "11111111-1111-4111-8111-111111111111";

fn key() -> SymmetricKey {
    SymmetricKey::from_bytes([7; 32])
}

fn new_safe() -> (TempDir, Safe) {
    let dir = tempfile::tempdir().unwrap();
    let safe = Safe::create(&dir.path().join("safe"), SAFE_ID, &key()).unwrap();
    (dir, safe)
}

fn file(safe: &Safe, folder: &str, name: &str, bytes: &[u8]) -> String {
    let entry = safe.create_file(folder, name).unwrap();
    safe.write(&entry.id, 0, bytes).unwrap();
    safe.flush(&entry.id).unwrap();
    entry.id
}

fn read_whole(safe: &Safe, id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    safe.export(id, &mut out).unwrap();
    out
}

fn on_disk(root: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    let mut stack = vec![root.to_owned()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            all.extend_from_slice(entry.file_name().as_encoded_bytes());
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else {
                all.extend_from_slice(&fs::read(entry.path()).unwrap());
            }
        }
    }
    all
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn a_new_safe_is_empty_and_comes_back() {
    let (_dir, safe) = new_safe();
    assert!(safe.list(ROOT).unwrap().is_empty());
    let root = safe.root().to_owned();
    drop(safe);
    let safe = Safe::open(&root, &key()).unwrap();
    assert_eq!(safe.safe_id().unwrap(), SAFE_ID);
}

#[test]
fn files_and_folders_survive_a_lock() {
    let (_dir, safe) = new_safe();
    let folder = safe.create_folder(ROOT, "Taxes").unwrap();
    let id = file(&safe, &folder.id, "2026.pdf", b"numbers");
    let root = safe.root().to_owned();
    safe.lock().unwrap();
    assert!(matches!(safe.list(ROOT), Err(SafeError::Locked)));
    assert!(matches!(safe.read(&id, 0, 1), Err(SafeError::Locked)));

    let safe = Safe::open(&root, &key()).unwrap();
    let found = safe.resolve("Taxes/2026.pdf").unwrap();
    assert_eq!(found.id, id);
    assert_eq!(found.size, 7);
    assert_eq!(read_whole(&safe, &id), b"numbers");
}

#[test]
fn nothing_readable_reaches_the_disk() {
    let (_dir, safe) = new_safe();
    let folder = safe.create_folder(ROOT, "SECRETFOLDERNAME").unwrap();
    let id = file(
        &safe,
        &folder.id,
        "SECRETFILENAME.txt",
        b"SECRETCONTENTS SECRETCONTENTS",
    );
    // Written but not flushed.
    safe.write(&id, 0, b"UNFLUSHEDCONTENTS").unwrap();
    let disk = on_disk(safe.root());
    for needle in [
        b"SECRETFOLDERNAME".as_slice(),
        b"SECRETFILENAME",
        b"SECRETCONTENTS",
        b"UNFLUSHEDCONTENTS",
        id.as_bytes(),
    ] {
        assert!(!contains(&disk, needle));
    }
}

#[test]
fn the_wrong_key_opens_nothing() {
    let (_dir, safe) = new_safe();
    file(&safe, ROOT, "a", b"1");
    let root = safe.root().to_owned();
    drop(safe);
    let wrong = Safe::open(&root, &SymmetricKey::from_bytes([1; 32])).unwrap();
    assert!(wrong.list(ROOT).unwrap().is_empty());
    assert_eq!(wrong.warnings().unwrap().len(), 1);
}

#[test]
fn not_a_safe_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        Safe::open(dir.path(), &key()),
        Err(SafeError::NotASafe)
    ));
    fs::write(dir.path().join("x"), b"").unwrap();
    assert!(matches!(
        Safe::create(dir.path(), SAFE_ID, &key()),
        Err(SafeError::Exists)
    ));
}

#[test]
fn every_revision_gets_a_new_blob_and_old_ones_go() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", b"one");
    let before = local_blobs(safe.root()).unwrap();
    assert_eq!(before.len(), 2);
    safe.write(&id, 0, b"two").unwrap();
    safe.flush(&id).unwrap();
    let after = local_blobs(safe.root()).unwrap();
    assert_eq!(after.len(), 2);
    assert!(before.iter().all(|blob| !after.contains(blob)));
    assert_eq!(read_whole(&safe, &id), b"two");
}

#[test]
fn renames_touch_only_the_record() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", b"body");
    let content = |safe: &Safe| {
        let mut blobs = local_blobs(safe.root()).unwrap();
        blobs.retain(|blob| blob_kind(blob) == Some(BlobKind::Content));
        blobs
    };
    let before = content(&safe);
    safe.rename(&id, ROOT, "b").unwrap();
    assert_eq!(content(&safe), before);
    assert!(matches!(safe.lookup(ROOT, "a"), Err(SafeError::NotFound)));
    assert_eq!(safe.lookup(ROOT, "b").unwrap().id, id);
}

#[test]
fn renaming_over_a_file_replaces_it() {
    let (_dir, safe) = new_safe();
    let old = file(&safe, ROOT, "old", b"old");
    let new = file(&safe, ROOT, "new.tmp", b"new");
    safe.rename(&new, ROOT, "old").unwrap();
    assert!(matches!(safe.entry(&old), Err(SafeError::NotFound)));
    assert_eq!(read_whole(&safe, &new), b"new");
    assert_eq!(safe.list(ROOT).unwrap().len(), 1);
}

#[test]
fn a_folder_can_not_move_into_itself() {
    let (_dir, safe) = new_safe();
    let a = safe.create_folder(ROOT, "a").unwrap();
    let b = safe.create_folder(&a.id, "b").unwrap();
    assert!(matches!(
        safe.rename(&a.id, &b.id, "a"),
        Err(SafeError::InvalidMove)
    ));
    assert!(matches!(
        safe.rename(&a.id, &a.id, "a"),
        Err(SafeError::InvalidMove)
    ));
}

#[test]
fn folders_must_be_empty_to_go() {
    let (_dir, safe) = new_safe();
    let folder = safe.create_folder(ROOT, "a").unwrap();
    let id = file(&safe, &folder.id, "x", b"1");
    assert!(matches!(safe.remove(&folder.id), Err(SafeError::NotEmpty)));
    safe.remove(&id).unwrap();
    safe.remove(&folder.id).unwrap();
    assert!(safe.list(ROOT).unwrap().is_empty());
}

#[test]
fn remove_all_takes_the_whole_tree() {
    let (_dir, safe) = new_safe();
    let a = safe.create_folder(ROOT, "a").unwrap();
    let b = safe.create_folder(&a.id, "b").unwrap();
    file(&safe, &a.id, "x", b"1");
    file(&safe, &b.id, "y", b"2");
    safe.remove_all(&a.id).unwrap();
    assert!(safe.list(ROOT).unwrap().is_empty());
    assert!(
        local_blobs(safe.root())
            .unwrap()
            .iter()
            .all(|blob| blob_kind(blob) == Some(BlobKind::Record))
    );
}

#[test]
fn deletions_stay_deleted_after_reopening() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", b"1");
    safe.remove(&id).unwrap();
    let root = safe.root().to_owned();
    drop(safe);
    let safe = Safe::open(&root, &key()).unwrap();
    assert!(safe.list(ROOT).unwrap().is_empty());
    assert!(safe.warnings().unwrap().is_empty());
}

#[test]
fn bad_names_and_duplicates_are_refused() {
    let (_dir, safe) = new_safe();
    for name in ["", ".", "..", "a/b"] {
        assert!(matches!(
            safe.create_file(ROOT, name),
            Err(SafeError::InvalidName)
        ));
    }
    safe.create_file(ROOT, "a").unwrap();
    assert!(matches!(
        safe.create_file(ROOT, "a"),
        Err(SafeError::Exists)
    ));
}

#[test]
fn big_files_read_and_rewrite_in_the_middle() {
    let (_dir, safe) = new_safe();
    let mut body: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
    let id = file(&safe, ROOT, "big", &body);
    assert_eq!(read_whole(&safe, &id), body);
    assert_eq!(*safe.read(&id, 123_456, 70_000).unwrap(), body[123_456..193_456]);

    let patch = vec![0xAB; 100_000];
    safe.write(&id, 300_000, &patch).unwrap();
    body[300_000..400_000].copy_from_slice(&patch);
    // Readable before it's flushed, and after.
    assert_eq!(read_whole(&safe, &id), body);
    safe.flush(&id).unwrap();
    assert_eq!(read_whole(&safe, &id), body);
}

#[test]
fn writing_past_the_end_leaves_zeros() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", b"abc");
    safe.write(&id, 200_000, b"z").unwrap();
    safe.flush(&id).unwrap();
    let body = read_whole(&safe, &id);
    assert_eq!(body.len(), 200_001);
    assert_eq!(&body[..3], b"abc");
    assert!(body[3..200_000].iter().all(|byte| *byte == 0));
    assert_eq!(body[200_000], b'z');
}

#[test]
fn truncating_shrinks_and_grows() {
    let (_dir, safe) = new_safe();
    let body = vec![9u8; 200_000];
    let id = file(&safe, ROOT, "a", &body);
    safe.truncate(&id, 100_001).unwrap();
    assert_eq!(safe.entry(&id).unwrap().size, 100_001);
    safe.flush(&id).unwrap();
    assert_eq!(read_whole(&safe, &id), body[..100_001]);
    safe.truncate(&id, 150_000).unwrap();
    safe.flush(&id).unwrap();
    let grown = read_whole(&safe, &id);
    assert_eq!(grown.len(), 150_000);
    assert_eq!(grown[100_000], 9);
    assert!(grown[100_001..].iter().all(|byte| *byte == 0));
    safe.truncate(&id, 0).unwrap();
    safe.flush(&id).unwrap();
    assert!(read_whole(&safe, &id).is_empty());
}

#[test]
fn growing_after_a_cut_gives_zeros_not_the_old_bytes() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", &vec![0x6a; 200_000]);
    safe.truncate(&id, 1000).unwrap();
    safe.write(&id, 180_000, b"end").unwrap();
    let check = |body: Vec<u8>| {
        assert_eq!(body.len(), 180_003);
        assert!(body[..1000].iter().all(|byte| *byte == 0x6a));
        assert!(body[1000..180_000].iter().all(|byte| *byte == 0));
    };
    check(read_whole(&safe, &id));
    safe.flush(&id).unwrap();
    check(read_whole(&safe, &id));
}

#[test]
fn import_replaces_a_file_as_one_revision() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", b"old contents, longer");
    safe.import(&id, &mut &b"new"[..]).unwrap();
    assert_eq!(read_whole(&safe, &id), b"new");
}

/// Hands out one piece, then locks the Safe as if the vault locked, then hands out the rest.
struct LockingReader<'a> {
    safe: &'a Safe,
    pieces: Vec<Vec<u8>>,
}

impl Read for LockingReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.pieces.is_empty() {
            return Ok(0);
        }
        if self.pieces.len() == 1 {
            self.safe.lock().unwrap();
        }
        let piece = self.pieces.remove(0);
        buffer[..piece.len()].copy_from_slice(&piece);
        Ok(piece.len())
    }
}

#[test]
fn a_lock_during_an_import_leaves_the_old_file_whole() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", b"the original");
    let root = safe.root().to_owned();
    let mut reader = LockingReader {
        safe: &safe,
        pieces: vec![vec![1u8; 1000], vec![2u8; 1000]],
    };
    assert!(matches!(safe.import(&id, &mut reader), Err(SafeError::Locked)));
    let safe = Safe::open(&root, &key()).unwrap();
    assert_eq!(read_whole(&safe, &id), b"the original");
}

#[test]
fn import_reads_inputs_that_come_in_small_pieces() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", b"");
    let body: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    // A reader that never gives more than 1000 bytes at a time.
    struct Trickle<'a>(&'a [u8]);
    impl Read for Trickle<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let take = self.0.len().min(1000).min(buffer.len());
            buffer[..take].copy_from_slice(&self.0[..take]);
            self.0 = &self.0[take..];
            Ok(take)
        }
    }
    assert_eq!(safe.import(&id, &mut Trickle(&body)).unwrap(), 200_000);
    assert_eq!(read_whole(&safe, &id), body);
    assert_eq!(safe.import(&id, &mut Trickle(&[])).unwrap(), 0);
    assert!(read_whole(&safe, &id).is_empty());
}

#[test]
fn locking_flushes_open_writes() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", b"one");
    safe.write(&id, 0, b"two").unwrap();
    let root = safe.root().to_owned();
    safe.lock().unwrap();
    let safe = Safe::open(&root, &key()).unwrap();
    assert_eq!(read_whole(&safe, &id), b"two");
}

#[test]
fn a_crash_between_writes_leaves_a_working_safe() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", b"one");
    let root = safe.root().to_owned();
    // A newer record's content left behind, and an old record that wasn't removed yet.
    let stale = local_blobs(&root)
        .unwrap()
        .into_iter()
        .find(|blob| blob_kind(blob) == Some(BlobKind::Record))
        .unwrap();
    let stale_bytes = fs::read(blob_path(&root, &stale)).unwrap();
    safe.write(&id, 0, b"two").unwrap();
    safe.flush(&id).unwrap();
    install_blob(&root, &stale, &stale_bytes).unwrap();
    let orphan = new_blob_id(BlobKind::Content, &mut OsRng);
    install_blob(&root, &orphan, b"leftover").unwrap();
    fs::write(root.join(TEMPORARY).join("partial"), b"x").unwrap();
    drop(safe);

    let safe = Safe::open(&root, &key()).unwrap();
    assert_eq!(read_whole(&safe, &id), b"two");
    assert_eq!(local_blobs(&root).unwrap().len(), 2);
    assert!(fs::read_dir(root.join(TEMPORARY)).unwrap().next().is_none());
}

#[test]
fn a_changed_blob_is_reported_not_trusted() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", &[1u8; 100]);
    let root = safe.root().to_owned();
    let content = local_blobs(&root)
        .unwrap()
        .into_iter()
        .find(|blob| blob_kind(blob) == Some(BlobKind::Content))
        .unwrap();
    let mut bytes = fs::read(blob_path(&root, &content)).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(blob_path(&root, &content), bytes).unwrap();
    assert!(matches!(safe.read(&id, 0, 10), Err(SafeError::Damaged(_))));
}

#[test]
fn an_older_copy_of_a_file_is_noticed() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", b"one");
    let root = safe.root().to_owned();
    let saved: Vec<(String, Vec<u8>)> = local_blobs(&root)
        .unwrap()
        .into_iter()
        .map(|blob| {
            let bytes = fs::read(blob_path(&root, &blob)).unwrap();
            (blob, bytes)
        })
        .collect();
    safe.write(&id, 0, b"two").unwrap();
    safe.flush(&id).unwrap();
    drop(safe);

    // Someone with the disk puts the old blobs back and removes the new ones.
    for blob in local_blobs(&root).unwrap() {
        remove_blob(&root, &blob).unwrap();
    }
    for (blob, bytes) in &saved {
        install_blob(&root, blob, bytes).unwrap();
    }
    let safe = Safe::open(&root, &key()).unwrap();
    assert_eq!(
        safe.warnings().unwrap(),
        vec![Warning::RolledBack { object: id }]
    );
}

#[test]
fn a_removed_record_is_noticed() {
    let (_dir, safe) = new_safe();
    let id = file(&safe, ROOT, "a", b"one");
    let root = safe.root().to_owned();
    drop(safe);
    for blob in local_blobs(&root).unwrap() {
        remove_blob(&root, &blob).unwrap();
    }
    let safe = Safe::open(&root, &key()).unwrap();
    assert_eq!(
        safe.warnings().unwrap(),
        vec![Warning::Missing { object: id }]
    );
}

#[test]
fn numbers_names() {
    assert_eq!(numbered_name("report.pdf", 2), "report (2).pdf");
    assert_eq!(numbered_name("report", 3), "report (3)");
    assert_eq!(numbered_name(".hidden", 2), ".hidden (2)");
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, max_shrink_iters: 200, ..ProptestConfig::default() })]

    /// A Safe file behaves like a byte vector, whatever is written where.
    #[test]
    fn behaves_like_a_vector(
        writes in prop::collection::vec(
            (0usize..300_000, 0usize..100_000, any::<u8>(), any::<bool>(), 0usize..300_000),
            1..12,
        )
    ) {
        let (_dir, safe) = new_safe();
        let id = safe.create_file(ROOT, "a").unwrap().id;
        let mut model: Vec<u8> = Vec::new();
        for (offset, len, byte, flush, cut) in writes {
            if byte % 5 == 0 {
                safe.truncate(&id, cut as u64).unwrap();
                model.resize(cut, 0);
            } else {
                let data = vec![byte; len];
                safe.write(&id, offset as u64, &data).unwrap();
                if !data.is_empty() {
                    if model.len() < offset + len {
                        model.resize(offset + len, 0);
                    }
                    model[offset..offset + len].copy_from_slice(&data);
                }
            }
            if flush {
                safe.flush(&id).unwrap();
            }
            prop_assert_eq!(safe.entry(&id).unwrap().size, model.len() as u64);
        }
        prop_assert!(read_whole(&safe, &id) == model);
        safe.flush(&id).unwrap();
        prop_assert!(read_whole(&safe, &id) == model);
    }
}
