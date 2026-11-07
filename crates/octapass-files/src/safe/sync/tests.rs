use std::collections::BTreeMap;
use std::sync::Mutex;

use octapass_core::keys::SymmetricKey;
use tempfile::TempDir;

use super::*;
use crate::safe::ROOT_ID;

const SAFE_ID: &str = "11111111-1111-4111-8111-111111111111";

/// The server: a plain map of blobs, which tests can tamper with.
#[derive(Default)]
struct Memory {
    blobs: Mutex<BTreeMap<String, Vec<u8>>>,
    max: Option<u64>,
}

impl Remote for Memory {
    async fn list(&self) -> Result<Vec<RemoteBlob>> {
        Ok(self
            .blobs
            .lock()
            .unwrap()
            .iter()
            .map(|(id, bytes)| RemoteBlob {
                id: id.clone(),
                size: bytes.len() as u64,
            })
            .collect())
    }

    async fn get(&self, id: &str) -> Result<Vec<u8>> {
        self.blobs
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| SafeError::Remote("missing".into()))
    }

    async fn put(&self, id: &str, bytes: Vec<u8>) -> Result<()> {
        self.blobs.lock().unwrap().insert(id.to_owned(), bytes);
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.blobs.lock().unwrap().remove(id);
        Ok(())
    }

    fn max_blob(&self) -> u64 {
        self.max.unwrap_or(u64::MAX)
    }
}

fn device(dir: &TempDir, name: &str) -> Safe {
    let key = SymmetricKey::from_bytes([7; 32]);
    Safe::create(&dir.path().join(name), SAFE_ID, &key).unwrap()
}

fn file(safe: &Safe, folder: &str, name: &str, bytes: &[u8]) -> String {
    let entry = safe.create_file(folder, name).unwrap();
    safe.write(&entry.id, 0, bytes).unwrap();
    safe.flush(&entry.id).unwrap();
    entry.id
}

fn edit(safe: &Safe, id: &str, bytes: &[u8]) {
    safe.import(id, &mut &bytes[..]).unwrap();
}

fn body(safe: &Safe, path: &str) -> Vec<u8> {
    let entry = safe.resolve(path).unwrap();
    let mut out = Vec::new();
    safe.export(&entry.id, &mut out).unwrap();
    out
}

fn names(safe: &Safe, folder: &str) -> Vec<String> {
    safe.list(folder)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

#[tokio::test]
async fn files_folders_and_changes_reach_the_other_device() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (device(&dir, "a"), device(&dir, "b"));
    let server = Memory::default();

    let folder = a.create_folder(ROOT_ID, "Docs").unwrap();
    let id = file(&a, &folder.id, "note.txt", b"one");
    let empty = file(&a, ROOT_ID, "empty", b"");
    a.sync(&server).await.unwrap();
    b.sync(&server).await.unwrap();
    assert_eq!(body(&b, "Docs/note.txt"), b"one");
    assert_eq!(b.resolve("empty").unwrap().id, empty);

    edit(&b, &id, b"two");
    b.sync(&server).await.unwrap();
    a.sync(&server).await.unwrap();
    assert_eq!(body(&a, "Docs/note.txt"), b"two");

    a.rename(&id, ROOT_ID, "moved.txt").unwrap();
    a.sync(&server).await.unwrap();
    b.sync(&server).await.unwrap();
    assert_eq!(body(&b, "moved.txt"), b"two");
    assert!(names(&b, &folder.id).is_empty());

    b.remove(&id).unwrap();
    b.sync(&server).await.unwrap();
    a.sync(&server).await.unwrap();
    assert!(matches!(a.resolve("moved.txt"), Err(SafeError::NotFound)));
}

#[tokio::test]
async fn the_server_holds_only_what_is_current() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (device(&dir, "a"), device(&dir, "b"));
    let server = Memory::default();
    let id = file(&a, ROOT_ID, "x", b"one");
    a.sync(&server).await.unwrap();
    assert_eq!(server.blobs.lock().unwrap().len(), 2);
    for round in 0..3u8 {
        edit(&a, &id, &[round; 10]);
        a.sync(&server).await.unwrap();
        assert_eq!(server.blobs.lock().unwrap().len(), 2);
    }
    // A sync that changes nothing sends nothing.
    let quiet = a.sync(&server).await.unwrap();
    assert_eq!(quiet, SyncReport::default());
    b.sync(&server).await.unwrap();
    let quiet = b.sync(&server).await.unwrap();
    assert_eq!(quiet, SyncReport::default());
}

#[tokio::test]
async fn the_server_learns_no_names_or_contents() {
    let dir = tempfile::tempdir().unwrap();
    let a = device(&dir, "a");
    let server = Memory::default();
    file(&a, ROOT_ID, "SECRETNAME.txt", b"SECRETBODY");
    a.sync(&server).await.unwrap();
    for (id, bytes) in server.blobs.lock().unwrap().iter() {
        assert!(!id.contains("SECRET"));
        assert!(!bytes.windows(6).any(|window| window == b"SECRET"));
    }
}

#[tokio::test]
async fn both_devices_editing_keeps_both_versions() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (device(&dir, "a"), device(&dir, "b"));
    let server = Memory::default();
    let id = file(&a, ROOT_ID, "doc.txt", b"base");
    a.sync(&server).await.unwrap();
    b.sync(&server).await.unwrap();

    edit(&a, &id, b"from a");
    edit(&b, &id, b"from b");
    a.sync(&server).await.unwrap();
    let report = b.sync(&server).await.unwrap();
    assert_eq!(report.conflicts.len(), 1);
    a.sync(&server).await.unwrap();
    b.sync(&server).await.unwrap();

    for device in [&a, &b] {
        assert_eq!(body(device, "doc.txt"), b"from a");
        let names = names(device, ROOT_ID);
        assert_eq!(names.len(), 2, "{names:?}");
        let copy = names.iter().find(|name| name.contains("conflict")).unwrap();
        assert_eq!(body(device, copy), b"from b");
    }
}

#[tokio::test]
async fn an_edit_beats_a_deletion() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (device(&dir, "a"), device(&dir, "b"));
    let server = Memory::default();
    let id = file(&a, ROOT_ID, "doc.txt", b"base");
    a.sync(&server).await.unwrap();
    b.sync(&server).await.unwrap();

    a.remove(&id).unwrap();
    edit(&b, &id, b"kept");
    a.sync(&server).await.unwrap();
    b.sync(&server).await.unwrap();
    a.sync(&server).await.unwrap();
    assert_eq!(body(&a, "doc.txt"), b"kept");
    assert_eq!(body(&b, "doc.txt"), b"kept");
}

#[tokio::test]
async fn renaming_on_both_keeps_one_name_and_one_file() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (device(&dir, "a"), device(&dir, "b"));
    let server = Memory::default();
    let id = file(&a, ROOT_ID, "doc.txt", b"base");
    a.sync(&server).await.unwrap();
    b.sync(&server).await.unwrap();
    a.rename(&id, ROOT_ID, "from-a.txt").unwrap();
    b.rename(&id, ROOT_ID, "from-b.txt").unwrap();
    a.sync(&server).await.unwrap();
    let report = b.sync(&server).await.unwrap();
    assert!(report.conflicts.is_empty());
    a.sync(&server).await.unwrap();
    assert_eq!(names(&a, ROOT_ID), names(&b, ROOT_ID));
    assert_eq!(names(&a, ROOT_ID).len(), 1);
}

#[tokio::test]
async fn two_files_of_one_name_both_show() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (device(&dir, "a"), device(&dir, "b"));
    let server = Memory::default();
    file(&a, ROOT_ID, "doc.txt", b"from a");
    file(&b, ROOT_ID, "doc.txt", b"from b");
    a.sync(&server).await.unwrap();
    b.sync(&server).await.unwrap();
    a.sync(&server).await.unwrap();
    assert_eq!(names(&a, ROOT_ID), vec!["doc (2).txt", "doc.txt"]);
    assert_eq!(names(&a, ROOT_ID), names(&b, ROOT_ID));
}

#[tokio::test]
async fn a_folder_deleted_elsewhere_does_not_take_its_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (device(&dir, "a"), device(&dir, "b"));
    let server = Memory::default();
    let folder = a.create_folder(ROOT_ID, "Old").unwrap();
    a.sync(&server).await.unwrap();
    b.sync(&server).await.unwrap();
    a.remove(&folder.id).unwrap();
    file(&b, &folder.id, "new.txt", b"new");
    a.sync(&server).await.unwrap();
    b.sync(&server).await.unwrap();
    assert_eq!(body(&b, "new.txt"), b"new");
    assert!(b.warnings().unwrap().iter().any(|warning| matches!(warning, Warning::Orphaned { .. })));
}

#[tokio::test]
async fn a_second_device_starts_from_nothing_with_a_big_tree() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (device(&dir, "a"), device(&dir, "b"));
    let server = Memory::default();
    for index in 0..40 {
        file(&a, ROOT_ID, &format!("f{index:02}"), &[index; 70_000]);
    }
    a.sync(&server).await.unwrap();
    let report = b.sync(&server).await.unwrap();
    assert_eq!(report.downloaded, 80);
    assert_eq!(names(&b, ROOT_ID).len(), 40);
    assert_eq!(body(&b, "f07"), vec![7; 70_000]);
}

#[tokio::test]
async fn files_too_big_for_the_server_stay_here_and_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (device(&dir, "a"), device(&dir, "b"));
    let server = Memory {
        max: Some(100_000),
        ..Memory::default()
    };
    file(&a, ROOT_ID, "big.bin", &vec![1u8; 200_000]);
    file(&a, ROOT_ID, "small.bin", b"s");
    let report = a.sync(&server).await.unwrap();
    assert_eq!(report.too_big, vec!["big.bin"]);
    b.sync(&server).await.unwrap();
    assert_eq!(names(&b, ROOT_ID), vec!["small.bin"]);
    // It's still fine here, and a later sync says so again.
    assert_eq!(body(&a, "big.bin"), vec![1u8; 200_000]);
    assert_eq!(a.sync(&server).await.unwrap().too_big, vec!["big.bin"]);
}

#[tokio::test]
async fn a_changed_record_from_the_server_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (device(&dir, "a"), device(&dir, "b"));
    let server = Memory::default();
    file(&a, ROOT_ID, "doc", b"x");
    a.sync(&server).await.unwrap();
    for (id, bytes) in server.blobs.lock().unwrap().iter_mut() {
        if blob_kind(id) == Some(BlobKind::Record) {
            *bytes.last_mut().unwrap() ^= 1;
        }
    }
    b.sync(&server).await.unwrap();
    assert!(names(&b, ROOT_ID).is_empty());
    assert!(matches!(
        b.warnings().unwrap().as_slice(),
        [Warning::DamagedBlob { .. }]
    ));
}

#[tokio::test]
async fn a_server_replaying_an_old_record_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (device(&dir, "a"), device(&dir, "b"));
    let server = Memory::default();
    let id = file(&a, ROOT_ID, "doc", b"one");
    a.sync(&server).await.unwrap();
    b.sync(&server).await.unwrap();
    let old = server.blobs.lock().unwrap().clone();

    edit(&a, &id, b"two");
    a.sync(&server).await.unwrap();
    b.sync(&server).await.unwrap();

    // The server puts the old revision back, beside the new one, and then in its place.
    server.blobs.lock().unwrap().extend(old.clone());
    b.sync(&server).await.unwrap();
    assert_eq!(body(&b, "doc"), b"two");
    *server.blobs.lock().unwrap() = old;
    b.sync(&server).await.unwrap();
    assert_eq!(body(&b, "doc"), b"two");
}

#[test]
fn dates_and_names() {
    assert_eq!(day_of(0), "1970-01-01");
    assert_eq!(day_of(1_793_577_600_000), "2026-11-02");
    assert_eq!(day_of(951_782_400_000), "2000-02-29");
    assert_eq!(conflict_name("a.pdf", "2026-11-02"), "a (conflict 2026-11-02).pdf");
    assert_eq!(conflict_name("a", "2026-11-02"), "a (conflict 2026-11-02)");
}
