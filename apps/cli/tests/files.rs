//! `octapass encrypt`, `decrypt`, `shred`, `file-key` and `safe`, against a real server.

use crate::common;

use std::fs;
use std::path::Path;

use common::*;

async fn setup() -> (Server, OtherDevice, Cli) {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    (server, other, cli)
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Every name and byte in a folder, however deep.
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

#[tokio::test(flavor = "multi_thread")]
async fn encrypt_for_yourself_and_back() {
    let (_server, _other, cli) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("plan.txt");
    fs::write(&source, b"launch on tuesday").unwrap();

    cli.run(&["encrypt", path(&source)]).await.ok();
    let sealed = dir.path().join("plan.txt.age");
    let bytes = fs::read(&sealed).unwrap();
    assert!(bytes.starts_with(b"age-encryption.org/v1\n"));
    assert!(!contains(&bytes, "tuesday"));
    assert_eq!(fs::read(&source).unwrap(), b"launch on tuesday");

    // Never over an existing file, unless asked.
    let again = cli.run(&["encrypt", path(&source)]).await;
    assert_eq!(again.code, 2);
    cli.run(&["encrypt", "--force", path(&source)]).await.ok();

    fs::remove_file(&source).unwrap();
    cli.run(&["decrypt", path(&sealed)]).await.ok();
    assert_eq!(fs::read(&source).unwrap(), b"launch on tuesday");
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypting_for_yourself_needs_no_unlock_once_the_key_is_known() {
    let (_server, _other, cli) = setup().await;
    let recipient = cli.run(&["file-key", "--json"]).await.ok().json();
    assert!(recipient["recipient"].as_str().unwrap().starts_with("age1"));
    cli.run(&["lock"]).await.ok();

    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("a");
    fs::write(&source, b"x").unwrap();
    // No password available in this run: it would fail if it tried to unlock.
    cli.run(&["encrypt", "--self", path(&source)]).await.ok();

    // Decrypting does need the keys.
    let locked = cli.run(&["decrypt", path(&dir.path().join("a.age")), "-o", path(&dir.path().join("b"))]).await;
    assert_eq!(locked.code, 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_folder_goes_in_one_file_and_comes_back() {
    let (_server, _other, cli) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("photos");
    fs::create_dir_all(folder.join("2026")).unwrap();
    fs::write(folder.join("2026/a.jpg"), b"aaa").unwrap();
    cli.run(&["encrypt", path(&folder)]).await.ok();
    fs::remove_dir_all(&folder).unwrap();
    let sealed = dir.path().join("photos.tar.age");
    assert!(sealed.is_file());
    cli.run(&["decrypt", path(&sealed)]).await.ok();
    assert_eq!(fs::read(folder.join("2026/a.jpg")).unwrap(), b"aaa");
}

#[tokio::test(flavor = "multi_thread")]
async fn another_octa_pass_user_can_open_what_was_sent() {
    let (server, _other, cli) = setup().await;
    let friend = OtherDevice::sign_up_as(&server, "grace@example.com").await;
    let friend_cli = Cli::new(&server);
    friend_cli
        .login_as("grace@example.com", &friend.secret_key)
        .await
        .ok();

    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("for-grace.txt");
    fs::write(&source, b"hello grace").unwrap();
    let sent = cli
        .run(&["encrypt", "--to", "grace@example.com", path(&source)])
        .await
        .ok();
    // The key came from the server, so the sender hears that.
    assert!(sent.stderr.contains("hasn't been compared"));

    let sealed = dir.path().join("for-grace.txt.age");
    fs::remove_file(&source).unwrap();
    // Only grace was named, so the sender can't open it.
    let refused = cli.run(&["decrypt", path(&sealed)]).await;
    assert_eq!(refused.code, 5);
    assert!(!source.exists());
    friend_cli.run(&["decrypt", path(&sealed)]).await.ok();
    assert_eq!(fs::read(&source).unwrap(), b"hello grace");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_public_key_and_an_exported_file_key_work_with_no_account() {
    let (_server, _other, cli) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("identity.txt");
    cli.run_password(&["file-key", "--export", "-o", path(&key_file)])
        .await
        .ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&key_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let text = fs::read_to_string(&key_file).unwrap();
    assert!(text.contains("AGE-SECRET-KEY-1"));
    let recipient = text
        .lines()
        .find_map(|line| line.strip_prefix("# public key: "))
        .unwrap();

    let source = dir.path().join("a");
    fs::write(&source, b"portable").unwrap();
    let sealed = dir.path().join("a.age");
    cli.run(&["encrypt", "--to", recipient, path(&source)])
        .await
        .ok();

    // A device with no account at all.
    let stranger = Cli::new_signed_out();
    let back = dir.path().join("back");
    stranger
        .run(&[
            "decrypt",
            "-i",
            path(&key_file),
            "-o",
            path(&back),
            path(&sealed),
        ])
        .await
        .ok();
    assert_eq!(fs::read(&back).unwrap(), b"portable");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_passphrase_file_needs_only_the_passphrase() {
    let stranger = Cli::new_signed_out();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("a");
    fs::write(&source, b"pp").unwrap();
    stranger
        .run_stdin(&["--password-stdin", "encrypt", "--passphrase", path(&source)], "open sesame\n")
        .await
        .ok();
    let sealed = dir.path().join("a.age");
    let wrong = stranger
        .run_stdin(&["--password-stdin", "decrypt", "-o", path(&dir.path().join("w")), path(&sealed)], "nope\n")
        .await;
    assert_eq!(wrong.code, 5);
    assert!(!dir.path().join("w").exists());
    stranger
        .run_stdin(&["--password-stdin", "decrypt", "-o", path(&dir.path().join("r")), path(&sealed)], "open sesame\n")
        .await
        .ok();
    assert_eq!(fs::read(dir.path().join("r")).unwrap(), b"pp");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_recipient_stops_before_anything_is_written() {
    let stranger = Cli::new_signed_out();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("a");
    fs::write(&source, b"pp").unwrap();
    let bad = stranger
        .run(&["encrypt", "--to", "age1notakey", path(&source)])
        .await;
    assert_eq!(bad.code, 2);
    assert!(!dir.path().join("a.age").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn shred_asks_and_tells_the_truth() {
    let stranger = Cli::new_signed_out();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("a");
    fs::write(&source, b"gone").unwrap();
    // No terminal and no --yes: nothing happens.
    let refused = stranger.run(&["shred", path(&source)]).await;
    assert_eq!(refused.code, 2);
    assert!(source.exists());

    let done = stranger
        .run(&["--json", "shred", "--yes", path(&source)])
        .await
        .ok()
        .json();
    assert!(!source.exists());
    let report = &done[0];
    assert_eq!(report["bytes"], 4);
    #[cfg(target_os = "macos")]
    {
        assert_eq!(report["storage"], "copyOnWrite");
        assert_eq!(report["guarantee"], "bestEffort");
    }
    assert!(report["note"].as_str().is_some_and(|note| !note.is_empty()));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypting_with_shred_removes_the_original_only_after_success() {
    let (_server, _other, cli) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("a");
    fs::write(&source, b"x").unwrap();
    cli.run(&["encrypt", "--shred", path(&source)]).await.ok();
    assert!(!source.exists());
    assert!(dir.path().join("a.age").exists());

    let kept = dir.path().join("b");
    fs::write(&kept, b"x").unwrap();
    fs::write(dir.path().join("b.age"), b"already here").unwrap();
    let failed = cli.run(&["encrypt", "--shred", path(&kept)]).await;
    assert_eq!(failed.code, 2);
    assert!(kept.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_safe_keeps_files_and_hides_from_lists() {
    let (_server, _other, cli) = setup().await;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("return.pdf");
    fs::write(&source, b"numbers").unwrap();
    cli.run(&["safe", "create", "Taxes"]).await.ok();
    cli.run(&["safe", "add", "Taxes", path(&source), "--to", "2026/q1"])
        .await
        .ok();
    let listed = cli
        .run(&["--json", "safe", "ls", "Taxes", "2026/q1"])
        .await
        .ok()
        .json();
    assert_eq!(listed[0]["name"], "return.pdf");
    assert_eq!(listed[0]["size"], 7);

    let out = dir.path().join("copy.pdf");
    cli.run(&["safe", "get", "Taxes", "2026/q1/return.pdf", "-o", path(&out)])
        .await
        .ok();
    assert_eq!(fs::read(&out).unwrap(), b"numbers");

    cli.run(&["safe", "mv", "Taxes", "2026/q1/return.pdf", "2026/final.pdf"])
        .await
        .ok();
    cli.run(&["safe", "rm", "Taxes", "2026/q1"]).await.ok();
    let top = cli.run(&["--json", "safe", "ls", "Taxes", "2026"]).await.ok().json();
    assert_eq!(top.as_array().unwrap().len(), 1);

    // The Safe's key item doesn't clutter the item list, and nothing readable sits on disk.
    let items = cli.run(&["--json", "list"]).await.ok().json();
    assert!(items.as_array().unwrap().is_empty());
    let disk = everything_under(cli.data_dir());
    assert!(!contains(&disk, "numbers"));
    assert!(!contains(&disk, "return.pdf"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_safe_syncs_between_devices_through_the_server() {
    let (server, other, cli) = setup().await;
    let second = Cli::new(&server);
    second.login(&other.secret_key).await.ok();

    cli.run(&["safe", "create", "Shared", "--sync"]).await.ok();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("note.txt");
    fs::write(&source, b"from one").unwrap();
    cli.run(&["safe", "add", "Shared", path(&source)]).await.ok();

    let out = dir.path().join("got.txt");
    second
        .run(&["safe", "get", "Shared", "note.txt", "-o", path(&out)])
        .await
        .ok();
    assert_eq!(fs::read(&out).unwrap(), b"from one");

    fs::write(&source, b"from two").unwrap();
    second.run(&["safe", "add", "Shared", path(&source)]).await.ok();
    cli.run(&["safe", "get", "Shared", "note.txt", "-o", path(&out), "--force"])
        .await
        .ok();
    assert_eq!(fs::read(&out).unwrap(), b"from two");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_safe_stays_here_unless_sync_is_on() {
    let (server, other, cli) = setup().await;
    cli.run(&["safe", "create", "Local"]).await.ok();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("note.txt");
    fs::write(&source, b"here").unwrap();
    cli.run(&["safe", "add", "Local", path(&source)]).await.ok();
    let refused = cli.run(&["safe", "sync", "Local"]).await;
    assert_eq!(refused.code, 2);

    let second = Cli::new(&server);
    second.login(&other.secret_key).await.ok();
    let listed = second
        .run(&["--json", "safe", "ls", "Local"])
        .await
        .ok()
        .json();
    assert!(listed.as_array().unwrap().is_empty());

    cli.run(&["safe", "set-sync", "Local", "on"]).await.ok();
    let listed = second
        .run(&["--json", "safe", "ls", "Local"])
        .await
        .ok()
        .json();
    assert_eq!(listed.as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_safe_is_gone_here_and_elsewhere() {
    let (server, other, cli) = setup().await;
    cli.run(&["safe", "create", "Old", "--sync"]).await.ok();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("a.txt");
    fs::write(&source, b"x").unwrap();
    cli.run(&["safe", "add", "Old", path(&source)]).await.ok();

    // Not without saying so.
    assert_eq!(cli.run(&["safe", "delete", "Old"]).await.code, 2);
    cli.run(&["safe", "delete", "Old", "--yes"]).await.ok();
    let listed = cli.run(&["--json", "safe", "list"]).await.ok().json();
    assert!(listed.as_array().unwrap().is_empty());
    assert!(!cli.data_dir().join("safes").read_dir().unwrap().any(|_| true));

    let second = Cli::new(&server);
    second.login(&other.secret_key).await.ok();
    let listed = second.run(&["--json", "safe", "list"]).await.ok().json();
    assert!(listed.as_array().unwrap().is_empty());
}
