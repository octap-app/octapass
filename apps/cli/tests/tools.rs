//! The developer toolkit commands. What the tools compute is tested in the core; this checks what
//! the CLI adds: stdin and files, JSON, exit codes, the vault, and where private keys may go.

use crate::common;

use common::*;
use serde_json::Value;

async fn setup() -> (Server, OtherDevice, Cli) {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    (server, other, cli)
}

/// A CLI that isn't signed in: most tools need no account.
async fn offline() -> (Server, Cli) {
    let server = server().await;
    let cli = Cli::new(&server);
    (server, cli)
}

fn stdin(text: &str) -> Run {
    Run {
        stdin: text.to_owned(),
        ..Run::default()
    }
}

fn terminal() -> Run {
    Run {
        stdout_is_terminal: true,
        ..Run::default()
    }
}

fn path_of(dir: &tempfile::TempDir, name: &str) -> String {
    dir.path().join(name).display().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn encodings_and_hashes_read_stdin_and_need_no_account() {
    let (_server, cli) = offline().await;
    let out = cli
        .run_with(&["encode", "base64"], stdin("hello"))
        .await
        .ok();
    assert_eq!(out.stdout.trim(), "aGVsbG8=");
    let out = cli
        .run_with(&["decode", "base64"], stdin("aGVsbG8=\n"))
        .await
        .ok();
    assert_eq!(out.stdout.trim(), "hello");
    let out = cli.run(&["detect", "SGVsbG8sIHdvcmxkIQ=="]).await.ok();
    assert!(out.stdout.starts_with("base64"), "{}", out.stdout);

    let out = cli.run_with(&["hash"], stdin("abc")).await.ok();
    assert!(
        out.stdout
            .starts_with("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    let out = cli
        .run(&["hash", "--text", "abc", "--algo", "md5"])
        .await
        .ok();
    assert!(out.stdout.starts_with("900150983cd24fb0d6963f7d28e17f72"));
    assert!(out.stderr.contains("old checksums only"), "{}", out.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn hash_files_and_checksums() {
    let (_server, cli) = offline().await;
    let dir = tempfile::tempdir().unwrap();
    let file = path_of(&dir, "a.txt");
    std::fs::write(&file, "abc").unwrap();
    let out = cli.run(&["hash", &file, "--json"]).await.ok().json();
    let hex = out[0]["hashes"][0]["hex"].as_str().unwrap().to_owned();
    let line = format!("{hex}  a.txt");
    let ok = cli.run(&["hash", &file, "--check", &line]).await.ok();
    assert!(ok.stdout.contains("OK (sha256)"), "{}", ok.stdout);
    let wrong = cli.run(&["hash", "--text", "abd", "--check", &hex]).await;
    assert_eq!(wrong.code, 1);
    assert!(wrong.stdout.contains("MISMATCH"));
}

#[tokio::test(flavor = "multi_thread")]
async fn random_values() {
    let (_server, cli) = offline().await;
    let out = cli.run(&["random", "bytes", "16"]).await.ok();
    assert_eq!(out.stdout.trim().len(), 32);
    let out = cli
        .run(&["random", "uuid", "--version", "7", "--count", "2"])
        .await
        .ok();
    assert_eq!(out.stdout.lines().count(), 2);
    let out = cli.run(&["random", "ulid", "--json"]).await.ok().json();
    assert_eq!(out["values"][0].as_str().unwrap().len(), 26);
    let out = cli
        .run(&["random", "token", "--prefix", "sk_live_"])
        .await
        .ok();
    assert!(out.stdout.starts_with("sk_live_"));
    let weak = cli
        .run(&["random", "token", "--shape", "hex", "--length", "4"])
        .await
        .ok();
    assert!(
        weak.stderr.contains("bits of randomness"),
        "{}",
        weak.stderr
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn private_keys_never_land_on_a_terminal() {
    let (_server, cli) = offline().await;
    for args in [
        vec!["key", "generate"],
        vec!["key", "age"],
        vec!["cert", "self-signed", "a.test"],
        vec!["cert", "ca-create"],
        vec!["cert", "csr", "a.test"],
        vec!["jwt", "keygen", "--alg", "ES256"],
    ] {
        let out = cli.run_with(&args, terminal()).await;
        assert_eq!(out.code, 2, "{args:?}: {out:#?}");
        assert!(
            out.stderr.contains("aren't printed in the terminal"),
            "{args:?}"
        );
        assert!(!out.stdout.contains("PRIVATE KEY"), "{args:?}");
    }
    // Piped, it's the caller's to handle.
    let piped = cli.run(&["key", "generate"]).await.ok();
    assert!(piped.stdout.contains("BEGIN PRIVATE KEY"));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn key_files_are_private_and_never_replaced_unasked() {
    use std::os::unix::fs::PermissionsExt;
    let (_server, cli) = offline().await;
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = (path_of(&dir, "cert.pem"), path_of(&dir, "key.pem"));
    let args = [
        "cert",
        "self-signed",
        "app.test",
        "--out",
        &cert,
        "--out-key",
        &key,
    ];
    let out = cli.run_with(&args, terminal()).await.ok();
    assert!(!out.stdout.contains("PRIVATE KEY"));
    let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert!(
        std::fs::read_to_string(&cert)
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    let again = cli.run_with(&args, terminal()).await;
    assert_eq!(again.code, 2);
    assert!(again.stderr.contains("already exists"));

    let read = cli
        .run(&["cert", "read", &cert, "--host", "app.test", "--json"])
        .await
        .ok()
        .json();
    assert_eq!(read["certificates"][0]["commonName"], "app.test");
    let piped = cli
        .run_with(
            &["cert", "read", "--host", "other.test"],
            stdin(&std::fs::read_to_string(&cert).unwrap()),
        )
        .await
        .ok();
    assert!(
        piped.stdout.contains("doesn't cover this host name"),
        "{}",
        piped.stdout
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn key_conversion_with_files() {
    let (_server, cli) = offline().await;
    let dir = tempfile::tempdir().unwrap();
    let key = path_of(&dir, "key.pem");
    let args = ["key", "generate", "--type", "ed25519", "--out-key", &key];
    let public = cli.run_with(&args, terminal()).await.ok().stdout;
    assert!(public.contains("BEGIN PUBLIC KEY"));
    let jwk = cli.run(&["key", "convert", &key, "--to", "jwk"]).await.ok();
    assert!(jwk.stdout.contains("\"d\""));
    // A private result needs a file on a terminal; a public one doesn't.
    let out = cli
        .run_with(&["key", "convert", &key, "--to", "jwk"], terminal())
        .await;
    assert_eq!(out.code, 2);
    let out = cli
        .run_with(
            &["key", "convert", &key, "--to", "openssh-public"],
            terminal(),
        )
        .await
        .ok();
    assert!(out.stdout.starts_with("ssh-ed25519 "));
    let inspected = cli
        .run(&["key", "inspect", &key, "--json"])
        .await
        .ok()
        .json();
    assert_eq!(inspected["isPrivate"], true);
    assert!(
        inspected["fingerprints"]["sshSha256"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn jwt_round_trip_and_exit_codes() {
    let (_server, cli) = offline().await;
    let dir = tempfile::tempdir().unwrap();
    let key = path_of(&dir, "key.pem");
    let public = path_of(&dir, "public.pem");
    let args = [
        "jwt",
        "keygen",
        "--alg",
        "ES256",
        "--out-key",
        &key,
        "--json",
    ];
    let made = cli.run(&args).await.ok().json();
    assert!(
        made.get("privateKey").is_none(),
        "--out-key keeps it out of the JSON"
    );
    std::fs::write(&public, made["publicKey"].as_str().unwrap()).unwrap();

    let token = cli
        .run(&[
            "jwt",
            "sign",
            "{\"sub\":\"ada\"}",
            "--alg",
            "ES256",
            "--key",
            &key,
            "--iat",
            "--expires-in",
            "720",
        ])
        .await
        .ok()
        .stdout;
    let token = token.trim();
    let decoded = cli.run(&["jwt", "decode", token]).await.ok();
    assert!(
        decoded.stdout.contains("Expires in 12 minutes"),
        "{}",
        decoded.stdout
    );
    assert!(decoded.stderr.contains("jwt verify"));

    let verified = cli
        .run(&["jwt", "verify", token, "--key", &public])
        .await
        .ok();
    assert!(verified.stdout.contains("Valid."));
    cli.advance(721);
    let expired = cli.run(&["jwt", "verify", token, "--key", &public]).await;
    assert_eq!(expired.code, 1);
    assert!(expired.stdout.contains("expired"));

    let none = cli.run(&["jwt", "verify", token]).await;
    assert_eq!(none.code, 2, "a token can't be verified with nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn password_hashes_over_stdin() {
    let (_server, cli) = offline().await;
    let made = cli
        .run_with(
            &["pwhash", "hash", "--scheme", "bcrypt", "--cost", "10"],
            stdin("hunter2\n"),
        )
        .await
        .ok()
        .stdout;
    let hash = made.trim();
    assert!(hash.starts_with("$2b$10$"));
    cli.run_with(&["pwhash", "verify", hash], stdin("hunter2\n"))
        .await
        .ok();
    let wrong = cli
        .run_with(&["pwhash", "verify", hash], stdin("nope\n"))
        .await;
    assert_eq!(wrong.code, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn trust_shows_its_plan_and_asks_first() {
    let (_server, cli) = offline().await;
    let dir = tempfile::tempdir().unwrap();
    let ca = path_of(&dir, "ca.pem");
    let key = path_of(&dir, "ca.key");
    cli.run(&["cert", "ca-create", "--out", &ca, "--out-key", &key])
        .await
        .ok();
    let plan = cli
        .run(&["cert", "trust", &ca, "--dry-run", "--json"])
        .await
        .ok()
        .json();
    assert!(!plan["steps"].as_array().unwrap().is_empty());
    // No terminal and no --yes: nothing runs.
    let refused = cli.run(&["cert", "trust", &ca]).await;
    assert_eq!(refused.code, 2);
    assert!(refused.stderr.contains("--yes"));
    // Saying no at the prompt: nothing runs either.
    let answered = cli
        .run_with(
            &["cert", "trust", &ca],
            Run {
                interactive: true,
                answers: vec!["n".into()],
                ..Run::default()
            },
        )
        .await;
    assert_eq!(answered.code, 1);
    assert!(answered.stderr.contains("Nothing changed"));
    // A certificate that isn't a CA is refused.
    let leaf = path_of(&dir, "leaf.pem");
    let leaf_key = path_of(&dir, "leaf.key");
    cli.run(&[
        "cert",
        "self-signed",
        "a.test",
        "--out",
        &leaf,
        "--out-key",
        &leaf_key,
    ])
    .await
    .ok();
    let refused = cli.run(&["cert", "trust", &leaf, "--dry-run"]).await;
    assert_eq!(refused.code, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn certificates_in_the_vault() {
    let (_server, _other, cli) = setup().await;
    let saved = cli
        .run(&["cert", "ca-create", "--name", "Dev CA", "--save", "--json"])
        .await
        .ok()
        .json();
    assert_eq!(saved["title"], "Dev CA");
    assert!(!saved.to_string().contains("PRIVATE KEY"));

    let issued = cli
        .run(&[
            "cert", "issue", "app.test", "--ca", "Dev CA", "--days", "90", "--save", "--title",
            "App",
        ])
        .await
        .ok();
    assert!(issued.stdout.contains("BEGIN CERTIFICATE"));
    assert!(!issued.stdout.contains("PRIVATE KEY"));

    let list = cli.run(&["cert", "list", "--json"]).await.ok().json();
    let titles: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["title"].as_str().unwrap())
        .collect();
    assert_eq!(
        titles,
        ["App", "Dev CA"],
        "the soonest to expire comes first"
    );

    // A public name, refused by the CA's own constraints.
    let refused = cli
        .run(&["cert", "issue", "example.com", "--ca", "Dev CA", "--save"])
        .await;
    assert_eq!(refused.code, 2);
    assert!(
        refused.stderr.contains("can't issue for that name"),
        "{}",
        refused.stderr
    );

    // Reminders start inside the window.
    let fine = cli.run(&["cert", "expiring"]).await;
    assert_eq!(fine.code, 0, "{fine:#?}");
    cli.advance(65 * 86_400);
    // That long idle locks the vault too.
    let due = cli.run_password(&["cert", "expiring", "--json"]).await;
    assert_eq!(due.code, 10, "{due:#?}");
    assert_eq!(due.json()[0]["title"], "App");
}

#[tokio::test(flavor = "multi_thread")]
async fn exporting_a_private_key_asks_for_the_master_password() {
    let (_server, _other, cli) = setup().await;
    cli.run(&[
        "cert",
        "self-signed",
        "app.test",
        "--save",
        "--title",
        "App",
    ])
    .await
    .ok();
    let dir = tempfile::tempdir().unwrap();
    let key = path_of(&dir, "key.pem");

    // The public certificate needs nothing more.
    let public = cli.run(&["cert", "export", "App"]).await.ok();
    assert!(public.stdout.contains("BEGIN CERTIFICATE"));

    let refused = cli
        .run(&["cert", "export", "App", "--part", "key", "--out", &key])
        .await;
    assert_ne!(refused.code, 0);
    assert!(!std::path::Path::new(&key).exists());

    cli.run_password(&["cert", "export", "App", "--part", "key", "--out", &key])
        .await
        .ok();
    assert!(
        std::fs::read_to_string(&key)
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_and_tokens_save_as_items() {
    let (_server, _other, cli) = setup().await;
    let saved = cli
        .run(&[
            "jwt", "keygen", "--alg", "EdDSA", "--save", "--title", "Signing", "--json",
        ])
        .await
        .ok()
        .json();
    assert_eq!(saved["title"], "Signing");
    cli.run(&["key", "age", "--save"]).await.ok();
    cli.run(&["random", "token", "--save", "--title", "API"])
        .await
        .ok();
    let listed = cli.run(&["list", "--json"]).await.ok().json();
    let types: Vec<Value> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["type"].clone())
        .collect();
    assert!(types.contains(&Value::from("key")), "{types:?}");
    assert!(types.contains(&Value::from("apiCredential")), "{types:?}");
}
