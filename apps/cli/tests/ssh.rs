//! `octapass ssh`: generating, importing (files and ~/.ssh), exporting and public keys.

use crate::common;

use std::path::{Path, PathBuf};

use common::*;
use octapass_core::Error;
use octapass_core::tools::ssh::read_private_key;

const PASSPHRASE: &str = "correct horse";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/octapass-core/tests/ssh-fixtures")
        .join(name)
}

async fn setup() -> (Server, OtherDevice, Cli) {
    let server = server().await;
    let other = OtherDevice::sign_up(&server).await;
    let cli = Cli::new(&server);
    cli.login(&other.secret_key).await.ok();
    (server, other, cli)
}

#[tokio::test(flavor = "multi_thread")]
async fn generate_list_and_public() {
    let (_server, other, cli) = setup().await;
    let made = cli
        .run(&["ssh", "generate", "--comment", "ada@laptop", "--json"])
        .await
        .ok()
        .json();
    assert_eq!(made["title"], "ada@laptop");
    assert_eq!(made["keyType"], "ssh-ed25519");
    let fingerprint = made["fingerprint"].as_str().unwrap().to_owned();
    assert!(fingerprint.starts_with("SHA256:"));
    assert!(made["publicKey"].as_str().unwrap().ends_with(" ada@laptop"));
    assert!(!made.to_string().contains("PRIVATE KEY"));

    cli.run(&[
        "ssh",
        "generate",
        "--type",
        "ecdsa-p384",
        "--title",
        "Server",
    ])
    .await
    .ok();

    // The other device sees both, as SSH key items.
    other.vault.sync().await.unwrap();
    let items = other.vault.live_items().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|i| i.overview["type"] == "sshKey"));

    let list = cli.run(&["ssh", "list"]).await.ok();
    let lines: Vec<&str> = list.stdout.lines().collect();
    assert!(
        lines[0].starts_with("TITLE") && lines[0].contains("FINGERPRINT"),
        "{lines:?}"
    );
    assert!(
        lines[1].starts_with("ada@laptop")
            && lines[1].contains("Ed25519")
            && lines[1].contains(&fingerprint)
    );
    assert!(lines[2].starts_with("Server") && lines[2].contains("ECDSA P-384"));
    assert!(!list.stdout.contains("PRIVATE"));
    assert_eq!(
        cli.run(&["ssh", "list", "--json"])
            .await
            .ok()
            .json()
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let public = cli.run(&["ssh", "public", "ada@laptop"]).await.ok();
    assert!(
        public.stdout.starts_with("ssh-ed25519 AAAA") && public.stdout.ends_with(" ada@laptop\n")
    );
    assert_eq!(cli.run(&["ssh", "public", "nothing"]).await.code, 6);
}

#[tokio::test(flavor = "multi_thread")]
async fn import_files_with_and_without_passphrases() {
    let (_server, other, cli) = setup().await;
    let plain = fixture("ed25519");
    let locked = fixture("rsa-3072-pkcs1-pass");
    let out = cli
        .run_with(
            &[
                "ssh",
                "import",
                plain.to_str().unwrap(),
                locked.to_str().unwrap(),
                "--json",
            ],
            Run {
                interactive: true,
                answers: vec![PASSPHRASE.into()],
                ..Run::default()
            },
        )
        .await
        .ok();
    assert_eq!(
        out.asked,
        [format!("Passphrase for {}: ", locked.display())]
    );
    let rows = out.json();
    assert_eq!(
        rows[0]["fingerprint"],
        "SHA256:cw5ZEN7m7AT7ImmissH+ctZwQN1s12PYZFmS2EC+Ovg"
    );
    assert_eq!(
        rows[1]["fingerprint"],
        "SHA256:xzr/aoj2pqKvUW6rlViIfr2XceviuQK04uwiVopNceM"
    );
    other.vault.sync().await.unwrap();
    let items = other.vault.live_items().unwrap();
    assert_eq!(items.len(), 2);
    let rsa = items
        .iter()
        .find(|i| i.overview["title"] == "rsa-3072-pkcs1-pass")
        .unwrap();
    // The comment comes from the .pub next to a PEM key, which has none of its own.
    assert_eq!(rsa.details["comment"], "rsa-pass@fixture");
    // Stored without the passphrase: the vault protects it.
    assert!(read_private_key(rsa.details["privateKey"].as_str().unwrap(), None).is_ok());

    // Importing again finds them in the vault.
    let again = cli
        .run(&["ssh", "import", plain.to_str().unwrap()])
        .await
        .ok();
    assert!(
        again.stderr.contains("already in the vault"),
        "{}",
        again.stderr
    );
    other.vault.sync().await.unwrap();
    assert_eq!(other.vault.live_items().unwrap().len(), 2);

    // A wrong passphrase, a public key and a file that isn't a key say so, and exit 2.
    let wrong = cli
        .run_with(
            &["ssh", "import", fixture("ed25519-pass").to_str().unwrap()],
            Run {
                interactive: true,
                answers: vec!["nope".into()],
                ..Run::default()
            },
        )
        .await;
    assert_eq!(wrong.code, 2);
    assert!(
        wrong.stderr.contains("wrong passphrase"),
        "{}",
        wrong.stderr
    );
    let public = cli
        .run(&["ssh", "import", fixture("ed25519.pub").to_str().unwrap()])
        .await;
    assert_eq!(public.code, 2);
    assert!(
        public.stderr.contains("is a public key"),
        "{}",
        public.stderr
    );
    assert_eq!(cli.run(&["ssh", "import"]).await.code, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_imports_new_keys_from_dot_ssh() {
    let (_server, other, cli) = setup().await;
    let home = tempfile::tempdir().unwrap();
    let dot_ssh = home.path().join(".ssh");
    std::fs::create_dir(&dot_ssh).unwrap();
    for name in ["ed25519", "ed25519.pub", "ecdsa-p256", "ecdsa-p256.pub"] {
        std::fs::copy(
            fixture(name),
            dot_ssh.join(
                name.replace("ed25519", "id_ed25519")
                    .replace("ecdsa-p256", "id_ecdsa"),
            ),
        )
        .unwrap();
    }
    std::fs::write(dot_ssh.join("known_hosts"), "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n").unwrap();
    std::fs::write(
        dot_ssh.join("config"),
        "Host *\n  IdentityFile ~/.ssh/id_ed25519\n",
    )
    .unwrap();
    // A key that's already in the vault is skipped.
    cli.run(&["ssh", "import", fixture("ed25519").to_str().unwrap()])
        .await
        .ok();

    let home_env = vec![("HOME".to_owned(), home.path().to_str().unwrap().to_owned())];
    let out = cli
        .run_with(
            &["ssh", "import", "--scan", "--json"],
            Run {
                env: home_env.clone(),
                ..Run::default()
            },
        )
        .await
        .ok();
    let rows = out.json();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(
        rows[0]["file"],
        dot_ssh.join("id_ecdsa").display().to_string()
    );
    assert_eq!(rows[0]["title"], "id_ecdsa");
    assert_eq!(rows[1]["skipped"], "alreadyInVault");
    other.vault.sync().await.unwrap();
    assert_eq!(other.vault.live_items().unwrap().len(), 2);

    let quiet = cli
        .run_with(
            &["ssh", "import", "--scan"],
            Run {
                env: home_env,
                ..Run::default()
            },
        )
        .await
        .ok();
    assert!(
        quiet.stderr.ends_with("No new keys to import.\n"),
        "{}",
        quiet.stderr
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn export_writes_a_private_file_and_asks_again() {
    let (_server, _other, cli) = setup().await;
    cli.run(&["ssh", "import", fixture("ed25519").to_str().unwrap()])
        .await
        .ok();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id_ed25519");
    let file = path.to_str().unwrap();

    // Without the master password there's no export.
    assert_eq!(
        cli.run(&["ssh", "export", "ed25519", "--out", file])
            .await
            .code,
        2
    );
    cli.run_password(&["ssh", "export", "ed25519", "--out", file])
        .await
        .ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let key = read_private_key(&text, None).unwrap();
    assert_eq!(
        key.info.fingerprint,
        "SHA256:cw5ZEN7m7AT7ImmissH+ctZwQN1s12PYZFmS2EC+Ovg"
    );
    assert_eq!(key.info.comment, "ed25519@fixture");

    // An existing file stays unless --force.
    let refused = cli
        .run_password(&["ssh", "export", "ed25519", "--out", file])
        .await;
    assert_eq!(refused.code, 2);
    assert!(refused.stderr.contains("--force"), "{}", refused.stderr);

    // With a new passphrase.
    let out = cli
        .run_with(
            &[
                "--password-stdin",
                "ssh",
                "export",
                "ed25519",
                "--out",
                file,
                "--force",
                "--passphrase",
            ],
            Run {
                stdin: format!("{PASSWORD}\n{PASSPHRASE}\n"),
                ..Run::default()
            },
        )
        .await
        .ok();
    assert!(
        out.stderr.contains("protected by a passphrase"),
        "{}",
        out.stderr
    );
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        read_private_key(&text, None).unwrap_err(),
        Error::SshPassphraseRequired
    );
    assert!(read_private_key(&text, Some(PASSPHRASE)).is_ok());

    // Never printed to a terminal.
    let terminal = cli
        .run_with(
            &["--password-stdin", "ssh", "export", "ed25519"],
            Run {
                stdin: format!("{PASSWORD}\n"),
                stdout_is_terminal: true,
                ..Run::default()
            },
        )
        .await;
    assert_eq!(terminal.code, 2);
    assert!(!terminal.stdout.contains("PRIVATE KEY"));
}
