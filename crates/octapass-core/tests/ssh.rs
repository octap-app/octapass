//! SSH keys: generating, reading every supported format and writing them back. The fixtures and the
//! commands that made them are in `ssh-fixtures/README.md`; expected fingerprints are what
//! `ssh-keygen -l -E sha256` prints.

use octapass_core::Error;
use octapass_core::tools::ssh::{
    SshKeyKind, authorized_keys_line, from_pkcs8_der, generate, read_private_key, read_public_key,
    to_pkcs8_der, write_private_key,
};
use rand_core::OsRng;
use ssh_key::{LineEnding, PrivateKey};

const PASS: &str = "correct horse";

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/ssh-fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).unwrap()
}

/// The `.pub` file without its comment.
fn public_of(name: &str) -> String {
    let line = fixture(&format!("{name}.pub"));
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn every_format_reads_with_ssh_keygen_fingerprints() {
    for (name, passphrase, key_type, bits, fingerprint, comment) in [
        (
            "ed25519",
            None,
            "ssh-ed25519",
            256,
            "SHA256:cw5ZEN7m7AT7ImmissH+ctZwQN1s12PYZFmS2EC+Ovg",
            "ed25519@fixture",
        ),
        (
            "ed25519-pass",
            Some(PASS),
            "ssh-ed25519",
            256,
            "SHA256:rYnfKDfSU0+bSm8xI+c0oxqqAcht6ht2zFaIWnHUuSA",
            "ed25519-pass@fixture",
        ),
        (
            "ecdsa-p256",
            None,
            "ecdsa-sha2-nistp256",
            256,
            "SHA256:UVFfmNWq/8OV+87JBleNxiy1fc8hmjFN6QRLDqWwG8M",
            "p256@fixture",
        ),
        // PEM and PKCS#8 files have no comment.
        (
            "ecdsa-p384-sec1",
            None,
            "ecdsa-sha2-nistp384",
            384,
            "SHA256:E+oPXd7hU66z2O8+ep4QhZjN0r3x7MazjbTA46Ogglk",
            "",
        ),
        (
            "ecdsa-p521-pkcs8",
            None,
            "ecdsa-sha2-nistp521",
            521,
            "SHA256:EFx61jBNdfMlvEAN4JkbpKd3ch83lD3gzbMglqnC5vo",
            "",
        ),
        (
            "ecdsa-p256-named-sec1",
            None,
            "ecdsa-sha2-nistp256",
            256,
            "SHA256:B72/FlPEF2DsQH4MH8udLMQIzuQL92Yt4uGE7DJ0Jn4",
            "",
        ),
        (
            "ecdsa-p256-named-pkcs8",
            None,
            "ecdsa-sha2-nistp256",
            256,
            "SHA256:B72/FlPEF2DsQH4MH8udLMQIzuQL92Yt4uGE7DJ0Jn4",
            "",
        ),
        (
            "ecdsa-p256-named-sec1-pass",
            Some(PASS),
            "ecdsa-sha2-nistp256",
            256,
            "SHA256:B72/FlPEF2DsQH4MH8udLMQIzuQL92Yt4uGE7DJ0Jn4",
            "",
        ),
        (
            "rsa-3072-pkcs1",
            None,
            "ssh-rsa",
            3072,
            "SHA256:1R1BTF8Op8iFxtUBRPYgec6Uuxk9pMq0tnG6pX358hI",
            "",
        ),
        (
            "rsa-3072-pkcs1-pass",
            Some(PASS),
            "ssh-rsa",
            3072,
            "SHA256:xzr/aoj2pqKvUW6rlViIfr2XceviuQK04uwiVopNceM",
            "",
        ),
        (
            "rsa-3072-pkcs8-pass",
            Some(PASS),
            "ssh-rsa",
            3072,
            "SHA256:wGufZ2GMlHw8n5uORLlzZwSWw/ju9/bzqcB4YVc50F8",
            "",
        ),
        (
            "rsa-4096-pass",
            Some(PASS),
            "ssh-rsa",
            4096,
            "SHA256:Bss6JQ3wGzND6KpzYKBNOZtf+VsiPqJreL17AxIMWK4",
            "rsa4096-pass@fixture",
        ),
    ] {
        let key =
            read_private_key(&fixture(name), passphrase).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(key.info.key_type, key_type, "{name}");
        assert_eq!(key.info.bits, bits, "{name}");
        assert_eq!(key.info.fingerprint, fingerprint, "{name}");
        assert_eq!(key.info.public_key, public_of(name), "{name}");
        assert_eq!(key.info.comment, comment, "{name}");
        assert!(key.info.usable, "{name}");
        // Stored as an OpenSSH key without a passphrase, which reads back as the same key.
        assert!(
            key.private_key
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"),
            "{name}"
        );
        let again = read_private_key(&key.private_key, None).unwrap();
        assert_eq!(again.info, key.info, "{name}");
        // The public key line reads too.
        assert_eq!(
            read_public_key(&fixture(&format!("{name}.pub")))
                .unwrap()
                .fingerprint,
            fingerprint
        );
    }
}

#[test]
fn passphrases_are_asked_for_and_checked() {
    for name in [
        "ed25519-pass",
        "rsa-3072-pkcs1-pass",
        "rsa-3072-pkcs8-pass",
        "ecdsa-p256-named-sec1-pass",
    ] {
        assert_eq!(
            read_private_key(&fixture(name), None).unwrap_err(),
            Error::SshPassphraseRequired,
            "{name}"
        );
        assert_eq!(
            read_private_key(&fixture(name), Some("")).unwrap_err(),
            Error::SshPassphraseRequired,
            "{name}"
        );
        assert_eq!(
            read_private_key(&fixture(name), Some("wrong horse")).unwrap_err(),
            Error::WrongPassphrase,
            "{name}"
        );
    }
    // A passphrase on a key that has none is ignored.
    assert!(read_private_key(&fixture("ed25519"), Some("unused")).is_ok());
}

#[test]
fn malformed_and_other_files_say_why() {
    assert_eq!(
        read_private_key("", None).unwrap_err(),
        Error::InvalidSshKey
    );
    assert_eq!(
        read_private_key("hello", None).unwrap_err(),
        Error::InvalidSshKey
    );
    assert_eq!(
        read_private_key(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
            None
        )
        .unwrap_err(),
        Error::InvalidSshKey
    );
    // A cut-off file.
    let full = fixture("ed25519");
    assert_eq!(
        read_private_key(&full[..full.len() / 2], None).unwrap_err(),
        Error::InvalidSshKey
    );
    assert_eq!(
        read_private_key(&fixture("ed25519.pub"), None).unwrap_err(),
        Error::SshPublicKeyOnly
    );
    assert_eq!(
        read_private_key(
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
            None
        )
        .unwrap_err(),
        Error::SshPublicKeyOnly
    );
    assert_eq!(
        read_private_key("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none", None).unwrap_err(),
        Error::UnsupportedSshKey
    );
    // Legacy PEM encrypted with 3DES isn't read.
    let des = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,0011223344556677\n\nAAAA\n-----END RSA PRIVATE KEY-----";
    assert_eq!(
        read_private_key(des, Some(PASS)).unwrap_err(),
        Error::UnsupportedSshKey
    );
    assert_eq!(
        read_public_key("ssh-ed25519 not-base64").unwrap_err(),
        Error::InvalidSshKey
    );
    // Windows line endings and a byte-order mark are fine.
    let crlf = format!("\u{feff}{}", fixture("ed25519").replace('\n', "\r\n"));
    assert!(read_private_key(&crlf, None).is_ok());
}

#[test]
fn generated_keys_round_trip_through_every_writer() {
    for (kind, key_type, bits) in [
        (SshKeyKind::Ed25519, "ssh-ed25519", 256),
        (SshKeyKind::EcdsaP256, "ecdsa-sha2-nistp256", 256),
        (SshKeyKind::EcdsaP384, "ecdsa-sha2-nistp384", 384),
        (SshKeyKind::Rsa3072, "ssh-rsa", 3072),
        (SshKeyKind::Rsa4096, "ssh-rsa", 4096),
    ] {
        let key = generate(kind, "me@laptop", &mut OsRng).unwrap();
        assert_eq!(
            (key.info.key_type.as_str(), key.info.bits),
            (key_type, bits)
        );
        assert_eq!(key.info.comment, "me@laptop");
        assert!(key.info.fingerprint.starts_with("SHA256:") && key.info.fingerprint.len() == 50);

        // Without a passphrase, with a new comment.
        let plain = write_private_key(&key.private_key, "work", None, &mut OsRng).unwrap();
        let read = read_private_key(&plain, None).unwrap();
        assert_eq!(
            (read.info.fingerprint.as_str(), read.info.comment.as_str()),
            (key.info.fingerprint.as_str(), "work")
        );

        // With one: only that passphrase opens it.
        let locked = write_private_key(&key.private_key, "work", Some(PASS), &mut OsRng).unwrap();
        assert!(
            PrivateKey::from_openssh(locked.as_bytes())
                .unwrap()
                .is_encrypted()
        );
        assert_eq!(
            read_private_key(&locked, None).unwrap_err(),
            Error::SshPassphraseRequired
        );
        assert_eq!(
            read_private_key(&locked, Some("nope")).unwrap_err(),
            Error::WrongPassphrase
        );
        assert_eq!(
            read_private_key(&locked, Some(PASS))
                .unwrap()
                .info
                .fingerprint,
            key.info.fingerprint
        );

        // PKCS#8 (Credential Exchange) and back.
        let der = to_pkcs8_der(&key.private_key).unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        let back = from_pkcs8_der(&der, "me@laptop").unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        assert_eq!(back.info, key.info);
        assert_eq!(
            read_private_key(&back.private_key, None)
                .unwrap()
                .private_key
                .len(),
            back.private_key.len()
        );

        // The authorized_keys line.
        assert_eq!(
            authorized_keys_line(&key.info.public_key, "me@laptop"),
            format!("{} me@laptop", key.info.public_key)
        );
        assert_eq!(
            authorized_keys_line(&key.info.public_key, " "),
            key.info.public_key
        );
    }
}

/// ssh-keygen reads what Octa Pass writes. Skipped where there's no ssh-keygen.
#[test]
fn ssh_keygen_reads_written_keys() {
    if std::process::Command::new("ssh-keygen")
        .arg("-?")
        .output()
        .is_err()
    {
        return;
    }
    let dir = std::env::temp_dir().join(format!("octapass-ssh-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for kind in [
        SshKeyKind::Ed25519,
        SshKeyKind::EcdsaP384,
        SshKeyKind::Rsa3072,
    ] {
        let key = generate(kind, "me@laptop", &mut OsRng).unwrap();
        for passphrase in ["", PASS] {
            let path = dir.join("id");
            let text =
                write_private_key(&key.private_key, "me@laptop", Some(passphrase), &mut OsRng)
                    .unwrap();
            std::fs::write(&path, text.as_bytes()).unwrap();
            #[cfg(unix)]
            std::os::unix::fs::PermissionsExt::set_mode(
                &mut std::fs::metadata(&path).unwrap().permissions(),
                0o600,
            );
            #[cfg(unix)]
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .unwrap();
            let out = std::process::Command::new("ssh-keygen")
                .args(["-y", "-P", passphrase, "-f"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{kind:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                String::from_utf8(out.stdout).unwrap().trim(),
                format!("{} me@laptop", key.info.public_key)
            );
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn ed25519_pkcs8_matches_the_openssh_key() {
    let key = read_private_key(&fixture("ed25519"), None).unwrap();
    let der = to_pkcs8_der(&key.private_key).unwrap();
    use base64::Engine;
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(&*der)
    );
    assert_eq!(
        read_private_key(&pem, None).unwrap().info.fingerprint,
        key.info.fingerprint
    );
}

#[test]
fn dsa_and_security_keys_are_kept_but_not_usable() {
    let dsa = read_private_key(&fixture("dsa"), None).unwrap();
    assert_eq!(
        (dsa.info.key_type.as_str(), dsa.info.bits, dsa.info.usable),
        ("ssh-dss", 1024, false)
    );
    assert!(dsa.info.public_key.starts_with("ssh-dss AAAAB3NzaC1kc3M"));
    assert_eq!(
        read_private_key(&dsa.private_key, None).unwrap().info,
        dsa.info
    );
    assert_eq!(
        to_pkcs8_der(&dsa.private_key).unwrap_err(),
        Error::UnsupportedSshKey
    );
    assert!(write_private_key(&dsa.private_key, "old", Some(PASS), &mut OsRng).is_ok());

    // A FIDO key's file holds the security key's handle, not a usable private key.
    let ed = ssh_key::private::Ed25519Keypair::random(&mut OsRng);
    let public = ssh_key::public::SkEd25519::new(ed.public, "ssh:");
    let sk = ssh_key::private::SkEd25519::new(public, 0x01, vec![7u8; 64]).unwrap();
    let text = PrivateKey::new(sk.into(), "yubikey")
        .unwrap()
        .to_openssh(LineEnding::LF)
        .unwrap();
    let key = read_private_key(&text, None).unwrap();
    assert_eq!(
        (
            key.info.key_type.as_str(),
            key.info.usable,
            key.info.comment.as_str()
        ),
        ("sk-ssh-ed25519@openssh.com", false, "yubikey")
    );
    assert!(
        key.info
            .public_key
            .starts_with("sk-ssh-ed25519@openssh.com ")
    );
    assert_eq!(
        to_pkcs8_der(&key.private_key).unwrap_err(),
        Error::UnsupportedSshKey
    );
}
