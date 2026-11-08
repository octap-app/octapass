//! OpenPGP signatures for Git. Keys are made here with rPGP; `rsa.asc` was exported by GnuPG
//! (`gpg-fixtures/README.md`).

#![cfg(feature = "pgp")]

use std::io::Write;
use std::process::{Command, Stdio};

use octapass_core::Error;
use octapass_core::tools::gpg::{read_private_key, sign_detached, signing_key};
use pgp::composed::{
    ArmorOptions, Deserializable, DetachedSignature, KeyType, SecretKeyParamsBuilder,
    SignedPublicKey, SubkeyParamsBuilder,
};
use rand_core::OsRng;

const MESSAGE: &[u8] = b"tree 0000\nauthor Ada\n\nA commit\n";

fn make_key(signing_subkey: bool, passphrase: Option<&str>) -> String {
    let mut builder = SecretKeyParamsBuilder::default();
    builder
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(!signing_subkey)
        .primary_user_id("Ada <ada@example.com>".into());
    if signing_subkey {
        builder.subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::Ed25519Legacy)
                .can_sign(true)
                .build()
                .unwrap(),
        );
    }
    let key = builder.build().unwrap().generate(OsRng).unwrap();
    let key = match passphrase {
        Some(passphrase) => {
            let mut key = key;
            key.primary_key
                .set_password(OsRng, &passphrase.into())
                .unwrap();
            for subkey in &mut key.secret_subkeys {
                subkey.key.set_password(OsRng, &passphrase.into()).unwrap();
            }
            key
        }
        None => key,
    };
    key.to_armored_string(ArmorOptions::default()).unwrap()
}

fn verify(public: &str, armored: &str) {
    let (public, _) = SignedPublicKey::from_string(public).unwrap();
    let (signature, _) = DetachedSignature::from_string(armored).unwrap();
    let verified = signature.verify(&public, MESSAGE).is_ok()
        || public
            .public_subkeys
            .iter()
            .any(|subkey| signature.verify(&subkey.key, MESSAGE).is_ok());
    assert!(verified, "the signature doesn't verify");
}

#[test]
fn a_key_with_a_signing_subkey_signs_with_it() {
    let key = make_key(true, None);
    let info = read_private_key(&key, None).unwrap();
    assert!(info.can_sign);
    assert_eq!(info.user_id, "Ada <ada@example.com>");
    assert_eq!(info.fingerprints.len(), 2);
    assert_eq!(info.key_id.len(), 16);
    assert!(info.fingerprint.ends_with(&info.key_id));
    let armored = sign_detached(&key, None, MESSAGE).unwrap();
    assert!(armored.starts_with("-----BEGIN PGP SIGNATURE-----"));
    verify(&info.public_key, &armored);
    assert_eq!(signing_key(&key).unwrap().0, info.fingerprints[1]);
}

#[test]
fn a_primary_key_signs_when_there_is_no_subkey() {
    let key = make_key(false, None);
    let info = read_private_key(&key, None).unwrap();
    verify(
        &info.public_key,
        &sign_detached(&key, None, MESSAGE).unwrap(),
    );
    assert_eq!(signing_key(&key).unwrap().0, info.fingerprint);
}

#[test]
fn a_protected_key_needs_its_passphrase() {
    let key = make_key(true, Some("correct horse"));
    assert_eq!(
        read_private_key(&key, Some("wrong")).unwrap_err(),
        Error::WrongPassphrase
    );
    assert_eq!(
        read_private_key(&key, None).unwrap_err(),
        Error::WrongPassphrase
    );
    let info = read_private_key(&key, Some("correct horse")).unwrap();
    verify(
        &info.public_key,
        &sign_detached(&key, Some("correct horse"), MESSAGE).unwrap(),
    );
}

#[test]
fn rsa_keys_are_read_but_refuse_to_sign() {
    let path = format!("{}/tests/gpg-fixtures/rsa.asc", env!("CARGO_MANIFEST_DIR"));
    let key = std::fs::read_to_string(path).unwrap();
    let info = read_private_key(&key, None).unwrap();
    assert!(!info.can_sign);
    assert_eq!(info.user_id, "Open Pass RSA <rsa@openpass.example>");
    assert_eq!(
        sign_detached(&key, None, MESSAGE).unwrap_err(),
        Error::UnsupportedSshKey
    );
}

/// What people actually have: `gpg --export-secret-keys` of an Ed25519 key with a signing subkey.
#[test]
fn a_gnupg_export_signs_with_its_subkey() {
    let dir = format!("{}/tests/gpg-fixtures", env!("CARGO_MANIFEST_DIR"));
    let key = std::fs::read_to_string(format!("{dir}/ed25519-subkey.asc")).unwrap();
    let public = std::fs::read_to_string(format!("{dir}/ed25519-subkey.pub.asc")).unwrap();
    let info = read_private_key(&key, None).unwrap();
    assert!(info.can_sign);
    assert_eq!(info.user_id, "Open Pass Fixture <fixture@openpass.example>");
    assert_eq!(info.fingerprints.len(), 2);
    verify(&public, &sign_detached(&key, None, MESSAGE).unwrap());
}

#[test]
fn other_text_is_not_a_key() {
    assert_eq!(
        read_private_key("nonsense", None).unwrap_err(),
        Error::InvalidGpgKey
    );
}

/// The real `gpg` accepts what the core signs, on machines that have it.
#[cfg(unix)]
#[test]
fn gpg_verifies_signatures() {
    if Command::new("gpg")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("skipped: no gpg");
        return;
    }
    // gpg's socket paths are short: not the test's usual temporary folder on macOS.
    let dir = tempfile::Builder::new()
        .prefix("opg")
        .tempdir_in("/tmp")
        .unwrap();
    let key = make_key(true, None);
    let info = read_private_key(&key, None).unwrap();
    let public = dir.path().join("public.asc");
    std::fs::write(&public, &info.public_key).unwrap();
    let signature = dir.path().join("sig.asc");
    std::fs::write(&signature, sign_detached(&key, None, MESSAGE).unwrap()).unwrap();
    let gpg = |args: &[&std::ffi::OsStr]| {
        Command::new("gpg")
            .env("GNUPGHOME", dir.path())
            .args(["--batch", "--no-tty", "--no-autostart"])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    assert!(
        gpg(&["--import".as_ref(), public.as_ref()])
            .wait_with_output()
            .unwrap()
            .status
            .success()
    );
    let mut verify = gpg(&[
        "--status-fd=1".as_ref(),
        "--verify".as_ref(),
        signature.as_ref(),
        "-".as_ref(),
    ]);
    verify.stdin.take().unwrap().write_all(MESSAGE).unwrap();
    let output = verify.wait_with_output().unwrap();
    let status = String::from_utf8_lossy(&output.stdout);
    assert!(status.contains("GOODSIG"), "{status}");
}
