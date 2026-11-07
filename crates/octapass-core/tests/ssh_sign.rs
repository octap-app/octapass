//! SSH signatures. The `.sshsig` fixtures are what `ssh-keygen -Y sign -n git` wrote for
//! `message.txt` (see `ssh-fixtures/README.md`): Ed25519 and RSA PKCS#1 v1.5 signatures are
//! deterministic, so they are test vectors, byte for byte.

use std::io::Write;
use std::process::{Command, Stdio};

use ed25519_dalek::Verifier;
use octapass_core::Error;
use octapass_core::tools::ssh::{
    RSA_SHA2_256, RSA_SHA2_512, SshKeyKind, generate, public_key_blob, read_private_key, sign,
    sign_sshsig,
};
use rand_core::OsRng;
use ssh_encoding::Decode;
use ssh_key::{HashAlg, PublicKey, Signature, SshSig};

const MESSAGE: &[u8] = b"Octa Pass signing test vector\n";

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/ssh-fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).unwrap()
}

fn stored(name: &str) -> String {
    read_private_key(&fixture(name), None)
        .unwrap()
        .private_key
        .to_string()
}

fn decode(mut bytes: &[u8]) -> Signature {
    let signature = Signature::decode(&mut bytes).unwrap();
    assert!(bytes.is_empty(), "nothing after the signature");
    signature
}

#[test]
fn sshsig_vectors_match_ssh_keygen_byte_for_byte() {
    for name in ["ed25519", "rsa-3072-pkcs1"] {
        assert_eq!(
            sign_sshsig(&stored(name), "git", MESSAGE).unwrap(),
            fixture(&format!("{name}.sshsig")),
            "{name}"
        );
    }
}

#[test]
fn every_usable_key_type_signs_and_verifies() {
    let kinds = [
        SshKeyKind::Ed25519,
        SshKeyKind::EcdsaP256,
        SshKeyKind::EcdsaP384,
        SshKeyKind::Rsa3072,
    ];
    for kind in kinds {
        let key = generate(kind, "test", &mut OsRng).unwrap();
        let public = PublicKey::from_openssh(&key.info.public_key).unwrap();
        let blob = sign(&key.private_key, MESSAGE, RSA_SHA2_512).unwrap();
        Verifier::verify(&public, MESSAGE, &decode(&blob)).unwrap();

        let armored = sign_sshsig(&key.private_key, "git", MESSAGE).unwrap();
        let sig = SshSig::from_pem(&armored).unwrap();
        assert_eq!(sig.hash_alg(), HashAlg::Sha512);
        public.verify("git", MESSAGE, &sig).unwrap();
        assert!(public.verify("file", MESSAGE, &sig).is_err());
    }
}

#[test]
fn a_p521_key_signs_too() {
    let key = stored("ecdsa-p521-pkcs8");
    let public = read_private_key(&fixture("ecdsa-p521-pkcs8"), None).unwrap();
    let public = PublicKey::from_openssh(&public.info.public_key).unwrap();
    let blob = sign(&key, MESSAGE, 0).unwrap();
    Verifier::verify(&public, MESSAGE, &decode(&blob)).unwrap();
}

#[test]
fn rsa_signs_with_the_hash_asked_for_and_never_sha1() {
    let key = stored("rsa-3072-pkcs1");
    assert_eq!(
        sign(&key, MESSAGE, 0).unwrap_err(),
        Error::SshSignatureRefused
    );
    let names = [
        (RSA_SHA2_256, "rsa-sha2-256"),
        (RSA_SHA2_512, "rsa-sha2-512"),
    ];
    for (flag, name) in names {
        let bytes = sign(&key, MESSAGE, flag).unwrap();
        assert_eq!(&bytes[4..4 + name.len()], name.as_bytes());
        let public = fixture("rsa-3072-pkcs1.pub");
        let public = PublicKey::from_openssh(public.trim()).unwrap();
        Verifier::verify(&public, MESSAGE, &decode(&bytes)).unwrap();
    }
}

#[test]
fn keys_that_cannot_be_used_refuse_to_sign() {
    let dsa = stored("dsa");
    assert_eq!(
        sign(&dsa, MESSAGE, 0).unwrap_err(),
        Error::UnsupportedSshKey
    );
    assert_eq!(
        sign_sshsig(&dsa, "git", MESSAGE).unwrap_err(),
        Error::UnsupportedSshKey
    );
    assert_eq!(
        sign_sshsig(&stored("ed25519"), "", MESSAGE).unwrap_err(),
        Error::SshSignatureRefused
    );
}

#[test]
fn public_key_blobs_are_the_wire_form() {
    let line = fixture("ed25519.pub");
    let blob = public_key_blob(
        line.split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
            .as_str(),
    )
    .unwrap();
    assert_eq!(&blob[..15], b"\0\0\0\x0bssh-ed25519");
    assert_eq!(
        public_key_blob("nonsense").unwrap_err(),
        Error::InvalidSshKey
    );
}

/// The real `ssh-keygen` accepts what the core signs, on machines that have it.
#[test]
fn ssh_keygen_verifies_signatures() {
    if Command::new("ssh-keygen")
        .arg("-?")
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("skipped: no ssh-keygen");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    for kind in [
        SshKeyKind::Ed25519,
        SshKeyKind::EcdsaP256,
        SshKeyKind::EcdsaP384,
        SshKeyKind::Rsa3072,
    ] {
        let key = generate(kind, "test", &mut OsRng).unwrap();
        let path = dir.path().join("allowed");
        std::fs::write(&path, format!("me@example.com {}\n", key.info.public_key)).unwrap();
        let sig = dir.path().join("sig");
        std::fs::write(&sig, sign_sshsig(&key.private_key, "git", MESSAGE).unwrap()).unwrap();
        let mut child = Command::new("ssh-keygen")
            .args(["-Y", "verify", "-n", "git", "-I", "me@example.com", "-f"])
            .arg(&path)
            .arg("-s")
            .arg(&sig)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(MESSAGE).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{kind:?}: {output:?}");
    }
}
