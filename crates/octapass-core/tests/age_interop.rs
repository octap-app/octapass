//! Files made by the reference age tool (Go, v1.3.2) open here. `tests/age-fixtures` was written by
//! `age-keygen` and `age`; these bytes never passed through this code. The other direction, the
//! reference tool opening our files, is checked by hand (plan 16 History).

use std::io::{Cursor, Read};

use octapass_core::tools::age::{AgeError, Keys, Opening, parse_identity_file, recipient_of};
use zeroize::Zeroizing;

const PLAIN: &[u8] = b"Made by the reference age tool.\n";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/age-fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn identity() -> Keys {
    let text = String::from_utf8(fixture("identity.txt")).unwrap();
    Keys {
        identities: parse_identity_file(&text).unwrap(),
        passphrase: None,
    }
}

fn open(name: &str, keys: &Keys) -> Result<Vec<u8>, AgeError> {
    let mut reader = Opening::new(Cursor::new(fixture(name)))?.decrypt(keys)?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

#[test]
fn opens_binary_and_armored_files() {
    assert_eq!(open("binary.age", &identity()).unwrap(), PLAIN);
    assert_eq!(open("armored.age", &identity()).unwrap(), PLAIN);
}

#[test]
fn opens_a_passphrase_file_and_tells_a_wrong_passphrase() {
    let with = |text: &str| Keys {
        identities: Vec::new(),
        passphrase: Some(Zeroizing::new(text.to_owned())),
    };
    assert!(
        Opening::new(Cursor::new(fixture("passphrase.age")))
            .unwrap()
            .needs_passphrase()
    );
    assert_eq!(
        open("passphrase.age", &with("correct horse battery")).unwrap(),
        PLAIN
    );
    assert!(matches!(
        open("passphrase.age", &with("wrong")),
        Err(AgeError::WrongPassphrase)
    ));
}

#[test]
fn reads_the_public_key_comment_the_same_way() {
    let text = String::from_utf8(fixture("identity.txt")).unwrap();
    let written = text
        .lines()
        .find_map(|line| line.strip_prefix("# public key: "))
        .unwrap();
    let identity = text.lines().find(|line| line.starts_with("AGE-")).unwrap();
    assert_eq!(recipient_of(identity).unwrap(), written);
}
