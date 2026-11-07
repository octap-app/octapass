//! File encryption in the [age](https://age-encryption.org/v1) format, on the `age` crate, so a
//! file encrypted here opens with any age tool, with or without Octa Pass.
//!
//! A file is encrypted for one of:
//!
//! - **Recipients**: age X25519 public keys, written `age1…`.
//! - **A passphrase**: age's scrypt recipient, which can't be mixed with other recipients.
//!
//! Two keys of an account work as age keys:
//!
//! - **The file identity** ("yourself"): an age key derived from the account's X25519 private key:
//!   `HKDF-SHA256(ikm = private key, salt = "", info = "openpass/v1/age-identity")`. Every device
//!   of the account derives the same one, and it can be exported for `age -d -i` without giving
//!   away the account key, because HKDF can't be run backwards.
//! - **The account's X25519 key**: an account's public key is already published to the people who
//!   share with it, so other people can encrypt to an Octa Pass user with nothing new on the
//!   server. Its private key is never exported: it also opens shared vaults.
//!
//! age and our sealed box both run X25519 and HKDF, but under different `info` labels
//! (`age-encryption.org/v1/X25519`, `openpass/v1/seal`), so neither can open the other's output.

use std::io::{self, BufReader, Read, Write};
use std::iter;
use std::str::FromStr;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::SecretString;
use age::stream::{StreamReader, StreamWriter};
use age::{DecryptError, Decryptor, Encryptor, Identity, Recipient, scrypt, x25519};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::account::AccountKeyPairs;
use crate::keys::hkdf_key;

const FILE_IDENTITY_INFO: &[u8] = b"openpass/v1/age-identity";
/// The first line of every age file.
pub const MAGIC: &[u8] = b"age-encryption.org/v1\n";
/// The first line of an armored age file.
pub const ARMOR_MAGIC: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

#[derive(Debug, Error)]
pub enum AgeError {
    #[error("not an age public key: {0}")]
    InvalidRecipient(String),
    #[error("not an age secret key")]
    InvalidIdentity,
    #[error("a file needs at least one recipient")]
    NoRecipients,
    #[error("the passphrase is wrong")]
    WrongPassphrase,
    #[error("none of your keys can open this file")]
    NoMatchingKey,
    #[error("this file needs a passphrase")]
    PassphraseRequired,
    #[error("this file wasn't encrypted with a passphrase")]
    NotPassphraseEncrypted,
    #[error("this file's passphrase protection is set too high to try here")]
    ExcessiveWork,
    #[error("this isn't an age file, or it's damaged")]
    Malformed,
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl From<DecryptError> for AgeError {
    fn from(error: DecryptError) -> Self {
        match error {
            DecryptError::DecryptionFailed => AgeError::WrongPassphrase,
            DecryptError::ExcessiveWork { .. } => AgeError::ExcessiveWork,
            DecryptError::NoMatchingKeys => AgeError::NoMatchingKey,
            DecryptError::Io(error) => AgeError::Io(error),
            _ => AgeError::Malformed,
        }
    }
}

type Result<T> = std::result::Result<T, AgeError>;

pub use crate::tools::age_keys::{identity_string, recipient_string};

/// The public key of an `AGE-SECRET-KEY-1…`, as `age1…`.
pub fn recipient_of(identity: &str) -> Result<String> {
    let parsed = x25519::Identity::from_str(identity).map_err(|_| AgeError::InvalidIdentity)?;
    Ok(parsed.to_public().to_string())
}

/// Checks an `age1…` and returns it in normal form.
pub fn check_recipient(recipient: &str) -> Result<String> {
    let recipient = recipient.trim();
    x25519::Recipient::from_str(recipient)
        .map(|parsed| parsed.to_string())
        .map_err(|_| AgeError::InvalidRecipient(recipient.to_owned()))
}

/// An account's keys as age keys. Dropping it zeroes them.
pub struct AccountFileKeys {
    /// `AGE-SECRET-KEY-1…`: the derived file identity. Safe to export.
    pub file_identity: Zeroizing<String>,
    /// `age1…` of the file identity: what "encrypt for yourself" encrypts to.
    pub file_recipient: String,
    /// `AGE-SECRET-KEY-1…` of the account's own X25519 key. Opens files other people encrypted to
    /// this account. **Never show or export this one**: it also opens shared vaults.
    pub account_identity: Zeroizing<String>,
    /// `age1…` of the account's X25519 key: what other people encrypt to.
    pub account_recipient: String,
}

impl AccountFileKeys {
    pub fn derive(pairs: &AccountKeyPairs) -> Result<Self> {
        let private = pairs.encryption_key().as_bytes();
        let derived = hkdf_key(private, b"", FILE_IDENTITY_INFO);
        let file_identity = identity_string(derived.as_bytes());
        let file_recipient = recipient_of(&file_identity)?;
        Ok(Self {
            file_identity,
            file_recipient,
            account_identity: identity_string(private),
            account_recipient: account_recipient(&pairs.public_enc_key()),
        })
    }

    /// Both identities, for [`Keys::identities`].
    pub fn identities(&self) -> Vec<Zeroizing<String>> {
        vec![self.file_identity.clone(), self.account_identity.clone()]
    }
}

/// The age public key of an account's published X25519 key.
pub fn account_recipient(public_enc_key: &[u8; 32]) -> String {
    recipient_string(public_enc_key)
}

/// Who a file is encrypted for.
pub enum Target<'a> {
    /// `age1…` public keys.
    Recipients(&'a [String]),
    Passphrase(&'a str),
}

/// What can open a file.
#[derive(Default)]
pub struct Keys {
    /// `AGE-SECRET-KEY-1…` strings.
    pub identities: Vec<Zeroizing<String>>,
    pub passphrase: Option<Zeroizing<String>>,
}

/// Encrypts everything written to it. Call [`EncryptWriter::finish`] at the end: without it the
/// file is cut short and won't open.
pub struct EncryptWriter<W: Write> {
    inner: StreamWriter<ArmoredWriter<W>>,
}

impl<W: Write> EncryptWriter<W> {
    /// Starts an encrypted file on `output`; `armor` writes it as PEM-style text.
    pub fn new(target: &Target<'_>, armor: bool, output: W) -> Result<Self> {
        let encryptor = match target {
            Target::Recipients(recipients) => {
                if recipients.is_empty() {
                    return Err(AgeError::NoRecipients);
                }
                let parsed = recipients
                    .iter()
                    .map(|recipient| {
                        x25519::Recipient::from_str(recipient.trim())
                            .map_err(|_| AgeError::InvalidRecipient(recipient.clone()))
                    })
                    .collect::<Result<Vec<_>>>()?;
                Encryptor::with_recipients(parsed.iter().map(|one| one as &dyn Recipient))
                    .map_err(|_| AgeError::NoRecipients)?
            }
            Target::Passphrase(passphrase) => {
                let recipient = scrypt::Recipient::new(SecretString::from(*passphrase));
                Encryptor::with_recipients(iter::once(&recipient as &dyn Recipient))
                    .map_err(|_| AgeError::NoRecipients)?
            }
        };
        let format = if armor {
            Format::AsciiArmor
        } else {
            Format::Binary
        };
        let armored = ArmoredWriter::wrap_output(output, format)?;
        Ok(Self {
            inner: encryptor.wrap_output(armored)?,
        })
    }

    /// Ends the file. Returns the output after everything was written to it.
    pub fn finish(self) -> Result<W> {
        Ok(self.inner.finish()?.finish()?)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Reads the plaintext of an age file. A read fails on the first chunk that doesn't check out, so
/// a file is only whole once this has reached its end without an error.
pub struct DecryptReader<R: Read> {
    inner: StreamReader<ArmoredReader<BufReader<R>>>,
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

/// An age file whose header was read. Tells which kind of key it needs before anything is asked.
pub struct Opening<R: Read> {
    decryptor: Decryptor<ArmoredReader<BufReader<R>>>,
}

impl<R: Read> Opening<R> {
    /// Reads the header; plain and armored files are told apart here.
    pub fn new(input: R) -> Result<Self> {
        let decryptor = Decryptor::new(ArmoredReader::new(input)).map_err(|error| match error {
            DecryptError::Io(error)
                if !matches!(
                    error.kind(),
                    io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
                ) =>
            {
                AgeError::Io(error)
            }
            _ => AgeError::Malformed,
        })?;
        Ok(Self { decryptor })
    }

    pub fn needs_passphrase(&self) -> bool {
        self.decryptor.is_scrypt()
    }

    /// Checks the keys against the header. The file key is found here; the content is checked as
    /// it's read.
    pub fn decrypt(self, keys: &Keys) -> Result<DecryptReader<R>> {
        let inner = if self.decryptor.is_scrypt() {
            let passphrase = keys
                .passphrase
                .as_ref()
                .ok_or(AgeError::PassphraseRequired)?;
            let identity = scrypt::Identity::new(SecretString::from(passphrase.as_str()));
            self.decryptor
                .decrypt(iter::once(&identity as &dyn Identity))?
        } else {
            if keys.identities.is_empty() {
                return Err(if keys.passphrase.is_some() {
                    AgeError::NotPassphraseEncrypted
                } else {
                    AgeError::NoMatchingKey
                });
            }
            let parsed = keys
                .identities
                .iter()
                .map(|one| {
                    x25519::Identity::from_str(one.trim()).map_err(|_| AgeError::InvalidIdentity)
                })
                .collect::<Result<Vec<_>>>()?;
            self.decryptor
                .decrypt(parsed.iter().map(|one| one as &dyn Identity))?
        };
        Ok(DecryptReader { inner })
    }
}

/// The identities in the text of an age identity file: `AGE-SECRET-KEY-1…` lines; `#` comments and
/// blank lines are skipped. A line that's neither is an error, so a mistyped key isn't dropped.
pub fn parse_identity_file(text: &str) -> Result<Vec<Zeroizing<String>>> {
    let mut identities = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        x25519::Identity::from_str(line).map_err(|_| AgeError::InvalidIdentity)?;
        identities.push(Zeroizing::new(line.to_owned()));
    }
    Ok(identities)
}

/// Whether these first bytes of a file look like age, plain or armored.
pub fn looks_encrypted(head: &[u8]) -> bool {
    head.starts_with(MAGIC) || head.starts_with(ARMOR_MAGIC)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    fn seal(target: &Target<'_>, armor: bool, plaintext: &[u8]) -> Vec<u8> {
        let mut writer = EncryptWriter::new(target, armor, Vec::new()).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap()
    }

    fn open(file: &[u8], keys: &Keys) -> Result<Vec<u8>> {
        let opening = Opening::new(Cursor::new(file))?;
        let mut reader = opening.decrypt(keys)?;
        let mut out = Vec::new();
        reader.read_to_end(&mut out)?;
        Ok(out)
    }

    fn pairs(seed: u8) -> AccountKeyPairs {
        AccountKeyPairs::generate(&mut ChaCha20Rng::from_seed([seed; 32]))
    }

    fn identity_keys(identity: &str) -> Keys {
        Keys {
            identities: vec![Zeroizing::new(identity.to_owned())],
            ..Keys::default()
        }
    }

    #[test]
    fn matches_the_age_spec_key_encoding() {
        // The key pair in the `age` crate's own tests.
        let identity = "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";
        let recipient = "age1t7rxyev2z3rw82stdlrrepyc39nvn86l5078zqkf5uasdy86jp6svpy7pa";
        assert_eq!(recipient_of(identity).unwrap(), recipient);
        let bytes = [0x42u8; 32];
        let derived = recipient_of(&identity_string(&bytes)).unwrap();
        assert_eq!(check_recipient(&derived).unwrap(), derived);
    }

    #[test]
    fn recipients_and_identities_round_trip() {
        let keys = AccountFileKeys::derive(&pairs(1)).unwrap();
        let plaintext = vec![7u8; 200_000];
        for armor in [false, true] {
            let file = seal(
                &Target::Recipients(&[keys.file_recipient.clone()]),
                armor,
                &plaintext,
            );
            assert!(looks_encrypted(&file));
            assert_eq!(
                open(&file, &identity_keys(&keys.file_identity)).unwrap(),
                plaintext
            );
        }
    }

    #[test]
    fn another_account_opens_a_file_with_its_account_key_only() {
        let alice = AccountFileKeys::derive(&pairs(1)).unwrap();
        let bob = AccountFileKeys::derive(&pairs(2)).unwrap();
        let file = seal(
            &Target::Recipients(&[bob.account_recipient.clone()]),
            false,
            b"hello",
        );
        assert_eq!(
            open(
                &file,
                &Keys {
                    identities: bob.identities(),
                    ..Keys::default()
                }
            )
            .unwrap(),
            b"hello"
        );
        assert!(matches!(
            open(
                &file,
                &Keys {
                    identities: alice.identities(),
                    ..Keys::default()
                }
            ),
            Err(AgeError::NoMatchingKey)
        ));
    }

    #[test]
    fn the_file_identity_is_stable_and_not_the_account_key() {
        let one = AccountFileKeys::derive(&pairs(1)).unwrap();
        let again = AccountFileKeys::derive(&pairs(1)).unwrap();
        let other = AccountFileKeys::derive(&pairs(2)).unwrap();
        assert_eq!(*one.file_identity, *again.file_identity);
        assert_ne!(*one.file_identity, *one.account_identity);
        assert_ne!(*one.file_identity, *other.file_identity);
        assert_eq!(
            one.account_recipient,
            account_recipient(&pairs(1).public_enc_key())
        );
    }

    #[test]
    fn passphrases_round_trip_and_fail_cleanly() {
        let file = seal(&Target::Passphrase("correct horse"), false, b"hi");
        let opening = Opening::new(Cursor::new(&file)).unwrap();
        assert!(opening.needs_passphrase());
        let with = |text: &str| Keys {
            passphrase: Some(Zeroizing::new(text.to_owned())),
            ..Keys::default()
        };
        assert_eq!(open(&file, &with("correct horse")).unwrap(), b"hi");
        assert!(matches!(
            open(&file, &with("wrong")),
            Err(AgeError::WrongPassphrase)
        ));
        assert!(matches!(
            open(&file, &Keys::default()),
            Err(AgeError::PassphraseRequired)
        ));
    }

    #[test]
    fn a_passphrase_file_refuses_identities_and_vice_versa() {
        let keys = AccountFileKeys::derive(&pairs(1)).unwrap();
        let file = seal(
            &Target::Recipients(&[keys.file_recipient.clone()]),
            false,
            b"hi",
        );
        assert!(matches!(
            open(
                &file,
                &Keys {
                    passphrase: Some(Zeroizing::new("x".into())),
                    ..Keys::default()
                }
            ),
            Err(AgeError::NotPassphraseEncrypted)
        ));
    }

    #[test]
    fn tampering_and_truncation_are_caught() {
        let keys = AccountFileKeys::derive(&pairs(1)).unwrap();
        let identity = identity_keys(&keys.file_identity);
        let file = seal(
            &Target::Recipients(&[keys.file_recipient.clone()]),
            false,
            &vec![1u8; 100_000],
        );
        let mut flipped = file.clone();
        let middle = flipped.len() / 2;
        flipped[middle] ^= 1;
        assert!(open(&flipped, &identity).is_err());
        assert!(open(&file[..file.len() - 40], &identity).is_err());
        // At a chunk boundary too.
        assert!(open(&file[..file.len() - 34_000], &identity).is_err());
    }

    #[test]
    fn rubbish_is_not_an_age_file() {
        assert!(matches!(
            Opening::new(Cursor::new(b"hello world, not encrypted")),
            Err(AgeError::Malformed)
        ));
        assert!(!looks_encrypted(b"hello"));
    }

    #[test]
    fn bad_keys_are_named() {
        assert!(matches!(
            check_recipient("age1nope"),
            Err(AgeError::InvalidRecipient(_))
        ));
        assert!(matches!(
            EncryptWriter::new(&Target::Recipients(&[]), false, Vec::new()).err(),
            Some(AgeError::NoRecipients)
        ));
        assert!(parse_identity_file("AGE-SECRET-KEY-NOPE").is_err());
        let identity = identity_string(&[3; 32]);
        let parsed = parse_identity_file(&format!("# created\n\n{}\n", identity.as_str())).unwrap();
        assert_eq!(parsed.len(), 1);
    }
}
