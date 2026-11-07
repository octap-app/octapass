//! One-time share links: an item snapshot encrypted under a random key that travels in the
//! link's fragment (`https://<host>/s/<id>#<key>`), which browsers never send to the server.
//!
//! ```text
//! link_key    = 32 random bytes, the fragment (base64url)
//! pass_key    = Argon2id(NFKD(passphrase), salt, params)            only with a passphrase
//! content_key = HKDF-SHA256(ikm = link_key [‖ pass_key], salt = "", info = "openpass/v1/share-link")
//! ciphertext  = header ‖ nonce (24) ‖ XChaCha20-Poly1305(content_key, item JSON,
//!                                                       aad = "openpass/v1|share-link|" ‖ header)
//! header      = 0x01 ‖ flags (1)                                    no passphrase: flags = 0
//!             | 0x01 ‖ 0x01 ‖ salt (16) ‖ memory_kib ‖ iterations ‖ parallelism (u32 BE each)
//! ```
//!
//! The passphrase adds a second secret for links sent over a channel that might leak, such as
//! a chat that stores message history: the link alone no longer opens the item.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::encoding::{b64_decode, b64_decode_array, b64_encode};
use crate::envelope::{NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::item::Item;
use crate::kdf::{KdfAlgorithm, KdfParams, normalize_password};
use crate::keys::{KEY_LEN, SymmetricKey, hkdf_key};

const VERSION: u8 = 0x01;
const FLAG_PASSPHRASE: u8 = 0x01;
const SALT_LEN: usize = 16;
const PLAIN_HEADER_LEN: usize = 2;
const PASSPHRASE_HEADER_LEN: usize = PLAIN_HEADER_LEN + SALT_LEN + 12;

/// What `POST /v1/share-links` uploads (`ciphertext`) and what stays in the link (`key`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareLink {
    pub ciphertext: String,
    /// The link fragment: base64url of the 32-byte link key.
    pub key: String,
    pub passphrase_required: bool,
}

/// Encrypts a snapshot of `item`. With a passphrase this runs Argon2id (about a second).
pub fn create(
    item: &Item,
    passphrase: Option<&str>,
    rng: &mut impl CryptoRngCore,
) -> Result<ShareLink> {
    create_with_params(item, passphrase, KdfParams::DEFAULT, rng)
}

fn create_with_params(
    item: &Item,
    passphrase: Option<&str>,
    params: KdfParams,
    rng: &mut impl CryptoRngCore,
) -> Result<ShareLink> {
    let link_key = SymmetricKey::generate(rng);
    let mut header = vec![VERSION, 0];
    let passphrase = match passphrase {
        Some(passphrase) => {
            let mut salt = [0u8; SALT_LEN];
            rng.fill_bytes(&mut salt);
            header[1] = FLAG_PASSPHRASE;
            header.extend_from_slice(&salt);
            for value in [params.memory_kib, params.iterations, params.parallelism] {
                header.extend_from_slice(&value.to_be_bytes());
            }
            Some((passphrase, salt, params))
        }
        None => None,
    };
    let content_key = content_key(&link_key, passphrase)?;

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let plaintext = Zeroizing::new(item.to_json());
    let ciphertext = XChaCha20Poly1305::new(content_key.as_bytes().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &associated_data(&header),
            },
        )
        .map_err(|_| Error::EncryptionFailed)?;

    let passphrase_required = passphrase.is_some();
    let mut out = header;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(ShareLink {
        ciphertext: b64_encode(&out),
        key: b64_encode(link_key.as_bytes()),
        passphrase_required,
    })
}

/// Whether the ciphertext needs a passphrase as well as the link key, so a viewer page knows to
/// ask for one before calling [`open`].
pub fn needs_passphrase(ciphertext: &str) -> Result<bool> {
    let bytes = b64_decode(ciphertext)?;
    Ok(parse_header(&bytes)?.passphrase.is_some())
}

/// Decrypts a share link. Fails with [`Error::WrongPassphrase`] when the passphrase is missing
/// or wrong, and [`Error::InvalidShareLink`] when the key or ciphertext don't belong together.
pub fn open(ciphertext: &str, key: &str, passphrase: Option<&str>) -> Result<Item> {
    // The header comes from the server: refuse Argon2id parameters a client wouldn't pick.
    open_checked(ciphertext, key, passphrase, KdfParams::validate)
}

fn open_checked(
    ciphertext: &str,
    key: &str,
    passphrase: Option<&str>,
    check_params: impl Fn(&KdfParams) -> Result<()>,
) -> Result<Item> {
    let bytes = b64_decode(ciphertext)?;
    let header = parse_header(&bytes)?;
    let passphrase = match (passphrase, header.passphrase) {
        (Some(passphrase), Some((salt, params))) => {
            check_params(&params)?;
            Some((passphrase, salt, params))
        }
        (None, None) => None,
        _ => return Err(Error::WrongPassphrase),
    };
    let link_key = SymmetricKey::from_bytes(
        b64_decode_array::<KEY_LEN>(key).map_err(|_| Error::InvalidShareLink)?,
    );
    let content_key = content_key(&link_key, passphrase)?;
    let (head, body) = bytes.split_at(header.len);
    let plaintext = XChaCha20Poly1305::new(content_key.as_bytes().into())
        .decrypt(
            XNonce::from_slice(&body[..NONCE_LEN]),
            Payload {
                msg: &body[NONCE_LEN..],
                aad: &associated_data(head),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| match passphrase {
            Some(_) => Error::WrongPassphrase,
            None => Error::InvalidShareLink,
        })?;
    let json = core::str::from_utf8(&plaintext).map_err(|_| Error::InvalidItem)?;
    Item::from_json(json)
}

struct Header {
    len: usize,
    /// The Argon2id salt and parameters, for a link with a passphrase.
    passphrase: Option<([u8; SALT_LEN], KdfParams)>,
}

fn parse_header(bytes: &[u8]) -> Result<Header> {
    if bytes.len() < PLAIN_HEADER_LEN + NONCE_LEN + TAG_LEN {
        return Err(Error::MalformedCiphertext);
    }
    if bytes[0] != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    match bytes[1] {
        0 => Ok(Header {
            len: PLAIN_HEADER_LEN,
            passphrase: None,
        }),
        FLAG_PASSPHRASE if bytes.len() >= PASSPHRASE_HEADER_LEN + NONCE_LEN + TAG_LEN => {
            let salt = bytes[PLAIN_HEADER_LEN..PLAIN_HEADER_LEN + SALT_LEN]
                .try_into()
                .expect("16 bytes");
            let word = |i: usize| {
                let at = PLAIN_HEADER_LEN + SALT_LEN + 4 * i;
                u32::from_be_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
            };
            let params = KdfParams {
                algorithm: KdfAlgorithm::Argon2id,
                memory_kib: word(0),
                iterations: word(1),
                parallelism: word(2),
            };
            Ok(Header {
                len: PASSPHRASE_HEADER_LEN,
                passphrase: Some((salt, params)),
            })
        }
        _ => Err(Error::MalformedCiphertext),
    }
}

fn content_key(
    link_key: &SymmetricKey,
    passphrase: Option<(&str, [u8; SALT_LEN], KdfParams)>,
) -> Result<SymmetricKey> {
    let mut ikm = Zeroizing::new(link_key.as_bytes().to_vec());
    if let Some((passphrase, salt, params)) = passphrase {
        ikm.extend_from_slice(passphrase_key(passphrase, &salt, &params)?.as_bytes());
    }
    Ok(hkdf_key(&ikm, b"", b"openpass/v1/share-link"))
}

fn passphrase_key(passphrase: &str, salt: &[u8], params: &KdfParams) -> Result<SymmetricKey> {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| Error::UnsupportedKdf)?,
    );
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(
            normalize_password(passphrase).as_bytes(),
            salt,
            out.as_mut(),
        )
        .map_err(|_| Error::KdfFailed)?;
    Ok(SymmetricKey::from_bytes(*out))
}

fn associated_data(header: &[u8]) -> Vec<u8> {
    [b"openpass/v1|share-link|".as_slice(), header].concat()
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    /// Cheap Argon2id parameters, only reachable from tests: `open` refuses them.
    const TEST_PARAMS: KdfParams = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    fn item() -> Item {
        Item::from_json(
            r#"{"overview":{"title":"Router","type":"login"},"details":{"username":"admin","password":"hunter2"}}"#,
        )
        .unwrap()
    }

    #[test]
    fn round_trips_without_a_passphrase() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let link = create(&item(), None, &mut rng).unwrap();
        assert!(!link.passphrase_required);
        assert!(!needs_passphrase(&link.ciphertext).unwrap());
        assert_eq!(open(&link.ciphertext, &link.key, None).unwrap(), item());
        assert_eq!(b64_decode(&link.key).unwrap().len(), 32);
    }

    #[test]
    fn the_wrong_key_does_not_open() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let link = create(&item(), None, &mut rng).unwrap();
        let other = create(&item(), None, &mut rng).unwrap();
        assert_eq!(
            open(&link.ciphertext, &other.key, None).err(),
            Some(Error::InvalidShareLink)
        );
        assert_eq!(
            open(&link.ciphertext, "short", None).err(),
            Some(Error::InvalidShareLink)
        );
    }

    #[test]
    fn a_passphrase_is_needed_and_checked() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let link =
            create_with_params(&item(), Some("correct horse"), TEST_PARAMS, &mut rng).unwrap();
        assert!(link.passphrase_required);
        assert!(needs_passphrase(&link.ciphertext).unwrap());
        let open_any =
            |passphrase| open_checked(&link.ciphertext, &link.key, passphrase, |_| Ok(()));
        assert_eq!(open_any(Some("correct horse")).unwrap(), item());
        assert_eq!(
            open_any(Some("Correct horse")).err(),
            Some(Error::WrongPassphrase)
        );
        assert_eq!(open_any(None).err(), Some(Error::WrongPassphrase));
        // `open` refuses the cheap parameters, as it would refuse a tampered header.
        assert_eq!(
            open(&link.ciphertext, &link.key, Some("correct horse")).err(),
            Some(Error::UnsupportedKdf)
        );
        let plain = create(&item(), None, &mut rng).unwrap();
        assert_eq!(
            open(&plain.ciphertext, &plain.key, Some("correct horse")).err(),
            Some(Error::WrongPassphrase)
        );
    }

    #[test]
    fn the_header_is_authenticated() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let link = create(&item(), None, &mut rng).unwrap();
        let mut bytes = b64_decode(&link.ciphertext).unwrap();
        bytes[0] = 2;
        assert_eq!(
            open(&b64_encode(&bytes), &link.key, None).err(),
            Some(Error::UnsupportedVersion)
        );
        bytes[0] = VERSION;
        bytes[1] = 7;
        assert_eq!(
            open(&b64_encode(&bytes), &link.key, None).err(),
            Some(Error::MalformedCiphertext)
        );
        assert_eq!(
            open(&b64_encode(&bytes[..10]), &link.key, None).err(),
            Some(Error::MalformedCiphertext)
        );
    }
}
