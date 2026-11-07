//! SSH keys (plans 01 and 16): generate, read and write them, on the device only.
//!
//! The vault keeps a key as an OpenSSH private key without a passphrase (the vault encrypts it),
//! next to what lists and other apps show without reading it: the public key, its type and its
//! SHA256 fingerprint, as `ssh-keygen -l` shows them. A passphrase only protects copies written out
//! of the vault. Keys are read from OpenSSH, PEM (PKCS#1 RSA, SEC1 EC, DSA) and PKCS#8 files, with
//! or without a passphrase.
//!
//! DSA keys and FIDO security key (`sk-`) keys are stored and show their public key, but can't be
//! used or converted yet: [`SshPublicInfo::usable`] is false for them.

use aes::{Aes128, Aes192, Aes256};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use md5::{Digest, Md5};
use pkcs8::der::{Decode as _, Tagged as _};
use pkcs8::{EncodePrivateKey, ObjectIdentifier};
use rand_core::CryptoRngCore;
use rsa::pkcs1::DecodeRsaPrivateKey;
use serde::{Deserialize, Serialize};
use ssh_encoding::{Decode as _, Encode as _};
use ssh_key::private::{DsaKeypair, EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, Mpint, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// The keys Octa Pass makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SshKeyKind {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa3072,
    Rsa4096,
}

/// What can be shown without the private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshPublicInfo {
    /// The SSH algorithm name: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, `ssh-dss`,
    /// `sk-ssh-ed25519@openssh.com`, …
    pub key_type: String,
    /// The size `ssh-keygen -l` shows: 256 for Ed25519, the curve for ECDSA, the modulus for RSA.
    pub bits: u32,
    /// `SHA256:` and the unpadded base64 digest of the public key, as `ssh-keygen -l -E sha256`.
    pub fingerprint: String,
    /// The public key without its comment: `ssh-ed25519 AAAA…`.
    pub public_key: String,
    pub comment: String,
    /// False for keys that are stored but can't be used yet: DSA, and FIDO (`sk-`) keys, which need
    /// their security key.
    pub usable: bool,
}

/// A key ready for the vault.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKey {
    /// OpenSSH format, without a passphrase.
    pub private_key: Zeroizing<String>,
    #[serde(flatten)]
    pub info: SshPublicInfo,
}

/// Makes a new key.
pub fn generate(kind: SshKeyKind, comment: &str, rng: &mut impl CryptoRngCore) -> Result<SshKey> {
    let keypair = match kind {
        SshKeyKind::Ed25519 => KeypairData::from(Ed25519Keypair::random(rng)),
        SshKeyKind::EcdsaP256 => ecdsa(rng, EcdsaCurve::NistP256)?,
        SshKeyKind::EcdsaP384 => ecdsa(rng, EcdsaCurve::NistP384)?,
        SshKeyKind::Rsa3072 => rsa_keypair(rng, 3072)?,
        SshKeyKind::Rsa4096 => rsa_keypair(rng, 4096)?,
    };
    let mut key = PrivateKey::new(keypair, comment).map_err(|_| Error::InvalidSshKey)?;
    // Like ssh-keygen: a random check number, so two copies of a file don't show they're the same key.
    key = PrivateKey::from_bytes(&with_checkint(&key, rng.next_u32())?)
        .map_err(|_| Error::InvalidSshKey)?;
    stored(key)
}

fn ecdsa(rng: &mut impl CryptoRngCore, curve: EcdsaCurve) -> Result<KeypairData> {
    EcdsaKeypair::random(rng, curve)
        .map(KeypairData::from)
        .map_err(|_| Error::InvalidSshKey)
}

fn rsa_keypair(rng: &mut impl CryptoRngCore, bits: usize) -> Result<KeypairData> {
    RsaKeypair::random(rng, bits)
        .map(KeypairData::from)
        .map_err(|_| Error::InvalidSshKey)
}

/// The key's binary OpenSSH encoding with both check numbers set to `checkint`.
fn with_checkint(key: &PrivateKey, checkint: u32) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = key.to_bytes().map_err(|_| Error::InvalidSshKey)?;
    // magic, "none" cipher, "none" KDF, empty KDF options, one key, the public key, then the
    // private section's length and its two check numbers.
    let mut at = AUTH_MAGIC.len() + (4 + 4) + (4 + 4) + 4 + 4;
    let public_len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
    at += 4 + public_len + 4;
    let check = checkint.to_be_bytes();
    bytes[at..at + 4].copy_from_slice(&check);
    bytes[at + 4..at + 8].copy_from_slice(&check);
    Ok(bytes)
}

const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// Reads a private key in OpenSSH, PEM or PKCS#8 form. Throws [`Error::SshPassphraseRequired`]
/// when it's protected and no passphrase was given, [`Error::WrongPassphrase`],
/// [`Error::SshPublicKeyOnly`] for a `.pub` file, [`Error::UnsupportedSshKey`] for formats and
/// ciphers that can't be read, and [`Error::InvalidSshKey`] for anything else.
pub fn read_private_key(text: &str, passphrase: Option<&str>) -> Result<SshKey> {
    let passphrase = passphrase.filter(|p| !p.is_empty());
    let text = text.trim_start_matches('\u{feff}').trim();
    let Some(pem) = Pem::parse(text) else {
        return Err(not_pem(text));
    };
    let key = match pem.label.as_str() {
        "OPENSSH PRIVATE KEY" => {
            let key = PrivateKey::from_bytes(&pem.body).map_err(|_| Error::InvalidSshKey)?;
            if key.is_encrypted() {
                let passphrase = passphrase.ok_or(Error::SshPassphraseRequired)?;
                key.decrypt(passphrase)
                    .map_err(|_| Error::WrongPassphrase)?
            } else {
                key
            }
        }
        "RSA PRIVATE KEY" | "EC PRIVATE KEY" | "DSA PRIVATE KEY" => {
            let der = match pem.header("DEK-Info") {
                Some(info) => legacy_decrypt(&pem.body, info, passphrase)?,
                None => pem.body.clone(),
            };
            let keypair = match pem.label.as_str() {
                "RSA PRIVATE KEY" => rsa_pkcs1(&der),
                "EC PRIVATE KEY" => sec1(&der, None),
                _ => dsa(&der),
            };
            // A wrong passphrase on a legacy PEM key usually breaks the padding, but not always.
            let keypair = keypair.map_err(|error| match pem.header("DEK-Info") {
                Some(_) if error == Error::InvalidSshKey => Error::WrongPassphrase,
                _ => error,
            })?;
            new_key(keypair, "")?
        }
        "PRIVATE KEY" => new_key(pkcs8_keypair(&pem.body)?, "")?,
        "ENCRYPTED PRIVATE KEY" => {
            let info = pkcs8::EncryptedPrivateKeyInfo::from_der(&pem.body)
                .map_err(|_| Error::UnsupportedSshKey)?;
            let passphrase = passphrase.ok_or(Error::SshPassphraseRequired)?;
            let der = info
                .decrypt(passphrase)
                .map_err(|_| Error::WrongPassphrase)?;
            new_key(
                pkcs8_keypair(der.as_bytes()).map_err(|error| match error {
                    Error::InvalidSshKey => Error::WrongPassphrase,
                    other => other,
                })?,
                "",
            )?
        }
        "SSH2 PUBLIC KEY" | "PUBLIC KEY" | "RSA PUBLIC KEY" => return Err(Error::SshPublicKeyOnly),
        _ => return Err(Error::UnsupportedSshKey),
    };
    stored(key)
}

/// Why text that isn't a PEM block can't be read.
fn not_pem(text: &str) -> Error {
    if text.starts_with("PuTTY-User-Key-File-") || text.starts_with("---- BEGIN SSH2") {
        return if text.starts_with("----") {
            Error::SshPublicKeyOnly
        } else {
            Error::UnsupportedSshKey
        };
    }
    if PublicKey::from_openssh(text.lines().next().unwrap_or_default()).is_ok() {
        return Error::SshPublicKeyOnly;
    }
    Error::InvalidSshKey
}

fn new_key(keypair: KeypairData, comment: &str) -> Result<PrivateKey> {
    PrivateKey::new(keypair, comment).map_err(|_| Error::InvalidSshKey)
}

/// The key as the vault keeps it, with what's shown next to it.
fn stored(key: PrivateKey) -> Result<SshKey> {
    let private_key = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| Error::InvalidSshKey)?;
    Ok(SshKey {
        private_key,
        info: info(key.public_key())?,
    })
}

fn info(public: &PublicKey) -> Result<SshPublicInfo> {
    let data = public.key_data();
    let bits = match data {
        KeyData::Ed25519(_) | KeyData::SkEd25519(_) | KeyData::SkEcdsaSha2NistP256(_) => 256,
        KeyData::Ecdsa(key) => match key.curve() {
            EcdsaCurve::NistP256 => 256,
            EcdsaCurve::NistP384 => 384,
            EcdsaCurve::NistP521 => 521,
        },
        KeyData::Rsa(key) => bit_length(&key.n),
        KeyData::Dsa(key) => bit_length(&key.p),
        _ => 0,
    };
    Ok(SshPublicInfo {
        key_type: public.algorithm().as_str().to_owned(),
        bits,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        public_key: PublicKey::new(data.clone(), "")
            .to_openssh()
            .map_err(|_| Error::InvalidSshKey)?,
        comment: public.comment().to_owned(),
        usable: matches!(
            data,
            KeyData::Ed25519(_) | KeyData::Ecdsa(_) | KeyData::Rsa(_)
        ),
    })
}

fn bit_length(n: &Mpint) -> u32 {
    match n.as_positive_bytes() {
        Some([first, rest @ ..]) => rest.len() as u32 * 8 + (8 - first.leading_zeros()),
        _ => 0,
    }
}

/// Reads a public key line (`.pub`, `authorized_keys`): its type, size and fingerprint.
pub fn read_public_key(line: &str) -> Result<SshPublicInfo> {
    let line = line.trim();
    let key = PublicKey::from_openssh(line).map_err(|_| Error::InvalidSshKey)?;
    info(&key)
}

/// The `authorized_keys` line for a stored public key and comment.
pub fn authorized_keys_line(public_key: &str, comment: &str) -> String {
    let comment = comment.trim();
    if comment.is_empty() {
        public_key.trim().to_owned()
    } else {
        format!("{} {comment}", public_key.trim())
    }
}

/// A stored key as an OpenSSH private key file, with `comment`, protected by `passphrase` when
/// one is given (aes256-ctr and bcrypt-pbkdf, as ssh-keygen writes them).
pub fn write_private_key(
    private_key: &str,
    comment: &str,
    passphrase: Option<&str>,
    rng: &mut impl CryptoRngCore,
) -> Result<Zeroizing<String>> {
    let mut key = parse_stored(private_key)?;
    key.set_comment(comment.trim());
    let key = match passphrase.filter(|p| !p.is_empty()) {
        Some(passphrase) => key
            .encrypt(rng, passphrase)
            .map_err(|_| Error::EncryptionFailed)?,
        None => key,
    };
    key.to_openssh(LineEnding::LF)
        .map_err(|_| Error::InvalidSshKey)
}

fn parse_stored(private_key: &str) -> Result<PrivateKey> {
    let key = read_private_key(private_key, None)?;
    PrivateKey::from_openssh(key.private_key.as_bytes()).map_err(|_| Error::InvalidSshKey)
}

/// A stored key as PKCS#8 DER, as Credential Exchange carries it. Only usable keys convert.
pub fn to_pkcs8_der(private_key: &str) -> Result<Zeroizing<Vec<u8>>> {
    let key = parse_stored(private_key)?;
    let der = match key.key_data() {
        KeypairData::Ed25519(pair) => ed25519_dalek::SigningKey::from(&pair.private).to_pkcs8_der(),
        KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) => {
            p256::SecretKey::from_slice(private.as_slice())
                .map_err(|_| Error::InvalidSshKey)?
                .to_pkcs8_der()
        }
        KeypairData::Ecdsa(EcdsaKeypair::NistP384 { private, .. }) => {
            p384::SecretKey::from_slice(private.as_slice())
                .map_err(|_| Error::InvalidSshKey)?
                .to_pkcs8_der()
        }
        KeypairData::Ecdsa(EcdsaKeypair::NistP521 { private, .. }) => {
            p521::SecretKey::from_slice(private.as_slice())
                .map_err(|_| Error::InvalidSshKey)?
                .to_pkcs8_der()
        }
        KeypairData::Rsa(pair) => rsa_private(pair)?.to_pkcs8_der(),
        _ => return Err(Error::UnsupportedSshKey),
    };
    Ok(Zeroizing::new(
        der.map_err(|_| Error::InvalidSshKey)?.as_bytes().to_vec(),
    ))
}

/// ssh-key 0.6.7's own conversion passes `p` twice instead of `p` and `q`, so the key is built
/// from its parts here.
fn rsa_private(pair: &RsaKeypair) -> Result<rsa::RsaPrivateKey> {
    let int = |n: &Mpint| {
        n.as_positive_bytes()
            .map(rsa::BigUint::from_bytes_be)
            .ok_or(Error::InvalidSshKey)
    };
    rsa::RsaPrivateKey::from_components(
        int(&pair.public.n)?,
        int(&pair.public.e)?,
        int(&pair.private.d)?,
        vec![int(&pair.private.p)?, int(&pair.private.q)?],
    )
    .map_err(|_| Error::InvalidSshKey)
}

/// Reads a PKCS#8 DER private key (Credential Exchange), with `comment`.
pub fn from_pkcs8_der(der: &[u8], comment: &str) -> Result<SshKey> {
    stored(new_key(pkcs8_keypair(der)?, comment)?)
}

// ---------- PEM ----------

/// One PEM block, with the headers legacy encrypted keys have (`Proc-Type`, `DEK-Info`).
struct Pem {
    label: String,
    headers: Vec<(String, String)>,
    body: Zeroizing<Vec<u8>>,
}

impl Pem {
    /// The first `-----BEGIN …-----` block in `text`.
    fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines().map(str::trim);
        let label = lines.find_map(|line| {
            line.strip_prefix("-----BEGIN ")?
                .strip_suffix("-----")
                .map(str::to_owned)
        })?;
        let end = format!("-----END {label}-----");
        let mut headers = Vec::new();
        let mut body = Zeroizing::new(String::new());
        let mut ended = false;
        for line in lines {
            if line == end {
                ended = true;
                break;
            }
            match line.split_once(':') {
                Some((name, value)) if body.is_empty() => {
                    headers.push((name.trim().to_owned(), value.trim().to_owned()))
                }
                _ => body.push_str(line),
            }
        }
        if !ended {
            return None;
        }
        let body = Zeroizing::new(STANDARD.decode(body.as_bytes()).ok()?);
        Some(Self {
            label,
            headers,
            body,
        })
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Decrypts a legacy OpenSSL PEM body (`DEK-Info: AES-128-CBC,<iv>`): the key comes from MD5 of
/// the passphrase and the IV's first 8 bytes (OpenSSL's `EVP_BytesToKey`, one round).
fn legacy_decrypt(
    body: &[u8],
    dek_info: &str,
    passphrase: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    let (cipher, iv) = dek_info.split_once(',').ok_or(Error::InvalidSshKey)?;
    let key_len = match cipher.trim().to_ascii_uppercase().as_str() {
        "AES-128-CBC" => 16,
        "AES-192-CBC" => 24,
        "AES-256-CBC" => 32,
        _ => return Err(Error::UnsupportedSshKey),
    };
    let iv = hex(iv.trim()).ok_or(Error::InvalidSshKey)?;
    if iv.len() != 16 {
        return Err(Error::InvalidSshKey);
    }
    let passphrase = passphrase.ok_or(Error::SshPassphraseRequired)?;
    let mut key = Zeroizing::new(Vec::with_capacity(48));
    let mut previous: Option<Zeroizing<Vec<u8>>> = None;
    while key.len() < key_len {
        let mut md5 = Md5::new();
        if let Some(previous) = &previous {
            md5.update(previous.as_slice());
        }
        md5.update(passphrase.as_bytes());
        md5.update(&iv[..8]);
        let block = Zeroizing::new(md5.finalize().to_vec());
        key.extend_from_slice(&block);
        previous = Some(block);
    }
    let key = &key[..key_len];
    let mut buffer = Zeroizing::new(body.to_vec());
    let len = match key_len {
        16 => cbc::Decryptor::<Aes128>::new_from_slices(key, &iv)
            .map_err(|_| Error::InvalidSshKey)?
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map(|plain| plain.len()),
        24 => cbc::Decryptor::<Aes192>::new_from_slices(key, &iv)
            .map_err(|_| Error::InvalidSshKey)?
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map(|plain| plain.len()),
        _ => cbc::Decryptor::<Aes256>::new_from_slices(key, &iv)
            .map_err(|_| Error::InvalidSshKey)?
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map(|plain| plain.len()),
    }
    .map_err(|_| Error::WrongPassphrase)?;
    buffer.truncate(len);
    Ok(buffer)
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

// ---------- DER ----------

/// One DER element: its tag, its contents and what follows it.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let len = rest[..count]
            .iter()
            .fold(0usize, |n, &b| (n << 8) | b as usize);
        (len, &rest[count..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// A DER INTEGER's unsigned big-endian bytes.
fn integer(input: &[u8]) -> Option<(&[u8], &[u8])> {
    match tlv(input)? {
        (0x02, value, rest) => Some((value, rest)),
        _ => None,
    }
}

fn rsa_pkcs1(der: &[u8]) -> Result<KeypairData> {
    let key = rsa::RsaPrivateKey::from_pkcs1_der(der).map_err(|_| Error::InvalidSshKey)?;
    RsaKeypair::try_from(&key)
        .map(KeypairData::from)
        .map_err(|_| Error::UnsupportedSshKey)
}

/// `DSA PRIVATE KEY`: `SEQUENCE { 0, p, q, g, y, x }`.
fn dsa(der: &[u8]) -> Result<KeypairData> {
    let read = || -> Option<Zeroizing<Vec<u8>>> {
        let (0x30, mut rest, _) = tlv(der)? else {
            return None;
        };
        let (version, after) = integer(rest)?;
        if version != [0] {
            return None;
        }
        rest = after;
        let mut wire = Zeroizing::new(Vec::new());
        for _ in 0..5 {
            let (value, after) = integer(rest)?;
            Mpint::from_positive_bytes(value)
                .ok()?
                .encode(&mut *wire)
                .ok()?;
            rest = after;
        }
        Some(wire)
    };
    let wire = read().ok_or(Error::InvalidSshKey)?;
    DsaKeypair::decode(&mut wire.as_slice())
        .map(KeypairData::from)
        .map_err(|_| Error::InvalidSshKey)
}

#[derive(Clone, Copy)]
enum Curve {
    P256,
    P384,
    P521,
}

// The named curves' OIDs, and their primes for keys written with explicit parameters (LibreSSL).
const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384_OID: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const P521_OID: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const P256_PRIME: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const P384_PRIME: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";

/// The curve named by EC parameters: a named curve's OID, or explicit parameters whose prime is
/// one of the NIST curves'.
fn curve_of(tag: u8, value: &[u8]) -> Result<Curve> {
    match tag {
        0x06 if value == P256_OID => Ok(Curve::P256),
        0x06 if value == P384_OID => Ok(Curve::P384),
        0x06 if value == P521_OID => Ok(Curve::P521),
        0x30 => {
            // SEQUENCE { version, SEQUENCE { prime-field OID, prime }, curve, base, order, … }
            let prime = (|| {
                let (_, rest) = integer(value)?;
                let (0x30, field, _) = tlv(rest)? else {
                    return None;
                };
                let (0x06, _, field) = tlv(field)? else {
                    return None;
                };
                integer(field).map(|(prime, _)| prime)
            })()
            .ok_or(Error::InvalidSshKey)?;
            let prime: Vec<u8> = prime.iter().copied().skip_while(|&b| b == 0).collect();
            if Some(&prime) == hex(P256_PRIME).as_ref() {
                Ok(Curve::P256)
            } else if Some(&prime) == hex(P384_PRIME).as_ref() {
                Ok(Curve::P384)
            } else if prime.len() == 66 && prime[0] == 0x01 && prime[1..].iter().all(|&b| b == 0xff)
            {
                Ok(Curve::P521)
            } else {
                Err(Error::UnsupportedSshKey)
            }
        }
        _ => Err(Error::UnsupportedSshKey),
    }
}

/// `EC PRIVATE KEY` (SEC1): `SEQUENCE { 1, privateKey, [0] parameters, [1] publicKey }`. PKCS#8
/// keys pass the curve from their algorithm, since the inner key may leave it out.
fn sec1(der: &[u8], curve: Option<Curve>) -> Result<KeypairData> {
    let (0x30, rest, _) = tlv(der).ok_or(Error::InvalidSshKey)? else {
        return Err(Error::InvalidSshKey);
    };
    let (version, rest) = integer(rest).ok_or(Error::InvalidSshKey)?;
    let (0x04, private, mut rest) = tlv(rest).ok_or(Error::InvalidSshKey)? else {
        return Err(Error::InvalidSshKey);
    };
    if version != [1] {
        return Err(Error::InvalidSshKey);
    }
    let mut curve = curve;
    let mut public = None;
    while let Some((tag, value, after)) = tlv(rest) {
        match tag {
            0xa0 => {
                let (tag, value, _) = tlv(value).ok_or(Error::InvalidSshKey)?;
                curve = Some(curve_of(tag, value)?);
            }
            0xa1 => match tlv(value) {
                Some((0x03, [0, point @ ..], _)) => public = Some(point),
                _ => return Err(Error::InvalidSshKey),
            },
            _ => {}
        }
        rest = after;
    }
    let curve = curve.ok_or(Error::UnsupportedSshKey)?;
    macro_rules! keypair {
        ($crate_:ident, $variant:ident) => {{
            let secret =
                $crate_::SecretKey::from_slice(private).map_err(|_| Error::InvalidSshKey)?;
            let point = secret.public_key();
            if let Some(public) = public {
                if $crate_::PublicKey::from_sec1_bytes(public).ok() != Some(point) {
                    return Err(Error::InvalidSshKey);
                }
            }
            EcdsaKeypair::$variant {
                public: point.into(),
                private: secret.into(),
            }
        }};
    }
    let keypair = match curve {
        Curve::P256 => keypair!(p256, NistP256),
        Curve::P384 => keypair!(p384, NistP384),
        Curve::P521 => keypair!(p521, NistP521),
    };
    Ok(KeypairData::from(keypair))
}

const RSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// `PRIVATE KEY` (PKCS#8): RSA, EC or Ed25519.
fn pkcs8_keypair(der: &[u8]) -> Result<KeypairData> {
    let info = pkcs8::PrivateKeyInfo::from_der(der).map_err(|_| Error::InvalidSshKey)?;
    let oid = info.algorithm.oid;
    if oid == RSA_OID {
        rsa_pkcs1(info.private_key)
    } else if oid == EC_OID {
        let params = info.algorithm.parameters.ok_or(Error::InvalidSshKey)?;
        let curve = curve_of(params.tag().octet(), params.value())?;
        sec1(info.private_key, Some(curve))
    } else if oid == ED25519_OID {
        // An OCTET STRING holding the 32-byte seed.
        match tlv(info.private_key) {
            Some((0x04, seed, _)) => {
                let seed: &[u8; 32] = seed.try_into().map_err(|_| Error::InvalidSshKey)?;
                Ok(KeypairData::from(Ed25519Keypair::from_seed(seed)))
            }
            _ => Err(Error::InvalidSshKey),
        }
    } else {
        Err(Error::UnsupportedSshKey)
    }
}

// ---------- Signing ----------

/// `SSH_AGENT_RSA_SHA2_256` in an agent's sign request: an `rsa-sha2-256` signature.
#[cfg(feature = "ssh-sign")]
pub const RSA_SHA2_256: u32 = 2;
/// `SSH_AGENT_RSA_SHA2_512` in an agent's sign request: an `rsa-sha2-512` signature.
#[cfg(feature = "ssh-sign")]
pub const RSA_SHA2_512: u32 = 4;

/// Signs `data` with a stored key, as an SSH agent does: the result is the signature's wire form,
/// `string format ‖ string blob`. `flags` picks the RSA hash; without one, RSA keys refuse
/// ([`Error::SshSignatureRefused`]), because the old `ssh-rsa` signatures use SHA-1.
///
/// Ed25519 and ECDSA sign with the RustCrypto crates. RSA signs with `ring`, never the `rsa`
/// crate: RUSTSEC-2023-0071 (plan 16).
#[cfg(feature = "ssh-sign")]
pub fn sign(private_key: &str, data: &[u8], flags: u32) -> Result<Vec<u8>> {
    let hash = if flags & RSA_SHA2_512 != 0 {
        HashAlg::Sha512
    } else if flags & RSA_SHA2_256 != 0 {
        HashAlg::Sha256
    } else {
        // Only RSA looks at it.
        HashAlg::Sha512
    };
    let rsa_allowed = flags & (RSA_SHA2_256 | RSA_SHA2_512) != 0;
    let signature = raw_signature(&parse_stored(private_key)?, data, hash, rsa_allowed)?;
    signature.to_vec_encoded()
}

#[cfg(feature = "ssh-sign")]
trait EncodedSignature {
    fn to_vec_encoded(&self) -> Result<Vec<u8>>;
}

#[cfg(feature = "ssh-sign")]
impl EncodedSignature for ssh_key::Signature {
    fn to_vec_encoded(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.encode(&mut bytes).map_err(|_| Error::InvalidSshKey)?;
        Ok(bytes)
    }
}

#[cfg(feature = "ssh-sign")]
fn raw_signature(
    key: &PrivateKey,
    data: &[u8],
    hash: HashAlg,
    rsa_allowed: bool,
) -> Result<ssh_key::Signature> {
    use ed25519_dalek::Signer as _;
    match key.key_data() {
        KeypairData::Ed25519(_) | KeypairData::Ecdsa(_) => key
            .key_data()
            .try_sign(data)
            .map_err(|_| Error::SshSignatureRefused),
        KeypairData::Rsa(pair) if rsa_allowed => rsa_sign(pair, data, hash),
        KeypairData::Rsa(_) => Err(Error::SshSignatureRefused),
        _ => Err(Error::UnsupportedSshKey),
    }
}

/// `ring` wants the key as PKCS#1 DER, with its CRT values. Building that uses the `rsa` crate's
/// big numbers once, on the key alone: no attacker-chosen input reaches it, which is what the
/// Marvin attack needs.
#[cfg(feature = "ssh-sign")]
fn rsa_sign(pair: &RsaKeypair, data: &[u8], hash: HashAlg) -> Result<ssh_key::Signature> {
    use ring::signature::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA512, RsaKeyPair};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    let der = rsa_private(pair)?
        .to_pkcs1_der()
        .map_err(|_| Error::InvalidSshKey)?;
    let keypair = RsaKeyPair::from_der(der.as_bytes()).map_err(|_| Error::SshSignatureRefused)?;
    let padding = match hash {
        HashAlg::Sha256 => &RSA_PKCS1_SHA256,
        _ => &RSA_PKCS1_SHA512,
    };
    let mut signature = vec![0u8; keypair.public().modulus_len()];
    keypair
        .sign(
            padding,
            &ring::rand::SystemRandom::new(),
            data,
            &mut signature,
        )
        .map_err(|_| Error::SshSignatureRefused)?;
    ssh_key::Signature::new(Algorithm::Rsa { hash: Some(hash) }, signature)
        .map_err(|_| Error::SshSignatureRefused)
}

/// A detached signature in OpenSSH's SSHSIG format (`ssh-keygen -Y sign`): what Git stores in a
/// commit signed with an SSH key, for `namespace` `git`. SHA-512, as `ssh-keygen` does.
#[cfg(feature = "ssh-sign")]
pub fn sign_sshsig(private_key: &str, namespace: &str, data: &[u8]) -> Result<String> {
    let key = parse_stored(private_key)?;
    let signed = ssh_key::SshSig::signed_data(namespace, HashAlg::Sha512, data)
        .map_err(|_| Error::SshSignatureRefused)?;
    let signature = raw_signature(&key, &signed, HashAlg::Sha512, true)?;
    ssh_key::SshSig::new(
        key.public_key().key_data().clone(),
        namespace,
        HashAlg::Sha512,
        signature,
    )
    .and_then(|sig| sig.to_pem(LineEnding::LF))
    .map_err(|_| Error::SshSignatureRefused)
}

/// The SSH wire form of a public key line (`ssh-ed25519 AAAA…`): what agents and sign requests
/// name a key by.
pub fn public_key_blob(public_key: &str) -> Result<Vec<u8>> {
    PublicKey::from_openssh(public_key.trim())
        .map_err(|_| Error::InvalidSshKey)?
        .to_bytes()
        .map_err(|_| Error::InvalidSshKey)
}

/// The algorithm a stored key would be generated with, for tests and callers that check it.
pub fn algorithm_of(kind: SshKeyKind) -> Algorithm {
    match kind {
        SshKeyKind::Ed25519 => Algorithm::Ed25519,
        SshKeyKind::EcdsaP256 => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        SshKeyKind::EcdsaP384 => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        SshKeyKind::Rsa3072 | SshKeyKind::Rsa4096 => Algorithm::Rsa { hash: None },
    }
}
