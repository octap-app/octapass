//! One model of asymmetric keys for the toolkit: generating, reading every common format, writing
//! them back, public keys, fingerprints and signatures (plan 16 §1–2). Certificates, JWTs and ACME
//! are built on it.
//!
//! RSA signing goes through the `rsa` crate's blinded operations. RUSTSEC-2023-0071 (Marvin) is a
//! timing side channel an attacker measures by making many remote requests; here the user runs a
//! private-key operation by hand on their own device, so nobody can collect those timings.

use der::pem::{self, LineEnding};
use der::{Decode, Encode};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rand_core::CryptoRngCore;
use rsa::pkcs1::{
    DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey,
};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256, Sha384, Sha512};
use ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey as SshRsaPublicKey};
use zeroize::Zeroizing;

use super::encode::{decode_base64, hex_encode};
use crate::encoding::{b64_decode, b64_encode};
use crate::error::{Error, Result};
use crate::tools::ssh;

/// Key types the toolkit makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    P256,
    P384,
    Ed25519,
}

/// Signature algorithms, named as JOSE names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    Es512,
    EdDsa,
}

impl SignatureAlgorithm {
    pub fn parse(name: &str) -> Result<Self> {
        Ok(match name {
            "RS256" => Self::Rs256,
            "RS384" => Self::Rs384,
            "RS512" => Self::Rs512,
            "PS256" => Self::Ps256,
            "PS384" => Self::Ps384,
            "PS512" => Self::Ps512,
            "ES256" => Self::Es256,
            "ES384" => Self::Es384,
            "ES512" => Self::Es512,
            "EdDSA" => Self::EdDsa,
            _ => return Err(Error::UnsupportedAlgorithm),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::EdDsa => "EdDSA",
        }
    }
}

/// A private key. Each variant wipes itself when dropped.
#[derive(Clone)]
pub enum PrivateKey {
    Rsa(Box<RsaPrivateKey>),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
    Ed25519(Box<ed25519_dalek::SigningKey>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Rsa(RsaPublicKey),
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    P521(p521::PublicKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

/// What a file or pasted text holds.
pub enum ParsedKey {
    Private(PrivateKey),
    Public(PublicKey),
}

impl ParsedKey {
    pub fn public(&self) -> PublicKey {
        match self {
            ParsedKey::Private(key) => key.public(),
            ParsedKey::Public(key) => key.clone(),
        }
    }
}

pub fn generate(kind: KeyKind, rng: &mut impl CryptoRngCore) -> Result<PrivateKey> {
    let rsa = |bits, rng: &mut _| {
        RsaPrivateKey::new(rng, bits)
            .map(|key| PrivateKey::Rsa(Box::new(key)))
            .map_err(|_| Error::InvalidKey)
    };
    match kind {
        KeyKind::Rsa2048 => rsa(2048, rng),
        KeyKind::Rsa3072 => rsa(3072, rng),
        KeyKind::Rsa4096 => rsa(4096, rng),
        KeyKind::P256 => Ok(PrivateKey::P256(p256::SecretKey::random(rng))),
        KeyKind::P384 => Ok(PrivateKey::P384(p384::SecretKey::random(rng))),
        KeyKind::Ed25519 => Ok(PrivateKey::Ed25519(Box::new(
            ed25519_dalek::SigningKey::generate(rng),
        ))),
    }
}

impl PrivateKey {
    pub fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Rsa(key) => PublicKey::Rsa(key.to_public_key()),
            PrivateKey::P256(key) => PublicKey::P256(key.public_key()),
            PrivateKey::P384(key) => PublicKey::P384(key.public_key()),
            PrivateKey::P521(key) => PublicKey::P521(key.public_key()),
            PrivateKey::Ed25519(key) => PublicKey::Ed25519(key.verifying_key()),
        }
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        if let Ok(key) = RsaPrivateKey::from_pkcs8_der(der) {
            return Ok(PrivateKey::Rsa(Box::new(key)));
        }
        if let Ok(key) = p256::SecretKey::from_pkcs8_der(der) {
            return Ok(PrivateKey::P256(key));
        }
        if let Ok(key) = p384::SecretKey::from_pkcs8_der(der) {
            return Ok(PrivateKey::P384(key));
        }
        if let Ok(key) = p521::SecretKey::from_pkcs8_der(der) {
            return Ok(PrivateKey::P521(key));
        }
        if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
            return Ok(PrivateKey::Ed25519(Box::new(key)));
        }
        Err(Error::InvalidKeyFile)
    }

    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let document = match self {
            PrivateKey::Rsa(key) => key.to_pkcs8_der(),
            PrivateKey::P256(key) => key.to_pkcs8_der(),
            PrivateKey::P384(key) => key.to_pkcs8_der(),
            PrivateKey::P521(key) => key.to_pkcs8_der(),
            PrivateKey::Ed25519(key) => key.to_pkcs8_der(),
        }
        .map_err(|_| Error::InvalidKey)?;
        Ok(Zeroizing::new(document.as_bytes().to_vec()))
    }

    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>> {
        pem_text("PRIVATE KEY", &self.to_pkcs8_der()?)
    }

    /// PKCS#8 protected by a passphrase: PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC, which every
    /// current OpenSSL reads. The 600,000 rounds are OWASP's figure for PBKDF2-HMAC-SHA256.
    pub fn to_encrypted_pkcs8_pem(
        &self,
        passphrase: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Zeroizing<String>> {
        if passphrase.is_empty() {
            return Err(Error::WrongPassphrase);
        }
        let mut salt = [0u8; 16];
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut iv);
        let params = pkcs8::pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(600_000, &salt, &iv)
            .map_err(|_| Error::EncryptionFailed)?;
        let der = self.to_pkcs8_der()?;
        let info =
            pkcs8::PrivateKeyInfo::try_from(der.as_slice()).map_err(|_| Error::InvalidKey)?;
        let encrypted = info
            .encrypt_with_params(params, passphrase)
            .map_err(|_| Error::EncryptionFailed)?;
        pem_text("ENCRYPTED PRIVATE KEY", encrypted.as_bytes())
    }

    /// PKCS#1 for RSA, SEC1 for EC. Ed25519 has no format of its own: PKCS#8 is it.
    pub fn to_traditional_pem(&self) -> Result<Zeroizing<String>> {
        match self {
            PrivateKey::Rsa(key) => {
                let der = key.to_pkcs1_der().map_err(|_| Error::InvalidKey)?;
                pem_text("RSA PRIVATE KEY", der.as_bytes())
            }
            PrivateKey::P256(key) => sec1_pem(key.to_sec1_der(), "1.2.840.10045.3.1.7"),
            PrivateKey::P384(key) => sec1_pem(key.to_sec1_der(), "1.3.132.0.34"),
            PrivateKey::P521(key) => sec1_pem(key.to_sec1_der(), "1.3.132.0.35"),
            PrivateKey::Ed25519(_) => Err(Error::UnsupportedAlgorithm),
        }
    }

    /// The OpenSSH private key file, optionally protected by a passphrase.
    pub fn to_openssh(
        &self,
        comment: &str,
        passphrase: Option<&str>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Zeroizing<String>> {
        let key = ssh::from_pkcs8_der(&self.to_pkcs8_der()?, comment)?;
        ssh::write_private_key(&key.private_key, comment, passphrase, rng)
    }

    /// A JWK with the private parts (`d`, and RSA's CRT values).
    pub fn to_jwk(&self) -> Result<Value> {
        let mut jwk = self.public().to_jwk();
        match self {
            PrivateKey::Rsa(key) => {
                let [p, q, ..] = key.primes() else {
                    return Err(Error::InvalidKey);
                };
                let mut key = key.clone();
                key.precompute().map_err(|_| Error::InvalidKey)?;
                jwk["d"] = big(key.d());
                jwk["p"] = big(p);
                jwk["q"] = big(q);
                jwk["dp"] = big(key.dp().ok_or(Error::InvalidKey)?);
                jwk["dq"] = big(key.dq().ok_or(Error::InvalidKey)?);
                jwk["qi"] = json!(b64_encode(
                    &key.crt_coefficient()
                        .ok_or(Error::InvalidKey)?
                        .to_bytes_be()
                ));
            }
            PrivateKey::P256(key) => jwk["d"] = json!(b64_encode(&key.to_bytes())),
            PrivateKey::P384(key) => jwk["d"] = json!(b64_encode(&key.to_bytes())),
            PrivateKey::P521(key) => jwk["d"] = json!(b64_encode(&key.to_bytes())),
            PrivateKey::Ed25519(key) => jwk["d"] = json!(b64_encode(&key.to_bytes())),
        }
        Ok(jwk)
    }

    /// Signs `message`. ECDSA signatures come out as `r ‖ s`, as JOSE writes them.
    pub fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        message: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        use SignatureAlgorithm as Alg;
        match (self, algorithm) {
            (PrivateKey::Rsa(key), algorithm) if key.size() >= 256 => {
                let key = key.as_ref().clone();
                Ok(match algorithm {
                    Alg::Rs256 => pkcs1_sign::<Sha256>(key, message, rng),
                    Alg::Rs384 => pkcs1_sign::<Sha384>(key, message, rng),
                    Alg::Rs512 => pkcs1_sign::<Sha512>(key, message, rng),
                    Alg::Ps256 => pss_sign::<Sha256>(key, message, rng),
                    Alg::Ps384 => pss_sign::<Sha384>(key, message, rng),
                    Alg::Ps512 => pss_sign::<Sha512>(key, message, rng),
                    _ => return Err(Error::KeyAlgorithmMismatch),
                })
            }
            (PrivateKey::P256(key), Alg::Es256) => {
                let signature: p256::ecdsa::Signature =
                    p256::ecdsa::SigningKey::from(key).sign(message);
                Ok(signature.to_bytes().to_vec())
            }
            (PrivateKey::P384(key), Alg::Es384) => {
                let signature: p384::ecdsa::Signature =
                    p384::ecdsa::SigningKey::from(key).sign(message);
                Ok(signature.to_bytes().to_vec())
            }
            (PrivateKey::P521(key), Alg::Es512) => {
                let signing = p521::ecdsa::SigningKey::from_bytes(&key.to_bytes())
                    .map_err(|_| Error::InvalidKey)?;
                let signature: p521::ecdsa::Signature = signing.sign(message);
                Ok(signature.to_bytes().to_vec())
            }
            (PrivateKey::Ed25519(key), Alg::EdDsa) => Ok(key.sign(message).to_bytes().to_vec()),
            _ => Err(Error::KeyAlgorithmMismatch),
        }
    }

    /// The algorithm JOSE and X.509 use with this key by default.
    pub fn default_algorithm(&self) -> SignatureAlgorithm {
        self.public().default_algorithm()
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateKey(…)")
    }
}

fn pkcs1_sign<D>(key: RsaPrivateKey, message: &[u8], rng: &mut impl CryptoRngCore) -> Vec<u8>
where
    D: Digest + pkcs8::AssociatedOid,
{
    rsa::pkcs1v15::SigningKey::<D>::new(key)
        .sign_with_rng(rng, message)
        .to_vec()
}

fn pss_sign<D>(key: RsaPrivateKey, message: &[u8], rng: &mut impl CryptoRngCore) -> Vec<u8>
where
    D: Digest + rsa::sha2::digest::FixedOutputReset,
{
    rsa::pss::BlindedSigningKey::<D>::new(key)
        .sign_with_rng(rng, message)
        .to_vec()
}

fn big(value: &BigUint) -> Value {
    json!(b64_encode(&value.to_bytes_be()))
}

fn pem_text(label: &'static str, der: &[u8]) -> Result<Zeroizing<String>> {
    pem::encode_string(label, LineEnding::LF, der)
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidKey)
}

/// SEC1 with the curve named: the curve crates leave it out, and OpenSSL needs it.
fn sec1_pem<E>(
    der: core::result::Result<Zeroizing<Vec<u8>>, E>,
    curve: &str,
) -> Result<Zeroizing<String>> {
    let der = der.map_err(|_| Error::InvalidKey)?;
    let mut key = sec1::EcPrivateKey::from_der(&der).map_err(|_| Error::InvalidKey)?;
    let oid = der::asn1::ObjectIdentifier::new(curve).map_err(|_| Error::InvalidKey)?;
    key.parameters = Some(sec1::EcParameters::NamedCurve(oid));
    let named = Zeroizing::new(key.to_der().map_err(|_| Error::InvalidKey)?);
    pem_text("EC PRIVATE KEY", &named)
}

impl PublicKey {
    pub fn from_spki_der(der: &[u8]) -> Result<Self> {
        if let Ok(key) = RsaPublicKey::from_public_key_der(der) {
            return Ok(PublicKey::Rsa(key));
        }
        if let Ok(key) = p256::PublicKey::from_public_key_der(der) {
            return Ok(PublicKey::P256(key));
        }
        if let Ok(key) = p384::PublicKey::from_public_key_der(der) {
            return Ok(PublicKey::P384(key));
        }
        if let Ok(key) = p521::PublicKey::from_public_key_der(der) {
            return Ok(PublicKey::P521(key));
        }
        if let Ok(key) = ed25519_dalek::VerifyingKey::from_public_key_der(der) {
            return Ok(PublicKey::Ed25519(key));
        }
        Err(Error::InvalidKeyFile)
    }

    pub fn to_spki_der(&self) -> Result<Vec<u8>> {
        let document = match self {
            PublicKey::Rsa(key) => key.to_public_key_der(),
            PublicKey::P256(key) => key.to_public_key_der(),
            PublicKey::P384(key) => key.to_public_key_der(),
            PublicKey::P521(key) => key.to_public_key_der(),
            PublicKey::Ed25519(key) => key.to_public_key_der(),
        }
        .map_err(|_| Error::InvalidKey)?;
        Ok(document.into_vec())
    }

    pub fn to_spki_pem(&self) -> Result<String> {
        pem::encode_string("PUBLIC KEY", LineEnding::LF, &self.to_spki_der()?)
            .map_err(|_| Error::InvalidKey)
    }

    /// `-----BEGIN RSA PUBLIC KEY-----`; RSA only.
    pub fn to_pkcs1_pem(&self) -> Result<String> {
        match self {
            PublicKey::Rsa(key) => {
                let der = key.to_pkcs1_der().map_err(|_| Error::InvalidKey)?;
                pem::encode_string("RSA PUBLIC KEY", LineEnding::LF, der.as_bytes())
                    .map_err(|_| Error::InvalidKey)
            }
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }

    fn ssh_key_data(&self) -> Result<KeyData> {
        Ok(match self {
            PublicKey::Rsa(key) => {
                let mpint =
                    |value: &BigUint| ssh_key::Mpint::from_positive_bytes(&value.to_bytes_be());
                KeyData::Rsa(SshRsaPublicKey {
                    e: mpint(key.e()).map_err(|_| Error::InvalidKey)?,
                    n: mpint(key.n()).map_err(|_| Error::InvalidKey)?,
                })
            }
            PublicKey::P256(key) => {
                KeyData::Ecdsa(EcdsaPublicKey::NistP256(key.to_encoded_point(false)))
            }
            PublicKey::P384(key) => {
                KeyData::Ecdsa(EcdsaPublicKey::NistP384(key.to_encoded_point(false)))
            }
            PublicKey::P521(key) => {
                KeyData::Ecdsa(EcdsaPublicKey::NistP521(key.to_encoded_point(false)))
            }
            PublicKey::Ed25519(key) => KeyData::Ed25519(Ed25519PublicKey(key.to_bytes())),
        })
    }

    fn from_ssh_key_data(data: &KeyData) -> Result<Self> {
        Ok(match data {
            KeyData::Rsa(key) => {
                let number = |value: &ssh_key::Mpint| {
                    value
                        .as_positive_bytes()
                        .map(BigUint::from_bytes_be)
                        .ok_or(Error::InvalidKeyFile)
                };
                PublicKey::Rsa(
                    RsaPublicKey::new(number(&key.n)?, number(&key.e)?)
                        .map_err(|_| Error::InvalidKeyFile)?,
                )
            }
            KeyData::Ecdsa(EcdsaPublicKey::NistP256(point)) => PublicKey::P256(
                Option::from(p256::PublicKey::from_encoded_point(point))
                    .ok_or(Error::InvalidKeyFile)?,
            ),
            KeyData::Ecdsa(EcdsaPublicKey::NistP384(point)) => PublicKey::P384(
                Option::from(p384::PublicKey::from_encoded_point(point))
                    .ok_or(Error::InvalidKeyFile)?,
            ),
            KeyData::Ecdsa(EcdsaPublicKey::NistP521(point)) => PublicKey::P521(
                Option::from(p521::PublicKey::from_encoded_point(point))
                    .ok_or(Error::InvalidKeyFile)?,
            ),
            KeyData::Ed25519(key) => PublicKey::Ed25519(
                ed25519_dalek::VerifyingKey::from_bytes(&key.0)
                    .map_err(|_| Error::InvalidKeyFile)?,
            ),
            _ => return Err(Error::UnsupportedAlgorithm),
        })
    }

    /// The `authorized_keys` form: `ssh-ed25519 AAAA…`, without a comment.
    pub fn to_openssh(&self) -> Result<String> {
        ssh_key::PublicKey::from(self.ssh_key_data()?)
            .to_openssh()
            .map_err(|_| Error::InvalidKey)
    }

    /// `SHA256:…`, as `ssh-keygen -l` shows it.
    pub fn ssh_fingerprint(&self) -> Result<String> {
        Ok(self
            .ssh_key_data()?
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string())
    }

    /// The public members only, in a fixed order.
    pub fn to_jwk(&self) -> Value {
        match self {
            PublicKey::Rsa(key) => json!({ "kty": "RSA", "n": big(key.n()), "e": big(key.e()) }),
            PublicKey::P256(key) => ec_jwk("P-256", key.to_encoded_point(false).as_bytes()),
            PublicKey::P384(key) => ec_jwk("P-384", key.to_encoded_point(false).as_bytes()),
            PublicKey::P521(key) => ec_jwk("P-521", key.to_encoded_point(false).as_bytes()),
            PublicKey::Ed25519(key) => {
                json!({ "kty": "OKP", "crv": "Ed25519", "x": b64_encode(&key.to_bytes()) })
            }
        }
    }

    /// RFC 7638: base64url of the SHA-256 of the required members in lexical order.
    pub fn jwk_thumbprint(&self) -> String {
        jwk_thumbprint(&self.to_jwk())
    }

    /// `rsa`, `ec`, `ed25519`, with the size or curve.
    pub fn describe(&self) -> KeyDescription {
        let (key_type, bits, curve) = match self {
            PublicKey::Rsa(key) => ("rsa", key.size() as u32 * 8, None),
            PublicKey::P256(_) => ("ec", 256, Some("P-256")),
            PublicKey::P384(_) => ("ec", 384, Some("P-384")),
            PublicKey::P521(_) => ("ec", 521, Some("P-521")),
            PublicKey::Ed25519(_) => ("ed25519", 256, None),
        };
        KeyDescription {
            key_type: key_type.to_owned(),
            bits,
            curve: curve.map(str::to_owned),
        }
    }

    pub fn default_algorithm(&self) -> SignatureAlgorithm {
        match self {
            PublicKey::Rsa(_) => SignatureAlgorithm::Rs256,
            PublicKey::P256(_) => SignatureAlgorithm::Es256,
            PublicKey::P384(_) => SignatureAlgorithm::Es384,
            PublicKey::P521(_) => SignatureAlgorithm::Es512,
            PublicKey::Ed25519(_) => SignatureAlgorithm::EdDsa,
        }
    }

    /// Checks `signature` over `message`. A key that doesn't fit the algorithm doesn't verify:
    /// the algorithm in a token's header never changes how a key is read.
    pub fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        use SignatureAlgorithm as Alg;
        let ok = match (self, algorithm) {
            (PublicKey::Rsa(key), Alg::Rs256) => pkcs1_verify::<Sha256>(key, message, signature),
            (PublicKey::Rsa(key), Alg::Rs384) => pkcs1_verify::<Sha384>(key, message, signature),
            (PublicKey::Rsa(key), Alg::Rs512) => pkcs1_verify::<Sha512>(key, message, signature),
            (PublicKey::Rsa(key), Alg::Ps256) => pss_verify::<Sha256>(key, message, signature),
            (PublicKey::Rsa(key), Alg::Ps384) => pss_verify::<Sha384>(key, message, signature),
            (PublicKey::Rsa(key), Alg::Ps512) => pss_verify::<Sha512>(key, message, signature),
            (PublicKey::P256(key), Alg::Es256) => p256::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|signature| {
                    p256::ecdsa::VerifyingKey::from(key)
                        .verify(message, &signature)
                        .is_ok()
                }),
            (PublicKey::P384(key), Alg::Es384) => p384::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|signature| {
                    p384::ecdsa::VerifyingKey::from(key)
                        .verify(message, &signature)
                        .is_ok()
                }),
            (PublicKey::P521(key), Alg::Es512) => p521::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|signature| {
                    let encoded = key.to_encoded_point(false);
                    p521::ecdsa::VerifyingKey::from_encoded_point(&encoded)
                        .is_ok_and(|key| key.verify(message, &signature).is_ok())
                }),
            (PublicKey::Ed25519(key), Alg::EdDsa) => {
                ed25519_dalek::Signature::from_slice(signature)
                    .is_ok_and(|signature| key.verify_strict(message, &signature).is_ok())
            }
            _ => return Err(Error::KeyAlgorithmMismatch),
        };
        Ok(ok)
    }
}

fn pkcs1_verify<D>(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> bool
where
    D: Digest + pkcs8::AssociatedOid,
{
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(signature) else {
        return false;
    };
    rsa::pkcs1v15::VerifyingKey::<D>::new(key.clone())
        .verify(message, &signature)
        .is_ok()
}

fn pss_verify<D>(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> bool
where
    D: Digest + rsa::sha2::digest::FixedOutputReset,
{
    let Ok(signature) = rsa::pss::Signature::try_from(signature) else {
        return false;
    };
    rsa::pss::VerifyingKey::<D>::new(key.clone())
        .verify(message, &signature)
        .is_ok()
}

/// `sec1` is an uncompressed point: `04 ‖ x ‖ y`.
fn ec_jwk(curve: &str, sec1: &[u8]) -> Value {
    let (x, y) = sec1[1..].split_at((sec1.len() - 1) / 2);
    json!({ "kty": "EC", "crv": curve, "x": b64_encode(x), "y": b64_encode(y) })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyDescription {
    pub key_type: String,
    pub bits: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
}

/// RFC 7638's thumbprint of any JWK, `oct` included.
pub fn jwk_thumbprint(jwk: &Value) -> String {
    let members: &[&str] = match jwk.get("kty").and_then(Value::as_str) {
        Some("RSA") => &["e", "kty", "n"],
        Some("EC") => &["crv", "kty", "x", "y"],
        Some("OKP") => &["crv", "kty", "x"],
        _ => &["k", "kty"],
    };
    // `serde_json::Map` keeps keys sorted here, and the members are one-liners: this is the
    // canonical form RFC 7638 §3.3 specifies.
    let mut required = Map::new();
    for member in members {
        if let Some(value) = jwk.get(*member) {
            required.insert((*member).to_owned(), value.clone());
        }
    }
    let canonical = Value::Object(required).to_string();
    b64_encode(&Sha256::digest(canonical.as_bytes()))
}

/// Every fingerprint people compare keys by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fingerprints {
    /// SHA-256 of the SubjectPublicKeyInfo, in hex: `openssl pkey -pubout -outform der | sha256sum`.
    pub spki_sha256: String,
    /// The same in base64: an HPKP or `pin-sha256` pin.
    pub spki_pin: String,
    /// `SHA256:…`, as `ssh-keygen -l` shows it.
    pub ssh_sha256: String,
    /// RFC 7638.
    pub jwk_thumbprint: String,
}

pub fn fingerprints(key: &PublicKey) -> Result<Fingerprints> {
    use base64::Engine;
    let digest = Sha256::digest(key.to_spki_der()?);
    Ok(Fingerprints {
        spki_sha256: hex_encode(&digest),
        spki_pin: base64::engine::general_purpose::STANDARD.encode(digest),
        ssh_sha256: key.ssh_fingerprint()?,
        jwk_thumbprint: key.jwk_thumbprint(),
    })
}

/// Reads a key from pasted text: PEM (PKCS#8, encrypted PKCS#8, PKCS#1, SEC1, SPKI), an OpenSSH
/// private or public key, a JWK, a one-key JWKS, the public key of a certificate, or base64 DER.
pub fn parse(text: &str, passphrase: Option<&str>) -> Result<ParsedKey> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        return parse_jwk_text(trimmed);
    }
    if let Some(label) = pem_label(trimmed) {
        return parse_pem(label, trimmed, passphrase);
    }
    if trimmed.starts_with("ssh-") || trimmed.starts_with("ecdsa-sha2-") {
        let key = ssh_key::PublicKey::from_openssh(trimmed).map_err(|_| Error::InvalidKeyFile)?;
        return PublicKey::from_ssh_key_data(key.key_data()).map(ParsedKey::Public);
    }
    let der = Zeroizing::new(decode_base64(trimmed).map_err(|_| Error::InvalidKeyFile)?);
    parse_der(&der, passphrase)
}

/// The first `-----BEGIN X-----` label of `text`.
pub fn pem_label(text: &str) -> Option<&str> {
    let start = text.find("-----BEGIN ")? + "-----BEGIN ".len();
    let rest = &text[start..];
    Some(&rest[..rest.find("-----")?])
}

fn parse_pem(label: &str, text: &str, passphrase: Option<&str>) -> Result<ParsedKey> {
    match label {
        "PRIVATE KEY" => {
            let (_, der) = decode_pem(text)?;
            PrivateKey::from_pkcs8_der(&der).map(ParsedKey::Private)
        }
        "ENCRYPTED PRIVATE KEY" => {
            let passphrase = passphrase.ok_or(Error::WrongPassphrase)?;
            let (_, der) = decode_pem(text)?;
            decrypt_pkcs8(&der, passphrase).map(ParsedKey::Private)
        }
        "RSA PRIVATE KEY" | "EC PRIVATE KEY" | "OPENSSH PRIVATE KEY" => {
            let key = ssh::read_private_key(text, passphrase).map_err(|error| match error {
                Error::SshPassphraseRequired => Error::WrongPassphrase,
                Error::InvalidSshKey => Error::InvalidKeyFile,
                other => other,
            })?;
            let der = ssh::to_pkcs8_der(&key.private_key)?;
            PrivateKey::from_pkcs8_der(&der).map(ParsedKey::Private)
        }
        "PUBLIC KEY" => {
            let (_, der) = decode_pem(text)?;
            PublicKey::from_spki_der(&der).map(ParsedKey::Public)
        }
        "RSA PUBLIC KEY" => {
            let (_, der) = decode_pem(text)?;
            RsaPublicKey::from_pkcs1_der(&der)
                .map(|key| ParsedKey::Public(PublicKey::Rsa(key)))
                .map_err(|_| Error::InvalidKeyFile)
        }
        "CERTIFICATE" => {
            let (_, der) = decode_pem(text)?;
            public_of_certificate(&der).map(ParsedKey::Public)
        }
        _ => Err(Error::InvalidKeyFile),
    }
}

fn public_of_certificate(der: &[u8]) -> Result<PublicKey> {
    let certificate =
        x509_cert::Certificate::from_der(der).map_err(|_| Error::InvalidCertificate)?;
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| Error::InvalidCertificate)?;
    PublicKey::from_spki_der(&spki)
}

fn decode_pem(text: &str) -> Result<(&str, Zeroizing<Vec<u8>>)> {
    // Text before or after the block (`openssl` writes "Bag Attributes") isn't part of it.
    let start = text.find("-----BEGIN ").ok_or(Error::InvalidKeyFile)?;
    let (label, der) =
        pem::decode_vec(&text.as_bytes()[start..]).map_err(|_| Error::InvalidKeyFile)?;
    Ok((label, Zeroizing::new(der)))
}

fn decrypt_pkcs8(der: &[u8], passphrase: &str) -> Result<PrivateKey> {
    let info = pkcs8::EncryptedPrivateKeyInfo::try_from(der).map_err(|_| Error::InvalidKeyFile)?;
    let document = info
        .decrypt(passphrase)
        .map_err(|_| Error::WrongPassphrase)?;
    PrivateKey::from_pkcs8_der(document.as_bytes())
}

/// DER of any of the structures [`parse`] reads.
pub fn parse_der(der: &[u8], passphrase: Option<&str>) -> Result<ParsedKey> {
    if let Ok(key) = PrivateKey::from_pkcs8_der(der) {
        return Ok(ParsedKey::Private(key));
    }
    if let Ok(key) = PublicKey::from_spki_der(der) {
        return Ok(ParsedKey::Public(key));
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs1_der(der) {
        return Ok(ParsedKey::Private(PrivateKey::Rsa(Box::new(key))));
    }
    if let Ok(key) = RsaPublicKey::from_pkcs1_der(der) {
        return Ok(ParsedKey::Public(PublicKey::Rsa(key)));
    }
    if let Ok(key) = p256::SecretKey::from_sec1_der(der) {
        return Ok(ParsedKey::Private(PrivateKey::P256(key)));
    }
    if let Ok(key) = p384::SecretKey::from_sec1_der(der) {
        return Ok(ParsedKey::Private(PrivateKey::P384(key)));
    }
    if let Ok(key) = p521::SecretKey::from_sec1_der(der) {
        return Ok(ParsedKey::Private(PrivateKey::P521(key)));
    }
    if let Ok(key) = public_of_certificate(der) {
        return Ok(ParsedKey::Public(key));
    }
    if pkcs8::EncryptedPrivateKeyInfo::try_from(der).is_ok() {
        return decrypt_pkcs8(der, passphrase.ok_or(Error::WrongPassphrase)?)
            .map(ParsedKey::Private);
    }
    Err(Error::InvalidKeyFile)
}

fn parse_jwk_text(text: &str) -> Result<ParsedKey> {
    let value: Value = serde_json::from_str(text).map_err(|_| Error::InvalidKeyFile)?;
    if let Some(keys) = value.get("keys").and_then(Value::as_array) {
        return match keys.as_slice() {
            [only] => parse_jwk(only),
            _ => Err(Error::InvalidKeyFile),
        };
    }
    parse_jwk(&value)
}

/// One asymmetric JWK, public or private. `oct` keys are secrets, not key pairs: see `jose`.
pub fn parse_jwk(jwk: &Value) -> Result<ParsedKey> {
    let field = |name: &str| jwk.get(name).and_then(Value::as_str);
    let bytes = |name: &str| -> Result<Zeroizing<Vec<u8>>> {
        field(name)
            .ok_or(Error::InvalidKeyFile)
            .and_then(|text| {
                b64_decode(text.trim_end_matches('=')).map_err(|_| Error::InvalidKeyFile)
            })
            .map(Zeroizing::new)
    };
    let number = |name: &str| bytes(name).map(|value| BigUint::from_bytes_be(&value));
    match field("kty") {
        Some("RSA") => {
            let n = number("n")?;
            let e = number("e")?;
            if field("d").is_none() {
                return RsaPublicKey::new(n, e)
                    .map(|key| ParsedKey::Public(PublicKey::Rsa(key)))
                    .map_err(|_| Error::InvalidKeyFile);
            }
            let d = number("d")?;
            let primes = vec![number("p")?, number("q")?];
            let key = RsaPrivateKey::from_components(n, e, d, primes)
                .map_err(|_| Error::InvalidKeyFile)?;
            key.validate().map_err(|_| Error::InvalidKeyFile)?;
            Ok(ParsedKey::Private(PrivateKey::Rsa(Box::new(key))))
        }
        Some("EC") => parse_ec_jwk(field("crv"), &bytes("x")?, &bytes("y")?, bytes("d").ok()),
        Some("OKP") if field("crv") == Some("Ed25519") => {
            if let Ok(secret) = bytes("d") {
                let secret: [u8; 32] = secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidKeyFile)?;
                let key = ed25519_dalek::SigningKey::from_bytes(&secret);
                if key.verifying_key().to_bytes().as_slice() != bytes("x")?.as_slice() {
                    return Err(Error::KeyMismatch);
                }
                return Ok(ParsedKey::Private(PrivateKey::Ed25519(Box::new(key))));
            }
            let public: [u8; 32] = bytes("x")?
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidKeyFile)?;
            ed25519_dalek::VerifyingKey::from_bytes(&public)
                .map(|key| ParsedKey::Public(PublicKey::Ed25519(key)))
                .map_err(|_| Error::InvalidKeyFile)
        }
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

macro_rules! ec_from_jwk {
    ($curve:ident, $variant:ident, $x:expr, $y:expr, $d:expr, $size:expr) => {{
        if $x.len() != $size || $y.len() != $size {
            return Err(Error::InvalidKeyFile);
        }
        let mut point = Vec::with_capacity(1 + 2 * $size);
        point.push(4);
        point.extend_from_slice($x);
        point.extend_from_slice($y);
        let public =
            $curve::PublicKey::from_sec1_bytes(&point).map_err(|_| Error::InvalidKeyFile)?;
        match $d {
            Some(d) => {
                let key = $curve::SecretKey::from_slice(&d).map_err(|_| Error::InvalidKeyFile)?;
                if key.public_key() != public {
                    return Err(Error::KeyMismatch);
                }
                Ok(ParsedKey::Private(PrivateKey::$variant(key)))
            }
            None => Ok(ParsedKey::Public(PublicKey::$variant(public))),
        }
    }};
}

fn parse_ec_jwk(
    curve: Option<&str>,
    x: &[u8],
    y: &[u8],
    d: Option<Zeroizing<Vec<u8>>>,
) -> Result<ParsedKey> {
    match curve {
        Some("P-256") => ec_from_jwk!(p256, P256, x, y, d, 32),
        Some("P-384") => ec_from_jwk!(p384, P384, x, y, d, 48),
        Some("P-521") => ec_from_jwk!(p521, P521, x, y, d, 66),
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, SeedableRng};

    use super::*;

    fn seeded() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::from_seed([3; 32])
    }

    fn public_jwk(key: &PrivateKey) -> Value {
        key.public().to_jwk()
    }

    fn fast_keys() -> Vec<PrivateKey> {
        let mut rng = seeded();
        vec![
            generate(KeyKind::P256, &mut rng).unwrap(),
            generate(KeyKind::P384, &mut rng).unwrap(),
            generate(KeyKind::Ed25519, &mut rng).unwrap(),
            generate(KeyKind::Rsa2048, &mut rng).unwrap(),
        ]
    }

    #[test]
    fn every_format_round_trips() {
        for key in fast_keys() {
            let expected = public_jwk(&key);
            let check = |text: &str, passphrase: Option<&str>| {
                let ParsedKey::Private(parsed) = parse(text, passphrase).unwrap() else {
                    panic!("not private: {text}");
                };
                assert_eq!(public_jwk(&parsed), expected, "{text}");
            };
            check(&key.to_pkcs8_pem().unwrap(), None);
            check(
                &key.to_encrypted_pkcs8_pem("hunter2", &mut seeded())
                    .unwrap(),
                Some("hunter2"),
            );
            if let Ok(pem) = key.to_traditional_pem() {
                check(&pem, None);
            }
            check(&key.to_openssh("c", None, &mut seeded()).unwrap(), None);
            check(&key.to_jwk().unwrap().to_string(), None);
            check(&b64_encode(&key.to_pkcs8_der().unwrap()), None);

            let public = key.public();
            for text in [
                public.to_spki_pem().unwrap(),
                public.to_openssh().unwrap(),
                public.to_jwk().to_string(),
            ] {
                let ParsedKey::Public(parsed) = parse(&text, None).unwrap() else {
                    panic!("not public: {text}");
                };
                assert_eq!(parsed, public, "{text}");
            }
        }
    }

    #[test]
    fn wrong_passphrase_is_reported() {
        let key = generate(KeyKind::P256, &mut seeded()).unwrap();
        let pem = key.to_encrypted_pkcs8_pem("right", &mut seeded()).unwrap();
        assert!(matches!(
            parse(&pem, Some("wrong")),
            Err(Error::WrongPassphrase)
        ));
        assert!(matches!(parse(&pem, None), Err(Error::WrongPassphrase)));
    }

    #[test]
    fn signatures_verify_and_tampering_fails() {
        for key in fast_keys() {
            let public = key.public();
            let algorithms: &[SignatureAlgorithm] = match public {
                PublicKey::Rsa(_) => &[
                    SignatureAlgorithm::Rs256,
                    SignatureAlgorithm::Rs384,
                    SignatureAlgorithm::Rs512,
                    SignatureAlgorithm::Ps256,
                    SignatureAlgorithm::Ps384,
                    SignatureAlgorithm::Ps512,
                ],
                _ => std::slice::from_ref(&SignatureAlgorithm::Es256),
            };
            for &algorithm in algorithms {
                let algorithm = if matches!(public, PublicKey::Rsa(_)) {
                    algorithm
                } else {
                    public.default_algorithm()
                };
                let mut signature = key.sign(algorithm, b"message", &mut OsRng).unwrap();
                assert!(public.verify(algorithm, b"message", &signature).unwrap());
                assert!(!public.verify(algorithm, b"massage", &signature).unwrap());
                signature[0] ^= 1;
                assert!(!public.verify(algorithm, b"message", &signature).unwrap());
            }
        }
    }

    #[test]
    fn keys_only_work_with_their_algorithm() {
        let key = generate(KeyKind::P256, &mut seeded()).unwrap();
        assert!(matches!(
            key.sign(SignatureAlgorithm::Es384, b"m", &mut OsRng),
            Err(Error::KeyAlgorithmMismatch)
        ));
        assert_eq!(
            key.public()
                .verify(SignatureAlgorithm::Rs256, b"m", &[0; 256]),
            Err(Error::KeyAlgorithmMismatch)
        );
    }

    #[test]
    fn jwk_with_a_mismatched_private_part_is_refused() {
        let key = generate(KeyKind::P256, &mut seeded()).unwrap();
        let mut jwk = key.to_jwk().unwrap();
        let different = generate(KeyKind::P256, &mut OsRng).unwrap();
        jwk["d"] = different.to_jwk().unwrap()["d"].clone();
        assert!(matches!(
            parse(&jwk.to_string(), None),
            Err(Error::KeyMismatch)
        ));
    }

    #[test]
    fn garbage_is_refused() {
        for text in [
            "",
            "hello",
            "{}",
            "{\"kty\":\"RSA\"}",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
        ] {
            assert!(parse(text, None).is_err(), "{text}");
        }
    }
}
