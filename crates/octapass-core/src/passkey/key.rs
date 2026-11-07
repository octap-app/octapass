//! Passkey key pairs: ES256 (ECDSA P-256 with SHA-256) and EdDSA (Ed25519).

use ed25519_dalek::Signer as _;
use ed25519_dalek::pkcs8::{EncodePrivateKey as _, KeypairBytes};
use p256::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use super::cbor;
use crate::error::{Error, Result};

/// A COSE algorithm identifier (IANA "COSE Algorithms") this authenticator supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Es256,
    EdDsa,
}

impl Algorithm {
    pub fn cose(self) -> i64 {
        match self {
            Algorithm::Es256 => -7,
            Algorithm::EdDsa => -8,
        }
    }

    pub fn from_cose(alg: i64) -> Option<Self> {
        match alg {
            -7 => Some(Algorithm::Es256),
            -8 => Some(Algorithm::EdDsa),
            _ => None,
        }
    }
}

/// A passkey's private key. Both variants zero themselves on drop.
pub(crate) enum PrivateKey {
    Es256(p256::ecdsa::SigningKey),
    EdDsa(ed25519_dalek::SigningKey),
}

impl PrivateKey {
    pub fn generate(algorithm: Algorithm, rng: &mut impl CryptoRngCore) -> Self {
        match algorithm {
            Algorithm::Es256 => PrivateKey::Es256(p256::ecdsa::SigningKey::random(rng)),
            Algorithm::EdDsa => {
                let mut seed = Zeroizing::new([0u8; 32]);
                rng.fill_bytes(seed.as_mut());
                PrivateKey::EdDsa(ed25519_dalek::SigningKey::from_bytes(&seed))
            }
        }
    }

    /// Parses an unencrypted PKCS#8 `PrivateKeyInfo` (DER) for either algorithm.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self> {
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(PrivateKey::Es256(key));
        }
        ed25519_dalek::SigningKey::from_pkcs8_der(der)
            .map(PrivateKey::EdDsa)
            .map_err(|_| Error::InvalidKey)
    }

    /// PKCS#8 DER: the format WebCrypto, CXF and other passkey managers exchange. Ed25519 keys
    /// are written as v1 (no embedded public key), which every importer accepts.
    pub fn to_pkcs8(&self) -> Zeroizing<Vec<u8>> {
        let document = match self {
            PrivateKey::Es256(key) => key.to_pkcs8_der(),
            PrivateKey::EdDsa(key) => KeypairBytes {
                secret_key: key.to_bytes(),
                public_key: None,
            }
            .to_pkcs8_der(),
        };
        let document = document.expect("encoding a valid key as PKCS#8 can't fail");
        Zeroizing::new(document.as_bytes().to_vec())
    }

    /// The credential public key as a COSE_Key (RFC 9052/9053), in CTAP2 canonical order.
    pub fn cose_public_key(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(77);
        match self {
            PrivateKey::Es256(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                cbor::map(&mut out, 5);
                cbor::int(&mut out, 1); // kty
                cbor::int(&mut out, 2); // EC2
                cbor::int(&mut out, 3); // alg
                cbor::int(&mut out, Algorithm::Es256.cose());
                cbor::int(&mut out, -1); // crv
                cbor::int(&mut out, 1); // P-256
                cbor::int(&mut out, -2); // x
                cbor::bytes(&mut out, point.x().expect("uncompressed point"));
                cbor::int(&mut out, -3); // y
                cbor::bytes(&mut out, point.y().expect("uncompressed point"));
            }
            PrivateKey::EdDsa(key) => {
                cbor::map(&mut out, 4);
                cbor::int(&mut out, 1); // kty
                cbor::int(&mut out, 1); // OKP
                cbor::int(&mut out, 3); // alg
                cbor::int(&mut out, Algorithm::EdDsa.cose());
                cbor::int(&mut out, -1); // crv
                cbor::int(&mut out, 6); // Ed25519
                cbor::int(&mut out, -2); // x
                cbor::bytes(&mut out, key.verifying_key().as_bytes());
            }
        }
        out
    }

    /// The public key as a DER `SubjectPublicKeyInfo`, for `AuthenticatorAttestationResponse.getPublicKey()`.
    pub fn spki_public_key(&self) -> Vec<u8> {
        let document = match self {
            PrivateKey::Es256(key) => key.verifying_key().to_public_key_der(),
            PrivateKey::EdDsa(key) => key.verifying_key().to_public_key_der(),
        };
        document
            .expect("encoding a valid public key can't fail")
            .into_vec()
    }

    /// A WebAuthn signature: ASN.1 DER for ES256, the raw 64 bytes for EdDSA.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            PrivateKey::Es256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(message);
                signature.to_der().as_bytes().to_vec()
            }
            PrivateKey::EdDsa(key) => key.sign(message).to_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use coset::{CborSerializable, CoseKey, KeyType, iana};
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::DecodePublicKey as _;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    fn keys() -> [PrivateKey; 2] {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        [
            PrivateKey::generate(Algorithm::Es256, &mut rng),
            PrivateKey::generate(Algorithm::EdDsa, &mut rng),
        ]
    }

    #[test]
    fn pkcs8_round_trip() {
        for key in keys() {
            let der = key.to_pkcs8();
            let parsed = PrivateKey::from_pkcs8(&der).unwrap();
            assert_eq!(parsed.spki_public_key(), key.spki_public_key());
        }
        assert_eq!(
            PrivateKey::from_pkcs8(b"not a key").err(),
            Some(Error::InvalidKey)
        );
    }

    #[test]
    fn ed25519_pkcs8_is_v1() {
        let [_, ed] = keys();
        let der = ed.to_pkcs8();
        // RFC 8410 §10.3: SEQUENCE { INTEGER 0, AlgorithmIdentifier { 1.3.101.112 }, OCTET STRING { OCTET STRING (32) } }
        assert_eq!(&der[..16], &hex("302e020100300506032b657004220420")[..]);
        assert_eq!(der.len(), 48);
    }

    #[test]
    fn cose_keys_parse_with_coset_and_match_the_spki() {
        let [es, ed] = keys();

        let cose = CoseKey::from_slice(&es.cose_public_key()).unwrap();
        assert_eq!(cose.kty, KeyType::Assigned(iana::KeyType::EC2));
        assert_eq!(
            cose.alg,
            Some(coset::Algorithm::Assigned(iana::Algorithm::ES256))
        );
        let x = param(&cose, iana::Ec2KeyParameter::X as i64);
        let y = param(&cose, iana::Ec2KeyParameter::Y as i64);
        let spki = p256::ecdsa::VerifyingKey::from_public_key_der(&es.spki_public_key()).unwrap();
        let point = spki.to_encoded_point(false);
        assert_eq!(
            (x, y),
            (point.x().unwrap().to_vec(), point.y().unwrap().to_vec())
        );

        let cose = CoseKey::from_slice(&ed.cose_public_key()).unwrap();
        assert_eq!(cose.kty, KeyType::Assigned(iana::KeyType::OKP));
        assert_eq!(
            cose.alg,
            Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA))
        );
        let x = param(&cose, iana::OkpKeyParameter::X as i64);
        let spki = ed.spki_public_key();
        assert_eq!(x, spki[spki.len() - 32..]);
    }

    #[test]
    fn signatures_verify() {
        let [es, ed] = keys();
        let message = b"authenticatorData || clientDataHash";

        let verifier =
            p256::ecdsa::VerifyingKey::from_public_key_der(&es.spki_public_key()).unwrap();
        let signature = p256::ecdsa::Signature::from_der(&es.sign(message)).unwrap();
        assert!(verifier.verify(message, &signature).is_ok());

        let PrivateKey::EdDsa(signing) = &ed else {
            unreachable!()
        };
        let signature = ed25519_dalek::Signature::from_slice(&ed.sign(message)).unwrap();
        assert!(
            signing
                .verifying_key()
                .verify_strict(message, &signature)
                .is_ok()
        );
    }

    fn param(key: &CoseKey, label: i64) -> Vec<u8> {
        key.params
            .iter()
            .find(|(l, _)| *l == coset::Label::Int(label))
            .and_then(|(_, value)| value.as_bytes().cloned())
            .unwrap()
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
}
