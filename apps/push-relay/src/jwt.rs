//! The two signed tokens the relay needs: an ES256 provider token for APNs, and an RS256
//! assertion traded for a Google access token. Both are compact JWS, signed with ring.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("not a PEM private key")]
    NotPem,
    #[error("the key isn't a {0} PKCS#8 key")]
    WrongKey(&'static str),
}

/// The DER inside a `-----BEGIN PRIVATE KEY-----` block.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, KeyError> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .skip_while(|line| !line.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|line| !line.starts_with("-----END"))
        .collect();
    if body.is_empty() {
        return Err(KeyError::NotPem);
    }
    STANDARD.decode(body).map_err(|_| KeyError::NotPem)
}

pub fn ecdsa_key(pem: &str) -> Result<EcdsaKeyPair, KeyError> {
    let der = pem_to_der(pem)?;
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &SystemRandom::new())
        .map_err(|_| KeyError::WrongKey("P-256"))
}

pub fn rsa_key(pem: &str) -> Result<RsaKeyPair, KeyError> {
    let der = pem_to_der(pem)?;
    RsaKeyPair::from_pkcs8(&der).map_err(|_| KeyError::WrongKey("RSA"))
}

fn signing_input(header: &Value, claims: &Value) -> String {
    let part = |value: &Value| URL_SAFE_NO_PAD.encode(value.to_string());
    format!("{}.{}", part(header), part(claims))
}

pub fn es256(key: &EcdsaKeyPair, header: &Value, claims: &Value) -> String {
    let input = signing_input(header, claims);
    let signature = key
        .sign(&SystemRandom::new(), input.as_bytes())
        .expect("ECDSA signing doesn't fail with the system RNG");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
}

pub fn rs256(key: &RsaKeyPair, header: &Value, claims: &Value) -> String {
    let input = signing_input(header, claims);
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        input.as_bytes(),
        &mut signature,
    )
    .expect("RSA signing doesn't fail with a buffer of the modulus' size");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

pub fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::signature::{
        ECDSA_P256_SHA256_FIXED, KeyPair, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey,
    };
    use serde_json::json;

    /// A fresh P-256 key as the PEM a `.p8` file holds.
    pub fn p256_pem() -> String {
        let der =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(der.as_ref())
        )
    }

    pub const RSA_PEM: &str = include_str!("../tests/fixtures/test-rsa.pem");

    fn verify(token: &str, check: impl Fn(&[u8], &[u8])) {
        let (input, signature) = token.rsplit_once('.').unwrap();
        check(
            input.as_bytes(),
            &URL_SAFE_NO_PAD.decode(signature).unwrap(),
        );
    }

    #[test]
    fn es256_verifies_with_the_public_key() {
        let key = ecdsa_key(&p256_pem()).unwrap();
        let token = es256(
            &key,
            &json!({"alg": "ES256", "kid": "K"}),
            &json!({"iss": "T"}),
        );
        let public = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key().as_ref());
        verify(&token, |input, signature| {
            public.verify(input, signature).unwrap()
        });
        let header = token.split('.').next().unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap(),
            json!({"alg": "ES256", "kid": "K"})
        );
    }

    #[test]
    fn rs256_verifies_with_the_public_key() {
        let key = rsa_key(RSA_PEM).unwrap();
        let token = rs256(&key, &json!({"alg": "RS256"}), &json!({"iss": "a"}));
        let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public().as_ref());
        verify(&token, |input, signature| {
            public.verify(input, signature).unwrap()
        });
    }

    #[test]
    fn refuses_the_wrong_keys() {
        assert!(matches!(pem_to_der("nothing"), Err(KeyError::NotPem)));
        assert!(rsa_key(&p256_pem()).is_err());
        assert!(ecdsa_key(RSA_PEM).is_err());
    }
}
