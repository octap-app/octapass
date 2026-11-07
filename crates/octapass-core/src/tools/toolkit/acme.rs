//! The pure half of ACME (RFC 8555): signed requests, challenge answers and the finalize CSR. The
//! network half lives in `octapass-net-tools`, so the core stays free of I/O.
//!
//! The account key is a separate key from the certificate's (RFC 8555 §11.1 requires that), and
//! the CA only ever sees public keys, CSRs and signatures.

use rand_core::CryptoRngCore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::keys::{PrivateKey, SignatureAlgorithm};
use super::x509::{self, CsrOptions, Subject};
use crate::encoding::{b64_decode, b64_encode};
use crate::error::{Error, Result};

/// Which account a request speaks for: a new account's key, or the URL of a registered one.
pub enum Signer<'a> {
    Jwk,
    Kid(&'a str),
}

fn algorithm_for(key: &PrivateKey) -> Result<SignatureAlgorithm> {
    match key {
        // RFC 8555 §6.2 requires ES256 and EdDSA support from clients and most CAs take RS256; P-256
        // is what every CA accepts.
        PrivateKey::P256(_) | PrivateKey::Ed25519(_) | PrivateKey::Rsa(_) | PrivateKey::P384(_) => {
            Ok(key.default_algorithm())
        }
        PrivateKey::P521(_) => Err(Error::UnsupportedAlgorithm),
    }
}

/// A flattened JWS for a POST to `url`. `payload` of `None` is a POST-as-GET (an empty payload).
pub fn signed_request(
    key: &PrivateKey,
    signer: Signer<'_>,
    nonce: &str,
    url: &str,
    payload: Option<&Value>,
    rng: &mut impl CryptoRngCore,
) -> Result<Value> {
    let algorithm = algorithm_for(key)?;
    let mut protected = json!({ "alg": algorithm.name(), "nonce": nonce, "url": url });
    match signer {
        Signer::Jwk => protected["jwk"] = key.public().to_jwk(),
        Signer::Kid(kid) => protected["kid"] = json!(kid),
    }
    let protected = b64_encode(protected.to_string().as_bytes());
    let payload = payload
        .map(|payload| b64_encode(payload.to_string().as_bytes()))
        .unwrap_or_default();
    let signature = key.sign(algorithm, format!("{protected}.{payload}").as_bytes(), rng)?;
    Ok(json!({
        "protected": protected,
        "payload": payload,
        "signature": b64_encode(&signature),
    }))
}

/// External account binding (RFC 8555 §7.3.4), which ZeroSSL and other CAs ask for: an HS256 JWS over
/// the account's public key, with the key the CA issued.
pub fn external_account_binding(
    account_key: &PrivateKey,
    eab_kid: &str,
    eab_hmac_key: &str,
    new_account_url: &str,
) -> Result<Value> {
    use hmac::{Hmac, Mac};
    let secret =
        b64_decode(eab_hmac_key.trim_end_matches('=')).map_err(|_| Error::InvalidToolInput)?;
    let protected = json!({ "alg": "HS256", "kid": eab_kid, "url": new_account_url });
    let protected = b64_encode(protected.to_string().as_bytes());
    let payload = b64_encode(account_key.public().to_jwk().to_string().as_bytes());
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret).map_err(|_| Error::InvalidKey)?;
    mac.update(format!("{protected}.{payload}").as_bytes());
    Ok(json!({
        "protected": protected,
        "payload": payload,
        "signature": b64_encode(&mac.finalize().into_bytes()),
    }))
}

/// RFC 8555 §8.1: a challenge token, a dot and the thumbprint of the account key.
pub fn key_authorization(account_key: &PrivateKey, token: &str) -> Result<String> {
    check_token(token)?;
    Ok(format!("{token}.{}", account_key.public().jwk_thumbprint()))
}

/// The token comes from the server and becomes a file name for HTTP-01. RFC 8555 limits it to the
/// base64url alphabet; anything else, `../` included, is refused.
pub fn check_token(token: &str) -> Result<()> {
    let valid = token.len() >= 16
        && token.len() <= 512
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    valid.then_some(()).ok_or(Error::InvalidAcme)
}

/// RFC 8555 §8.4: what goes in the `_acme-challenge` TXT record.
pub fn dns01_value(key_authorization: &str) -> String {
    b64_encode(&Sha256::digest(key_authorization.as_bytes()))
}

/// The record name for `domain`; a wildcard's challenge sits on its base name.
pub fn dns01_name(domain: &str) -> String {
    format!("_acme-challenge.{}", domain.trim_start_matches("*."))
}

/// The `finalize` body's CSR, as base64url DER, for `domains`, signed by the certificate's key.
pub fn finalize_csr(
    domains: &[String],
    certificate_key: &PrivateKey,
    rng: &mut impl CryptoRngCore,
) -> Result<String> {
    use der::Encode;
    let options = CsrOptions {
        subject: Subject::default(),
        sans: domains.to_vec(),
    };
    let csr = x509::create_csr(&options, certificate_key, rng)?;
    Ok(b64_encode(
        &csr.to_der().map_err(|_| Error::InvalidCertificate)?,
    ))
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use super::*;
    use crate::tools::toolkit::keys::{KeyKind, ParsedKey, generate, parse_jwk};

    fn account() -> PrivateKey {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([6; 32]);
        generate(KeyKind::P256, &mut rng).unwrap()
    }

    fn rng() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::from_seed([8; 32])
    }

    #[test]
    fn signed_request_verifies_with_the_embedded_key() {
        let key = account();
        let body = json!({ "termsOfServiceAgreed": true });
        let request = signed_request(
            &key,
            Signer::Jwk,
            "nonce-1",
            "https://ca.test/acct",
            Some(&body),
            &mut rng(),
        )
        .unwrap();
        let protected: Value =
            serde_json::from_slice(&b64_decode(request["protected"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(protected["alg"], "ES256");
        assert_eq!(protected["nonce"], "nonce-1");
        assert_eq!(protected["url"], "https://ca.test/acct");
        let ParsedKey::Public(public) = parse_jwk(&protected["jwk"]).unwrap() else {
            panic!("no public key");
        };
        let input = format!(
            "{}.{}",
            request["protected"].as_str().unwrap(),
            request["payload"].as_str().unwrap()
        );
        let signature = b64_decode(request["signature"].as_str().unwrap()).unwrap();
        assert!(
            public
                .verify(SignatureAlgorithm::Es256, input.as_bytes(), &signature)
                .unwrap()
        );
    }

    #[test]
    fn post_as_get_has_an_empty_payload_and_a_kid() {
        let request = signed_request(
            &account(),
            Signer::Kid("https://ca.test/acct/1"),
            "n",
            "https://ca.test/o",
            None,
            &mut rng(),
        )
        .unwrap();
        assert_eq!(request["payload"], "");
        let protected: Value =
            serde_json::from_slice(&b64_decode(request["protected"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(protected["kid"], "https://ca.test/acct/1");
        assert!(protected.get("jwk").is_none());
    }

    #[test]
    fn challenge_values() {
        let key = account();
        let token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
        let answer = key_authorization(&key, token).unwrap();
        assert_eq!(answer, format!("{token}.{}", key.public().jwk_thumbprint()));
        assert_eq!(dns01_value(&answer).len(), 43);
        assert_eq!(dns01_name("*.example.com"), "_acme-challenge.example.com");
        assert_eq!(dns01_name("a.example.com"), "_acme-challenge.a.example.com");
    }

    #[test]
    fn hostile_tokens_are_refused() {
        for token in [
            "../../etc/passwd/aaaaaaaa",
            "short",
            "aaaaaaaaaaaaaaaa/bbbb",
            "aaaaaaaaaaaaaaaa.bbbb",
        ] {
            assert_eq!(
                key_authorization(&account(), token).err(),
                Some(Error::InvalidAcme),
                "{token}"
            );
        }
    }

    #[test]
    fn external_binding_is_hs256_over_the_account_key() {
        let key = account();
        let secret = b64_encode(b"a key issued by the CA for binding");
        let binding =
            external_account_binding(&key, "kid-1", &secret, "https://ca.test/new-acct").unwrap();
        let protected: Value =
            serde_json::from_slice(&b64_decode(binding["protected"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(protected["alg"], "HS256");
        assert_eq!(protected["kid"], "kid-1");
        let payload: Value =
            serde_json::from_slice(&b64_decode(binding["payload"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(payload, key.public().to_jwk());
    }

    #[test]
    fn finalize_csr_lists_the_domains() {
        let mut rng = rng();
        let key = generate(KeyKind::P256, &mut rng).unwrap();
        let csr = finalize_csr(&["a.test".into(), "*.a.test".into()], &key, &mut rng).unwrap();
        let info = x509::inspect_csr(&x509::parse_csr(&csr).unwrap()).unwrap();
        assert!(info.signature_valid);
        assert_eq!(info.sans, ["a.test", "*.a.test"]);
    }
}
