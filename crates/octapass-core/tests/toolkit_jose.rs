//! JOSE against the published examples: RFC 7520 (the JOSE cookbook), RFC 7638 and RFC 8037.
//! `tests/toolkit-fixtures/jose-rfc.json` is taken from the RFC text, byte for byte.

#![cfg(feature = "toolkit")]

use octapass_core::Error;
use octapass_core::tools::toolkit::jose::{self, DecryptOptions, SecretInput, VerifyOptions};
use octapass_core::tools::toolkit::keys::{self, ParsedKey, SignatureAlgorithm};
use rand_core::OsRng;
use serde_json::Value;
use zeroize::Zeroizing;

// Cookbook tokens carry no time claims, so any time will do.
const NOW: u64 = 1_700_000_000;

fn fixture() -> Value {
    serde_json::from_str(include_str!("toolkit-fixtures/jose-rfc.json")).unwrap()
}

fn text(value: &Value) -> Zeroizing<String> {
    Zeroizing::new(value.to_string())
}

fn signatures() -> Vec<Value> {
    fixture()["jws"].as_array().unwrap().clone()
}

fn entry(name: &str) -> Value {
    fixture()["jwe"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap_or_else(|| panic!("no vector {name}"))
        .clone()
}

fn decrypt_with_jwk(name: &str) -> Result<jose::Decrypted, Error> {
    let vector = entry(name);
    jose::decrypt(
        &DecryptOptions {
            token: vector["token"].as_str().unwrap().to_owned(),
            key: Some(text(&vector["jwk"])),
            ..DecryptOptions::default()
        },
        NOW,
        &mut OsRng,
    )
}

fn assert_cookbook_plaintext(result: &jose::Decrypted) {
    let plaintext = result.text.as_ref().expect("plaintext is UTF-8");
    assert!(
        plaintext.starts_with("You can trust us to stick with you"),
        "{}",
        plaintext.as_str()
    );
    assert!(
        plaintext.ends_with("We are your friends, Frodo."),
        "{}",
        plaintext.as_str()
    );
}

#[test]
fn rfc7520_signatures_verify() {
    for vector in signatures() {
        let token = vector["token"].as_str().unwrap().to_owned();
        let algorithm = vector["algorithm"].as_str().unwrap();
        let options = if algorithm == "HS256" {
            VerifyOptions {
                token: token.clone(),
                secret: Some(SecretInput {
                    value: Zeroizing::new(vector["jwk"]["k"].as_str().unwrap().to_owned()),
                    encoding: Some("base64url".into()),
                }),
                ..VerifyOptions::default()
            }
        } else {
            VerifyOptions {
                token: token.clone(),
                key: Some(text(&vector["jwk"])),
                ..VerifyOptions::default()
            }
        };
        let verified = jose::verify(&options, NOW).unwrap();
        assert!(verified.signature_valid, "{algorithm}");
        assert_eq!(verified.decoded.algorithm.as_deref(), Some(algorithm));
        assert_eq!(
            verified.decoded.key_id.as_deref(),
            vector["jwk"]["kid"].as_str(),
            "{algorithm}"
        );

        // One changed byte of payload.
        let mut parts: Vec<&str> = token.split('.').collect();
        let changed = format!("A{}", &parts[1][1..]);
        parts[1] = &changed;
        let tampered = VerifyOptions {
            token: parts.join("."),
            ..options
        };
        assert!(
            !jose::verify(&tampered, NOW).unwrap().signature_valid,
            "{algorithm}"
        );
    }
}

#[test]
fn rfc7520_rs256_signature_is_reproduced_exactly() {
    // PKCS#1 v1.5 is deterministic, so signing the same input gives the RFC's bytes.
    let vector = &signatures()[0];
    assert_eq!(vector["algorithm"], "RS256");
    let token = vector["token"].as_str().unwrap();
    let ParsedKey::Private(key) = keys::parse_jwk(&vector["jwk"]).unwrap() else {
        panic!("the RFC gives the private key");
    };
    let (input, signature) = token.rsplit_once('.').unwrap();
    let ours = key
        .sign(SignatureAlgorithm::Rs256, input.as_bytes(), &mut OsRng)
        .unwrap();
    assert_eq!(octapass_core::encoding::b64_encode(&ours), signature);
}

#[test]
fn rfc7520_rsa_oaep_a256gcm() {
    assert_cookbook_plaintext(&decrypt_with_jwk("RSA-OAEP+A256GCM").unwrap());
}

#[test]
fn rfc7520_ecdh_es_a128kw() {
    assert_cookbook_plaintext(&decrypt_with_jwk("ECDH-ES+A128KW+A128GCM").unwrap());
}

#[test]
fn rfc7520_ecdh_es_direct() {
    assert_cookbook_plaintext(&decrypt_with_jwk("ECDH-ES+A128CBC-HS256").unwrap());
}

#[test]
fn rfc7520_direct_encryption() {
    assert_cookbook_plaintext(&decrypt_with_jwk("dir+A128GCM").unwrap());
}

#[test]
fn rfc7520_aes_gcm_key_wrap() {
    assert_cookbook_plaintext(&decrypt_with_jwk("A256GCMKW+A128CBC-HS256").unwrap());
}

#[test]
fn rfc7520_aes_key_wrap() {
    assert_cookbook_plaintext(&decrypt_with_jwk("A128KW+A128GCM").unwrap());
}

#[test]
fn rfc7520_compressed_payload() {
    assert_cookbook_plaintext(&decrypt_with_jwk("A128KW+A128GCM+DEF").unwrap());
}

#[test]
fn rfc7520_password_based() {
    let vector = entry("PBES2-HS512+A256KW+A128CBC-HS256");
    let options = |password: &str| DecryptOptions {
        token: vector["token"].as_str().unwrap().to_owned(),
        secret: Some(SecretInput {
            value: Zeroizing::new(password.to_owned()),
            encoding: None,
        }),
        ..DecryptOptions::default()
    };
    let opened = jose::decrypt(
        &options(vector["password"].as_str().unwrap()),
        NOW,
        &mut OsRng,
    )
    .unwrap();
    // This one's plaintext is a JWK set, not the story.
    assert_eq!(
        opened.payload.as_ref().unwrap()["keys"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        jose::decrypt(&options("wrong"), NOW, &mut OsRng).err(),
        Some(Error::DecryptionFailed)
    );
}

#[test]
fn rsa1_5_is_refused() {
    assert_eq!(
        decrypt_with_jwk("RSA1_5+A128CBC-HS256").err(),
        Some(Error::UnsupportedAlgorithm)
    );
}

#[test]
fn a_changed_ciphertext_fails_authentication() {
    let vector = entry("dir+A128GCM");
    let token = vector["token"].as_str().unwrap();
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let first = if parts[3].starts_with('A') { 'B' } else { 'A' };
    parts[3].replace_range(0..1, &first.to_string());
    let options = DecryptOptions {
        token: parts.join("."),
        key: Some(text(&vector["jwk"])),
        ..DecryptOptions::default()
    };
    assert_eq!(
        jose::decrypt(&options, NOW, &mut OsRng).err(),
        Some(Error::DecryptionFailed)
    );
}

#[test]
fn a_jwe_is_read_without_its_key() {
    let vector = entry("dir+A128GCM");
    let decoded = jose::decode(vector["token"].as_str().unwrap(), NOW).unwrap();
    assert_eq!(decoded.kind, "jwe");
    assert_eq!(decoded.algorithm.as_deref(), Some("dir"));
    assert_eq!(decoded.encryption.as_deref(), Some("A128GCM"));
    assert!(decoded.payload.is_none());
}

#[test]
fn rfc7638_thumbprint() {
    let vector = &fixture()["thumbprint"];
    assert_eq!(keys::jwk_thumbprint(&vector["jwk"]), vector["value"]);
}

#[test]
fn rfc8037_ed25519() {
    let vector = &fixture()["eddsa"];
    assert_eq!(keys::jwk_thumbprint(&vector["jwk"]), vector["thumbprint"]);
    let token = vector["token"].as_str().unwrap();
    let (input, signature) = token.rsplit_once('.').unwrap();
    let ParsedKey::Private(key) = keys::parse_jwk(&vector["jwk"]).unwrap() else {
        panic!("the RFC gives the private key");
    };
    // Ed25519 is deterministic too.
    let ours = key
        .sign(SignatureAlgorithm::EdDsa, input.as_bytes(), &mut OsRng)
        .unwrap();
    assert_eq!(octapass_core::encoding::b64_encode(&ours), signature);
    let verified = jose::verify(
        &VerifyOptions {
            token: token.to_owned(),
            key: Some(text(&vector["jwk"])),
            ..VerifyOptions::default()
        },
        NOW,
    )
    .unwrap();
    assert!(verified.signature_valid);
}
