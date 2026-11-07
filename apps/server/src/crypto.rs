//! The few primitives the server needs. None of them touch vault data.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use opaque_ke::CipherSuite;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

/// The contract's OPAQUE ciphersuite. Argon2id already ran on the client, so
/// the key stretching function here is the identity.
pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn base64url(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A 256-bit bearer token, base64url.
pub fn random_token() -> String {
    base64url(random_bytes::<32>())
}

/// Tokens are stored only as this hash, so a database leak doesn't leak sessions.
pub fn token_hash(token: &str) -> String {
    base64url(Sha256::digest(token.as_bytes()))
}

/// HMAC-SHA256 under the server secret, with a label per purpose so one
/// output can never stand in for another.
pub fn keyed_hash(secret: &[u8], label: &str, data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(label.as_bytes());
    mac.update(&[0]);
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// The digits form of an account's key fingerprint, as `octapass-core`
/// computes it: SHA-256 of a label and both public keys, as 6 groups of 4
/// digits. It's only a convenience in responses: clients compute their own,
/// because a server could lie about the keys and the fingerprint alike.
pub fn fingerprint(public_enc_key: &str, public_sign_key: &str) -> String {
    let decode = |key: &str| URL_SAFE_NO_PAD.decode(key).unwrap_or_default();
    let digest = Sha256::new()
        .chain_update(b"openpass/v1/fingerprint\0")
        .chain_update(decode(public_enc_key))
        .chain_update(decode(public_sign_key))
        .finalize();
    digest[..30]
        .chunks(5)
        .map(|chunk| {
            let value = chunk.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
            format!("{:04}", value % 10_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// A uniformly random 6-digit code.
pub fn six_digit_code() -> String {
    // 4_294_000_000 is the largest multiple of 1_000_000 below 2^32, so
    // rejecting values above it removes the modulo bias.
    loop {
        let value = OsRng.next_u32();
        if value < 4_294_000_000 {
            return format!("{:06}", value % 1_000_000);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_hash_stably() {
        let (a, b) = (random_token(), random_token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert_eq!(token_hash(&a), token_hash(&a));
        assert_ne!(token_hash(&a), token_hash(&b));
    }

    #[test]
    fn keyed_hash_separates_labels() {
        let secret = [7u8; 32];
        assert_eq!(
            keyed_hash(&secret, "a", b"x"),
            keyed_hash(&secret, "a", b"x")
        );
        assert_ne!(
            keyed_hash(&secret, "a", b"x"),
            keyed_hash(&secret, "b", b"x")
        );
        assert_ne!(
            keyed_hash(&secret, "a", b"x"),
            keyed_hash(&[8u8; 32], "a", b"x")
        );
    }

    #[test]
    fn fingerprints_match_the_core() {
        use octapass_core::sharing::fingerprint::fingerprint as core_fingerprint;
        let (enc, sign) = ([1u8; 32], [2u8; 32]);
        assert_eq!(
            fingerprint(&base64url(enc), &base64url(sign)),
            core_fingerprint(&enc, &sign).digits
        );
    }

    #[test]
    fn codes_have_six_digits() {
        for _ in 0..100 {
            let code = six_digit_code();
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|b| b.is_ascii_digit()));
        }
    }
}
