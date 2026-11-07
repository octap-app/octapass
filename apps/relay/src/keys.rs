//! The relay's secret and what is derived from it. Each purpose has its own key, so a lookup hash
//! can never stand in for a return path, and neither can open a sealed address.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Lowercase RFC 4648 base32 (`a-z2-7`), cut to `chars` characters. Mail systems may fold the case
/// of a local part, so the relay's addresses have only one case.
pub fn base32_lower(bytes: &[u8], chars: usize) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(chars);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            if out.len() == chars {
                return out;
            }
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 && out.len() < chars {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    assert_eq!(out.len(), chars, "not enough input for {chars} characters");
    out
}

pub struct Keys {
    lookup: Zeroizing<[u8; 32]>,
    seal: Zeroizing<[u8; 32]>,
    pub(crate) srs: Zeroizing<[u8; 32]>,
}

pub(crate) fn hmac(key: &[u8], label: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(label.as_bytes());
    for part in parts {
        mac.update(&[0]);
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

impl Keys {
    pub fn derive(secret: &[u8]) -> Self {
        let derive = |label| Zeroizing::new(hmac(secret, label, &[]));
        Self {
            lookup: derive("octapass/relay/v1/lookup"),
            seal: derive("octapass/relay/v1/seal"),
            srs: derive("octapass/relay/v1/srs"),
        }
    }

    /// Finds an address without opening it. `scope` keeps one sender's hashes on two aliases
    /// apart, so the table alone doesn't show who wrote to which aliases.
    pub fn lookup(&self, scope: &str, address: &str) -> String {
        URL_SAFE_NO_PAD.encode(hmac(
            &*self.lookup,
            "address",
            &[scope.as_bytes(), address.as_bytes()],
        ))
    }

    /// `context` ties a sealed address to its row, so rows can't be swapped in the database.
    pub fn seal(&self, context: &str, plaintext: &str) -> String {
        let nonce = random_bytes::<24>();
        let cipher = XChaCha20Poly1305::new((&*self.seal).into());
        let sealed = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: context.as_bytes(),
                },
            )
            .expect("sealing a short address can't fail");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed);
        URL_SAFE_NO_PAD.encode(out)
    }

    pub fn open(&self, context: &str, sealed: &str) -> Option<String> {
        let bytes = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        if bytes.len() < 24 {
            return None;
        }
        let (nonce, ciphertext) = bytes.split_at(24);
        let cipher = XChaCha20Poly1305::new((&*self.seal).into());
        let plain = cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: context.as_bytes(),
                },
            )
            .ok()?;
        String::from_utf8(plain).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_is_the_rfc_alphabet() {
        // RFC 4648 section 10: BASE32("foobar") = MZXW6YTBOI======
        assert_eq!(base32_lower(b"foobar", 10), "mzxw6ytboi");
        assert_eq!(base32_lower(b"foob", 5), "mzxw6");
    }

    #[test]
    fn sealed_addresses_open_only_in_their_own_row() {
        let keys = Keys::derive(&[7; 32]);
        let sealed = keys.seal("contact:a", "jane@example.com");
        assert!(!sealed.contains("jane"));
        assert_eq!(
            keys.open("contact:a", &sealed).as_deref(),
            Some("jane@example.com")
        );
        assert_eq!(keys.open("contact:b", &sealed), None);
        assert_eq!(Keys::derive(&[8; 32]).open("contact:a", &sealed), None);
        assert_eq!(keys.open("contact:a", "AAAA"), None);
    }

    #[test]
    fn lookups_depend_on_the_scope_and_the_key() {
        let keys = Keys::derive(&[7; 32]);
        let hash = keys.lookup("a", "jane@example.com");
        assert_eq!(hash, keys.lookup("a", "jane@example.com"));
        assert_ne!(hash, keys.lookup("b", "jane@example.com"));
        assert_ne!(hash, Keys::derive(&[8; 32]).lookup("a", "jane@example.com"));
    }
}
