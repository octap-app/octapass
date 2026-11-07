//! Two-step sign-in (plan 03, "Authentication to the server"): after the
//! master password, a new device proves possession of an authenticator app,
//! a security key or a recovery code. It guards access to the ciphertext; it
//! takes no part in the encryption.

pub mod totp;
pub mod webauthn;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::crypto::{base64url, keyed_hash, random_bytes};
use crate::secrets::ServerSecrets;
use crate::validate;

/// How many recovery codes an account gets at a time.
pub const RECOVERY_CODES: usize = 10;
/// Crockford base32: no I, L, O or U, so codes read aloud and type cleanly.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 10 characters, 50 bits each.
const RECOVERY_CODE_LEN: usize = 10;

/// A sign-in that passed the password and waits for its second step.
pub struct SecondFactorLogin {
    pub account_id: String,
    pub email: String,
    pub device_name: String,
    pub device_platform: String,
    /// The WebAuthn challenge, when the account has security keys.
    pub webauthn_challenge: Option<[u8; 32]>,
    /// Wrong tries so far.
    pub failures: u32,
    /// When SSO passed for this sign-in, if it was asked for.
    pub sso_at: Option<i64>,
}

fn seal_cipher(secrets: &ServerSecrets) -> XChaCha20Poly1305 {
    let key = keyed_hash(&*secrets.hmac_key, "openpass/two-step-seal", b"");
    XChaCha20Poly1305::new((&key).into())
}

fn seal_aad(account_id: &str) -> Vec<u8> {
    [b"openpass/two-step\0".as_slice(), account_id.as_bytes()].concat()
}

/// Seals a secret the server must read back (an authenticator secret) under a
/// key derived from the server secret, bound to the account.
pub fn seal(secrets: &ServerSecrets, account_id: &str, plaintext: &[u8]) -> String {
    let nonce = random_bytes::<24>();
    let aad = seal_aad(account_id);
    let ciphertext = seal_cipher(secrets)
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 encrypts any length");
    base64url([nonce.as_slice(), &ciphertext].concat())
}

pub fn open(secrets: &ServerSecrets, account_id: &str, sealed: &str) -> Option<Vec<u8>> {
    let bytes = validate::base64url("sealed", sealed, 1024).ok()?;
    if bytes.len() < 24 {
        return None;
    }
    let (nonce, ciphertext) = bytes.split_at(24);
    let aad = seal_aad(account_id);
    seal_cipher(secrets)
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .ok()
}

/// Fresh recovery codes, as shown to the user: `XXXXX-XXXXX`.
pub fn new_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let bytes = random_bytes::<8>();
            let value = u64::from_be_bytes(bytes);
            let chars: String = (0..RECOVERY_CODE_LEN)
                .map(|i| char::from(CROCKFORD[((value >> (5 * i)) & 31) as usize]))
                .collect();
            format!("{}-{}", &chars[..5], &chars[5..])
        })
        .collect()
}

/// A typed recovery code in canonical form, forgiving case, spaces, dashes
/// and the letters people confuse with digits.
pub fn normalize_recovery_code(typed: &str) -> Option<String> {
    let code: String = typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect();
    (code.len() == RECOVERY_CODE_LEN && code.bytes().all(|b| CROCKFORD.contains(&b)))
        .then_some(code)
}

/// What a recovery code is stored as: an HMAC under the server secret, bound
/// to the account.
pub fn recovery_code_hash(secrets: &ServerSecrets, account_id: &str, code: &str) -> String {
    let normalized = normalize_recovery_code(code).unwrap_or_default();
    base64url(keyed_hash(
        &*secrets.hmac_key,
        "openpass/recovery-code",
        format!("{account_id}\0{normalized}").as_bytes(),
    ))
}

/// The WebAuthn user handle for an account: stable, but not the account id.
pub fn webauthn_user_id(secrets: &ServerSecrets, account_id: &str) -> String {
    base64url(
        &keyed_hash(
            &*secrets.hmac_key,
            "openpass/webauthn-user",
            account_id.as_bytes(),
        )[..16],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn secrets() -> ServerSecrets {
        ServerSecrets {
            opaque_setup: opaque_ke::ServerSetup::new(&mut rand_core::OsRng),
            hmac_key: Zeroizing::new([3; 32]),
        }
    }

    #[test]
    fn sealed_secrets_open_only_for_their_account() {
        let secrets = secrets();
        let sealed = seal(&secrets, "account-a", b"secret");
        assert_eq!(open(&secrets, "account-a", &sealed).unwrap(), b"secret");
        assert!(open(&secrets, "account-b", &sealed).is_none());
        assert_ne!(
            sealed,
            seal(&secrets, "account-a", b"secret"),
            "random nonces"
        );
        assert!(open(&secrets, "account-a", "AAAA").is_none());
    }

    #[test]
    fn recovery_codes_are_distinct_and_forgiving() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), RECOVERY_CODES);
        for code in &codes {
            assert_eq!(code.len(), 11);
            assert_eq!(&code[5..6], "-");
            assert_eq!(
                normalize_recovery_code(code).unwrap(),
                code.replace('-', "")
            );
        }
        assert_eq!(
            normalize_recovery_code(" abcde o1il2 ").as_deref(),
            Some("ABCDE01112")
        );
        assert_eq!(normalize_recovery_code("ABCDE-0111U"), None, "U isn't used");
        assert_eq!(normalize_recovery_code("ABCDE"), None);

        let secrets = secrets();
        assert_eq!(
            recovery_code_hash(&secrets, "a", "abcde-01112"),
            recovery_code_hash(&secrets, "a", "ABCDE O1IL2")
        );
        assert_ne!(
            recovery_code_hash(&secrets, "a", "ABCDE-01112"),
            recovery_code_hash(&secrets, "b", "ABCDE-01112")
        );
    }
}
