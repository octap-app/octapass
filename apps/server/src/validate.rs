//! Input checks. The server can't look inside ciphertext, but it can make sure
//! every field has the shape the contract promises.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use octapass_api::{Grant, KdfAlgorithm, KdfParams};

use crate::error::{ApiError, ApiResult};

pub const ACCOUNT_SALT_LEN: usize = 16;

/// `version (1) ‖ key_id (16) ‖ nonce (24) ‖ tag (16)`, with an empty plaintext.
const MIN_ENVELOPE_LEN: usize = 1 + 16 + 24 + 16;
const ENVELOPE_VERSION: u8 = 0x01;
/// `version (1) ‖ ephemeral public key (32) ‖ nonce (24) ‖ key (32) ‖ tag (16)`.
const SEALED_KEY_LEN: usize = 105;
const SEALED_KEY_VERSION: u8 = 0x01;
const HYBRID_SEALED_KEY_LEN: usize = 1193;
const HYBRID_SEALED_KEY_VERSION: u8 = 0x02;
pub const KEY_ID_LEN: usize = 16;
const SIGNATURE_LEN: usize = 64;

/// Trims and lowercases, as clients do before using the email as the OPAQUE
/// credential identifier.
pub fn email(raw: &str) -> ApiResult<String> {
    let email = raw.trim().to_lowercase();
    let valid = email.len() <= 254
        && !email.chars().any(char::is_whitespace)
        && matches!(email.split_once('@'), Some((local, domain)) if !local.is_empty() && !domain.is_empty() && !domain.contains('@'));
    if valid {
        Ok(email)
    } else {
        Err(bad("email", "is not a valid email address"))
    }
}

pub fn base64url(field: &str, value: &str, max_len: usize) -> ApiResult<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| bad(field, "must be base64url without padding"))?;
    if bytes.len() > max_len {
        return Err(bad(field, "is too long"));
    }
    Ok(bytes)
}

pub fn exact_bytes(field: &str, value: &str, len: usize) -> ApiResult<Vec<u8>> {
    let bytes = base64url(field, value, len)?;
    if bytes.len() != len {
        return Err(bad(field, &format!("must be {len} bytes")));
    }
    Ok(bytes)
}

/// Checks that `value` is a version 1 ciphertext envelope of at most `max_len` bytes.
pub fn envelope(field: &str, value: &str, max_len: usize) -> ApiResult<()> {
    let bytes = base64url(field, value, max_len)?;
    if bytes.len() < MIN_ENVELOPE_LEN || bytes[0] != ENVELOPE_VERSION {
        return Err(bad(field, "must be a version 1 ciphertext envelope"));
    }
    Ok(())
}

/// The key id inside a valid ciphertext envelope, base64url.
pub fn envelope_key_id(value: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    let key_id = bytes.get(1..1 + KEY_ID_LEN)?;
    Some(URL_SAFE_NO_PAD.encode(key_id))
}

/// Checks that `value` has the shape of a 32-byte key in a sealed box of either version.
pub fn sealed_key(field: &str, value: &str) -> ApiResult<()> {
    let bytes = base64url(field, value, HYBRID_SEALED_KEY_LEN)?;
    match (bytes.len(), bytes.first()) {
        (SEALED_KEY_LEN, Some(&SEALED_KEY_VERSION))
        | (HYBRID_SEALED_KEY_LEN, Some(&HYBRID_SEALED_KEY_VERSION)) => Ok(()),
        _ => Err(bad(field, "must be a version 1 or 2 sealed key")),
    }
}

/// Checks a grant's shape. Only clients can check what it means.
pub fn grant(field: &str, grant: &Grant) -> ApiResult<()> {
    id(&format!("{field}.vaultId"), &grant.vault_id)?;
    id(
        &format!("{field}.recipientAccountId"),
        &grant.recipient_account_id,
    )?;
    id(&format!("{field}.grantedBy"), &grant.granted_by)?;
    sealed_key(
        &format!("{field}.wrappedVaultKey"),
        &grant.wrapped_vault_key,
    )?;
    exact_bytes(
        &format!("{field}.signature"),
        &grant.signature,
        SIGNATURE_LEN,
    )?;
    Ok(())
}

/// Parses an RFC 3339 timestamp into Unix milliseconds.
pub fn timestamp(field: &str, value: &str) -> ApiResult<i64> {
    let parsed = time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| bad(field, "must be an RFC 3339 timestamp"))?;
    i64::try_from(parsed.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| bad(field, "is out of range"))
}

/// Ids are client-generated UUIDs in canonical lowercase hyphenated form, so
/// the id a client sends is exactly the id it gets back.
pub fn id(field: &str, value: &str) -> ApiResult<String> {
    match uuid::Uuid::try_parse(value) {
        Ok(uuid) if uuid.hyphenated().to_string() == value => Ok(value.to_owned()),
        _ => Err(bad(field, "must be a lowercase hyphenated UUID")),
    }
}

/// The contract's parameters are the floor. The ceiling is the one clients
/// accept (`KdfParams::validate` in octapass-core), so a bad client can't lock
/// its own account behind parameters other devices refuse to compute.
pub fn kdf(kdf: &KdfParams) -> ApiResult<()> {
    let KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib,
        iterations,
        parallelism,
    } = *kdf;
    let valid = (65_536..=1_048_576).contains(&memory_kib)
        && (3..=16).contains(&iterations)
        && (1..=4).contains(&parallelism);
    if valid {
        Ok(())
    } else {
        Err(bad("kdf", "parameters are out of range"))
    }
}

pub fn text(field: &str, value: &str, max_chars: usize) -> ApiResult<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > max_chars || value.chars().any(char::is_control)
    {
        return Err(bad(
            field,
            &format!("must be 1 to {max_chars} printable characters"),
        ));
    }
    Ok(value.to_owned())
}

fn bad(field: &str, reason: &str) -> ApiError {
    ApiError::BadRequest(format!("{field} {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_email() {
        assert_eq!(email("  Alice@Example.COM ").unwrap(), "alice@example.com");
        for bad in [
            "",
            "alice",
            "@example.com",
            "alice@",
            "a b@example.com",
            "a@b@c",
        ] {
            assert!(email(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn checks_envelopes() {
        let mut envelope_bytes = vec![0u8; MIN_ENVELOPE_LEN];
        envelope_bytes[0] = ENVELOPE_VERSION;
        let good = URL_SAFE_NO_PAD.encode(&envelope_bytes);
        assert!(envelope("f", &good, 1024).is_ok());
        assert!(envelope("f", &good, MIN_ENVELOPE_LEN - 1).is_err());
        assert!(envelope("f", &URL_SAFE_NO_PAD.encode(&envelope_bytes[1..]), 1024).is_err());
        envelope_bytes[0] = 2;
        assert!(envelope("f", &URL_SAFE_NO_PAD.encode(&envelope_bytes), 1024).is_err());
        assert!(envelope("f", &format!("{good}="), 1024).is_err());
    }

    #[test]
    fn checks_ids() {
        let uuid = uuid::Uuid::now_v7().to_string();
        assert_eq!(id("id", &uuid).unwrap(), uuid);
        assert!(id("id", &uuid.to_uppercase()).is_err());
        assert!(id("id", &uuid.replace('-', "")).is_err());
        assert!(id("id", "item_123").is_err());
    }

    #[test]
    fn checks_kdf_range() {
        let base = KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        };
        assert!(kdf(&base).is_ok());
        assert!(
            kdf(&KdfParams {
                memory_kib: 19_456,
                ..base
            })
            .is_err()
        );
        assert!(
            kdf(&KdfParams {
                iterations: 1,
                ..base
            })
            .is_err()
        );
        assert!(
            kdf(&KdfParams {
                parallelism: 0,
                ..base
            })
            .is_err()
        );
        let ceiling = KdfParams {
            memory_kib: 1_048_576,
            iterations: 16,
            parallelism: 4,
            ..base
        };
        assert!(kdf(&ceiling).is_ok());
        for over in [
            KdfParams {
                iterations: 17,
                ..ceiling
            },
            KdfParams {
                parallelism: 5,
                ..ceiling
            },
            KdfParams {
                memory_kib: 1_048_577,
                ..ceiling
            },
        ] {
            assert!(kdf(&over).is_err());
        }
    }

    #[test]
    fn checks_sealed_keys_and_key_ids() {
        let mut sealed = vec![0u8; SEALED_KEY_LEN];
        sealed[0] = SEALED_KEY_VERSION;
        assert!(sealed_key("k", &URL_SAFE_NO_PAD.encode(&sealed)).is_ok());
        let mut hybrid = vec![0u8; HYBRID_SEALED_KEY_LEN];
        hybrid[0] = HYBRID_SEALED_KEY_VERSION;
        assert!(sealed_key("k", &URL_SAFE_NO_PAD.encode(&hybrid)).is_ok());
        hybrid[0] = SEALED_KEY_VERSION;
        assert!(sealed_key("k", &URL_SAFE_NO_PAD.encode(&hybrid)).is_err());
        assert!(sealed_key("k", &URL_SAFE_NO_PAD.encode(&sealed[1..])).is_err());
        sealed[0] = 2;
        assert!(sealed_key("k", &URL_SAFE_NO_PAD.encode(&sealed)).is_err());

        let mut envelope = vec![1u8; MIN_ENVELOPE_LEN];
        envelope[1..17].copy_from_slice(&[7; 16]);
        assert_eq!(
            envelope_key_id(&URL_SAFE_NO_PAD.encode(&envelope)),
            Some(URL_SAFE_NO_PAD.encode([7; 16]))
        );
        assert_eq!(envelope_key_id("AA"), None);
    }

    #[test]
    fn parses_timestamps() {
        assert_eq!(
            timestamp("t", "2025-10-23T00:00:00.123Z").unwrap(),
            1_761_177_600_123
        );
        assert_eq!(
            timestamp("t", "2025-10-23T02:00:00+02:00").unwrap(),
            1_761_177_600_000
        );
        assert!(timestamp("t", "yesterday").is_err());
    }

    #[test]
    fn checks_exact_lengths() {
        assert!(exact_bytes("k", &URL_SAFE_NO_PAD.encode([0u8; 32]), 32).is_ok());
        assert!(exact_bytes("k", &URL_SAFE_NO_PAD.encode([0u8; 31]), 32).is_err());
    }
}
