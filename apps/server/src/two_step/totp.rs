//! RFC 6238 one-time codes as every authenticator app makes them: HMAC-SHA-1,
//! 6 digits, 30-second steps.

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::crypto::constant_time_eq;

/// 160 bits, the size RFC 4226 recommends for SHA-1.
pub const SECRET_LEN: usize = 20;
const STEP_MS: i64 = 30_000;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The 30-second step `now` (Unix milliseconds) falls in.
pub fn step_at(now: i64) -> i64 {
    now.div_euclid(STEP_MS)
}

/// The code for one step (RFC 4226 dynamic truncation).
pub fn code(secret: &[u8], step: i64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let value =
        u32::from_be_bytes(digest[offset..offset + 4].try_into().expect("4 bytes")) & 0x7fff_ffff;
    format!("{:06}", value % 1_000_000)
}

/// The step a typed code matches: the current one or its neighbours (clocks
/// drift, people type slowly), and only steps after `last_step`, so a code
/// works once.
pub fn verify(secret: &[u8], typed: &str, now: i64, last_step: i64) -> Option<i64> {
    let typed: String = typed.chars().filter(|c| !c.is_whitespace()).collect();
    if typed.len() != 6 || !typed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let current = step_at(now);
    // Every candidate is checked, so timing doesn't tell which step matched.
    let mut matched = None;
    for step in [current - 1, current, current + 1] {
        if constant_time_eq(code(secret, step).as_bytes(), typed.as_bytes()) && step > last_step {
            matched = Some(step);
        }
    }
    matched
}

/// RFC 4648 base32 without padding, as authenticator apps expect secrets.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    for chunk in bytes.chunks(5) {
        let mut buffer = [0u8; 5];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let value = buffer
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..chars {
            let index = (value >> (35 - 5 * i)) & 31;
            out.push(char::from(BASE32[index as usize]));
        }
    }
    out
}

/// The `otpauth://` URI apps read from a QR code. The label and issuer say
/// which account the code is for.
pub fn otpauth_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        percent_encode(issuer),
        percent_encode(account),
        base32(secret),
        percent_encode(issuer),
    )
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~@".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, SHA-1 rows (the last 6 of the 8 digits).
    #[test]
    fn matches_the_rfc_vectors() {
        let secret = b"12345678901234567890";
        for (seconds, expected) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(code(secret, step_at(seconds * 1000)), expected);
        }
    }

    #[test]
    fn accepts_neighbouring_steps_once() {
        let secret = b"12345678901234567890";
        let now = 1_111_111_111_000;
        let step = step_at(now);
        assert_eq!(verify(secret, &code(secret, step), now, 0), Some(step));
        assert_eq!(
            verify(secret, &code(secret, step - 1), now, 0),
            Some(step - 1)
        );
        assert_eq!(
            verify(secret, &code(secret, step + 1), now, 0),
            Some(step + 1)
        );
        assert_eq!(verify(secret, &code(secret, step - 2), now, 0), None);
        assert_eq!(verify(secret, &code(secret, step), now, step), None);
        let spaced = format!("{} {}", &code(secret, step)[..3], &code(secret, step)[3..]);
        assert_eq!(verify(secret, &spaced, now, 0), Some(step));
        assert_eq!(verify(secret, "12345", now, 0), None);
        assert_eq!(verify(secret, "abcdef", now, 0), None);
    }

    #[test]
    fn encodes_base32_and_uris() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(
            base32(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        assert_eq!(
            otpauth_uri(b"12345678901234567890", "Octa Pass", "a+b@example.com"),
            "otpauth://totp/Open%20Pass:a%2Bb@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
             &issuer=Open%20Pass&algorithm=SHA1&digits=6&period=30"
        );
    }
}
