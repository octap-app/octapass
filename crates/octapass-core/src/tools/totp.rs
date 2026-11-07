//! One-time passwords: HOTP (RFC 4226) and TOTP (RFC 6238).

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use super::otpauth::{OtpAlgorithm, OtpKind, OtpParams};
use crate::error::{Error, Result};

/// The current code for a TOTP item, with what the UI needs to show a countdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
    /// Seconds per code.
    pub period: u64,
    /// Seconds until the next code.
    pub remaining: u64,
}

/// The TOTP code at `unix_seconds` for an item's `totp` field (an `otpauth://totp/…` URI or a
/// bare base32 secret).
pub fn totp_code(totp: &str, unix_seconds: u64) -> Result<TotpCode> {
    let params = OtpParams::parse(totp)?;
    let OtpKind::Totp { period } = params.kind else {
        return Err(Error::InvalidTotp);
    };
    Ok(TotpCode {
        code: hotp(
            &params.secret,
            unix_seconds / period,
            params.digits,
            params.algorithm,
        ),
        period,
        remaining: period - unix_seconds % period,
    })
}

/// A counter-based code. Unlike TOTP, a code exists only once the counter moves, so apps show a code
/// when the user asks for one, never by themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HotpCode {
    pub code: String,
    /// The counter this code was made from.
    pub counter: u64,
}

/// Whether an item's `totp` field is a counter-based (HOTP) setup.
pub fn is_hotp(totp: &str) -> bool {
    matches!(
        OtpParams::parse(totp).map(|params| params.kind),
        Ok(OtpKind::Hotp { .. })
    )
}

/// The counter of the next code. Fails for anything but an `otpauth://hotp/…` URI.
pub fn hotp_counter(totp: &str) -> Result<u64> {
    match OtpParams::parse(totp)?.kind {
        OtpKind::Hotp { counter } => Ok(counter),
        OtpKind::Totp { .. } => Err(Error::InvalidTotp),
    }
}

/// The next code, and the `totp` field to store for the one after it.
///
/// An item's stored counter is always the next one to use, as in Aegis and RFC 4226's test values
/// (counter 0 is the first code). Save the returned URI **before showing the code**: then a code
/// is never handed out twice, at worst one is skipped, which the site's look-ahead window accepts.
pub fn next_hotp_code(totp: &str) -> Result<(HotpCode, Zeroizing<String>)> {
    let params = OtpParams::parse(totp)?;
    let OtpKind::Hotp { counter } = params.kind else {
        return Err(Error::InvalidTotp);
    };
    let next = counter.checked_add(1).ok_or(Error::InvalidTotp)?;
    let code = hotp(&params.secret, counter, params.digits, params.algorithm);
    let stored = OtpParams {
        kind: OtpKind::Hotp { counter: next },
        ..params
    };
    Ok((HotpCode { code, counter }, stored.to_uri()))
}

/// The `totp` field with its counter set, for bringing a token back in step with the site.
pub fn with_hotp_counter(totp: &str, counter: u64) -> Result<Zeroizing<String>> {
    let params = OtpParams::parse(totp)?;
    let OtpKind::Hotp { .. } = params.kind else {
        return Err(Error::InvalidTotp);
    };
    Ok(OtpParams {
        kind: OtpKind::Hotp { counter },
        ..params
    }
    .to_uri())
}

/// For two copies of one HOTP setup, the one with the higher counter: counters only move forward,
/// and the lower one has already given out codes the site won't take again. `None` when they
/// aren't both HOTP with the same secret, digits and algorithm.
pub fn newest_hotp<'a>(a: &'a str, b: &'a str) -> Option<&'a str> {
    let (first, second) = (OtpParams::parse(a).ok()?, OtpParams::parse(b).ok()?);
    let same = first.secret == second.secret
        && first.digits == second.digits
        && first.algorithm == second.algorithm;
    match (first.kind, second.kind) {
        (OtpKind::Hotp { counter: x }, OtpKind::Hotp { counter: y }) if same => {
            Some(if x >= y { a } else { b })
        }
        _ => None,
    }
}

/// RFC 4226 HOTP: dynamic truncation of `HMAC(secret, counter)`.
pub fn hotp(secret: &[u8], counter: u64, digits: u32, algorithm: OtpAlgorithm) -> String {
    let digest = match algorithm {
        OtpAlgorithm::Sha1 => mac::<Hmac<Sha1>>(secret, counter),
        OtpAlgorithm::Sha256 => mac::<Hmac<Sha256>>(secret, counter),
        OtpAlgorithm::Sha512 => mac::<Hmac<Sha512>>(secret, counter),
    };
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    let code = u64::from(binary) % 10u64.pow(digits);
    format!("{code:0width$}", width = digits as usize)
}

fn mac<M: Mac + hmac::digest::KeyInit>(secret: &[u8], counter: u64) -> Vec<u8> {
    let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(secret)
        .expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::base32_encode;

    const SEED20: &[u8] = b"12345678901234567890";
    const SEED32: &[u8] = b"12345678901234567890123456789012";
    const SEED64: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn rfc4226_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(hotp(SEED20, counter as u64, 6, OtpAlgorithm::Sha1), *code);
        }
    }

    #[test]
    fn rfc6238_vectors() {
        let cases = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (time, sha1, sha256, sha512) in cases {
            assert_eq!(hotp(SEED20, time / 30, 8, OtpAlgorithm::Sha1), sha1);
            assert_eq!(hotp(SEED32, time / 30, 8, OtpAlgorithm::Sha256), sha256);
            assert_eq!(hotp(SEED64, time / 30, 8, OtpAlgorithm::Sha512), sha512);
        }
    }

    #[test]
    fn totp_from_uri_and_bare_secret() {
        let secret = base32_encode(SEED32);
        let uri = format!(
            "otpauth://totp/ACME:alice?secret={secret}&algorithm=SHA256&digits=8&period=30"
        );
        assert_eq!(
            totp_code(&uri, 59).unwrap(),
            TotpCode {
                code: "46119246".into(),
                period: 30,
                remaining: 1
            }
        );
        let bare = totp_code(&base32_encode(SEED20), 1_111_111_109).unwrap();
        assert_eq!(
            bare,
            TotpCode {
                code: "081804".into(),
                period: 30,
                remaining: 1
            }
        );
    }

    #[test]
    fn hotp_uris_have_no_totp_code() {
        let uri = "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1";
        assert_eq!(totp_code(uri, 0).unwrap_err(), Error::InvalidTotp);
    }

    fn hotp_uri(counter: u64) -> String {
        let secret = base32_encode(SEED20);
        format!("otpauth://hotp/ACME:alice?secret={secret}&counter={counter}&issuer=ACME")
    }

    #[test]
    fn next_hotp_codes_follow_rfc4226_and_move_the_counter() {
        // RFC 4226 appendix D: every counter from 0 gives the next published value.
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        let mut stored = hotp_uri(0);
        for (counter, code) in expected.iter().enumerate() {
            let (next, uri) = next_hotp_code(&stored).unwrap();
            assert_eq!(
                next,
                HotpCode {
                    code: (*code).into(),
                    counter: counter as u64
                }
            );
            stored = uri.to_string();
            assert_eq!(hotp_counter(&stored).unwrap(), counter as u64 + 1);
        }
        // What was around the counter survives.
        let params = OtpParams::parse(&stored).unwrap();
        assert_eq!(params.issuer.as_deref(), Some("ACME"));
        assert_eq!(params.account.as_deref(), Some("alice"));
    }

    #[test]
    fn hotp_counters_can_be_set_and_never_wrap() {
        let set = with_hotp_counter(&hotp_uri(3), 7).unwrap();
        assert_eq!(hotp_counter(&set).unwrap(), 7);
        assert_eq!(next_hotp_code(&set).unwrap().0.code, "162583");
        let last = with_hotp_counter(&hotp_uri(0), u64::MAX).unwrap();
        assert_eq!(next_hotp_code(&last).unwrap_err(), Error::InvalidTotp);
    }

    #[test]
    fn hotp_helpers_refuse_totp() {
        let totp = base32_encode(SEED20);
        assert!(!is_hotp(&totp));
        assert!(is_hotp(&hotp_uri(1)));
        assert!(!is_hotp("not a secret!"));
        assert_eq!(hotp_counter(&totp).unwrap_err(), Error::InvalidTotp);
        assert_eq!(next_hotp_code(&totp).unwrap_err(), Error::InvalidTotp);
        assert_eq!(with_hotp_counter(&totp, 1).unwrap_err(), Error::InvalidTotp);
    }

    #[test]
    fn the_newest_hotp_copy_is_the_higher_counter() {
        let (low, high) = (hotp_uri(4), hotp_uri(9));
        assert_eq!(newest_hotp(&low, &high), Some(high.as_str()));
        assert_eq!(newest_hotp(&high, &low), Some(high.as_str()));
        // Another secret is another token, and TOTP has no counter.
        let other = format!(
            "otpauth://hotp/x?secret={}&counter=20",
            base32_encode(SEED32)
        );
        assert_eq!(newest_hotp(&low, &other), None);
        assert_eq!(newest_hotp(&low, &base32_encode(SEED20)), None);
    }
}
