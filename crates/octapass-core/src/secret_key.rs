//! The Secret Key: 128 random bits generated on the device and never sent to the server.
//!
//! Text form: `OP1-` + 26 Crockford base32 characters grouped `6-6-5-5-4`, for example
//! `OP1-4T9ZQG-0B1N6C-8XKTV-2MRSE-JD7H`.

use core::fmt;

use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encoding::{crockford_decode, crockford_encode, group, strip_separators};
use crate::error::{Error, Result};

pub const SECRET_KEY_LEN: usize = 16;
const PREFIX: &str = "OP1";
const GROUPS: [usize; 5] = [6, 6, 5, 5, 4];

#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SecretKey([u8; SECRET_KEY_LEN]);

impl SecretKey {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; SECRET_KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.0
    }

    /// Parses the text form, ignoring case, spaces and dashes. The `OP1` prefix may be left out.
    pub fn parse(text: &str) -> Result<Self> {
        let compact = Zeroizing::new(strip_separators(text).to_ascii_uppercase());
        let body = match compact.strip_prefix(PREFIX) {
            Some(body) if body.len() == 26 => body,
            _ => compact.as_str(),
        };
        let bytes =
            Zeroizing::new(crockford_decode(body, SECRET_KEY_LEN).ok_or(Error::InvalidSecretKey)?);
        let mut out = [0u8; SECRET_KEY_LEN];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    /// The text form shown in the Recovery Kit.
    pub fn to_text(&self) -> Zeroizing<String> {
        let body = Zeroizing::new(crockford_encode(&self.0));
        Zeroizing::new(format!("{PREFIX}-{}", group(&body, &GROUPS)))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn format() {
        let key = SecretKey::from_bytes([0xff; 16]);
        assert_eq!(key.to_text().as_str(), "OP1-ZZZZZZ-ZZZZZZ-ZZZZZ-ZZZZZ-ZZZW");
        let zero = SecretKey::from_bytes([0; 16]);
        assert_eq!(
            zero.to_text().as_str(),
            "OP1-000000-000000-00000-00000-0000"
        );
    }

    #[test]
    fn parse_is_forgiving_about_case_spaces_and_dashes() {
        let key = SecretKey::from_bytes(*b"0123456789abcdef");
        let text = key.to_text();
        assert_eq!(SecretKey::parse(&text).unwrap(), key);
        assert_eq!(SecretKey::parse(&text.to_lowercase()).unwrap(), key);
        assert_eq!(SecretKey::parse(&text.replace('-', " ")).unwrap(), key);
        assert_eq!(SecretKey::parse(&text[4..].replace('-', "")).unwrap(), key);
    }

    #[test]
    fn parse_rejects_garbage() {
        for bad in [
            "",
            "OP1-",
            "OP1-ZZZZZZ-ZZZZZZ-ZZZZZ-ZZZZZ-ZZZ",
            "OP1-ZZZZZZ-ZZZZZZ-ZZZZZ-ZZZZZ-ZZZZ",
            "OP1-UUUUUU-UUUUUU-UUUUU-UUUUU-UUUU",
        ] {
            assert_eq!(
                SecretKey::parse(bad).unwrap_err(),
                Error::InvalidSecretKey,
                "{bad}"
            );
        }
    }

    #[test]
    fn debug_is_redacted() {
        assert_eq!(
            format!("{:?}", SecretKey::from_bytes([1; 16])),
            "SecretKey(<redacted>)"
        );
    }

    proptest! {
        #[test]
        fn round_trip(bytes in any::<[u8; 16]>()) {
            let key = SecretKey::from_bytes(bytes);
            let text = key.to_text();
            prop_assert_eq!(text.len(), 4 + 26 + 4);
            prop_assert_eq!(SecretKey::parse(&text).unwrap(), key);
        }
    }
}
