//! Wire encodings: base64url without padding, and Crockford base32 for human-typed codes.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::{Error, Result};

pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64_decode(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Error::InvalidBase64)
}

/// Decodes base64url into a fixed-size array, rejecting any other length.
pub fn b64_decode_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    b64_decode(text)?
        .try_into()
        .map_err(|_| Error::InvalidBase64)
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encodes bytes as unpadded Crockford base32 (most significant bit first).
pub fn crockford_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decodes Crockford base32 into exactly `len` bytes.
///
/// Accepts lower case and the Crockford aliases (`O` → `0`, `I`/`L` → `1`). Returns `None` for
/// other characters, the wrong length, or non-zero padding bits, so every value has exactly one
/// accepted spelling (up to case and aliases).
pub fn crockford_decode(text: &str, len: usize) -> Option<Vec<u8>> {
    if text.len() != (len * 8).div_ceil(5) {
        return None;
    }
    let mut out = Vec::with_capacity(len);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in text.chars() {
        buffer = (buffer << 5) | crockford_value(c)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
        buffer &= (1 << bits) - 1;
    }
    (buffer == 0).then_some(out)
}

fn crockford_value(c: char) -> Option<u32> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        c => c,
    };
    CROCKFORD
        .iter()
        .position(|&x| x as char == c)
        .map(|v| v as u32)
}

const RFC4648: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding: the alphabet TOTP secrets use.
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(RFC4648[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(RFC4648[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decodes RFC 4648 base32 as people paste it: any case, with spaces, dashes or `=` padding.
/// Trailing bits are ignored, as authenticator apps do.
pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
    {
        let value = RFC4648
            .iter()
            .position(|&x| x as char == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
        buffer &= (1 << bits) - 1;
    }
    Some(out)
}

/// Removes the separators people type or copy along with a code: spaces and dashes.
pub(crate) fn strip_separators(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

/// Joins `text` into `-`-separated groups of the given sizes.
pub(crate) fn group(text: &str, sizes: &[usize]) -> String {
    let mut out = String::with_capacity(text.len() + sizes.len());
    let mut rest = text;
    for (i, &size) in sizes.iter().enumerate() {
        if i > 0 {
            out.push('-');
        }
        let (head, tail) = rest.split_at(size);
        out.push_str(head);
        rest = tail;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn crockford_known_values() {
        assert_eq!(crockford_encode(&[]), "");
        assert_eq!(crockford_encode(&[0xff]), "ZW");
        assert_eq!(crockford_encode(b"hello"), "D1JPRV3F");
        assert_eq!(crockford_decode("d1jprv3f", 5).unwrap(), b"hello");
        assert_eq!(crockford_decode("ZW", 1).unwrap(), [0xff]);
    }

    #[test]
    fn crockford_aliases_and_rejections() {
        assert_eq!(crockford_decode("oi", 1), crockford_decode("01", 1));
        assert_eq!(crockford_decode("ZX", 1), None, "non-zero padding bits");
        assert_eq!(crockford_decode("ZU", 1), None, "U is not in the alphabet");
        assert_eq!(crockford_decode("Z", 1), None, "wrong length");
    }

    #[test]
    fn grouping() {
        assert_eq!(group("abcdefghij", &[3, 3, 4]), "abc-def-ghij");
        assert_eq!(strip_separators(" ab-c d\t"), "abcd");
    }

    #[test]
    fn base32_known_values() {
        assert_eq!(base32_encode(b"Hello!\xde\xad\xbe\xef"), "JBSWY3DPEHPK3PXP");
        assert_eq!(
            base32_decode("jbsw y3dp-ehpk 3pxp====").unwrap(),
            b"Hello!\xde\xad\xbe\xef"
        );
        assert_eq!(base32_decode("JBSW1"), None);
    }

    proptest! {
        #[test]
        fn base32_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            prop_assert_eq!(base32_decode(&base32_encode(&bytes)), Some(bytes));
        }

        #[test]
        fn crockford_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let text = crockford_encode(&bytes);
            prop_assert_eq!(crockford_decode(&text.to_lowercase(), bytes.len()), Some(bytes));
        }

        #[test]
        fn base64_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let text = b64_encode(&bytes);
            prop_assert!(!text.contains('='));
            prop_assert_eq!(b64_decode(&text).unwrap(), bytes);
        }
    }
}
