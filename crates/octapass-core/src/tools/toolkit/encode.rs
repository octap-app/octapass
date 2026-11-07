//! Text encodings (plan 16 §2): Base64, base64url, base32, hex, URL encoding, HTML entities and
//! Unicode escapes, and a guess at what a pasted string is.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::encoding::{base32_decode, base32_encode};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Base64,
    Base64url,
    Base32,
    Hex,
    Url,
    Html,
    Unicode,
}

impl Format {
    const ALL: [Format; 7] = [
        Format::Base64,
        Format::Base64url,
        Format::Base32,
        Format::Hex,
        Format::Url,
        Format::Html,
        Format::Unicode,
    ];
}

/// The bytes of `data` written in `format`.
pub fn encode(format: Format, data: &[u8]) -> Result<String> {
    Ok(match format {
        Format::Base64 => STANDARD.encode(data),
        Format::Base64url => URL_SAFE_NO_PAD.encode(data),
        Format::Base32 => base32_with_padding(data),
        Format::Hex => hex_encode(data),
        Format::Url => percent_encode(data),
        Format::Html => html_encode(text_of(data)?),
        Format::Unicode => unicode_encode(text_of(data)?),
    })
}

/// The bytes `text` stands for in `format`.
pub fn decode(format: Format, text: &str) -> Result<Vec<u8>> {
    let trimmed = text.trim();
    match format {
        Format::Base64 | Format::Base64url => decode_base64(trimmed),
        Format::Base32 => base32_decode(trimmed).ok_or(Error::InvalidEncoding),
        Format::Hex => hex_decode(trimmed),
        Format::Url => percent_decode(trimmed),
        Format::Html => Ok(html_decode(text).into_bytes()),
        Format::Unicode => unicode_decode(text).map(String::into_bytes),
    }
}

fn text_of(data: &[u8]) -> Result<&str> {
    std::str::from_utf8(data).map_err(|_| Error::InvalidEncoding)
}

fn base32_with_padding(data: &[u8]) -> String {
    let mut text = base32_encode(data);
    while !text.len().is_multiple_of(8) {
        text.push('=');
    }
    text
}

/// Base64 or base64url, padded or not, with line breaks and spaces (PEM bodies, wrapped mail).
pub fn decode_base64(text: &str) -> Result<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.contains(['-', '_']) {
        if compact.contains('=') {
            return URL_SAFE
                .decode(&compact)
                .map_err(|_| Error::InvalidEncoding);
        }
        return URL_SAFE_NO_PAD
            .decode(&compact)
            .map_err(|_| Error::InvalidEncoding);
    }
    if compact.contains('=') {
        return STANDARD
            .decode(&compact)
            .map_err(|_| Error::InvalidEncoding);
    }
    STANDARD_NO_PAD
        .decode(&compact)
        .map_err(|_| Error::InvalidEncoding)
}

pub fn hex_encode(data: &[u8]) -> String {
    let mut text = String::with_capacity(data.len() * 2);
    for byte in data {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Hex with or without `0x`, colons or spaces between bytes.
pub fn hex_decode(text: &str) -> Result<Vec<u8>> {
    let text = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b':')
        .collect();
    if !digits.len().is_multiple_of(2) {
        return Err(Error::InvalidEncoding);
    }
    digits
        .chunks(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16);
            let low = (pair[1] as char).to_digit(16);
            match (high, low) {
                (Some(high), Some(low)) => Ok((high * 16 + low) as u8),
                _ => Err(Error::InvalidEncoding),
            }
        })
        .collect()
}

fn percent_encode(data: &[u8]) -> String {
    let mut text = String::with_capacity(data.len());
    for &byte in data {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            text.push(byte as char);
        } else {
            text.push('%');
            text.push(HEX[(byte >> 4) as usize].to_ascii_uppercase() as char);
            text.push(HEX[(byte & 15) as usize].to_ascii_uppercase() as char);
        }
    }
    text
}

/// RFC 3986 percent-decoding, plus `+` as a space, as form bodies and query strings write it.
fn percent_decode(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let pair = bytes
                    .get(index + 1..index + 3)
                    .ok_or(Error::InvalidEncoding)?;
                out.extend(hex_decode(
                    std::str::from_utf8(pair).map_err(|_| Error::InvalidEncoding)?,
                )?);
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    Ok(out)
}

/// The five characters HTML gives meaning to, plus every non-ASCII character as a numeric entity.
fn html_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_ascii() => out.push(c),
            c => out.push_str(&format!("&#{};", c as u32)),
        }
    }
    out
}

/// The named entities people meet in pasted text. Anything else stays as written.
const NAMED_ENTITIES: &[(&str, char)] = &[
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("nbsp", '\u{a0}'),
    ("copy", '©'),
    ("reg", '®'),
    ("trade", '™'),
    ("hellip", '…'),
    ("mdash", '—'),
    ("ndash", '–'),
    ("lsquo", '‘'),
    ("rsquo", '’'),
    ("ldquo", '“'),
    ("rdquo", '”'),
    ("laquo", '«'),
    ("raquo", '»'),
    ("euro", '€'),
    ("pound", '£'),
    ("yen", '¥'),
    ("cent", '¢'),
    ("sect", '§'),
    ("deg", '°'),
    ("middot", '·'),
    ("bull", '•'),
];

fn html_decode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        // Entities are short; a `;` further away isn't closing this one.
        let Some(end) = rest
            .char_indices()
            .take(12)
            .find(|(_, c)| *c == ';')
            .map(|(i, _)| i)
        else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        match entity(&rest[1..end]) {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn entity(name: &str) -> Option<char> {
    if let Some(number) = name.strip_prefix('#') {
        let code = match number.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => number.parse().ok()?,
        };
        return char::from_u32(code);
    }
    NAMED_ENTITIES
        .iter()
        .find(|(entity, _)| *entity == name)
        .map(|(_, c)| *c)
}

/// Non-ASCII as JSON-style `\uXXXX`, with surrogate pairs above the Basic Multilingual Plane.
fn unicode_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() && !c.is_ascii_control() && c != '\\' {
            out.push(c);
        } else if c == '\\' {
            out.push_str("\\\\");
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

/// `\uXXXX` (with surrogate pairs), `\u{X…}` and `\xXX`; `\\` is one backslash.
fn unicode_decode(text: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut pending_high: Option<u16> = None;
    while let Some(c) = chars.next() {
        if c != '\\' {
            if pending_high.is_some() {
                return Err(Error::InvalidEncoding);
            }
            out.push(c);
            continue;
        }
        let code: u32 = match chars.next() {
            Some('\\') if pending_high.is_none() => {
                out.push('\\');
                continue;
            }
            Some('u') if chars.peek() == Some(&'{') => {
                chars.next();
                let digits: String = chars.by_ref().take_while(|c| *c != '}').collect();
                u32::from_str_radix(&digits, 16).map_err(|_| Error::InvalidEncoding)?
            }
            Some('u') => take_hex(&mut chars, 4)?,
            Some('x') => take_hex(&mut chars, 2)?,
            _ => return Err(Error::InvalidEncoding),
        };
        match (pending_high.take(), code) {
            (None, 0xD800..=0xDBFF) => pending_high = Some(code as u16),
            (Some(high), 0xDC00..=0xDFFF) => {
                let units = [high, code as u16];
                out.push(
                    char::decode_utf16(units)
                        .next()
                        .and_then(|c| c.ok())
                        .ok_or(Error::InvalidEncoding)?,
                );
            }
            (None, code) => out.push(char::from_u32(code).ok_or(Error::InvalidEncoding)?),
            (Some(_), _) => return Err(Error::InvalidEncoding),
        }
    }
    if pending_high.is_some() {
        return Err(Error::InvalidEncoding);
    }
    Ok(out)
}

fn take_hex(chars: &mut impl Iterator<Item = char>, count: usize) -> Result<u32> {
    let digits: String = chars.take(count).collect();
    if digits.len() != count {
        return Err(Error::InvalidEncoding);
    }
    u32::from_str_radix(&digits, 16).map_err(|_| Error::InvalidEncoding)
}

/// What a pasted string might be.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detected {
    /// One of the encodings, or `jwt`, `pem`, `uuid`, `ulid`, which have their own tools.
    pub format: String,
    /// 0–100. Short strings of plain letters fit several formats and score low.
    pub confidence: u8,
    /// The decoded text, when it's valid UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The decoded bytes as hex, when they're not text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
}

/// Every format `text` fits, the likeliest first.
pub fn detect(text: &str) -> Vec<Detected> {
    let trimmed = text.trim();
    let mut found = Vec::new();
    if trimmed.is_empty() {
        return found;
    }
    let structured = |format: &str| Detected {
        format: format.to_owned(),
        confidence: 100,
        text: None,
        hex: None,
    };
    if trimmed.starts_with("-----BEGIN ") {
        found.push(structured("pem"));
        return found;
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    if (parts.len() == 3 || parts.len() == 5)
        && parts[0].starts_with("eyJ")
        && parts.iter().all(|part| decode_base64(part).is_ok())
    {
        found.push(structured("jwt"));
        return found;
    }
    if super::random::is_uuid(trimmed) {
        found.push(structured("uuid"));
        return found;
    }
    // Long hex strings fit a ULID's alphabet too, so this one is only a candidate.
    if super::random::is_ulid(trimmed) {
        found.push(Detected {
            confidence: 60,
            ..structured("ulid")
        });
    }
    for format in Format::ALL {
        let Some(confidence) = confidence(format, trimmed) else {
            continue;
        };
        let Ok(bytes) = decode(format, trimmed) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        let text = String::from_utf8(bytes.clone())
            .ok()
            .filter(|text| !text.chars().any(|c| c.is_control() && !c.is_whitespace()));
        // Printable output is the strongest sign the guess is right.
        let confidence = match (&text, format) {
            (Some(_), Format::Url | Format::Html | Format::Unicode) => confidence,
            (Some(_), _) => confidence.saturating_add(20).min(95),
            (None, _) => confidence,
        };
        let hex = text.is_none().then(|| hex_encode(&bytes));
        found.push(Detected {
            format: format_name(format).to_owned(),
            confidence,
            text,
            hex,
        });
    }
    found.sort_by_key(|detected| std::cmp::Reverse(detected.confidence));
    found
}

fn format_name(format: Format) -> &'static str {
    match format {
        Format::Base64 => "base64",
        Format::Base64url => "base64url",
        Format::Base32 => "base32",
        Format::Hex => "hex",
        Format::Url => "url",
        Format::Html => "html",
        Format::Unicode => "unicode",
    }
}

fn confidence(format: Format, text: &str) -> Option<u8> {
    let long = text.len() >= 16;
    match format {
        Format::Hex => {
            let hex = text.bytes().all(|b| b.is_ascii_hexdigit());
            (hex && text.len().is_multiple_of(2)).then_some(if long { 85 } else { 45 })
        }
        Format::Base32 => {
            let body = text.trim_end_matches('=');
            let valid = body.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'));
            (valid && text.len() >= 8).then_some(if text.contains('=') { 70 } else { 50 })
        }
        Format::Base64 => {
            let body = text.trim_end_matches('=');
            let valid = !body.is_empty()
                && body
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'));
            let marked = text.contains(['=', '+', '/']);
            (valid && text.len() >= 4).then_some(if marked {
                70
            } else if long {
                55
            } else {
                35
            })
        }
        Format::Base64url => {
            let valid = text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'='));
            (valid && text.contains(['-', '_'])).then_some(70)
        }
        Format::Url => has_percent_escape(text).then_some(80),
        Format::Html => (text.contains('&') && html_decode(text) != text).then_some(85),
        Format::Unicode => (text.contains("\\u") || text.contains("\\x")).then_some(85),
    }
}

fn has_percent_escape(text: &str) -> bool {
    text.as_bytes().windows(3).any(|window| {
        window[0] == b'%' && window[1].is_ascii_hexdigit() && window[2].is_ascii_hexdigit()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(format: Format, text: &str, encoded: &str) {
        assert_eq!(encode(format, text.as_bytes()).unwrap(), encoded);
        assert_eq!(decode(format, encoded).unwrap(), text.as_bytes());
    }

    // RFC 4648 §10.
    #[test]
    fn rfc_4648_vectors() {
        for (text, base64, base32, hex) in [
            ("f", "Zg==", "MY======", "66"),
            ("fo", "Zm8=", "MZXQ====", "666f"),
            ("foo", "Zm9v", "MZXW6===", "666f6f"),
            ("foob", "Zm9vYg==", "MZXW6YQ=", "666f6f62"),
            ("fooba", "Zm9vYmE=", "MZXW6YTB", "666f6f6261"),
            ("foobar", "Zm9vYmFy", "MZXW6YTBOI======", "666f6f626172"),
        ] {
            round_trip(Format::Base64, text, base64);
            round_trip(Format::Base32, text, base32);
            round_trip(Format::Hex, text, hex);
        }
    }

    #[test]
    fn base64_reads_both_alphabets_with_or_without_padding() {
        let bytes = [0xfb, 0xff, 0xfe, 0x01];
        assert_eq!(encode(Format::Base64, &bytes).unwrap(), "+//+AQ==");
        assert_eq!(encode(Format::Base64url, &bytes).unwrap(), "-__-AQ");
        for text in ["+//+AQ==", "+//+AQ", "-__-AQ", "-__-AQ==", "+//+\nAQ=="] {
            assert_eq!(decode(Format::Base64, text).unwrap(), bytes, "{text}");
        }
    }

    #[test]
    fn url_encoding() {
        round_trip(Format::Url, "a b&c=d/é", "a%20b%26c%3Dd%2F%C3%A9");
        assert_eq!(decode(Format::Url, "a+b").unwrap(), b"a b");
        assert_eq!(decode(Format::Url, "%zz"), Err(Error::InvalidEncoding));
        assert_eq!(decode(Format::Url, "%4"), Err(Error::InvalidEncoding));
    }

    #[test]
    fn html_entities() {
        round_trip(
            Format::Html,
            "<a href=\"x\">Tom & 'Jerry' é</a>",
            "&lt;a href=&quot;x&quot;&gt;Tom &amp; &#39;Jerry&#39; &#233;&lt;/a&gt;",
        );
        assert_eq!(
            decode(Format::Html, "&#x41;&#66;&hellip;").unwrap(),
            "AB…".as_bytes()
        );
        // Not entities: left alone.
        assert_eq!(
            decode(Format::Html, "AT&T &nosuch; &").unwrap(),
            b"AT&T &nosuch; &"
        );
    }

    #[test]
    fn unicode_escapes() {
        round_trip(Format::Unicode, "é😀a\\", "\\u00e9\\ud83d\\ude00a\\\\");
        assert_eq!(
            decode(Format::Unicode, "\\u{1F600}\\x41").unwrap(),
            "😀A".as_bytes()
        );
        for broken in ["\\ud83d", "\\ud83da", "\\u12", "\\q"] {
            assert_eq!(
                decode(Format::Unicode, broken),
                Err(Error::InvalidEncoding),
                "{broken}"
            );
        }
    }

    #[test]
    fn hex_accepts_common_spellings() {
        for text in ["deadBEEF", "0xdeadbeef", "de:ad:be:ef", "de ad be ef"] {
            assert_eq!(decode(Format::Hex, text).unwrap(), [0xde, 0xad, 0xbe, 0xef]);
        }
        assert_eq!(decode(Format::Hex, "abc"), Err(Error::InvalidEncoding));
    }

    fn first(text: &str) -> String {
        detect(text)[0].format.clone()
    }

    #[test]
    fn detection() {
        assert_eq!(first("SGVsbG8sIHdvcmxkIQ=="), "base64");
        assert_eq!(
            detect("SGVsbG8sIHdvcmxkIQ==")[0].text.as_deref(),
            Some("Hello, world!")
        );
        assert_eq!(first("48656c6c6f2c20776f726c6421"), "hex");
        assert_eq!(first("JBSWY3DPEHPK3PXP===="), "base32");
        assert_eq!(first("a%20b%26c"), "url");
        assert_eq!(first("&lt;b&gt;"), "html");
        assert_eq!(first("\\u00e9"), "unicode");
        assert_eq!(
            first("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"),
            "pem"
        );
        assert_eq!(first("eyJhbGciOiJub25lIn0.eyJhIjoxfQ.AA"), "jwt");
        assert_eq!(first("550e8400-e29b-41d4-a716-446655440000"), "uuid");
        assert!(detect("").is_empty());
        assert!(detect("hello world, plainly").is_empty());
    }
}
