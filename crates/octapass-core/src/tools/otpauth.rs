//! Parsing one-time-password setup data: `otpauth://` URIs (the Key URI format every
//! authenticator QR code uses), bare base32 secrets, and Google Authenticator's
//! `otpauth-migration://` export.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use crate::encoding::{base32_decode, base32_encode};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl OtpAlgorithm {
    fn name(self) -> &'static str {
        match self {
            OtpAlgorithm::Sha1 => "SHA1",
            OtpAlgorithm::Sha256 => "SHA256",
            OtpAlgorithm::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    Totp { period: u64 },
    Hotp { counter: u64 },
}

/// Everything needed to compute codes. Not `Debug`: it holds the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct OtpParams {
    pub kind: OtpKind,
    pub secret: Zeroizing<Vec<u8>>,
    pub algorithm: OtpAlgorithm,
    pub digits: u32,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_DIGITS: u32 = 6;

impl OtpParams {
    /// Parses an `otpauth://totp|hotp/…` URI or a bare base32 secret (TOTP, SHA-1, 6 digits,
    /// 30 seconds).
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        // `get` rather than slicing: the input may have multi-byte characters anywhere.
        if let Some(rest) = strip_prefix_ignore_case(input, "otpauth://") {
            return Self::parse_uri(rest);
        }
        Ok(Self {
            kind: OtpKind::Totp {
                period: DEFAULT_PERIOD,
            },
            secret: decode_secret(input)?,
            algorithm: OtpAlgorithm::Sha1,
            digits: DEFAULT_DIGITS,
            issuer: None,
            account: None,
        })
    }

    fn parse_uri(rest: &str) -> Result<Self> {
        let (kind, rest) = rest.split_once('/').ok_or(Error::InvalidTotp)?;
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));

        let (mut secret, mut issuer, mut algorithm, mut digits) =
            (None, None, OtpAlgorithm::Sha1, DEFAULT_DIGITS);
        let (mut period, mut counter) = (DEFAULT_PERIOD, 0);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = Zeroizing::new(percent_decode(value)?);
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(decode_secret(&value)?),
                "issuer" => issuer = Some(value.to_string()),
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => OtpAlgorithm::Sha1,
                        "SHA256" => OtpAlgorithm::Sha256,
                        "SHA512" => OtpAlgorithm::Sha512,
                        _ => return Err(Error::InvalidTotp),
                    }
                }
                "digits" => digits = value.parse().map_err(|_| Error::InvalidTotp)?,
                "period" => period = value.parse().map_err(|_| Error::InvalidTotp)?,
                "counter" => counter = value.parse().map_err(|_| Error::InvalidTotp)?,
                _ => {}
            }
        }
        if !(6..=8).contains(&digits) || !(1..=3600).contains(&period) {
            return Err(Error::InvalidTotp);
        }
        let kind = match kind.to_ascii_lowercase().as_str() {
            "totp" => OtpKind::Totp { period },
            "hotp" => OtpKind::Hotp { counter },
            _ => return Err(Error::InvalidTotp),
        };

        let label = percent_decode(label)?;
        let (label_issuer, account) = match label.split_once(':') {
            Some((issuer, account)) => {
                (Some(issuer.trim().to_string()), account.trim().to_string())
            }
            None => (None, label.trim().to_string()),
        };
        Ok(Self {
            kind,
            secret: secret.ok_or(Error::InvalidTotp)?,
            algorithm,
            digits,
            issuer: issuer.or(label_issuer).filter(|s| !s.is_empty()),
            account: Some(account).filter(|s| !s.is_empty()),
        })
    }

    /// The canonical `otpauth://` URI, the form stored in an item's `totp` field.
    pub fn to_uri(&self) -> Zeroizing<String> {
        let account = self.account.as_deref().unwrap_or_default();
        let label = match &self.issuer {
            Some(issuer) => format!("{}:{}", percent_encode(issuer), percent_encode(account)),
            None => percent_encode(account),
        };
        let (kind, extra) = match self.kind {
            OtpKind::Totp { period } => ("totp", format!("period={period}")),
            OtpKind::Hotp { counter } => ("hotp", format!("counter={counter}")),
        };
        let mut uri = format!(
            "otpauth://{kind}/{label}?secret={}&algorithm={}&digits={}&{extra}",
            Zeroizing::new(base32_encode(&self.secret)).as_str(),
            self.algorithm.name(),
            self.digits,
        );
        if let Some(issuer) = &self.issuer {
            uri.push_str("&issuer=");
            uri.push_str(&percent_encode(issuer));
        }
        Zeroizing::new(uri)
    }
}

fn decode_secret(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let secret = Zeroizing::new(base32_decode(text).ok_or(Error::InvalidTotp)?);
    if secret.is_empty() {
        return Err(Error::InvalidTotp);
    }
    Ok(secret)
}

/// Parses a Google Authenticator export (`otpauth-migration://offline?data=…`, a base64
/// protobuf `MigrationPayload`) into one [`OtpParams`] per account.
pub fn parse_migration(uri: &str) -> Result<Vec<OtpParams>> {
    parse_migration_export(uri).map(|export| export.accounts)
}

/// One QR code of a Google Authenticator export. A big export is split over several QR codes:
/// `batch_size` of them, sharing a `batch_id`, numbered by `batch_index` from 0.
pub struct MigrationExport {
    pub accounts: Vec<OtpParams>,
    pub batch_size: u32,
    pub batch_index: u32,
    pub batch_id: i64,
}

/// [`parse_migration`], with where this QR code sits in a split export.
pub fn parse_migration_export(uri: &str) -> Result<MigrationExport> {
    let uri = uri.trim();
    let prefix = "otpauth-migration://offline?";
    let data = strip_prefix_ignore_case(uri, prefix)
        .ok_or(Error::InvalidTotp)?
        .split('&')
        .find_map(|pair| pair.strip_prefix("data="))
        .ok_or(Error::InvalidTotp)?;
    let data = Zeroizing::new(percent_decode(data)?.replace(' ', "+"));
    let payload = Zeroizing::new(
        STANDARD
            .decode(data.trim_end_matches('='))
            .or_else(|_| STANDARD.decode(data.as_str()))
            .map_err(|_| Error::InvalidTotp)?,
    );

    // MigrationPayload: otp_parameters = 1, version = 2, batch_size = 3, batch_index = 4,
    // batch_id = 5.
    let mut export = MigrationExport {
        accounts: Vec::new(),
        batch_size: 1,
        batch_index: 0,
        batch_id: 0,
    };
    for field in ProtoFields::new(&payload) {
        match field? {
            (1, ProtoValue::Bytes(bytes)) => export.accounts.push(parse_migration_entry(bytes)?),
            (3, ProtoValue::Varint(size)) => {
                export.batch_size = u32::try_from(size).unwrap_or(1).max(1)
            }
            (4, ProtoValue::Varint(index)) => {
                export.batch_index = u32::try_from(index).unwrap_or(0)
            }
            // An int32: negative ids arrive as 64-bit two's complement.
            (5, ProtoValue::Varint(id)) => export.batch_id = id as i64,
            _ => {}
        }
    }
    if export.batch_index >= export.batch_size {
        return Err(Error::InvalidTotp);
    }
    Ok(export)
}

/// One `OtpParameters` message: secret = 1, name = 2, issuer = 3, algorithm = 4, digits = 5,
/// type = 6, counter = 7.
fn parse_migration_entry(message: &[u8]) -> Result<OtpParams> {
    let mut params = OtpParams {
        kind: OtpKind::Totp {
            period: DEFAULT_PERIOD,
        },
        secret: Zeroizing::new(Vec::new()),
        algorithm: OtpAlgorithm::Sha1,
        digits: DEFAULT_DIGITS,
        issuer: None,
        account: None,
    };
    let (mut is_hotp, mut counter) = (false, 0);
    for field in ProtoFields::new(message) {
        match field? {
            (1, ProtoValue::Bytes(secret)) => params.secret = Zeroizing::new(secret.to_vec()),
            (2, ProtoValue::Bytes(name)) => params.account = Some(utf8(name)?),
            (3, ProtoValue::Bytes(issuer)) => params.issuer = Some(utf8(issuer)?),
            (4, ProtoValue::Varint(algorithm)) => {
                params.algorithm = match algorithm {
                    0 | 1 => OtpAlgorithm::Sha1,
                    2 => OtpAlgorithm::Sha256,
                    3 => OtpAlgorithm::Sha512,
                    _ => return Err(Error::InvalidTotp),
                }
            }
            (5, ProtoValue::Varint(digits)) => params.digits = if digits == 2 { 8 } else { 6 },
            (6, ProtoValue::Varint(kind)) => is_hotp = kind == 1,
            (7, ProtoValue::Varint(value)) => counter = value,
            _ => {}
        }
    }
    if is_hotp {
        params.kind = OtpKind::Hotp { counter };
    }
    // Google puts "Issuer:account" in the name when the issuer is set; keep just the account.
    if let (Some(issuer), Some(account)) = (&params.issuer, &params.account)
        && let Some(rest) = account.strip_prefix(&format!("{issuer}:"))
    {
        params.account = Some(rest.trim().to_string());
    }
    if params.secret.is_empty() {
        return Err(Error::InvalidTotp);
    }
    Ok(params)
}

fn utf8(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidTotp)
}

enum ProtoValue<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

/// A minimal protobuf reader: just varint and length-delimited fields, which is all the
/// migration format uses. Fixed-width fields are skipped.
struct ProtoFields<'a> {
    data: &'a [u8],
}

impl<'a> ProtoFields<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = self.data.split_first().ok_or(Error::InvalidTotp)?;
            self.data = rest;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Error::InvalidTotp)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.data.len() {
            return Err(Error::InvalidTotp);
        }
        let (head, rest) = self.data.split_at(len);
        self.data = rest;
        Ok(head)
    }

    fn next_field(&mut self) -> Result<Option<(u64, ProtoValue<'a>)>> {
        loop {
            if self.data.is_empty() {
                return Ok(None);
            }
            let key = self.varint()?;
            let (number, wire_type) = (key >> 3, key & 7);
            match wire_type {
                0 => return Ok(Some((number, ProtoValue::Varint(self.varint()?)))),
                2 => {
                    let len = usize::try_from(self.varint()?).map_err(|_| Error::InvalidTotp)?;
                    return Ok(Some((number, ProtoValue::Bytes(self.take(len)?))));
                }
                1 => drop(self.take(8)?),
                5 => drop(self.take(4)?),
                _ => return Err(Error::InvalidTotp),
            }
        }
    }
}

impl<'a> Iterator for ProtoFields<'a> {
    type Item = Result<(u64, ProtoValue<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_field() {
            Ok(Some(field)) => Some(Ok(field)),
            Ok(None) => None,
            Err(error) => {
                self.data = &[];
                Some(Err(error))
            }
        }
    }
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &text[prefix.len()..])
}

fn percent_decode(text: &str) -> Result<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = text.get(i + 1..i + 3).ok_or(Error::InvalidTotp)?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| Error::InvalidTotp)?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidTotp)
}

fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_uri() {
        let params = OtpParams::parse(
            "otpauth://totp/ACME%20Co:jane%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA512&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(params.kind, OtpKind::Totp { period: 60 });
        assert_eq!(params.secret.as_slice(), b"Hello!\xde\xad\xbe\xef");
        assert_eq!(params.algorithm, OtpAlgorithm::Sha512);
        assert_eq!(params.digits, 8);
        assert_eq!(params.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(params.account.as_deref(), Some("jane@example.com"));
        assert!(OtpParams::parse(&params.to_uri()).unwrap() == params);
    }

    #[test]
    fn defaults_and_bare_secrets() {
        let params = OtpParams::parse("otpauth://totp/x?secret=jbswy3dpehpk3pxp").unwrap();
        assert_eq!(
            (params.kind, params.algorithm, params.digits),
            (OtpKind::Totp { period: 30 }, OtpAlgorithm::Sha1, 6)
        );
        assert_eq!(params.issuer, None);
        let bare = OtpParams::parse(" JBSW Y3DP EHPK 3PXP ").unwrap();
        assert_eq!(bare.secret, params.secret);
        let hotp = OtpParams::parse("OTPAUTH://HOTP/x?secret=JBSWY3DPEHPK3PXP&counter=5").unwrap();
        assert_eq!(hotp.kind, OtpKind::Hotp { counter: 5 });
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            "not base32!",
            "otpauth://totp/x",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://steam/x?secret=JBSWY3DPEHPK3PXP",
            "🔐🔐🔐",
            "otpauth:/🔐",
        ] {
            assert!(OtpParams::parse(bad).is_err(), "{bad}");
        }
    }

    /// Builds a migration payload by hand: two accounts, one TOTP (SHA-1, 6 digits) and one
    /// HOTP (SHA-256, 8 digits).
    fn migration_uri() -> String {
        fn field(number: u8, bytes: &[u8]) -> Vec<u8> {
            let mut out = vec![number << 3 | 2, bytes.len() as u8];
            out.extend_from_slice(bytes);
            out
        }
        fn varint(number: u8, value: u8) -> Vec<u8> {
            vec![number << 3, value]
        }
        let first = [
            field(1, b"Hello!\xde\xad\xbe\xef"),
            field(2, b"ACME:jane@example.com"),
            field(3, b"ACME"),
            varint(4, 1),
            varint(5, 1),
            varint(6, 2),
        ]
        .concat();
        let second = [
            field(1, b"12345678901234567890"),
            field(2, b"bob"),
            varint(4, 2),
            varint(5, 2),
            varint(6, 1),
            varint(7, 9),
        ]
        .concat();
        let payload = [
            field(1, &first),
            field(1, &second),
            varint(2, 1),
            varint(3, 1),
        ]
        .concat();
        let data = STANDARD
            .encode(payload)
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        format!("otpauth-migration://offline?data={data}")
    }

    #[test]
    fn parses_google_authenticator_exports() {
        let accounts = parse_migration(&migration_uri()).unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(
            accounts[0].to_uri().as_str(),
            "otpauth://totp/ACME:jane@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30&issuer=ACME"
        );
        assert_eq!(accounts[1].kind, OtpKind::Hotp { counter: 9 });
        assert_eq!(
            (accounts[1].algorithm, accounts[1].digits),
            (OtpAlgorithm::Sha256, 8)
        );
        assert_eq!(accounts[1].account.as_deref(), Some("bob"));
    }

    #[test]
    fn rejects_broken_exports() {
        assert!(parse_migration("otpauth://totp/x?secret=A").is_err());
        assert!(parse_migration("otpauth-migration://🔐").is_err());
        assert!(parse_migration("otpauth-migratio🔐").is_err());
        assert!(parse_migration("otpauth-migration://offline?data=%%%").is_err());
        assert!(
            parse_migration("otpauth-migration://offline?data=CgU").is_err(),
            "truncated"
        );
    }
}
