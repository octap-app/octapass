//! What the authenticator-app importers (Aegis, 2FAS, andOTP, Ente Auth, Raivo) share.
//!
//! Each entry becomes a one-time code exactly as in `otp.rs`: a TOTP or HOTP code joins a login
//! already in the vault when the issuer matches, otherwise it becomes a new login. Steam, mOTP and
//! Yandex codes, and settings the app can't compute, are kept as a hidden field on a login of their
//! own, with a warning.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use serde_json::Value;
use zeroize::Zeroizing;

use super::build::{Collector, ItemMeta, LoginFields, clean, custom_field, note};
use super::otp::{ExistingLogin, find_login};
use super::{ImportResult, TotpUpdate};
use crate::encoding::base32_decode;
use crate::tools::otpauth::{OtpAlgorithm, OtpKind, OtpParams};

/// One code from an authenticator export, with the app's own type name and settings.
#[derive(Default)]
pub(super) struct Entry {
    /// `totp`, `hotp`, `steam`, `motp`, `yandex`, … (any case).
    pub kind: String,
    /// Base32, as the apps store it (mOTP secrets may be hex).
    pub secret: Zeroizing<String>,
    pub algorithm: Option<String>,
    pub digits: Option<u64>,
    pub period: Option<u64>,
    pub counter: Option<u64>,
    pub pin: Option<Zeroizing<String>>,
    /// The name shown in the app, when it has one besides the issuer.
    pub title: Option<String>,
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    /// The app's id for the entry and its dates, where the backup has them.
    pub meta: ItemMeta,
}

/// Turns entries into new logins or one-time codes for existing ones.
pub(super) struct Codes<'a> {
    existing: &'a [ExistingLogin],
    /// Logins that already got a code from this import.
    taken: Vec<&'a str>,
    out: Collector,
}

impl<'a> Codes<'a> {
    pub fn new(existing: &'a [ExistingLogin]) -> Self {
        Self {
            existing,
            taken: Vec::new(),
            out: Collector::default(),
        }
    }

    pub fn skip(&mut self, warning: String) {
        self.out.skip(Some(warning));
    }

    /// For skips reported together in one warning.
    pub fn skip_quietly(&mut self) {
        self.out.skip(None);
    }

    pub fn warn(&mut self, warning: String) {
        self.out.warn(warning);
    }

    pub fn finish(self) -> ImportResult {
        self.out.finish()
    }

    /// `number` is the entry's position in the file (from 1), for warnings.
    pub fn add(&mut self, number: usize, entry: Entry) {
        let issuer = clean(entry.issuer.as_deref());
        let account = clean(entry.account.as_deref());
        let label = clean(entry.title.as_deref())
            .or_else(|| issuer.clone())
            .or_else(|| account.clone())
            .unwrap_or_else(|| "One-time code".into());
        if entry.secret.trim().is_empty() {
            self.out
                .skip(Some(format!("Entry {number} skipped: it has no secret.")));
            return;
        }
        let kind = entry.kind.trim().to_ascii_lowercase();
        let params = otp_params(&kind, &entry, issuer, account.clone());
        let fields = LoginFields {
            title: Some(label.clone()),
            username: account,
            notes: entry.notes.clone(),
            tags: entry.tags.clone(),
            favorite: entry.favorite,
            meta: entry.meta.clone(),
            ..LoginFields::default()
        };
        let Some(params) = params else {
            let (field, warning) = match kind.as_str() {
                "steam" => (
                    "One-time code (Steam)",
                    format!(
                        "\"{label}\" uses Steam codes, which can't be shown yet: kept as a hidden field."
                    ),
                ),
                "motp" => (
                    "One-time code (mOTP)",
                    format!(
                        "\"{label}\" uses mOTP codes, which can't be shown yet: kept as a hidden field."
                    ),
                ),
                "yandex" => (
                    "One-time code (Yandex)",
                    format!(
                        "\"{label}\" uses Yandex codes, which can't be shown yet: kept as a hidden field."
                    ),
                ),
                _ => (
                    "One-time code",
                    format!(
                        "\"{label}\": the one-time code's settings aren't supported, so it was kept as a hidden field."
                    ),
                ),
            };
            self.out.warn(warning);
            let uri = other_uri(&kind, &entry);
            self.add_login(LoginFields {
                custom_fields: vec![custom_field(field, &uri, true)],
                ..fields
            });
            return;
        };
        let uri = params.to_uri();
        if let Some(login) = find_login(&params, self.existing, &self.taken) {
            self.taken.push(&login.id);
            let update = TotpUpdate {
                item_id: login.id.clone(),
                totp: uri.to_string(),
            };
            self.out.attach_code(update, &params, label.clone());
            // A code that joins a login brings only the code; its note stays as a note of its own.
            if let Some(notes) = clean(entry.notes.as_deref()) {
                self.out.warn(format!(
                    "\"{label}\": the code was added to your existing login, and its note was kept as a separate secure note."
                ));
                self.out.add(note(
                    Some(format!("{label} (note)")),
                    entry.tags,
                    false,
                    Some(notes),
                ));
            }
            return;
        }
        self.out.add_code(
            LoginFields {
                totp: Some(uri.to_string()),
                ..fields
            },
            &params,
        );
    }

    fn add_login(&mut self, fields: LoginFields) {
        if let Some(item) = fields.build(&mut self.out) {
            self.out.add(item);
        }
    }
}

/// The entry as a code Octa Pass can compute (TOTP or HOTP), or `None`.
fn otp_params(
    kind: &str,
    entry: &Entry,
    issuer: Option<String>,
    account: Option<String>,
) -> Option<OtpParams> {
    let kind = match kind {
        "totp" => OtpKind::Totp {
            period: entry.period.unwrap_or(30),
        },
        "hotp" => OtpKind::Hotp {
            counter: entry.counter.unwrap_or(0),
        },
        _ => return None,
    };
    if let OtpKind::Totp { period } = kind
        && !(1..=3600).contains(&period)
    {
        return None;
    }
    let algorithm = match entry
        .algorithm
        .as_deref()
        .map(|a| a.trim().to_ascii_uppercase().replace('-', ""))
        .as_deref()
    {
        None | Some("SHA1") => OtpAlgorithm::Sha1,
        Some("SHA256") => OtpAlgorithm::Sha256,
        Some("SHA512") => OtpAlgorithm::Sha512,
        Some(_) => return None,
    };
    let digits = entry.digits.unwrap_or(6);
    if !(6..=8).contains(&digits) {
        return None;
    }
    let secret = Zeroizing::new(base32_decode(&entry.secret)?);
    if secret.is_empty() {
        return None;
    }
    Some(OtpParams {
        kind,
        secret,
        algorithm,
        digits: digits as u32,
        issuer,
        account,
    })
}

/// An `otpauth://<type>/…` link with every setting the entry has, for codes kept as a field.
fn other_uri(kind: &str, entry: &Entry) -> String {
    // Spaces as %20, like `OtpParams::to_uri` (a literal "+" is already %2B).
    let encode = |text: &str| {
        url::form_urlencoded::byte_serialize(text.as_bytes())
            .collect::<String>()
            .replace('+', "%20")
    };
    let issuer = clean(entry.issuer.as_deref());
    let account = clean(entry.account.as_deref()).unwrap_or_default();
    let label = match &issuer {
        Some(issuer) => format!("{}:{}", encode(issuer), encode(&account)),
        None => encode(&account),
    };
    let kind = if kind.chars().all(|c| c.is_ascii_alphanumeric()) && !kind.is_empty() {
        kind
    } else {
        "unknown"
    };
    let mut uri = format!(
        "otpauth://{kind}/{label}?secret={}",
        encode(entry.secret.trim())
    );
    let mut param = |name: &str, value: Option<String>| {
        if let Some(value) = value {
            uri.push_str(&format!("&{name}={}", encode(&value)));
        }
    };
    param("algorithm", clean(entry.algorithm.as_deref()));
    param("digits", entry.digits.map(|d| d.to_string()));
    param("period", entry.period.map(|p| p.to_string()));
    param("counter", entry.counter.map(|c| c.to_string()));
    param("pin", entry.pin.as_deref().and_then(|p| clean(Some(p))));
    param("issuer", issuer);
    uri
}

/// Trimmed, non-empty text at `key`.
pub(super) fn text(value: &Value, key: &str) -> Option<String> {
    clean(value.get(key)?.as_str())
}

/// A whole number at `key`, written as a number or as text.
pub(super) fn number(value: &Value, key: &str) -> Option<u64> {
    match value.get(key)? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// AES-256-GCM with a 96-bit nonce and the 16-byte tag after the ciphertext. `None` when the tag
/// doesn't match, which is what a wrong key gives.
pub(super) fn open_gcm(key: &[u8; 32], nonce: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if nonce.len() != 12 {
        return None;
    }
    Aes256Gcm::new(key.into())
        .decrypt(Nonce::from_slice(nonce), sealed)
        .ok()
        .map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::ItemDetails;

    const SECRET: &str = "JBSWY3DPEHPK3PXP";

    fn entry(kind: &str, issuer: &str, account: &str) -> Entry {
        Entry {
            kind: kind.into(),
            secret: Zeroizing::new(SECRET.into()),
            issuer: Some(issuer.into()),
            account: Some(account.into()),
            ..Entry::default()
        }
    }

    #[test]
    fn totp_joins_existing_logins_like_otpauth_links() {
        let existing = [ExistingLogin {
            id: "gh".into(),
            title: "GitHub".into(),
            ..ExistingLogin::default()
        }];
        let mut codes = Codes::new(&existing);
        codes.add(
            1,
            Entry {
                notes: Some("Recovery codes in the safe".into()),
                tags: vec!["Work".into()],
                ..entry("TOTP", "GitHub", "octo")
            },
        );
        // The same login never gets two codes from one import.
        codes.add(2, entry("totp", "GitHub", "octo"));
        let result = codes.finish();
        assert_eq!(result.totp_updates.len(), 1);
        assert_eq!(
            result.totp_updates[0].totp,
            "otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30&issuer=GitHub"
        );
        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].overview.title, "GitHub (note)");
        let ItemDetails::SecureNote(note) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(note.notes, "Recovery codes in the safe");
        assert_eq!(result.items[0].overview.tags.as_deref().unwrap(), ["Work"]);
        let ItemDetails::Login(login) = &result.items[1].details else {
            panic!()
        };
        assert!(login.totp.is_some());
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn other_kinds_and_settings_become_hidden_fields() {
        let mut codes = Codes::new(&[]);
        codes.add(
            1,
            Entry {
                counter: Some(7),
                ..entry("hotp", "Bank", "me")
            },
        );
        codes.add(
            2,
            Entry {
                digits: Some(5),
                ..entry("steam", "Steam", "gamer")
            },
        );
        codes.add(
            3,
            Entry {
                secret: Zeroizing::new("0123abcd".into()),
                pin: Some(Zeroizing::new("1234".into())),
                ..entry("motp", "VPN", "me")
            },
        );
        codes.add(
            4,
            Entry {
                algorithm: Some("SHA224".into()),
                ..entry("totp", "Shop", "me")
            },
        );
        codes.add(
            5,
            Entry {
                secret: Zeroizing::new(" ".into()),
                ..entry("totp", "Empty", "me")
            },
        );
        let result = codes.finish();
        // HOTP is a working code: only what the app can't compute stays a hidden field.
        let ItemDetails::Login(bank) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(
            bank.totp.as_deref(),
            Some(
                "otpauth://hotp/Bank:me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&counter=7&issuer=Bank"
            )
        );
        let fields: Vec<(String, String)> = result.items[1..]
            .iter()
            .map(|item| {
                let ItemDetails::Login(login) = &item.details else {
                    panic!()
                };
                assert!(login.totp.is_none());
                let field = &login.custom_fields.as_ref().unwrap()[0];
                assert!(field.hidden);
                (field.label.clone(), field.value.clone())
            })
            .collect();
        assert_eq!(
            fields,
            [
                (
                    "One-time code (Steam)".into(),
                    "otpauth://steam/Steam:gamer?secret=JBSWY3DPEHPK3PXP&digits=5&issuer=Steam"
                        .into()
                ),
                (
                    "One-time code (mOTP)".into(),
                    "otpauth://motp/VPN:me?secret=0123abcd&pin=1234&issuer=VPN".into()
                ),
                (
                    "One-time code".into(),
                    "otpauth://totp/Shop:me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA224&issuer=Shop"
                        .into()
                ),
            ]
        );
        assert_eq!(result.skipped, 1);
        assert_eq!(result.warnings.len(), 4);
        assert_eq!(result.warnings[3], "Entry 5 skipped: it has no secret.");
    }

    #[test]
    fn gcm_rejects_wrong_keys_and_nonces() {
        let key = [7u8; 32];
        let sealed = Aes256Gcm::new((&key).into())
            .encrypt(Nonce::from_slice(&[1u8; 12]), b"hello".as_slice())
            .unwrap();
        assert_eq!(
            open_gcm(&key, &[1u8; 12], &sealed).unwrap().as_slice(),
            b"hello"
        );
        assert!(open_gcm(&[8u8; 32], &[1u8; 12], &sealed).is_none());
        assert!(open_gcm(&key, &[1u8; 16], &sealed).is_none());
        assert!(open_gcm(&key, &[1u8; 12], &sealed[..4]).is_none());
    }
}
