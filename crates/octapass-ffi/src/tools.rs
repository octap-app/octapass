//! Local tools that need no unlocked vault. None of them send anything anywhere.

use octapass_core::secret_key::SecretKey;
use octapass_core::tools::{generator, qr, strength, totp};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::error::{OctaPassError, Result};

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum GeneratorOptions {
    /// 4–128 characters from the chosen sets, at least one of each.
    Random {
        length: u32,
        lowercase: bool,
        uppercase: bool,
        digits: bool,
        symbols: bool,
        /// Leaves out `I l 1 O 0 o |`.
        avoid_ambiguous: bool,
    },
    /// 3–20 words from the EFF large wordlist.
    Passphrase {
        words: u32,
        separator: String,
        capitalize: bool,
        include_number: bool,
    },
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct Strength {
    /// 0 (too guessable) to 4 (very unguessable).
    pub score: u8,
    pub guesses_log10: f64,
    /// zxcvbn's most useful hint, in English.
    pub feedback: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    /// Seconds per code.
    pub period: u64,
    /// Seconds until the next code.
    pub remaining: u64,
}

/// A suggested password for a sign-up form: the generator's defaults, adjusted to what the password
/// rules dataset knows about `url`. An Android app's address has no rules and gets the defaults.
#[uniffi::export]
pub fn suggested_password(url: String) -> Result<String> {
    let options = generator::RandomOptions::default();
    let password = octapass_core::rules::generate_for_site(&url, None, &options, &mut OsRng)
        .map_err(|_| OctaPassError::InvalidGeneratorOptions)?;
    Ok(password.to_string())
}

/// The website to add to a login the user filled from another part of its domain
/// (`Session.otherLogins`): the page's scheme, host and port, `https://login.example.com`. `nil`
/// for an Android app or anything else that isn't a website.
#[uniffi::export]
pub fn website_for_page(url: String) -> Option<String> {
    octapass_core::matching::website_for_page(&url)
}

#[uniffi::export]
pub fn generate_password(options: GeneratorOptions) -> Result<String> {
    let options = match options {
        GeneratorOptions::Random {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
            avoid_ambiguous,
        } => generator::GeneratorOptions::Random(generator::RandomOptions {
            length: length as usize,
            lowercase,
            uppercase,
            digits,
            symbols,
            avoid_ambiguous,
        }),
        GeneratorOptions::Passphrase {
            words,
            separator,
            capitalize,
            include_number,
        } => generator::GeneratorOptions::Passphrase(generator::PassphraseOptions {
            words: words as usize,
            separator,
            capitalize,
            include_number,
        }),
    };
    Ok(generator::generate(&options, &mut OsRng)?.to_string())
}

/// `user_inputs` (email, name, site) make a password containing them weaker.
#[uniffi::export]
pub fn estimate_strength(password: String, user_inputs: Vec<String>) -> Strength {
    let password = Zeroizing::new(password);
    let inputs: Vec<&str> = user_inputs.iter().map(String::as_str).collect();
    let strength = strength::estimate(&password, &inputs);
    Strength {
        score: strength.score,
        guesses_log10: strength.guesses_log10,
        feedback: strength.feedback,
    }
}

/// The code for a TOTP secret (`otpauth://totp/…` or base32) at `unix_seconds`, e.g. right after
/// scanning a QR code.
#[uniffi::export]
pub fn totp_code(totp: String, unix_seconds: u64) -> Result<TotpCode> {
    let code = totp::totp_code(&Zeroizing::new(totp), unix_seconds)?;
    Ok(TotpCode {
        code: code.code,
        period: code.period,
        remaining: code.remaining,
    })
}

/// What scanned QR codes hold (see `summarize_qr_scans`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct QrScan {
    pub codes: Vec<ScannedCode>,
    /// Google Authenticator exports split over several QR codes that still miss some.
    pub incomplete: Vec<ExportBatch>,
    /// QR codes that aren't one-time codes.
    pub other: u32,
    /// QR codes that look like one-time codes but can't be read.
    pub broken: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ScannedCode {
    /// The `otpauth://` link for the item's `totp` field. A secret.
    pub uri: String,
    pub issuer: Option<String>,
    pub account: Option<String>,
    /// Counter-based (HOTP): kept, but its codes can't be shown yet.
    pub counter_based: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ExportBatch {
    pub id: i64,
    pub size: u32,
    /// The parts scanned so far, counted from 1.
    pub scanned: Vec<u32>,
}

/// The text of every QR code in a PNG, JPEG, WebP or GIF image (a chosen photo or screenshot),
/// read on the device. An image without QR codes gives an empty list; bytes that aren't an
/// image are `Core { code: "invalid_image" }`.
#[uniffi::export]
pub fn read_qr_image(image: Vec<u8>) -> Result<Vec<String>> {
    Ok(qr::read_image(&Zeroizing::new(image))?)
}

/// Says what scanned QR texts hold: one-time codes (`otpauth://`, and every account of a Google
/// Authenticator export), the parts of a split export still missing, and how many aren't codes.
/// Pass every text scanned so far.
#[uniffi::export]
pub fn summarize_qr_scans(texts: Vec<String>) -> QrScan {
    let texts = Zeroizing::new(texts);
    let scan = qr::summarize(&texts);
    QrScan {
        codes: scan
            .codes
            .into_iter()
            .map(|code| ScannedCode {
                uri: code.uri.to_string(),
                issuer: code.issuer,
                account: code.account,
                counter_based: code.counter_based,
            })
            .collect(),
        incomplete: scan
            .incomplete
            .into_iter()
            .map(|batch| ExportBatch {
                id: batch.id,
                size: batch.size,
                scanned: batch.scanned,
            })
            .collect(),
        other: scan.other as u32,
        broken: scan.broken as u32,
    }
}

/// Checks a typed or scanned Secret Key and returns it as `OP1-XXXXXX-…`.
#[uniffi::export]
pub fn normalize_secret_key(text: String) -> Result<String> {
    let key = SecretKey::parse(&Zeroizing::new(text)).map_err(OctaPassError::from)?;
    Ok(key.to_text().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_codes_reach_the_core() {
        assert!(matches!(
            read_qr_image(b"not an image".to_vec()),
            Err(OctaPassError::Core { code, .. }) if code == "invalid_image"
        ));
        let scan = summarize_qr_scans(vec![
            "otpauth://totp/ACME:jane?secret=JBSWY3DPEHPK3PXP&issuer=ACME".into(),
            "https://example.com".into(),
        ]);
        assert_eq!(scan.codes.len(), 1);
        assert_eq!(scan.codes[0].issuer.as_deref(), Some("ACME"));
        assert_eq!((scan.other, scan.broken), (1, 0));
    }

    #[test]
    fn generator_options_reach_the_core() {
        let password = generate_password(GeneratorOptions::Random {
            length: 32,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            avoid_ambiguous: false,
        })
        .unwrap();
        assert_eq!(password.len(), 32);
        assert!(password.chars().all(|c| c.is_ascii_digit()));

        let phrase = generate_password(GeneratorOptions::Passphrase {
            words: 4,
            separator: "_".into(),
            capitalize: false,
            include_number: false,
        })
        .unwrap();
        assert_eq!(phrase.split('_').count(), 4);

        assert_eq!(
            generate_password(GeneratorOptions::Passphrase {
                words: 1,
                separator: "-".into(),
                capitalize: false,
                include_number: false,
            }),
            Err(OctaPassError::InvalidGeneratorOptions)
        );
    }

    #[test]
    fn rfc_6238_code() {
        // RFC 6238 appendix B, SHA-1, T = 59.
        let code = totp_code(
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8".into(),
            59,
        )
        .unwrap();
        assert_eq!(code.code, "94287082");
        assert_eq!((code.period, code.remaining), (30, 1));
        assert_eq!(
            totp_code("not base32!".into(), 0),
            Err(OctaPassError::InvalidTotp)
        );
    }

    #[test]
    fn secret_keys_come_back_canonical() {
        assert_eq!(
            normalize_secret_key("op1 000g40 r40m30 e2091 85gr3 8e1w".into()).unwrap(),
            "OP1-000G40-R40M30-E2091-85GR3-8E1W"
        );
        assert_eq!(
            normalize_secret_key("OP1-nope".into()),
            Err(OctaPassError::InvalidSecretKey)
        );
        assert!(estimate_strength("correct horse battery staple zebra".into(), vec![]).score >= 3);
    }
}
