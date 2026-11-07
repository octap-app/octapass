//! Local tools that need no unlocked vault and send nothing anywhere: the generator, the
//! strength meter, one-time codes and Secret Key formatting.

use octapass_core::rules;
use octapass_core::tools::{generator, strength, toolkit, totp};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result, VaultError};

/// The web vault's generator settings.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum GeneratorOptions {
    /// 4–128 characters from the chosen sets, at least one of each.
    Password {
        length: u32,
        uppercase: bool,
        lowercase: bool,
        digits: bool,
        symbols: bool,
        /// Leaves out look-alikes such as `0 O 1 l I`.
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

/// A code the UI turns into a translated hint (`generator.feedback.<name>`), as the web vault's
/// `StrengthFeedback`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum StrengthFeedback {
    TooShort,
    CommonPassword,
    DictionaryWord,
    Sequence,
    Repeat,
    KeyboardPattern,
    Date,
    AddMoreWords,
    AddVariety,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct StrengthEstimate {
    /// 0 (too guessable) to 4 (very unguessable).
    pub score: u8,
    pub guesses_log10: f64,
    /// None at score 4.
    pub feedback: Option<StrengthFeedback>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    /// Seconds per code.
    pub period: u64,
    /// Seconds until the next code.
    pub remaining: u64,
}

/// Passwords shorter than this never rate above fair: every 7-character password falls to an
/// offline attack in hours.
const MIN_LENGTH: usize = 8;

/// Runs a developer toolkit tool (plan 16): `op` is its name, `input` and the result are JSON objects.
/// This is the core's `toolkit::run`, so a tool works here exactly as in the other apps. Runs on the
/// caller's thread: RSA key generation takes seconds, so apps call it off the main thread.
#[uniffi::export]
pub fn toolkit_run(op: String, input: String) -> Result<String> {
    let input = Zeroizing::new(input);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64);
    toolkit::run(&op, &input, now_ms, &mut OsRng)
        .map(|output| output.to_string())
        .map_err(|error| VaultError::new(ErrorCode::InvalidInput, error.code()))
}

#[uniffi::export]
pub fn generate_password(options: GeneratorOptions) -> Result<String> {
    let password = generator::generate(&core_options(options), &mut OsRng)
        .map_err(|_| VaultError::new(ErrorCode::InvalidInput, "invalid generator options"))?;
    Ok(password.to_string())
}

/// A password in these options, adjusted to what the password rules dataset knows about `url`, so a
/// suggestion is accepted the first time. A passphrase has no rules to follow, and comes back as is.
#[uniffi::export]
pub fn generate_password_for_site(url: String, options: GeneratorOptions) -> Result<String> {
    let generator::GeneratorOptions::Random(random) = core_options(options.clone()) else {
        return generate_password(options);
    };
    let password = rules::generate_for_site(&url, None, &random, &mut OsRng)
        .map_err(|_| VaultError::new(ErrorCode::InvalidInput, "invalid generator options"))?;
    Ok(password.to_string())
}

/// The generator's bits of entropy for these options, shown next to what it made.
#[uniffi::export]
pub fn generator_entropy_bits(options: GeneratorOptions) -> f64 {
    generator::entropy_bits(&core_options(options))
}

/// The web vault's generator defaults: a 20-character password with every set, or five words
/// joined by `-`.
#[uniffi::export]
pub fn default_generator_options(passphrase: bool) -> GeneratorOptions {
    if passphrase {
        GeneratorOptions::Passphrase {
            words: 5,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        }
    } else {
        GeneratorOptions::Password {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

fn core_options(options: GeneratorOptions) -> generator::GeneratorOptions {
    match options {
        GeneratorOptions::Password {
            length,
            uppercase,
            lowercase,
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
    }
}

/// The core's zxcvbn hint, as the web vault's feedback codes.
fn feedback(password: &str, hint: Option<&str>) -> StrengthFeedback {
    let hint = hint.unwrap_or_default().to_lowercase();
    let has = |words: &[&str]| words.iter().any(|word| hint.contains(word));
    if has(&["common password", "top-10", "top-100", "very common"]) {
        StrengthFeedback::CommonPassword
    } else if password.chars().count() < MIN_LENGTH {
        StrengthFeedback::TooShort
    } else if has(&["sequence"]) {
        StrengthFeedback::Sequence
    } else if has(&["repeat"]) {
        StrengthFeedback::Repeat
    } else if has(&["keyboard", "straight rows"]) {
        StrengthFeedback::KeyboardPattern
    } else if has(&["date", "year"]) {
        StrengthFeedback::Date
    } else if has(&["word by itself", "names", "common words", "dictionary"]) {
        StrengthFeedback::DictionaryWord
    } else if has(&["another word", "more words"]) {
        StrengthFeedback::AddMoreWords
    } else {
        StrengthFeedback::AddVariety
    }
}

/// How hard the password is to guess. `user_inputs` (the email, the site) make passwords that
/// contain them weaker. Runs on the phone.
pub(crate) fn estimate(password: &str, user_inputs: &[&str]) -> StrengthEstimate {
    let password = Zeroizing::new(password.to_owned());
    if password.is_empty() {
        return StrengthEstimate {
            score: 0,
            guesses_log10: 0.0,
            feedback: Some(StrengthFeedback::TooShort),
        };
    }
    let strength = strength::estimate(&password, user_inputs);
    let mut score = strength.score;
    if password.chars().count() < MIN_LENGTH {
        score = score.min(2);
    }
    StrengthEstimate {
        score,
        guesses_log10: strength.guesses_log10,
        feedback: (score < 4).then(|| feedback(&password, strength.feedback.as_deref())),
    }
}

/// The code for a one-time code secret (`otpauth://totp/…` or base32) at `at_ms` (Unix
/// milliseconds), or now.
#[uniffi::export]
pub fn totp_code(totp: String, at_ms: Option<u64>) -> Result<TotpCode> {
    let at_ms = at_ms.unwrap_or_else(crate::vault::now_ms);
    let code = totp::totp_code(&Zeroizing::new(totp), at_ms / 1000)
        .map_err(|_| VaultError::new(ErrorCode::InvalidInput, "invalid one-time code secret"))?;
    Ok(TotpCode {
        code: code.code,
        period: code.period,
        remaining: code.remaining,
    })
}

/// Whether an item's `totp` field is a counter-based (HOTP) code: show `nextHotpCode`'s button
/// instead of a live code.
#[uniffi::export]
pub fn is_hotp(totp: String) -> bool {
    totp::is_hotp(&Zeroizing::new(totp))
}

/// The number of the next counter-based code; `None` for a time-based one.
#[uniffi::export]
pub fn hotp_counter(totp: String) -> Option<u64> {
    totp::hotp_counter(&Zeroizing::new(totp)).ok()
}

/// A Secret Key as typed or scanned from a Recovery Kit, in its canonical form. Fails with
/// `invalidSecretKey`.
#[uniffi::export]
pub fn normalize_secret_key(text: String) -> Result<String> {
    octapass_ffi::normalize_secret_key(text).map_err(|_| ErrorCode::InvalidSecretKey.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_and_strength() {
        let password = generate_password(GeneratorOptions::Password {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: false,
            avoid_ambiguous: true,
        })
        .unwrap();
        assert_eq!(password.len(), 20);
        let phrase = generate_password(GeneratorOptions::Passphrase {
            words: 4,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        })
        .unwrap();
        assert_eq!(phrase.split('-').count(), 4);
        let bits = generator_entropy_bits(default_generator_options(false));
        assert!(bits > 120.0 && bits < 140.0, "{bits}");
        assert!(generator_entropy_bits(default_generator_options(true)) > 64.0);
        assert!(generate_password(default_generator_options(true)).is_ok());
        assert_eq!(
            generate_password(GeneratorOptions::Passphrase {
                words: 1,
                separator: "-".into(),
                capitalize: false,
                include_number: false
            })
            .unwrap_err()
            .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(estimate("", &[]).feedback, Some(StrengthFeedback::TooShort));
        let weak = estimate("password1", &[]);
        assert_eq!(
            (weak.score, weak.feedback),
            (0, Some(StrengthFeedback::CommonPassword))
        );
        assert!(estimate("Tr0ub4dour&3", &[]).score <= 3);
        assert!(
            estimate("x7#Kq", &[]).score <= 2,
            "short ones never rate above fair"
        );
        let strong = estimate(&password, &[]);
        assert_eq!((strong.score, strong.feedback), (4, None));
    }

    #[test]
    fn one_time_codes() {
        let code = totp_code("JBSWY3DPEHPK3PXP".into(), Some(59_000)).unwrap();
        assert_eq!((code.period, code.remaining), (30, 1));
        assert_eq!(code.code.len(), 6);
        assert_eq!(
            totp_code("not a secret!".into(), None).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }
}
