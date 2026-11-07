//! A random password that satisfies a site's rules, staying as close to the user's generator
//! settings as the rules allow: the rules always win.

use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use super::parse::is_ascii_printable;
use super::{CharacterClass, NamedClass, PasswordRules};
use crate::error::{Error, Result};
use crate::tools::generator::{
    AMBIGUOUS, DIGITS, LENGTH_RANGE, LOWERCASE, RandomOptions, UPPERCASE, pick, uniform,
};

const SPECIAL: &str = " -~!@#$%^&*_+=`|(){}[:;\"'<>,.?]";
/// Allowed by many sites but awkward in forms and shells (see the generator's `SYMBOLS`). Used
/// only when a set has nothing else to offer.
const AWKWARD: &str = " \"'\\`";
/// Retries when `max-consecutive` paints a position into a corner. Only near-impossible rules
/// (a one-character alphabet with `max-consecutive: 1`) exhaust them.
const ATTEMPTS: usize = 100;

/// Generates a password for `rules`. `options` are the user's random-password settings: their
/// length is clamped into the rules' range, and character sets they turned off are used only
/// where the rules require them. Fails with [`Error::InvalidPasswordRules`] when no password can
/// satisfy the rules.
pub fn generate_for_rules(
    rules: &PasswordRules,
    options: &RandomOptions,
    rng: &mut impl CryptoRngCore,
) -> Result<Zeroizing<String>> {
    let required_raw: Vec<Vec<char>> = rules.required.iter().map(CharacterClass::chars).collect();
    if required_raw.iter().any(Vec::is_empty) {
        return Err(Error::InvalidPasswordRules);
    }
    let mut allowed = match &rules.allowed {
        Some(class) => class.chars(),
        None if !rules.required.is_empty() => Vec::new(),
        None => named_chars(NamedClass::AsciiPrintable),
    };
    allowed.extend(required_raw.iter().flatten());
    allowed.sort_unstable();
    allowed.dedup();

    let enabled: Vec<char> = allowed
        .iter()
        .copied()
        .filter(|&c| user_enabled(c, options))
        .collect();
    let pool = prefer(if enabled.is_empty() { allowed } else { enabled }, options);
    let required: Vec<Vec<char>> = required_raw
        .into_iter()
        .map(|set| prefer(set, options))
        .collect();

    let min = rules.min_length.unwrap_or(1).max(required.len()).max(1);
    let max = rules
        .max_length
        .unwrap_or(*LENGTH_RANGE.end())
        .min(*LENGTH_RANGE.end());
    if min > max {
        return Err(Error::InvalidPasswordRules);
    }
    let length = options.length.clamp(min, max);
    let max_run = rules.max_consecutive.unwrap_or(usize::MAX);

    'attempt: for _ in 0..ATTEMPTS {
        // Which position draws from which required set (the rest draw from the pool).
        let mut positions: Vec<usize> = (0..length).collect();
        for i in (1..positions.len()).rev() {
            positions.swap(i, uniform(rng, i + 1));
        }
        let mut source: Vec<&[char]> = vec![&pool; length];
        for (set, &position) in required.iter().zip(&positions) {
            source[position] = set;
        }

        let mut password: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(length));
        let mut run = 0;
        for set in source {
            let last = password.last().copied();
            let choices: Vec<char> = if run >= max_run {
                set.iter().copied().filter(|&c| Some(c) != last).collect()
            } else {
                set.to_vec()
            };
            if choices.is_empty() {
                continue 'attempt;
            }
            let c = *pick(&choices, rng);
            run = if Some(c) == last { run + 1 } else { 1 };
            password.push(c);
        }
        return Ok(Zeroizing::new(password.iter().collect()));
    }
    Err(Error::InvalidPasswordRules)
}

impl CharacterClass {
    /// Every character in the class that a generated password may use, sorted.
    fn chars(&self) -> Vec<char> {
        let mut chars: Vec<char> = self
            .named
            .iter()
            .flat_map(|&named| named_chars(named))
            .chain(self.custom.chars().filter(|&c| is_ascii_printable(c)))
            .collect();
        chars.sort_unstable();
        chars.dedup();
        chars
    }
}

fn named_chars(class: NamedClass) -> Vec<char> {
    match class {
        NamedClass::Upper => UPPERCASE.chars().collect(),
        NamedClass::Lower => LOWERCASE.chars().collect(),
        NamedClass::Digit => DIGITS.chars().collect(),
        NamedClass::Special => SPECIAL.chars().collect(),
        NamedClass::AsciiPrintable | NamedClass::Unicode => (' '..='~').collect(),
    }
}

fn user_enabled(c: char, options: &RandomOptions) -> bool {
    if c.is_ascii_lowercase() {
        options.lowercase
    } else if c.is_ascii_uppercase() {
        options.uppercase
    } else if c.is_ascii_digit() {
        options.digits
    } else {
        options.symbols
    }
}

/// Drops awkward characters, and ambiguous ones if the user asked, unless that would leave the
/// set empty.
fn prefer(set: Vec<char>, options: &RandomOptions) -> Vec<char> {
    let without = |set: Vec<char>, unwanted: &str| {
        let kept: Vec<char> = set
            .iter()
            .copied()
            .filter(|c| !unwanted.contains(*c))
            .collect();
        if kept.is_empty() { set } else { kept }
    };
    let set = without(set, AWKWARD);
    if options.avoid_ambiguous {
        without(set, AMBIGUOUS)
    } else {
        set
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::rules::{dataset, parse};

    fn rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    fn generate(rules: &str, options: &RandomOptions, seed: u64) -> Result<String> {
        generate_for_rules(&parse(rules), options, &mut rng(seed)).map(|p| p.to_string())
    }

    /// Checks a password against rules independently of the generator.
    fn satisfies(password: &str, rules: &PasswordRules) -> bool {
        let length = password.chars().count();
        let in_class = |c: char, class: &CharacterClass| class.chars().contains(&c);
        let allowed = |c: char| match &rules.allowed {
            Some(class) => in_class(c, class) || rules.required.iter().any(|r| in_class(c, r)),
            None if rules.required.is_empty() => is_ascii_printable(c),
            None => rules.required.iter().any(|r| in_class(c, r)),
        };
        let chars: Vec<char> = password.chars().collect();
        let longest_run = chars
            .chunk_by(|a, b| a == b)
            .map(<[char]>::len)
            .max()
            .unwrap_or(0);
        rules.min_length.is_none_or(|min| length >= min)
            && rules.max_length.is_none_or(|max| length <= max)
            && rules.max_consecutive.is_none_or(|max| longest_run <= max)
            && rules
                .required
                .iter()
                .all(|r| chars.iter().any(|&c| in_class(c, r)))
            && chars.iter().all(|&c| allowed(c))
    }

    #[test]
    fn satisfies_every_rule_in_the_dataset() {
        for (domain, text) in dataset() {
            let rules = parse(text);
            for seed in 0..5 {
                let password =
                    generate_for_rules(&rules, &RandomOptions::default(), &mut rng(seed))
                        .unwrap_or_else(|e| panic!("{domain}: {e}"));
                assert!(
                    satisfies(&password, &rules),
                    "{domain}: {text} → {}",
                    password.as_str()
                );
            }
        }
    }

    #[test]
    fn length_follows_the_user_within_the_rules() {
        let default = RandomOptions::default();
        assert_eq!(generate("", &default, 1).unwrap().len(), 20);
        assert_eq!(generate("maxlength: 12", &default, 1).unwrap().len(), 12);
        assert_eq!(generate("minlength: 32", &default, 1).unwrap().len(), 32);
        let short = RandomOptions {
            length: 4,
            ..default
        };
        assert_eq!(
            generate("minlength: 8; maxlength: 10", &short, 1)
                .unwrap()
                .len(),
            8
        );
    }

    #[test]
    fn user_settings_apply_unless_the_rules_require_otherwise() {
        let no_symbols = RandomOptions {
            symbols: false,
            ..RandomOptions::default()
        };
        for seed in 0..20 {
            let password = generate("allowed: ascii-printable", &no_symbols, seed).unwrap();
            assert!(
                password.chars().all(|c| c.is_ascii_alphanumeric()),
                "{password}"
            );
            let password = generate("required: [!]; allowed: lower", &no_symbols, seed).unwrap();
            assert!(password.contains('!'));
        }
        // Only symbols allowed: the user's setting can't be honoured, the rules win.
        let password = generate("allowed: [!#$]", &no_symbols, 1).unwrap();
        assert!(password.chars().all(|c| "!#$".contains(c)));
    }

    #[test]
    fn awkward_and_ambiguous_characters_are_avoided_when_possible() {
        let careful = RandomOptions {
            avoid_ambiguous: true,
            length: 128,
            ..RandomOptions::default()
        };
        let password = generate("allowed: ascii-printable", &careful, 3).unwrap();
        assert!(
            !password
                .chars()
                .any(|c| AWKWARD.contains(c) || AMBIGUOUS.contains(c))
        );
        // A required set made only of awkward characters still gets one.
        assert!(
            generate("required: [ ]; allowed: lower", &careful, 3)
                .unwrap()
                .contains(' ')
        );
    }

    #[test]
    fn max_consecutive_is_respected_even_with_tiny_alphabets() {
        for seed in 0..20 {
            let password = generate(
                "allowed: [ab]; max-consecutive: 1; minlength: 30",
                &RandomOptions::default(),
                seed,
            )
            .unwrap();
            assert!(
                !password.contains("aa") && !password.contains("bb"),
                "{password}"
            );
        }
    }

    #[test]
    fn impossible_rules_are_errors() {
        let default = RandomOptions::default();
        for impossible in [
            "minlength: 20; maxlength: 10",
            "allowed: [a]; max-consecutive: 1; minlength: 2",
            "required: lower; required: upper; required: digit; maxlength: 2",
        ] {
            assert_eq!(
                generate(impossible, &default, 1).unwrap_err(),
                Error::InvalidPasswordRules,
                "{impossible}"
            );
        }
        let empty_class = PasswordRules {
            required: vec![CharacterClass {
                named: vec![],
                custom: "é".into(),
            }],
            ..PasswordRules::default()
        };
        assert!(generate_for_rules(&empty_class, &default, &mut rng(1)).is_err());
    }

    proptest! {
        #[test]
        fn random_rules_are_satisfied_or_rejected(
            min in 0usize..40, span in 0usize..40, consecutive in 1usize..4,
            upper: bool, digit: bool, special: bool, seed in any::<u64>(),
        ) {
            let mut text = format!("minlength: {min}; maxlength: {}; max-consecutive: {consecutive}; allowed: lower;", min + span);
            for (on, name) in [(upper, "upper"), (digit, "digit"), (special, "special")] {
                if on { text.push_str(&format!(" required: {name};")); }
            }
            let rules = parse(&text);
            match generate_for_rules(&rules, &RandomOptions::default(), &mut rng(seed)) {
                Ok(password) => prop_assert!(satisfies(&password, &rules), "{} → {}", text, password.as_str()),
                Err(error) => prop_assert_eq!(error, Error::InvalidPasswordRules),
            }
        }
    }
}
