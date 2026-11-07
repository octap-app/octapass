//! Random password and passphrase generation.
//!
//! Every choice is uniform (rejection sampling, no modulo bias). Random passwords contain at
//! least one character from each enabled set.

use rand_core::CryptoRngCore;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub(crate) const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
pub(crate) const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub(crate) const DIGITS: &str = "0123456789";
// No quotes, backslash, backtick or space: they break too many sign-up forms and shells.
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
pub(crate) const AMBIGUOUS: &str = "Il1O0o|";

/// The EFF large wordlist: 7,776 words, about 12.9 bits each.
/// Source: <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt> (dice numbers removed;
/// SHA-256 of the original `addd3553…996b903e`).
const WORDLIST: &str = include_str!("eff_large_wordlist.txt");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum GeneratorOptions {
    Random(RandomOptions),
    Passphrase(PassphraseOptions),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RandomOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Leaves out characters that are easy to misread: `I l 1 O 0 o |`.
    pub avoid_ambiguous: bool,
}

impl Default for RandomOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    /// Appends one random digit to one random word, for sites that demand a number.
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 5,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        }
    }
}

pub const LENGTH_RANGE: core::ops::RangeInclusive<usize> = 4..=128;
pub const WORDS_RANGE: core::ops::RangeInclusive<usize> = 3..=20;

pub fn generate(
    options: &GeneratorOptions,
    rng: &mut impl CryptoRngCore,
) -> Result<Zeroizing<String>> {
    match options {
        GeneratorOptions::Random(options) => random_password(options, rng),
        GeneratorOptions::Passphrase(options) => passphrase(options, rng),
    }
}

pub fn random_password(
    options: &RandomOptions,
    rng: &mut impl CryptoRngCore,
) -> Result<Zeroizing<String>> {
    let sets: Vec<Vec<char>> = [
        (options.lowercase, LOWERCASE),
        (options.uppercase, UPPERCASE),
        (options.digits, DIGITS),
        (options.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, set)| {
        set.chars()
            .filter(|c| !(options.avoid_ambiguous && AMBIGUOUS.contains(*c)))
            .collect()
    })
    .collect();
    if sets.is_empty() || !LENGTH_RANGE.contains(&options.length) || options.length < sets.len() {
        return Err(Error::InvalidGeneratorOptions);
    }
    let all: Vec<char> = sets.concat();

    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(options.length));
    chars.extend(sets.iter().map(|set| *pick(set, rng)));
    while chars.len() < options.length {
        chars.push(*pick(&all, rng));
    }
    // Shuffle so the guaranteed characters aren't always first (Fisher–Yates).
    for i in (1..chars.len()).rev() {
        chars.swap(i, uniform(rng, i + 1));
    }
    Ok(Zeroizing::new(chars.iter().collect()))
}

pub fn passphrase(
    options: &PassphraseOptions,
    rng: &mut impl CryptoRngCore,
) -> Result<Zeroizing<String>> {
    if !WORDS_RANGE.contains(&options.words) || options.separator.chars().count() > 3 {
        return Err(Error::InvalidGeneratorOptions);
    }
    let wordlist: Vec<&str> = WORDLIST.lines().collect();
    let mut words: Vec<Zeroizing<String>> = (0..options.words)
        .map(|_| {
            let word = *pick(&wordlist, rng);
            Zeroizing::new(if options.capitalize {
                capitalize(word)
            } else {
                word.to_string()
            })
        })
        .collect();
    if options.include_number {
        let index = uniform(rng, words.len());
        let digit = *pick(&DIGITS.chars().collect::<Vec<_>>(), rng);
        words[index].push(digit);
    }
    let joined: Vec<&str> = words.iter().map(|w| w.as_str()).collect();
    Ok(Zeroizing::new(joined.join(&options.separator)))
}

/// How many bits of entropy what `generate` makes with these options has, as the generator
/// screens show it: the length times the bits per character, or the words times the bits per
/// word, plus the digit and where it goes. Options `generate` refuses count as none.
pub fn entropy_bits(options: &GeneratorOptions) -> f64 {
    match options {
        GeneratorOptions::Random(options) => {
            let characters = [
                (options.lowercase, LOWERCASE),
                (options.uppercase, UPPERCASE),
                (options.digits, DIGITS),
                (options.symbols, SYMBOLS),
            ]
            .into_iter()
            .filter(|(enabled, _)| *enabled)
            .flat_map(|(_, set)| set.chars())
            .filter(|c| !(options.avoid_ambiguous && AMBIGUOUS.contains(*c)))
            .count();
            if characters == 0 || !LENGTH_RANGE.contains(&options.length) {
                return 0.0;
            }
            options.length as f64 * (characters as f64).log2()
        }
        GeneratorOptions::Passphrase(options) => {
            if !WORDS_RANGE.contains(&options.words) {
                return 0.0;
            }
            let words = options.words as f64 * (WORDLIST.lines().count() as f64).log2();
            if options.include_number {
                words + (10.0 * options.words as f64).log2()
            } else {
                words
            }
        }
    }
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

pub(crate) fn pick<'a, T>(items: &'a [T], rng: &mut impl CryptoRngCore) -> &'a T {
    &items[uniform(rng, items.len())]
}

/// A uniform index in `0..n` (rejection sampling avoids modulo bias).
pub(crate) fn uniform(rng: &mut impl CryptoRngCore, n: usize) -> usize {
    let n = n as u64;
    let zone = (1u64 << 32) - (1u64 << 32) % n;
    loop {
        let x = u64::from(rng.next_u32());
        if x < zone {
            return (x % n) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    fn rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    #[test]
    fn wordlist_is_complete() {
        let words: Vec<&str> = WORDLIST.lines().collect();
        assert_eq!(words.len(), 7776);
        assert_eq!(words[0], "abacus");
        assert_eq!(words[7775], "zoom");
    }

    /// Documents the list's strength; it doesn't choose it (the list is the maintainer's call).
    /// 6^5 unique words, picked uniformly, give log2(7776) ≈ 12.925 bits each: about 64.6 bits
    /// for the default five words and 38.8 for the minimum of three. Capitals and the digit add
    /// little and aren't counted.
    #[test]
    fn entropy_follows_the_options() {
        let random = |length, avoid_ambiguous| {
            entropy_bits(&GeneratorOptions::Random(RandomOptions {
                length,
                avoid_ambiguous,
                ..RandomOptions::default()
            }))
        };
        let all = (26 + 26 + 10 + SYMBOLS.len()) as f64;
        assert!((random(20, false) - 20.0 * all.log2()).abs() < 1e-9);
        assert!(random(20, true) < random(20, false));
        assert_eq!(random(2, false), 0.0);
        let phrase = |include_number| {
            entropy_bits(&GeneratorOptions::Passphrase(PassphraseOptions {
                include_number,
                ..PassphraseOptions::default()
            }))
        };
        assert!((phrase(false) - 5.0 * 7776f64.log2()).abs() < 1e-9);
        assert!((phrase(true) - phrase(false) - 50f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn wordlist_size_and_entropy_per_word() {
        let words: std::collections::HashSet<&str> = WORDLIST.lines().collect();
        assert_eq!(
            words.len(),
            6usize.pow(5),
            "five dice per word, no duplicates"
        );
        let bits_per_word = (words.len() as f64).log2();
        assert!((bits_per_word - 12.925).abs() < 0.001, "{bits_per_word}");
        let bits = |n: usize| n as f64 * bits_per_word;
        assert!((bits(PassphraseOptions::default().words) - 64.62).abs() < 0.01);
        assert!((bits(*WORDS_RANGE.start()) - 38.77).abs() < 0.01);
    }

    #[test]
    fn options_parse_from_json_with_defaults() {
        let options: GeneratorOptions =
            serde_json::from_str(r#"{"type":"random","length":12,"symbols":false}"#).unwrap();
        assert_eq!(
            options,
            GeneratorOptions::Random(RandomOptions {
                length: 12,
                symbols: false,
                ..RandomOptions::default()
            })
        );
        let options: GeneratorOptions = serde_json::from_str(r#"{"type":"passphrase"}"#).unwrap();
        assert_eq!(
            options,
            GeneratorOptions::Passphrase(PassphraseOptions::default())
        );
    }

    #[test]
    fn invalid_options() {
        let none = RandomOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(random_password(&none, &mut rng(1)).is_err());
        assert!(
            random_password(
                &RandomOptions {
                    length: 3,
                    ..Default::default()
                },
                &mut rng(1)
            )
            .is_err()
        );
        assert!(
            random_password(
                &RandomOptions {
                    length: 129,
                    ..Default::default()
                },
                &mut rng(1)
            )
            .is_err()
        );
        assert!(
            passphrase(
                &PassphraseOptions {
                    words: 2,
                    ..Default::default()
                },
                &mut rng(1)
            )
            .is_err()
        );
    }

    #[test]
    fn avoid_ambiguous() {
        let options = RandomOptions {
            length: 128,
            avoid_ambiguous: true,
            ..Default::default()
        };
        for seed in 0..20 {
            let password = random_password(&options, &mut rng(seed)).unwrap();
            assert!(!password.chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn passphrase_shape() {
        let options = PassphraseOptions {
            words: 6,
            separator: ".".into(),
            capitalize: true,
            include_number: true,
        };
        let phrase = passphrase(&options, &mut rng(3)).unwrap();
        let words: Vec<&str> = phrase.split('.').collect();
        assert_eq!(words.len(), 6);
        assert!(
            words
                .iter()
                .all(|w| w.chars().next().unwrap().is_uppercase())
        );
        assert_eq!(phrase.chars().filter(|c| c.is_ascii_digit()).count(), 1);
    }

    #[test]
    fn uniform_is_roughly_uniform() {
        let mut counts = [0u32; 7];
        let mut rng = rng(4);
        for _ in 0..70_000 {
            counts[uniform(&mut rng, 7)] += 1;
        }
        assert!(
            counts.iter().all(|&c| (9_000..11_000).contains(&c)),
            "{counts:?}"
        );
    }

    proptest! {
        #[test]
        fn random_passwords_honour_every_set(seed in any::<u64>(), length in 4usize..64, lower: bool, upper: bool, digits: bool, symbols: bool) {
            prop_assume!(lower || upper || digits || symbols);
            let options = RandomOptions { length, lowercase: lower, uppercase: upper, digits, symbols, avoid_ambiguous: false };
            let password = random_password(&options, &mut rng(seed)).unwrap();
            prop_assert_eq!(password.chars().count(), length);
            for (enabled, set) in [(lower, LOWERCASE), (upper, UPPERCASE), (digits, DIGITS), (symbols, SYMBOLS)] {
                prop_assert_eq!(password.chars().any(|c| set.contains(c)), enabled);
            }
        }
    }
}
