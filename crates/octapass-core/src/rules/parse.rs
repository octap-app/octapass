//! The `passwordrules` parser. Like Apple's reference parser it never fails: malformed or
//! unknown properties are skipped, so a site's typo can't block password generation.

use super::{CharacterClass, NamedClass, PasswordRules};

pub fn parse(text: &str) -> PasswordRules {
    let mut rules = PasswordRules::default();
    for property in split_properties(text) {
        let Some((name, value)) = property.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "minlength" => {
                if let Some(n) = number(value) {
                    rules.min_length = Some(rules.min_length.map_or(n, |m| m.max(n)));
                }
            }
            "maxlength" => {
                if let Some(n) = number(value).filter(|&n| n > 0) {
                    rules.max_length = Some(rules.max_length.map_or(n, |m| m.min(n)));
                }
            }
            "max-consecutive" => {
                if let Some(n) = number(value).filter(|&n| n > 0) {
                    rules.max_consecutive = Some(rules.max_consecutive.map_or(n, |m| m.min(n)));
                }
            }
            "required" => {
                let class = character_class(value);
                if !class.is_empty() {
                    rules.required.push(class);
                }
            }
            "allowed" => {
                let class = character_class(value);
                if !class.is_empty() {
                    let allowed = rules.allowed.get_or_insert_with(CharacterClass::default);
                    allowed.named.extend(class.named);
                    allowed.custom.push_str(&class.custom);
                    allowed.normalize();
                }
            }
            _ => {}
        }
    }
    rules
}

/// Splits on `;`, except inside `[…]`, where `;` is just a character.
fn split_properties(text: &str) -> Vec<&str> {
    let mut properties = Vec::new();
    let (mut start, mut in_class) = (0, false);
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '[' if !in_class => in_class = true,
            // `]]` ends a class that contains `]`.
            ']' if in_class => {
                if let Some(&(_, ']')) = chars.peek() {
                    chars.next();
                }
                in_class = false;
            }
            ';' if !in_class => {
                properties.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    properties.push(&text[start..]);
    properties
}

fn number(value: &str) -> Option<usize> {
    value.parse().ok()
}

/// `upper, digit, [-_.]`: named classes and custom characters, comma separated.
fn character_class(value: &str) -> CharacterClass {
    let mut class = CharacterClass::default();
    let mut rest = value.trim();
    while !rest.is_empty() {
        if let Some(body) = rest.strip_prefix('[') {
            let (custom, after) = custom_class(body);
            class.custom.push_str(&custom);
            rest = after;
        } else {
            let end = rest.find([',', '[']).unwrap_or(rest.len());
            let name = rest[..end].trim().to_ascii_lowercase();
            if let Some(named) = named_class(&name) {
                class.named.push(named);
            }
            rest = &rest[end..];
        }
        rest = rest.trim_start().trim_start_matches(',').trim_start();
    }
    class.normalize();
    class
}

/// The characters of `[…]` (with the `[` already consumed) and the text after the closing `]`.
/// Only printable ASCII counts, as in Apple's parser.
fn custom_class(body: &str) -> (String, &str) {
    let mut chars = String::new();
    let mut rest = body;
    if let Some(after) = rest.strip_prefix('-') {
        chars.push('-');
        rest = after;
    }
    let mut iter = rest.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        if c == ']' {
            if let Some(&(j, ']')) = iter.peek() {
                chars.push(']');
                return (chars, &rest[j + 1..]);
            }
            return (chars, &rest[i + 1..]);
        }
        if is_ascii_printable(c) {
            chars.push(c);
        }
    }
    // Unterminated: keep what was there.
    (chars, "")
}

fn named_class(name: &str) -> Option<NamedClass> {
    Some(match name {
        "upper" => NamedClass::Upper,
        "lower" => NamedClass::Lower,
        "digit" => NamedClass::Digit,
        "special" => NamedClass::Special,
        "ascii-printable" => NamedClass::AsciiPrintable,
        "unicode" => NamedClass::Unicode,
        _ => return None,
    })
}

pub(super) fn is_ascii_printable(c: char) -> bool {
    (' '..='~').contains(&c)
}

impl CharacterClass {
    pub fn is_empty(&self) -> bool {
        self.named.is_empty() && self.custom.is_empty()
    }

    /// Sorted, without duplicates, so equal sets compare equal.
    fn normalize(&mut self) {
        self.named.sort_by_key(|named| *named as u8);
        self.named.dedup();
        let mut custom: Vec<char> = self.custom.chars().collect();
        custom.sort_unstable();
        custom.dedup();
        self.custom = custom.into_iter().collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use NamedClass::*;

    fn class(named: &[NamedClass], custom: &str) -> CharacterClass {
        CharacterClass {
            named: named.to_vec(),
            custom: custom.into(),
        }
    }

    #[test]
    fn parses_every_property() {
        let rules = parse(
            "minlength: 8; maxlength: 16; required: lower; required: upper, digit; allowed: [-_.]; max-consecutive: 2;",
        );
        assert_eq!(
            rules,
            PasswordRules {
                min_length: Some(8),
                max_length: Some(16),
                max_consecutive: Some(2),
                required: vec![class(&[Lower], ""), class(&[Upper, Digit], "")],
                allowed: Some(class(&[], "-._")),
            }
        );
    }

    #[test]
    fn custom_classes_follow_apples_quoting() {
        // `-` first and `]` last are literals; `;` and `[` inside a class are characters.
        let rules = parse("required: [- !\"#$&'()*+,.:;<=>?@[^_`{|}~]]; allowed: lower, upper;");
        assert_eq!(
            rules.required,
            [class(&[], " !\"#$&'()*+,-.:;<=>?@[]^_`{|}~")]
        );
        assert_eq!(rules.allowed, Some(class(&[Upper, Lower], "")));
        // Non-ASCII characters are ignored.
        assert_eq!(parse("allowed: [§$%]").allowed, Some(class(&[], "$%")));
        assert_eq!(parse("required: [abc").required, [class(&[], "abc")]);
    }

    #[test]
    fn repeated_properties_combine_strictly() {
        let rules = parse(
            "minlength: 6; maxlength: 30; minlength: 10; maxlength: 20; max-consecutive: 3; max-consecutive: 2; allowed: digit; allowed: lower;",
        );
        assert_eq!(rules.min_length, Some(10));
        assert_eq!(rules.max_length, Some(20));
        assert_eq!(rules.max_consecutive, Some(2));
        assert_eq!(rules.allowed, Some(class(&[Lower, Digit], "")));
    }

    #[test]
    fn malformed_and_unknown_input_is_skipped() {
        assert!(parse("").is_empty());
        assert!(
            parse(";;; nonsense; foo: bar; minlength: x; maxlength: 0; required: sparkles")
                .is_empty()
        );
        let rules = parse("MinLength : 12 ; REQUIRED: Upper");
        assert_eq!(rules.min_length, Some(12));
        assert_eq!(rules.required, [class(&[Upper], "")]);
    }
}
