//! Auto-type sequences: what to type, as text with placeholders in braces.
//!
//! ```text
//! {USERNAME}{TAB}{PASSWORD}{ENTER}      the default
//! {USERNAME}{ENTER}{DELAY 1500}{PASSWORD}{ENTER}
//! {PASSWORD}{TAB}{TOTP}{ENTER}
//! ```
//!
//! Placeholders are `{USERNAME}`, `{PASSWORD}`, `{TOTP}` (the current one-time code), `{TAB}`,
//! `{ENTER}` and `{DELAY n}` (wait `n` milliseconds, at most 10 000), in any case. Anything else
//! is typed as it is; `{{}` and `{}}` type a brace. The same rules are in
//! `packages/vault-client/src/autoType.ts`, which the item editor uses to check a sequence.

use std::fmt;
use std::time::Duration;

use serde::Serialize;
use zeroize::Zeroizing;

pub const DEFAULT_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";
/// Password items have no username.
pub const PASSWORD_SEQUENCE: &str = "{PASSWORD}{ENTER}";
pub const MAX_DELAY_MS: u32 = 10_000;
/// Longer sequences are almost certainly a mistake (a pasted note).
pub const MAX_LEN: usize = 500;

/// An item field a sequence can type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Field {
    Username,
    Password,
    /// The current one-time code.
    Totp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Tab,
    Enter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Text(String),
    Field(Field),
    Key(Key),
    Delay(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sequence(Vec<Token>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "camelCase")]
pub enum SequenceError {
    Empty,
    TooLong,
    /// A `{` with no `}` after it, at this character.
    Unclosed {
        at: usize,
    },
    /// `{SOMETHING}` that isn't a placeholder.
    Unknown {
        name: String,
    },
    /// `{DELAY …}` without a whole number of milliseconds up to [`MAX_DELAY_MS`].
    BadDelay {
        value: String,
    },
}

impl fmt::Display for SequenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "the sequence is empty"),
            Self::TooLong => write!(f, "the sequence is longer than {MAX_LEN} characters"),
            Self::Unclosed { at } => write!(f, "the brace at {at} isn't closed"),
            Self::Unknown { name } => write!(f, "{{{name}}} isn't a placeholder"),
            Self::BadDelay { value } => write!(
                f,
                "a delay must be 0 to {MAX_DELAY_MS} milliseconds, not “{value}”"
            ),
        }
    }
}

impl std::error::Error for SequenceError {}

impl Sequence {
    /// The item's own sequence, or `default` when it has none (or only spaces).
    pub fn for_item(sequence: Option<&str>, default: &str) -> Result<Self, SequenceError> {
        match sequence.map(str::trim) {
            Some(text) if !text.is_empty() => Self::parse(text),
            _ => Self::parse(default),
        }
    }

    pub fn parse(text: &str) -> Result<Self, SequenceError> {
        if text.is_empty() {
            return Err(SequenceError::Empty);
        }
        if text.chars().count() > MAX_LEN {
            return Err(SequenceError::TooLong);
        }
        let mut tokens = Vec::new();
        let mut literal = String::new();
        let mut chars = text.char_indices().peekable();
        while let Some((at, c)) = chars.next() {
            if c != '{' {
                literal.push(c);
                continue;
            }
            // `{{}` and `{}}`: a literal brace.
            let rest = &text[at..];
            if rest.starts_with("{{}") || rest.starts_with("{}}") {
                literal.push(rest.as_bytes()[1] as char);
                chars.nth(1);
                continue;
            }
            let Some(len) = rest.find('}') else {
                return Err(SequenceError::Unclosed {
                    at: text[..at].chars().count(),
                });
            };
            let name = &rest[1..len];
            let token = placeholder(name)?;
            if !literal.is_empty() {
                tokens.push(Token::Text(std::mem::take(&mut literal)));
            }
            tokens.push(token);
            while chars.peek().is_some_and(|(i, _)| *i <= at + len) {
                chars.next();
            }
        }
        if !literal.is_empty() {
            tokens.push(Token::Text(literal));
        }
        Ok(Self(tokens))
    }

    pub fn tokens(&self) -> &[Token] {
        &self.0
    }

    /// The fields this sequence types, so only those are decrypted.
    pub fn fields(&self) -> impl Iterator<Item = Field> + '_ {
        self.0.iter().filter_map(|token| match token {
            Token::Field(field) => Some(*field),
            _ => None,
        })
    }

    /// The keystrokes, with the item's values filled in. A field the sequence uses but the item
    /// doesn't have is an error, so nothing half-typed reaches the window.
    pub fn actions(
        &self,
        values: &dyn Fn(Field) -> Option<Zeroizing<String>>,
    ) -> Result<Vec<Action>, Field> {
        self.0
            .iter()
            .map(|token| {
                Ok(match token {
                    Token::Text(text) => Action::Text(Zeroizing::new(text.clone())),
                    Token::Field(field) => Action::Text(values(*field).ok_or(*field)?),
                    Token::Key(key) => Action::Key(*key),
                    Token::Delay(ms) => Action::Delay(Duration::from_millis(u64::from(*ms))),
                })
            })
            .collect()
    }
}

fn placeholder(name: &str) -> Result<Token, SequenceError> {
    let name = name.trim();
    Ok(match name.to_uppercase().as_str() {
        "USERNAME" | "USER" => Token::Field(Field::Username),
        "PASSWORD" => Token::Field(Field::Password),
        "TOTP" => Token::Field(Field::Totp),
        "TAB" => Token::Key(Key::Tab),
        "ENTER" => Token::Key(Key::Enter),
        _ => match name
            .get(..5)
            .filter(|head| head.eq_ignore_ascii_case("DELAY"))
            .map(|_| &name[5..])
        {
            Some(value) => {
                let value = value.trim_start_matches([' ', '=']).trim();
                match value.parse::<u32>() {
                    Ok(ms) if ms <= MAX_DELAY_MS && value.bytes().all(|b| b.is_ascii_digit()) => {
                        Token::Delay(ms)
                    }
                    _ => {
                        return Err(SequenceError::BadDelay {
                            value: value.to_owned(),
                        });
                    }
                }
            }
            None => {
                return Err(SequenceError::Unknown {
                    name: name.to_owned(),
                });
            }
        },
    })
}

/// One step of typing. Text is zeroed when dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Text(Zeroizing<String>),
    Key(Key),
    Delay(Duration),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Token {
        Token::Text(value.into())
    }

    #[test]
    fn the_default_is_username_tab_password_enter() {
        assert_eq!(
            Sequence::for_item(None, DEFAULT_SEQUENCE).unwrap().tokens(),
            [
                Token::Field(Field::Username),
                Token::Key(Key::Tab),
                Token::Field(Field::Password),
                Token::Key(Key::Enter),
            ]
        );
        assert_eq!(
            Sequence::for_item(Some("  "), PASSWORD_SEQUENCE).unwrap(),
            Sequence::parse("{PASSWORD}{ENTER}").unwrap()
        );
    }

    #[test]
    fn placeholders_ignore_case_and_text_is_kept() {
        let sequence = Sequence::parse("hi {username}{Tab}x{DELAY 250}{password}{enter}é").unwrap();
        assert_eq!(
            sequence.tokens(),
            [
                text("hi "),
                Token::Field(Field::Username),
                Token::Key(Key::Tab),
                text("x"),
                Token::Delay(250),
                Token::Field(Field::Password),
                Token::Key(Key::Enter),
                text("é"),
            ]
        );
        assert_eq!(
            Sequence::parse("{DELAY=10}{TOTP}{user}").unwrap().tokens(),
            [
                Token::Delay(10),
                Token::Field(Field::Totp),
                Token::Field(Field::Username)
            ]
        );
    }

    #[test]
    fn braces_can_be_typed() {
        assert_eq!(
            Sequence::parse("{{}a{}}{TAB}{}}").unwrap().tokens(),
            [text("{a}"), Token::Key(Key::Tab), text("}")]
        );
        assert_eq!(Sequence::parse("}").unwrap().tokens(), [text("}")]);
    }

    #[test]
    fn mistakes_are_explained() {
        assert_eq!(Sequence::parse(""), Err(SequenceError::Empty));
        assert_eq!(
            Sequence::parse("ab{TAB"),
            Err(SequenceError::Unclosed { at: 2 })
        );
        assert_eq!(
            Sequence::parse("{PASSWROD}"),
            Err(SequenceError::Unknown {
                name: "PASSWROD".into()
            })
        );
        for value in ["", "abc", "-5", "10001", "1.5"] {
            assert_eq!(
                Sequence::parse(&format!("{{DELAY {value}}}")),
                Err(SequenceError::BadDelay {
                    value: value.into()
                }),
                "{value}"
            );
        }
        assert_eq!(
            Sequence::parse(&"a".repeat(MAX_LEN + 1)),
            Err(SequenceError::TooLong)
        );
        assert_eq!(
            SequenceError::Unknown { name: "X".into() }.to_string(),
            "{X} isn't a placeholder"
        );
    }

    #[test]
    fn actions_fill_in_the_fields() {
        let sequence = Sequence::parse("{USERNAME}{TAB}{PASSWORD}{DELAY 5}{ENTER}").unwrap();
        assert_eq!(
            sequence.fields().collect::<Vec<_>>(),
            [Field::Username, Field::Password]
        );
        let values = |field| match field {
            Field::Username => Some(Zeroizing::new("ada".to_owned())),
            Field::Password => Some(Zeroizing::new("p€ss".to_owned())),
            Field::Totp => None,
        };
        assert_eq!(
            sequence.actions(&values).unwrap(),
            [
                Action::Text(Zeroizing::new("ada".into())),
                Action::Key(Key::Tab),
                Action::Text(Zeroizing::new("p€ss".into())),
                Action::Delay(Duration::from_millis(5)),
                Action::Key(Key::Enter),
            ]
        );
        let totp = Sequence::parse("{TOTP}").unwrap();
        assert_eq!(totp.actions(&values), Err(Field::Totp));
    }
}
