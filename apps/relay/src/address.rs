//! Mail addresses, read strictly, and the relay's own address forms.
//!
//! The relay is not a general mail system, so it refuses what it has no use for instead of
//! interpreting it: source routes, quoted local parts, `%` and `!` routing, address literals and
//! non-ASCII. That refusal is one half of what keeps it from being an open relay; the other is
//! that a recipient must be exactly one of the addresses it issued (see [`Local`]).

use std::fmt;

/// A lowercased `local@domain`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    pub local: String,
    pub domain: String,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not an address this relay accepts")]
pub struct InvalidAddress;

const MAX_LOCAL: usize = 64;
const MAX_DOMAIN: usize = 253;

/// RFC 5321's atext without `%` and `!`, which old systems treat as routing.
fn local_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"#$&'*+-/=?^_`{|}~.".contains(&byte)
}

fn valid_local(local: &str) -> bool {
    !local.is_empty()
        && local.len() <= MAX_LOCAL
        && local.bytes().all(local_char)
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
}

fn valid_domain(domain: &str) -> bool {
    domain.len() <= MAX_DOMAIN
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

impl Address {
    pub fn parse(text: &str) -> Result<Self, InvalidAddress> {
        let (local, domain) = text.rsplit_once('@').ok_or(InvalidAddress)?;
        let (local, domain) = (local.to_ascii_lowercase(), domain.to_ascii_lowercase());
        if valid_local(&local) && valid_domain(&domain) {
            Ok(Self { local, domain })
        } else {
            Err(InvalidAddress)
        }
    }
}

/// What a recipient's local part means on the relay's domain, decided by its shape alone. Each
/// form must still be found in the database or pass its HMAC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Local {
    Alias,
    Reverse,
    /// A signed return path, where bounces and complaints arrive.
    Srs,
    /// `postmaster` or `abuse`, which RFC 5321 and RFC 2142 require.
    Operator,
    Unknown,
}

const ALIAS_CHARS: usize = 12;
const REVERSE_CHARS: usize = 26;
const REVERSE_PREFIX: &str = "r-";

pub fn classify(local: &str) -> Local {
    let base32 = |text: &str| {
        text.bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    };
    if local == "postmaster" || local == "abuse" {
        Local::Operator
    } else if local.starts_with("srs0=") {
        Local::Srs
    } else if let Some(random) = local.strip_prefix(REVERSE_PREFIX) {
        if random.len() == REVERSE_CHARS && base32(random) {
            Local::Reverse
        } else {
            Local::Unknown
        }
    } else if local.len() == ALIAS_CHARS && base32(local) {
        Local::Alias
    } else {
        Local::Unknown
    }
}

/// 60 random bits: too many to guess one that exists, short enough to read out.
pub fn new_alias() -> String {
    crate::keys::base32_lower(&crate::keys::random_bytes::<8>(), ALIAS_CHARS)
}

/// 130 random bits: holding a reverse alias is half of being able to mail someone's contact.
pub fn new_reverse() -> String {
    let random = crate::keys::random_bytes::<17>();
    format!(
        "{REVERSE_PREFIX}{}",
        crate::keys::base32_lower(&random, REVERSE_CHARS)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_plain_addresses_and_lowercases_them() {
        let address = Address::parse("Jane.Doe+tag@Example.COM").unwrap();
        assert_eq!(address.to_string(), "jane.doe+tag@example.com");
    }

    #[test]
    fn refuses_everything_with_routing_meaning() {
        for bad in [
            "",
            "a",
            "@example.com",
            "a@",
            "a@b",
            "\"a b\"@example.com",
            "\"a@evil.example\"@example.com",
            "a%evil.example@example.com",
            "evil.example!a@example.com",
            "a@[192.0.2.1]",
            "a@example.com.",
            "a@-example.com",
            "a..b@example.com",
            ".a@example.com",
            "a.@example.com",
            "a b@example.com",
            "a@exa mple.com",
            "jöhn@example.com",
            "a@exämple.com",
            "@a.example,@b.example:c@example.com",
            "a\r\nRCPT TO:<b@evil.example>@example.com",
        ] {
            assert_eq!(Address::parse(bad), Err(InvalidAddress), "{bad:?}");
        }
        assert_eq!(
            Address::parse(&format!("{}@example.com", "a".repeat(65))),
            Err(InvalidAddress)
        );
    }

    #[test]
    fn the_issued_forms_are_recognised_and_nothing_else() {
        assert_eq!(classify(&new_alias()), Local::Alias);
        assert_eq!(classify(&new_reverse()), Local::Reverse);
        assert_eq!(classify("postmaster"), Local::Operator);
        assert_eq!(classify("abuse"), Local::Operator);
        assert_eq!(classify("srs0=x"), Local::Srs);
        for other in [
            "jane",
            "r-short",
            "administrator",
            "abcdefghijkl1",
            "abcdefghij18",
            "r-abcdefghijklmnopqrstuvwxy1",
        ] {
            assert_eq!(classify(other), Local::Unknown, "{other}");
        }
    }
}
