//! Signed return paths, in the shape of SRS0 (`SRS0=hash=time=domain=local`).
//!
//! A forwarded message needs a return path on our own domain, or SPF fails and bounces would reach
//! the original sender. Classic SRS encodes the original sender so a bounce can go back to them.
//! This relay must never do that: a bounce from the user's mailbox names the user's real address.
//! So the payload is the alias the mail went through, and the domain field holds what kind of mail
//! it was (`f` forwarded, `r` a reply). The hash is an HMAC, the time is in days and wraps at
//! 1024, and everything is lowercase base32 because mail systems may fold case.

use subtle::ConstantTimeEq;

use crate::keys::{Keys, base32_lower, hmac};

const HASH_CHARS: usize = 10;
const TIME_CHARS: usize = 2;
const TIME_WRAP: u64 = 1024;
const DAY: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Forward,
    Reply,
}

impl Kind {
    fn tag(self) -> &'static str {
        match self {
            Self::Forward => "f",
            Self::Reply => "r",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnPath {
    pub kind: Kind,
    pub alias: String,
}

fn hash(keys: &Keys, time: &str, kind: Kind, alias: &str) -> String {
    let mac = hmac(
        &*keys.srs,
        "srs0",
        &[time.as_bytes(), kind.tag().as_bytes(), alias.as_bytes()],
    );
    base32_lower(&mac, HASH_CHARS)
}

fn time_field(days: u64) -> String {
    let wrapped = (days % TIME_WRAP) as u16;
    base32_lower(&(wrapped << 6).to_be_bytes(), TIME_CHARS)
}

fn days_of(field: &str) -> Option<u64> {
    let mut days = 0u64;
    for byte in field.bytes() {
        let value = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        days = days * 32 + u64::from(value);
    }
    (field.len() == TIME_CHARS).then_some(days)
}

/// The local part of a return path for `alias`.
pub fn encode(keys: &Keys, kind: Kind, alias: &str, now_secs: u64) -> String {
    let time = time_field(now_secs / DAY);
    let hash = hash(keys, &time, kind, alias);
    format!("srs0={hash}={time}={}={alias}", kind.tag())
}

/// Checks a local part (already lowercase) against the key and the age limit. Nothing is trusted
/// until the hash matches.
pub fn decode(keys: &Keys, local: &str, now_secs: u64, max_age_days: u64) -> Option<ReturnPath> {
    let mut fields = local.split('=');
    if fields.next()? != "srs0" {
        return None;
    }
    let (given, time, tag, alias) = (
        fields.next()?,
        fields.next()?,
        fields.next()?,
        fields.next()?,
    );
    if fields.next().is_some() {
        return None;
    }
    let kind = match tag {
        "f" => Kind::Forward,
        "r" => Kind::Reply,
        _ => return None,
    };
    let expected = hash(keys, time, kind, alias);
    if !bool::from(expected.as_bytes().ct_eq(given.as_bytes())) {
        return None;
    }
    let sent = days_of(time)?;
    let today = (now_secs / DAY) % TIME_WRAP;
    let age = (today + TIME_WRAP - sent) % TIME_WRAP;
    (age <= max_age_days).then(|| ReturnPath {
        kind,
        alias: alias.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const NOW: u64 = 1_793_000_000;

    fn keys() -> Keys {
        Keys::derive(&[3; 32])
    }

    #[test]
    fn round_trips_and_fits_a_local_part() {
        for kind in [Kind::Forward, Kind::Reply] {
            let local = encode(&keys(), kind, "abcdefghijkl", NOW);
            assert!(local.len() <= 64, "{local}");
            assert_eq!(local, local.to_lowercase());
            assert_eq!(
                decode(&keys(), &local, NOW, 21),
                Some(ReturnPath {
                    kind,
                    alias: "abcdefghijkl".into()
                })
            );
        }
    }

    #[test]
    fn expires_after_the_limit_and_across_the_wrap() {
        let local = encode(&keys(), Kind::Forward, "abcdefghijkl", NOW);
        let day = 24 * 60 * 60;
        assert!(decode(&keys(), &local, NOW + 21 * day, 21).is_some());
        assert!(decode(&keys(), &local, NOW + 22 * day, 21).is_none());
        // Near day 1023 the wrap must not make a fresh address look old.
        let edge = 1023 * 1024 * day;
        let local = encode(&keys(), Kind::Forward, "abcdefghijkl", edge + 1023 * day);
        assert!(decode(&keys(), &local, edge + 1025 * day, 21).is_some());
    }

    #[test]
    fn nothing_but_the_exact_signed_value_passes() {
        let local = encode(&keys(), Kind::Forward, "abcdefghijkl", NOW);
        assert!(decode(&Keys::derive(&[4; 32]), &local, NOW, 21).is_none());
        let swapped = local.replace("=abcdefghijkl", "=bcdefghijklm");
        assert!(decode(&keys(), &swapped, NOW, 21).is_none());
        let other_kind = local.replace("=f=", "=r=");
        assert!(decode(&keys(), &other_kind, NOW, 21).is_none());
        for bad in ["srs0=", "srs0=a=b=f=c", "srs0=====", "srs1=a=b=f=c", ""] {
            assert!(decode(&keys(), bad, NOW, 21).is_none(), "{bad}");
        }
        assert!(decode(&keys(), &format!("{local}=x"), NOW, 21).is_none());
    }

    proptest! {
        #[test]
        fn decode_never_accepts_a_changed_character(index in 5usize..30, byte in b'a'..=b'z') {
            let local = encode(&keys(), Kind::Forward, "abcdefghijkl", NOW);
            let mut changed = local.clone().into_bytes();
            let at = index.min(changed.len() - 1);
            changed[at] = byte;
            let changed = String::from_utf8(changed).unwrap();
            prop_assume!(changed != local);
            prop_assert!(decode(&keys(), &changed, NOW, 21).is_none());
        }

        #[test]
        fn decode_never_panics(local in "\\PC{0,80}") {
            let _ = decode(&keys(), &local, NOW, 21);
        }
    }
}
