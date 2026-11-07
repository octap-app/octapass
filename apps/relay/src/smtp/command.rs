//! SMTP command lines. Pure and strict: anything unexpected is a syntax error, never a guess.

use crate::address::Address;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReversePath {
    /// `MAIL FROM:<>`: a bounce or other automatic message.
    Null,
    Address(Address),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Ehlo(String),
    Helo(String),
    Mail {
        from: ReversePath,
        size: Option<u64>,
    },
    Rcpt(Address),
    Data,
    Rset,
    Noop,
    Quit,
    StartTls,
    /// VRFY, EXPN and HELP: answered "not implemented", so an address can't be probed with them.
    NotImplemented,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// 500: not a command.
    Unknown,
    /// 501: a known command with bad arguments.
    Syntax,
    /// 553: an address this relay doesn't accept.
    Address,
    /// 555: a MAIL or RCPT parameter that wasn't offered.
    Parameter,
}

/// Parses one line, without its CRLF.
pub fn parse(line: &[u8]) -> Result<Command, Error> {
    let line = std::str::from_utf8(line).map_err(|_| Error::Unknown)?;
    if !line.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(Error::Unknown);
    }
    let (verb, rest) = line.split_once(' ').unwrap_or((line, ""));
    let verb = verb.to_ascii_uppercase();
    let no_arguments = |command| {
        if rest.is_empty() {
            Ok(command)
        } else {
            Err(Error::Syntax)
        }
    };
    match verb.as_str() {
        "EHLO" => host(rest).map(Command::Ehlo),
        "HELO" => host(rest).map(Command::Helo),
        "MAIL" => mail(rest),
        "RCPT" => rcpt(rest),
        "DATA" => no_arguments(Command::Data),
        "RSET" => no_arguments(Command::Rset),
        "QUIT" => no_arguments(Command::Quit),
        "STARTTLS" => no_arguments(Command::StartTls),
        // RFC 5321 lets NOOP carry a string and ignores it.
        "NOOP" => Ok(Command::Noop),
        "VRFY" | "EXPN" | "HELP" => Ok(Command::NotImplemented),
        _ => Err(Error::Unknown),
    }
}

fn host(text: &str) -> Result<String, Error> {
    let name = text.trim_end();
    let valid = !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:[]".contains(&b));
    valid.then(|| name.to_owned()).ok_or(Error::Syntax)
}

/// Splits `KEYWORD:<path> params` after the keyword, case-insensitively. RFC 5321 has no space
/// after the colon; some senders put one, and it's harmless.
fn path_and_params<'a>(text: &'a str, keyword: &str) -> Result<(&'a str, &'a str), Error> {
    if text.len() < keyword.len() || !text.is_char_boundary(keyword.len()) {
        return Err(Error::Syntax);
    }
    let (head, rest) = text.split_at(keyword.len());
    if !head.eq_ignore_ascii_case(keyword) {
        return Err(Error::Syntax);
    }
    let rest = rest.trim_start_matches(' ');
    let rest = rest.strip_prefix('<').ok_or(Error::Syntax)?;
    let (path, params) = rest.split_once('>').ok_or(Error::Syntax)?;
    if !params.is_empty() && !params.starts_with(' ') {
        return Err(Error::Syntax);
    }
    Ok((path, params.trim()))
}

fn mail(text: &str) -> Result<Command, Error> {
    let (path, params) = path_and_params(text, "FROM:")?;
    let from = if path.is_empty() {
        ReversePath::Null
    } else {
        ReversePath::Address(Address::parse(path).map_err(|_| Error::Address)?)
    };
    let mut size = None;
    for param in params.split(' ').filter(|p| !p.is_empty()) {
        let (name, value) = param.split_once('=').ok_or(Error::Parameter)?;
        match name.to_ascii_uppercase().as_str() {
            "SIZE" => {
                let digits = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
                size = Some(
                    digits
                        .then(|| value.parse().ok())
                        .flatten()
                        .ok_or(Error::Parameter)?,
                );
            }
            "BODY"
                if value.eq_ignore_ascii_case("7BIT") || value.eq_ignore_ascii_case("8BITMIME") => {
            }
            _ => return Err(Error::Parameter),
        }
    }
    Ok(Command::Mail { from, size })
}

fn rcpt(text: &str) -> Result<Command, Error> {
    let (path, params) = path_and_params(text, "TO:")?;
    if !params.is_empty() {
        return Err(Error::Parameter);
    }
    Address::parse(path)
        .map(Command::Rcpt)
        .map_err(|_| Error::Address)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn address(text: &str) -> Address {
        Address::parse(text).unwrap()
    }

    #[test]
    fn reads_the_commands_it_offers() {
        assert_eq!(
            parse(b"EHLO mail.example.com"),
            Ok(Command::Ehlo("mail.example.com".into()))
        );
        assert_eq!(
            parse(b"helo [192.0.2.1]"),
            Ok(Command::Helo("[192.0.2.1]".into()))
        );
        assert_eq!(
            parse(b"MAIL FROM:<Jane@Example.com> SIZE=1000 BODY=8BITMIME"),
            Ok(Command::Mail {
                from: ReversePath::Address(address("jane@example.com")),
                size: Some(1000)
            })
        );
        assert_eq!(
            parse(b"mail from:<>"),
            Ok(Command::Mail {
                from: ReversePath::Null,
                size: None
            })
        );
        assert_eq!(
            parse(b"RCPT TO:<a@example.com>"),
            Ok(Command::Rcpt(address("a@example.com")))
        );
        for (line, command) in [
            (&b"DATA"[..], Command::Data),
            (b"rset", Command::Rset),
            (b"NOOP anything", Command::Noop),
            (b"QUIT", Command::Quit),
            (b"STARTTLS", Command::StartTls),
            (b"VRFY jane", Command::NotImplemented),
            (b"EXPN list", Command::NotImplemented),
        ] {
            assert_eq!(parse(line), Ok(command));
        }
    }

    #[test]
    fn refuses_addresses_with_routing_in_them() {
        for line in [
            &b"RCPT TO:<@relay.example,@b.example:victim@evil.example>"[..],
            b"RCPT TO:<\"victim@evil.example\"@relay.example>",
            b"RCPT TO:<victim%evil.example@relay.example>",
            b"RCPT TO:<evil.example!victim@relay.example>",
            b"RCPT TO:<victim@[192.0.2.1]>",
            b"MAIL FROM:<@a.example:b@c.example>",
        ] {
            assert_eq!(
                parse(line),
                Err(Error::Address),
                "{}",
                String::from_utf8_lossy(line)
            );
        }
    }

    #[test]
    fn refuses_malformed_commands() {
        for (line, error) in [
            (&b""[..], Error::Unknown),
            (b"HELLO", Error::Unknown),
            (b"EHLO", Error::Syntax),
            (b"EHLO a b", Error::Syntax),
            (b"DATA now", Error::Syntax),
            (b"MAIL", Error::Syntax),
            (b"MAIL FROM", Error::Syntax),
            (b"MAIL FROM:a@b.example", Error::Syntax),
            (b"MAIL FROM:<a@b.example", Error::Syntax),
            (b"MAIL FROM:<a@b.example>x", Error::Syntax),
            (b"MAIL TO:<a@b.example>", Error::Syntax),
            (b"RCPT FROM:<a@b.example>", Error::Syntax),
            (b"RCPT TO:<>", Error::Address),
            (b"MAIL FROM:<a@b.example> SIZE=", Error::Parameter),
            (b"MAIL FROM:<a@b.example> SIZE=-1", Error::Parameter),
            (
                b"MAIL FROM:<a@b.example> SIZE=99999999999999999999999",
                Error::Parameter,
            ),
            (b"MAIL FROM:<a@b.example> SMTPUTF8", Error::Parameter),
            (b"MAIL FROM:<a@b.example> BODY=BINARYMIME", Error::Parameter),
            (b"RCPT TO:<a@b.example> NOTIFY=NEVER", Error::Parameter),
            (b"EHLO a\tb", Error::Unknown),
            (b"NOOP \xff", Error::Unknown),
            (b"RCPT TO:<a@b.example>\x00", Error::Unknown),
        ] {
            assert_eq!(parse(line), Err(error), "{}", String::from_utf8_lossy(line));
        }
    }

    proptest! {
        #[test]
        fn never_panics_on_bytes(line in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = parse(&line);
        }

        /// Whatever the text around it, a recipient that parses is a plain address.
        #[test]
        fn a_recipient_that_parses_has_no_routing(text in "[ -~]{0,120}") {
            if let Ok(Command::Rcpt(rcpt)) = parse(format!("RCPT TO:<{text}>").as_bytes()) {
                let plain = rcpt.to_string();
                prop_assert!(!plain.contains(['%', '!', '"', ':', ',', '[', ']', '<', '>', ' ']));
                prop_assert_eq!(plain.matches('@').count(), 1);
            }
        }
    }
}
