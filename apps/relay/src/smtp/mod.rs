//! The inbound SMTP server: one task per connection, strict limits, no queue.
//!
//! Each transaction takes one recipient. A second `RCPT` gets 452, and RFC 5321 has the sending
//! system retry it in a new transaction. That keeps the promise simple: the reply to DATA is the
//! fate of the one message, so there is no partly delivered mail to spool or bounce.

pub mod command;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::{Instant, timeout, timeout_at};

use crate::pipeline::{Relay, Reply, Route};
use command::{Command, Error as CommandError, ReversePath};

const MAX_LINE: u64 = 1024;
/// Read size while receiving a message; a longer line just arrives in pieces.
const DATA_CHUNK: u64 = 64 * 1024;

pub enum Outcome<S> {
    Closed,
    /// The client asked for TLS and got `220`: hand this stream to the TLS acceptor.
    StartTls(S),
}

enum Line {
    Text(Vec<u8>),
    /// Over the limit, or not ending in CRLF.
    Bad,
    Closed,
}

/// How much of an over-long command line is skipped before giving up on the connection.
const MAX_DISCARD: u64 = 64 * 1024;

async fn read_line<S: AsyncRead + Unpin>(reader: &mut BufReader<S>, wait: Duration) -> Line {
    let mut line = Vec::with_capacity(128);
    let read = timeout(
        wait,
        (&mut *reader).take(MAX_LINE).read_until(b'\n', &mut line),
    )
    .await;
    match read {
        Ok(Ok(0)) | Err(_) | Ok(Err(_)) => Line::Closed,
        // Too long: skip to its end, so what's left of it can't be read as commands of its own.
        Ok(Ok(length)) if length as u64 == MAX_LINE && !line.ends_with(b"\n") => {
            let mut rest = Vec::new();
            let skipped = timeout(
                wait,
                (&mut *reader)
                    .take(MAX_DISCARD)
                    .read_until(b'\n', &mut rest),
            )
            .await;
            match skipped {
                Ok(Ok(_)) if rest.ends_with(b"\n") => Line::Bad,
                _ => Line::Closed,
            }
        }
        Ok(Ok(_)) => match line.strip_suffix(b"\r\n") {
            Some(text) if !text.contains(&b'\r') && !text.contains(&b'\n') => {
                Line::Text(text.to_vec())
            }
            _ => Line::Bad,
        },
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Data {
    Message(Vec<u8>),
    TooLarge,
    /// A line ended in a bare CR or LF. Those are how SMTP smuggling hides a second message from
    /// one server and shows it to the next, so the whole message is refused.
    BareNewline,
    /// Far past the limit: refused without reading to the end.
    Abandoned,
    /// Timed out or dropped before the final dot.
    Closed,
}

/// Reads DATA up to the first `CRLF . CRLF`, undoing dot-stuffing. Only that exact sequence ends a
/// message: a dot after a bare LF is smuggling, not an ending, so such a dot stays inside the
/// message and the whole of it is refused at the real end. Past the size limit this keeps reading
/// only to find the end, up to the same amount again.
pub async fn read_data<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    max: usize,
    wait: Duration,
) -> Data {
    let deadline = Instant::now() + wait;
    let (mut message, mut too_large, mut bare) = (Vec::new(), false, false);
    let (mut received, mut at_line_start) = (0usize, true);
    loop {
        let mut piece = Vec::with_capacity(256);
        let read = timeout_at(
            deadline,
            (&mut *reader)
                .take(DATA_CHUNK)
                .read_until(b'\n', &mut piece),
        )
        .await;
        let Ok(Ok(length)) = read else {
            return Data::Closed;
        };
        if length == 0 {
            return Data::Closed;
        }
        received += length;
        let ends_line = piece.ends_with(b"\n");
        let terminated = piece.ends_with(b"\r\n");
        let text = if terminated {
            &piece[..piece.len() - 2]
        } else {
            &piece[..]
        };
        if (ends_line && !terminated) || text.contains(&b'\r') || text.contains(&b'\n') {
            bare = true;
        }
        if at_line_start && terminated && text == b"." {
            return match (too_large, bare) {
                (true, _) => Data::TooLarge,
                (_, true) => Data::BareNewline,
                _ => Data::Message(message),
            };
        }
        if received > max.saturating_mul(2) {
            return Data::Abandoned;
        }
        if message.len() + piece.len() > max {
            too_large = true;
            message = Vec::new();
        }
        if !too_large {
            let stuffed = at_line_start && piece.first() == Some(&b'.');
            message.extend_from_slice(if stuffed { &piece[1..] } else { &piece });
        }
        at_line_start = terminated;
    }
}

fn send(reply: &Reply) -> Vec<u8> {
    reply.line().into_bytes()
}

const fn fixed(code: u16, status: &'static str, text: &'static str) -> Reply {
    Reply { code, status, text }
}

const BAD_SEQUENCE: Reply = fixed(503, "5.5.1", "Bad sequence of commands");
const SYNTAX: Reply = fixed(501, "5.5.4", "Syntax error in arguments");
const UNKNOWN: Reply = fixed(500, "5.5.2", "Command not recognised");
const BAD_ADDRESS: Reply = fixed(553, "5.1.3", "Address not accepted");
const BAD_PARAMETER: Reply = fixed(555, "5.5.4", "Parameter not supported");
const NOT_IMPLEMENTED: Reply = fixed(502, "5.5.1", "Not implemented");
const TOO_MANY_RECIPIENTS: Reply = fixed(452, "4.5.3", "One recipient per message");
const TOO_LARGE: Reply = fixed(552, "5.3.4", "Message too large");
const BARE_NEWLINE: Reply = fixed(550, "5.5.2", "Lines must end in CRLF");
const NO_TLS: Reply = fixed(454, "4.7.0", "TLS not available");
const TOO_MANY_ERRORS: Reply = fixed(421, "4.7.0", "Too many errors");
const TOO_MANY_MESSAGES: Reply = fixed(421, "4.7.0", "Too many messages, reconnect");
const CLOSING: Reply = fixed(221, "2.0.0", "Bye");
const GO_AHEAD: Reply = fixed(354, "2.0.0", "End data with <CRLF>.<CRLF>");
const READY_FOR_TLS: Reply = fixed(220, "2.0.0", "Ready to start TLS");
const PIPELINED: Reply = fixed(501, "5.5.4", "Nothing may follow STARTTLS");

/// One connection, plain or already inside TLS. `tls_offered` is false once TLS is on.
pub async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    relay: Arc<Relay>,
    ip: IpAddr,
    tls_offered: bool,
    banner: bool,
) -> Outcome<S> {
    let limits = relay.config.limits.clone();
    let mut reader = BufReader::new(stream);
    let (mut errors, mut transactions) = (0u32, 0u32);
    let mut helo: Option<String> = None;
    let mut mail: Option<ReversePath> = None;
    let mut route: Option<Route> = None;
    let hostname = relay.config.hostname.clone();

    macro_rules! write {
        ($bytes:expr) => {
            if reader.get_mut().write_all($bytes).await.is_err() {
                return Outcome::Closed;
            }
        };
    }
    macro_rules! refuse {
        ($reply:expr) => {{
            write!(&send(&$reply));
            errors += 1;
            if errors >= limits.max_errors {
                write!(&send(&TOO_MANY_ERRORS));
                return Outcome::Closed;
            }
            continue;
        }};
    }

    if banner {
        write!(format!("220 {hostname} ESMTP\r\n").as_bytes());
    }
    loop {
        let line = match read_line(&mut reader, limits.command_timeout).await {
            Line::Text(line) => line,
            Line::Bad => refuse!(UNKNOWN),
            Line::Closed => return Outcome::Closed,
        };
        let command = match command::parse(&line) {
            Ok(command) => command,
            Err(CommandError::Unknown) => refuse!(UNKNOWN),
            Err(CommandError::Syntax) => refuse!(SYNTAX),
            Err(CommandError::Address) => refuse!(BAD_ADDRESS),
            Err(CommandError::Parameter) => refuse!(BAD_PARAMETER),
        };
        match command {
            Command::Ehlo(name) => {
                (mail, route) = (None, None);
                helo = Some(name);
                let mut hello = format!(
                    "250-{hostname}\r\n250-SIZE {}\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n",
                    limits.max_message_bytes
                );
                if tls_offered {
                    hello.push_str("250-STARTTLS\r\n");
                }
                hello.push_str("250 OK\r\n");
                write!(hello.as_bytes());
            }
            Command::Helo(name) => {
                (mail, route) = (None, None);
                helo = Some(name);
                write!(format!("250 {hostname}\r\n").as_bytes());
            }
            Command::StartTls => {
                if !tls_offered {
                    refuse!(NO_TLS);
                }
                // Anything already buffered would be read as if it came through TLS: the
                // STARTTLS command injection of CVE-2011-0411.
                if !reader.buffer().is_empty() {
                    write!(&send(&PIPELINED));
                    return Outcome::Closed;
                }
                write!(&send(&READY_FOR_TLS));
                return Outcome::StartTls(reader.into_inner());
            }
            Command::Mail { from, size } => {
                if helo.is_none() || mail.is_some() {
                    refuse!(BAD_SEQUENCE);
                }
                if size.is_some_and(|size| size > limits.max_message_bytes as u64) {
                    refuse!(TOO_LARGE);
                }
                if transactions >= limits.max_transactions {
                    write!(&send(&TOO_MANY_MESSAGES));
                    return Outcome::Closed;
                }
                transactions += 1;
                mail = Some(from);
                write!(&send(&crate::pipeline::OK));
            }
            Command::Rcpt(recipient) => {
                let Some(from) = &mail else {
                    refuse!(BAD_SEQUENCE);
                };
                if route.is_some() {
                    write!(&send(&TOO_MANY_RECIPIENTS));
                    continue;
                }
                match relay.route(from, &recipient).await {
                    Ok(found) => {
                        route = Some(found);
                        write!(&send(&crate::pipeline::OK));
                    }
                    Err(reply) if reply.code >= 500 => refuse!(reply),
                    Err(reply) => write!(&send(&reply)),
                }
            }
            Command::Data => {
                let (Some(found), Some(from)) = (route.take(), mail.take()) else {
                    refuse!(BAD_SEQUENCE);
                };
                write!(&send(&GO_AHEAD));
                let data = read_data(&mut reader, limits.max_message_bytes, limits.data_timeout);
                let reply = match data.await {
                    Data::Message(message) => {
                        let helo = helo.as_deref().unwrap_or_default();
                        relay.deliver(found, &message, ip, helo, &from).await
                    }
                    Data::TooLarge => TOO_LARGE,
                    Data::BareNewline => BARE_NEWLINE,
                    Data::Abandoned => {
                        write!(&send(&TOO_LARGE));
                        return Outcome::Closed;
                    }
                    Data::Closed => return Outcome::Closed,
                };
                write!(&send(&reply));
            }
            Command::Rset => {
                (mail, route) = (None, None);
                write!(&send(&crate::pipeline::OK));
            }
            Command::Noop => write!(&send(&crate::pipeline::OK)),
            Command::NotImplemented => refuse!(NOT_IMPLEMENTED),
            Command::Quit => {
                write!(&send(&CLOSING));
                return Outcome::Closed;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    async fn read(input: &[u8], max: usize) -> Data {
        let mut reader = BufReader::new(input);
        read_data(&mut reader, max, Duration::from_secs(5)).await
    }

    #[tokio::test]
    async fn undoes_dot_stuffing_and_stops_at_the_terminator() {
        assert_eq!(
            read(b"a\r\n..b\r\n.\r\nafter", 100).await,
            Data::Message(b"a\r\n.b\r\n".to_vec())
        );
        assert_eq!(read(b".\r\n", 100).await, Data::Message(vec![]));
    }

    #[tokio::test]
    async fn only_crlf_dot_crlf_ends_a_message() {
        for input in [
            &b"a\n.\r\nb\r\n.\r\n"[..],
            b"a\r.\r\nb\r\n.\r\n",
            b"a\r\n.\nb\r\n.\r\n",
            b"a\n.\nb\r\n.\r\n",
        ] {
            assert_eq!(read(input, 100).await, Data::BareNewline, "{input:?}");
        }
        assert_eq!(
            read(b"a\n.\r\n", 100).await,
            Data::Closed,
            "no real end yet"
        );
    }

    #[tokio::test]
    async fn size_is_enforced() {
        assert_eq!(read(b"12345678\r\n.\r\n", 4).await, Data::Abandoned);
        assert_eq!(read(b"123456\r\n.\r\n", 6).await, Data::TooLarge);
        assert_eq!(
            read(b"1234\r\n.\r\n", 6).await,
            Data::Message(b"1234\r\n".to_vec())
        );
        let long = [b"x".repeat(200_000), b"\r\n.\r\n".to_vec()].concat();
        assert_eq!(read(&long, 150_000).await, Data::TooLarge);
    }

    #[tokio::test]
    async fn an_over_long_command_is_dropped_whole() {
        let long = [b"x".repeat(5000), b"\r\nQUIT\r\n".to_vec()].concat();
        let mut reader = BufReader::new(&long[..]);
        let wait = Duration::from_secs(5);
        assert!(matches!(read_line(&mut reader, wait).await, Line::Bad));
        assert!(matches!(read_line(&mut reader, wait).await, Line::Text(t) if t == b"QUIT"));

        let endless = b"x".repeat(200_000);
        let mut reader = BufReader::new(&endless[..]);
        assert!(matches!(read_line(&mut reader, wait).await, Line::Closed));
    }

    #[tokio::test]
    async fn stops_when_the_client_goes_away() {
        assert_eq!(read(b"half a mess", 100).await, Data::Closed);
    }

    proptest! {
        /// A message survives stuffing, however it's cut into lines.
        #[test]
        fn stuffed_messages_round_trip(lines in proptest::collection::vec("[ -~]{0,120}", 0..40)) {
            let message: Vec<u8> = lines.iter().flat_map(|l| format!("{l}\r\n").into_bytes()).collect();
            let mut wire = Vec::new();
            for line in &lines {
                if line.starts_with('.') {
                    wire.push(b'.');
                }
                wire.extend_from_slice(line.as_bytes());
                wire.extend_from_slice(b"\r\n");
            }
            wire.extend_from_slice(b".\r\n");
            let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            let read = runtime.block_on(read(&wire, 1 << 20));
            prop_assert_eq!(read, Data::Message(message));
        }

        #[test]
        fn never_panics_on_bytes(input in proptest::collection::vec(any::<u8>(), 0..2000)) {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            let _ = runtime.block_on(read(&input, 1000));
        }
    }
}
