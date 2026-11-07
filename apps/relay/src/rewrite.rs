//! Rewriting headers so neither side learns the other's real address. Bodies pass untouched.
//!
//! Two different rules, on purpose. A forwarded message goes to the user, so its headers are kept
//! except the ones that would make the user's mail client write back around the relay. A reply
//! goes to a stranger, so it starts from nothing and only a short list of harmless headers
//! survives: anything a mail client or provider adds about the user is gone without having to be
//! known about.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// One header field, with its folding, CRLF included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field<'a> {
    pub name: &'a [u8],
    pub raw: &'a [u8],
}

impl Field<'_> {
    fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name.as_bytes())
    }

    /// The value, unfolded and trimmed.
    pub fn value(&self) -> String {
        let colon = self.raw.iter().position(|&b| b == b':').unwrap_or(0);
        let text = String::from_utf8_lossy(&self.raw[(colon + 1).min(self.raw.len())..]);
        text.replace("\r\n", "").trim().to_owned()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the header block isn't well formed")]
pub struct Malformed;

/// Splits a message into fields and the bytes after the blank line. A space before the colon is
/// old syntax that many parsers accept, so `From :` counts as `From`: treating it as anything
/// else would let a second From slip past the rewrite.
pub fn split(raw: &[u8]) -> Result<(Vec<Field<'_>>, &[u8]), Malformed> {
    let mut fields = Vec::new();
    let mut at = 0;
    loop {
        if at >= raw.len() {
            return Ok((fields, &[]));
        }
        if raw[at..].starts_with(b"\r\n") {
            return Ok((fields, &raw[at + 2..]));
        }
        let start = at;
        loop {
            let end = raw[at..]
                .windows(2)
                .position(|pair| pair == b"\r\n")
                .ok_or(Malformed)?;
            at += end + 2;
            if !matches!(raw.get(at), Some(b' ' | b'\t')) {
                break;
            }
        }
        let field = &raw[start..at];
        if matches!(field.first(), Some(b' ' | b'\t')) {
            return Err(Malformed);
        }
        let colon = field.iter().position(|&b| b == b':').ok_or(Malformed)?;
        let name = field[..colon].trim_ascii_end();
        if name.is_empty() || !name.iter().all(|b| (33..127).contains(b)) {
            return Err(Malformed);
        }
        fields.push(Field { name, raw: field });
    }
}

pub fn has_field(fields: &[Field<'_>], name: &str) -> bool {
    fields.iter().any(|field| field.is(name))
}

pub fn count_field(fields: &[Field<'_>], name: &str) -> usize {
    fields.iter().filter(|field| field.is(name)).count()
}

pub fn first_value(fields: &[Field<'_>], name: &str) -> Option<String> {
    fields.iter().find(|field| field.is(name)).map(Field::value)
}

/// `"Name" <address>`, with the name quoted or encoded, or only the address.
fn mailbox(name: Option<&str>, address: &str) -> String {
    match name.map(clean_name).filter(|name| !name.is_empty()) {
        Some(name) if name.is_ascii() => {
            format!(
                "\"{}\" <{address}>",
                name.replace('\\', "\\\\").replace('"', "\\\"")
            )
        }
        Some(name) => format!("=?UTF-8?B?{}?= <{address}>", STANDARD.encode(&name)),
        None => format!("<{address}>"),
    }
}

/// Short enough for one encoded word, with nothing that could end the header.
fn clean_name(name: &str) -> String {
    const MAX_BYTES: usize = 40;
    let mut out = String::new();
    for c in name.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_BYTES {
            break;
        }
        out.push(c);
    }
    out.trim().to_owned()
}

/// Headers that go nowhere on a forwarded message:
///
/// - the sender's identity and routing, replaced below (`From`, `Sender`, `Reply-To`, `To`, `Cc`)
/// - anything a mail client answers directly, which would send the user's real address to the
///   sender around the relay: read receipts and mailing-list `mailto:` links
/// - signatures that can't survive the rewrite, and results nobody here checked
/// - anything claiming to come from this relay
const DROPPED_ON_FORWARD: [&str; 26] = [
    "from",
    "sender",
    "reply-to",
    "to",
    "cc",
    "bcc",
    "return-path",
    "delivered-to",
    "dkim-signature",
    "authentication-results",
    "disposition-notification-to",
    "return-receipt-to",
    "read-receipt-to",
    "x-confirm-reading-to",
    "errors-to",
    "mail-reply-to",
    "mail-followup-to",
    "list-post",
    "list-owner",
    "list-help",
    "list-subscribe",
    "x-original-from",
    "x-original-to",
    "x-octapass-original-to",
    "x-octapass-original-cc",
    "x-octapass-loop",
];

/// The header that marks mail this relay already handled.
pub const LOOP_HEADER: &str = "X-OctaPass-Loop";

/// `List-Unsubscribe` with its `mailto:` links gone: unsubscribing by mail would come from the
/// user's real address. Web links are safe. `None` when nothing is left.
fn safe_unsubscribe(value: &str) -> Option<String> {
    let links: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|link| {
            let lower = link.to_ascii_lowercase();
            lower.starts_with("<https://") || lower.starts_with("<http://")
        })
        .collect();
    (!links.is_empty()).then(|| links.join(", "))
}

pub struct Forward<'a> {
    pub alias: &'a str,
    pub reverse: &'a str,
    pub sender: &'a str,
    pub sender_name: Option<&'a str>,
    pub domain: &'a str,
    /// The relay's own `Authentication-Results` header.
    pub results: &'a str,
}

pub fn forward(fields: &[Field<'_>], body: &[u8], forward: &Forward<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 1024);
    let line = |out: &mut Vec<u8>, text: String| {
        out.extend_from_slice(text.as_bytes());
        out.extend_from_slice(b"\r\n");
    };
    let shown = forward.sender_name.filter(|name| !name.trim().is_empty());
    let fallback = forward.sender.replacen('@', " at ", 1);
    out.extend_from_slice(forward.results.trim_end().as_bytes());
    out.extend_from_slice(b"\r\n");
    line(
        &mut out,
        format!(
            "From: {}",
            mailbox(Some(shown.unwrap_or(&fallback)), forward.reverse)
        ),
    );
    line(&mut out, format!("Reply-To: <{}>", forward.reverse));
    line(&mut out, format!("To: <{}>", forward.alias));
    line(&mut out, format!("X-Original-From: <{}>", forward.sender));
    line(&mut out, format!("{LOOP_HEADER}: {}", forward.domain));
    // Others on the message are kept for reading, under a name no client replies to, so Reply All
    // can't reach them from the user's real address.
    for (name, kept) in [
        ("to", "X-OctaPass-Original-To"),
        ("cc", "X-OctaPass-Original-Cc"),
    ] {
        for field in fields.iter().filter(|field| field.is(name)) {
            let value = field.value();
            if !value.eq_ignore_ascii_case(forward.alias)
                && value.to_ascii_lowercase() != format!("<{}>", forward.alias)
            {
                let colon = field.raw.iter().position(|&b| b == b':').unwrap_or(0);
                out.extend_from_slice(kept.as_bytes());
                out.extend_from_slice(&field.raw[colon..]);
            }
        }
    }
    for field in fields {
        let name = field.name.to_ascii_lowercase();
        if DROPPED_ON_FORWARD.iter().any(|d| d.as_bytes() == name) {
            continue;
        }
        if field.is("list-unsubscribe") {
            if let Some(links) = safe_unsubscribe(&field.value()) {
                line(&mut out, format!("List-Unsubscribe: {links}"));
            }
            continue;
        }
        if field.is("list-unsubscribe-post") && !unsubscribe_survives(fields) {
            continue;
        }
        out.extend_from_slice(field.raw);
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

fn unsubscribe_survives(fields: &[Field<'_>]) -> bool {
    first_value(fields, "list-unsubscribe").is_some_and(|value| safe_unsubscribe(&value).is_some())
}

/// All a reply keeps from what the user's mail client wrote.
const KEPT_ON_REPLY: [&str; 8] = [
    "subject",
    "in-reply-to",
    "references",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "content-disposition",
    "content-language",
];

pub struct Reply<'a> {
    pub alias: &'a str,
    pub to: &'a str,
    pub domain: &'a str,
    pub message_id: &'a str,
    /// The current time in RFC 5322 form. The user's `Date` shows their time zone.
    pub date: &'a str,
}

pub fn reply(fields: &[Field<'_>], body: &[u8], reply: &Reply<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 512);
    for text in [
        format!("From: <{}>", reply.alias),
        format!("To: <{}>", reply.to),
        format!("Date: {}", reply.date),
        format!("Message-ID: <{}@{}>", reply.message_id, reply.domain),
        format!("{LOOP_HEADER}: {}", reply.domain),
    ] {
        out.extend_from_slice(text.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    for field in fields {
        let name = field.name.to_ascii_lowercase();
        if KEPT_ON_REPLY.iter().any(|k| k.as_bytes() == name) {
            out.extend_from_slice(field.raw);
        }
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const MESSAGE: &[u8] = b"Received: from a by b; Mon, 1 Jan 2026 00:00:00 +0000\r\n\
        From : Jane Doe <jane@sender.example>\r\n\
        To: alias@relay.example,\r\n other@sender.example\r\n\
        Cc: friend@sender.example\r\n\
        Subject: Hello\r\n there\r\n\
        Reply-To: elsewhere@sender.example\r\n\
        DKIM-Signature: v=1; d=sender.example;\r\n b=abc\r\n\
        Authentication-Results: relay.example; dkim=pass (forged)\r\n\
        Disposition-Notification-To: jane@sender.example\r\n\
        List-Unsubscribe: <mailto:leave@sender.example>, <https://sender.example/leave>\r\n\
        List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\
        List-Post: <mailto:list@sender.example>\r\n\
        X-OctaPass-Original-Cc: forged\r\n\
        X-Mailer: Thing\r\n\
        \r\n\
        Body stays\r\n.dot\r\n";

    fn forwarded(message: &[u8]) -> Vec<u8> {
        let (fields, body) = split(message).unwrap();
        forward(
            &fields,
            body,
            &Forward {
                alias: "alias@relay.example",
                reverse: "r-x@relay.example",
                sender: "jane@sender.example",
                sender_name: Some("Jane Doe"),
                domain: "relay.example",
                results: "Authentication-Results: relay.example; dkim=none\r\n",
            },
        )
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn forwarding_keeps_the_real_address_out_of_every_reply_path() {
        let out = text(&forwarded(MESSAGE));
        assert!(
            out.contains("From: \"Jane Doe\" <r-x@relay.example>\r\n"),
            "{out}"
        );
        assert!(out.contains("Reply-To: <r-x@relay.example>\r\n"), "{out}");
        assert!(out.contains("To: <alias@relay.example>\r\n"), "{out}");
        assert!(
            out.contains("X-Original-From: <jane@sender.example>\r\n"),
            "{out}"
        );
        assert!(out.contains("X-OctaPass-Loop: relay.example\r\n"), "{out}");
        assert!(out.contains("Subject: Hello\r\n there\r\n"), "{out}");
        assert!(out.ends_with("Body stays\r\n.dot\r\n"), "{out}");
        for gone in [
            "elsewhere@",
            "DKIM-Signature",
            "dkim=pass",
            "Disposition-Notification-To",
            "mailto:",
            "List-Post",
            "forged",
            "From :",
        ] {
            assert!(!out.contains(gone), "{gone} in {out}");
        }
        // Reply All has nothing to reach; the addresses stay readable.
        let (fields, _) = split(out.as_bytes()).unwrap();
        assert_eq!(first_value(&fields, "cc"), None);
        assert_eq!(
            first_value(&fields, "x-octapass-original-cc").as_deref(),
            Some("friend@sender.example")
        );
        assert!(
            first_value(&fields, "x-octapass-original-to")
                .unwrap()
                .contains("other@sender.example")
        );
        assert_eq!(count_field(&fields, "from"), 1);
        assert_eq!(
            first_value(&fields, "list-unsubscribe").as_deref(),
            Some("<https://sender.example/leave>")
        );
        assert!(has_field(&fields, "list-unsubscribe-post"));
    }

    #[test]
    fn one_click_unsubscribe_goes_when_only_mailto_was_there() {
        let message = b"From: a@sender.example\r\n\
            List-Unsubscribe: <mailto:leave@sender.example>\r\n\
            List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\r\nx\r\n";
        let out = text(&forwarded(message));
        assert!(!out.contains("List-Unsubscribe"), "{out}");
    }

    #[test]
    fn names_are_quoted_or_encoded_and_can_not_break_the_header() {
        assert_eq!(
            mailbox(Some("Jane \"J\" D"), "a@b.example"),
            "\"Jane \\\"J\\\" D\" <a@b.example>"
        );
        assert_eq!(mailbox(None, "a@b.example"), "<a@b.example>");
        let injected = mailbox(Some("x\r\nBcc: evil@evil.example"), "a@b.example");
        assert_eq!(injected, "\"xBcc: evil@evil.example\" <a@b.example>");
        let arabic = mailbox(Some("سارة"), "a@b.example");
        assert!(arabic.starts_with("=?UTF-8?B?"), "{arabic}");
        // RFC 2047 allows an encoded word 75 characters.
        let long = mailbox(Some(&"ا".repeat(200)), "a@b.example");
        assert!(long.split(' ').next().unwrap().len() <= 75, "{long}");
    }

    #[test]
    fn a_reply_starts_from_nothing() {
        let message = b"Received: from laptop.home ([203.0.113.9]) by mail.example\r\n\
            From: Real Name <me@mail.example>\r\n\
            To: <r-x@relay.example>\r\n\
            Cc: someone@mail.example\r\n\
            Subject: Re: Hello\r\n\
            Date: Mon, 1 Jan 2026 10:00:00 +0300\r\n\
            Message-ID: <abc@laptop.home>\r\n\
            In-Reply-To: <orig@sender.example>\r\n\
            References: <orig@sender.example>\r\n\
            User-Agent: Thunderbird\r\n\
            X-Mailer: Thing\r\n\
            X-Originating-IP: [203.0.113.9]\r\n\
            DKIM-Signature: v=1; d=mail.example; b=abc\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\
            \r\n\
            Thanks!\r\n";
        let (fields, body) = split(message).unwrap();
        let out = text(&reply(
            &fields,
            body,
            &Reply {
                alias: "alias@relay.example",
                to: "jane@sender.example",
                domain: "relay.example",
                message_id: "xyz",
                date: "Mon, 01 Jan 2026 07:00:00 +0000",
            },
        ));
        assert!(
            out.starts_with("From: <alias@relay.example>\r\nTo: <jane@sender.example>\r\n"),
            "{out}"
        );
        assert!(out.contains("Subject: Re: Hello\r\n"), "{out}");
        assert!(
            out.contains("In-Reply-To: <orig@sender.example>\r\n"),
            "{out}"
        );
        assert!(out.contains("Message-ID: <xyz@relay.example>\r\n"), "{out}");
        assert!(
            out.contains("Date: Mon, 01 Jan 2026 07:00:00 +0000\r\n"),
            "{out}"
        );
        assert!(out.ends_with("\r\n\r\nThanks!\r\n"), "{out}");
        for gone in [
            "me@mail.example",
            "Real Name",
            "203.0.113.9",
            "laptop.home",
            "Thunderbird",
            "X-Mailer",
            "Received",
            "DKIM-Signature",
            "+0300",
            "someone@",
        ] {
            assert!(!out.contains(gone), "{gone} in {out}");
        }
    }

    #[test]
    fn refuses_headers_it_can_not_read() {
        for bad in [
            &b"no colon here\r\n\r\nbody"[..],
            b" starts folded\r\n\r\nbody",
            b": no name\r\n\r\nbody",
            b"Bad Name: value\r\n\r\nbody",
            b"From: a@b.example",
        ] {
            assert_eq!(split(bad).err(), Some(Malformed), "{}", text(bad));
        }
        let (fields, body) = split(b"A: b\r\n").unwrap();
        assert_eq!((fields.len(), body), (1, &b""[..]));
    }

    proptest! {
        #[test]
        fn split_never_panics(raw in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = split(&raw);
        }

        /// However a message spells its headers, what's forwarded has exactly one From, and it's ours.
        #[test]
        fn forwarding_always_ends_with_one_from(
            name in "(From|from|FROM|fRoM)( |\t){0,2}",
            value in "[ -~]{0,40}",
            fold in any::<bool>(),
        ) {
            let glue = if fold { "\r\n " } else { "" };
            let message = format!("{name}: {glue}{value}\r\nSubject: x\r\n{name}: {value}\r\n\r\nbody\r\n");
            let out = forwarded(message.as_bytes());
            let (fields, _) = split(&out).unwrap();
            prop_assert_eq!(count_field(&fields, "from"), 1);
            prop_assert!(first_value(&fields, "from").unwrap().contains("<r-x@relay.example>"));
        }
    }
}
