//! Reading what comes back to a return path: delivery status notifications (RFC 3464) and abuse
//! reports (RFC 5965). MIME is mail-parser's job; only the field lines inside the report parts are
//! read here. Nothing read from these messages is stored or passed on: the result is a class.

use mail_parser::MessageParser;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feedback {
    /// The mailbox doesn't exist or is gone.
    HardBounce,
    /// A temporary failure, a full mailbox, or a refusal that says nothing about the address.
    SoftBounce,
    Complaint,
    /// An automatic reply, a success notice or something unreadable. Counted as nothing.
    Other,
}

const MAX_PARTS: usize = 64;

fn field_lines(text: &str) -> impl Iterator<Item = (String, &str)> {
    text.lines().filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || name.starts_with([' ', '\t']) {
            return None;
        }
        Some((name.trim().to_ascii_lowercase(), value.trim()))
    })
}

/// Enhanced status codes (RFC 3463) say whether the address itself failed. A 5.7.x refusal is the
/// receiving system's policy, often about spam, and says nothing about the mailbox; counting those
/// as hard bounces would let a blocked sender switch off someone's forwarding.
fn class_of_status(status: &str) -> Feedback {
    let code = status.split_whitespace().next().unwrap_or("");
    let mut parts = code.split('.');
    let (Some(class), Some(subject), Some(detail)) = (parts.next(), parts.next(), parts.next())
    else {
        return Feedback::SoftBounce;
    };
    let digits = |s: &str| !s.is_empty() && s.len() <= 3 && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(class) || !digits(subject) || !digits(detail) || parts.next().is_some() {
        return Feedback::SoftBounce;
    }
    match (class, subject, detail) {
        ("5", "7" | "3" | "6", _) | ("5", "2", "2" | "3") => Feedback::SoftBounce,
        ("5", _, _) => Feedback::HardBounce,
        _ => Feedback::SoftBounce,
    }
}

fn read_delivery_status(text: &str) -> Feedback {
    let mut worst = Feedback::Other;
    let mut action: Option<String> = None;
    let mut status: Option<String> = None;
    let mut settle = |action: &mut Option<String>, status: &mut Option<String>| {
        if let Some(action) = action.take() {
            let class = match action.to_ascii_lowercase().as_str() {
                "failed" => status
                    .as_deref()
                    .map_or(Feedback::SoftBounce, class_of_status),
                "delayed" => Feedback::SoftBounce,
                _ => Feedback::Other,
            };
            worst = match (worst, class) {
                (Feedback::HardBounce, _) | (_, Feedback::HardBounce) => Feedback::HardBounce,
                (Feedback::SoftBounce, _) | (_, Feedback::SoftBounce) => Feedback::SoftBounce,
                _ => Feedback::Other,
            };
        }
        *status = None;
    };
    for line in text.lines() {
        // Per-recipient groups are separated by blank lines.
        if line.trim().is_empty() {
            settle(&mut action, &mut status);
            continue;
        }
        if let Some((name, value)) = field_lines(line).next() {
            match name.as_str() {
                "action" => action = Some(value.to_owned()),
                "status" => status = Some(value.to_owned()),
                _ => {}
            }
        }
    }
    settle(&mut action, &mut status);
    worst
}

fn is_report_type(text: &str) -> bool {
    field_lines(text).any(|(name, _)| name == "feedback-type")
}

/// Sorts a message that arrived at a return path.
pub fn classify(raw: &[u8]) -> Feedback {
    let Some(message) = MessageParser::default().parse(raw) else {
        return Feedback::Other;
    };
    for part in message.parts().take(MAX_PARTS) {
        let text = || String::from_utf8_lossy(&part.decoded()).into_owned();
        if part.is_content_type("message", "delivery-status")
            || part.is_content_type("message", "global-delivery-status")
        {
            return read_delivery_status(&text());
        }
        if part.is_content_type("message", "feedback-report") && is_report_type(&text()) {
            return Feedback::Complaint;
        }
    }
    Feedback::Other
}

/// The signed return path an abuse report names, for reports sent to `abuse@` rather than to the
/// return path. Feedback loops keep it in `Original-Mail-From` or in the quoted message.
pub fn reported_return_path(raw: &[u8], domain: &str) -> Option<String> {
    let text = String::from_utf8_lossy(raw).to_ascii_lowercase();
    let suffix = format!("@{domain}");
    let mut rest = text.as_str();
    while let Some(at) = rest.find("srs0=") {
        let tail = &rest[at..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || "=-.@".contains(c)))
            .unwrap_or(tail.len());
        if let Some(local) = tail[..end].strip_suffix(&suffix) {
            return Some(local.to_owned());
        }
        rest = &tail[5..];
    }
    None
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn dsn(fields: &str) -> Vec<u8> {
        format!(
            "From: MAILER-DAEMON@mx.example\r\n\
             To: srs0=x@relay.example\r\n\
             Subject: Undelivered Mail\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/report; report-type=delivery-status; boundary=\"b\"\r\n\
             \r\n\
             --b\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             I couldn't deliver this. Status: 5.1.1 Action: failed in prose doesn't count.\r\n\
             --b\r\n\
             Content-Type: message/delivery-status\r\n\
             \r\n\
             Reporting-MTA: dns; mx.example\r\n\
             \r\n\
             {fields}\r\n\
             --b\r\n\
             Content-Type: message/rfc822\r\n\
             \r\n\
             Subject: the original\r\n\
             \r\n\
             body\r\n\
             --b--\r\n"
        )
        .into_bytes()
    }

    fn recipient(action: &str, status: &str) -> String {
        format!(
            "Final-Recipient: rfc822; user@mail.example\r\nAction: {action}\r\nStatus: {status}\r\n"
        )
    }

    #[test]
    fn sorts_delivery_reports_by_their_status() {
        for (action, status, class) in [
            ("failed", "5.1.1", Feedback::HardBounce),
            ("failed", "5.1.10 (no such user)", Feedback::HardBounce),
            ("failed", "5.0.0", Feedback::HardBounce),
            ("failed", "5.2.1", Feedback::HardBounce),
            ("failed", "5.2.2", Feedback::SoftBounce),
            ("failed", "5.7.1", Feedback::SoftBounce),
            ("failed", "4.4.7", Feedback::SoftBounce),
            ("delayed", "4.4.1", Feedback::SoftBounce),
            ("delivered", "2.0.0", Feedback::Other),
            ("relayed", "2.0.0", Feedback::Other),
            ("failed", "nonsense", Feedback::SoftBounce),
            ("FAILED", "5.1.1", Feedback::HardBounce),
        ] {
            assert_eq!(
                classify(&dsn(&recipient(action, status))),
                class,
                "{action} {status}"
            );
        }
    }

    #[test]
    fn several_recipients_count_as_the_worst() {
        let two = format!(
            "{}\r\n{}",
            recipient("delayed", "4.0.0"),
            recipient("failed", "5.1.1")
        );
        assert_eq!(classify(&dsn(&two)), Feedback::HardBounce);
    }

    #[test]
    fn an_abuse_report_is_a_complaint() {
        let report = b"From: fbl@mail.example\r\n\
            Subject: Abuse report\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: multipart/report; report-type=feedback-report; boundary=\"b\"\r\n\
            \r\n\
            --b\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            This is an email abuse report.\r\n\
            --b\r\n\
            Content-Type: message/feedback-report\r\n\
            \r\n\
            Feedback-Type: abuse\r\n\
            User-Agent: SomeGenerator/1.0\r\n\
            Version: 1\r\n\
            Original-Mail-From: <srs0=abc=de=f=abcdefghijkl@relay.example>\r\n\
            \r\n\
            --b\r\n\
            Content-Type: message/rfc822\r\n\
            \r\n\
            Subject: the original\r\n\
            \r\n\
            body\r\n\
            --b--\r\n";
        assert_eq!(classify(report), Feedback::Complaint);
        assert_eq!(
            reported_return_path(report, "relay.example").as_deref(),
            Some("srs0=abc=de=f=abcdefghijkl")
        );
        assert_eq!(reported_return_path(report, "other.example"), None);
    }

    #[test]
    fn plain_mail_is_nothing() {
        let vacation = b"From: a@mail.example\r\nSubject: Out of office\r\n\r\nAction: failed\r\nStatus: 5.1.1\r\n";
        assert_eq!(classify(vacation), Feedback::Other);
        assert_eq!(classify(b""), Feedback::Other);
    }

    proptest! {
        #[test]
        fn never_panics_on_bytes(raw in proptest::collection::vec(any::<u8>(), 0..2000)) {
            let _ = classify(&raw);
            let _ = reported_return_path(&raw, "relay.example");
        }

        #[test]
        fn never_panics_on_fields(fields in "[ -~\r\n]{0,400}") {
            let _ = classify(&dsn(&fields));
        }

        #[test]
        fn status_codes_never_panic(status in "\\PC{0,40}") {
            let _ = class_of_status(&status);
        }
    }
}
