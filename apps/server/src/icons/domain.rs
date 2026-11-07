//! Which names the icon proxy fetches for: a public DNS name, nothing else.

/// Names that never resolve on the public internet (RFC 6761, RFC 6762, RFC 8375 and friends).
const SPECIAL_USE: [&str; 9] = [
    "localhost",
    "local",
    "internal",
    "home.arpa",
    "lan",
    "test",
    "example",
    "invalid",
    "onion",
];

/// A registrable domain or host as clients send it, lowercased and in ASCII (punycode), or `None`
/// when it isn't one: IP addresses, single labels, special-use names, paths, user info and ports
/// other than the defaults are refused.
pub fn normalise(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 300 {
        return None;
    }
    let host = match raw.rsplit_once(':') {
        Some((host, "443" | "80")) => host,
        Some(_) => return None,
        None => raw,
    };
    if host.contains(['/', '\\', '@', '?', '#', '%', '[', ']']) {
        return None;
    }
    let host = match url::Host::parse(host).ok()? {
        url::Host::Domain(domain) => domain,
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => return None,
    };
    let host = host.trim_end_matches('.').to_owned();
    if host.len() > 253 {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 || !labels.iter().all(|label| is_label(label)) {
        return None;
    }
    // A numeric last label is an IPv4 address in disguise (`127.1`) or not a name at all.
    if labels.last()?.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let special = SPECIAL_USE
        .iter()
        .any(|name| host == *name || host.ends_with(&format!(".{name}")));
    (!special).then_some(host)
}

fn is_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

#[cfg(test)]
mod tests {
    use super::normalise;

    #[test]
    fn accepts_domains_and_hosts() {
        assert_eq!(normalise("example.com").as_deref(), Some("example.com"));
        assert_eq!(normalise(" Example.COM. ").as_deref(), Some("example.com"));
        assert_eq!(
            normalise("login.bank.co.uk").as_deref(),
            Some("login.bank.co.uk")
        );
        assert_eq!(normalise("example.com:443").as_deref(), Some("example.com"));
        assert_eq!(normalise("example.com:80").as_deref(), Some("example.com"));
        assert_eq!(
            normalise("bücher.de").as_deref(),
            Some("xn--bcher-kva.de"),
            "international names become punycode"
        );
        assert_eq!(normalise("a-b.example").as_deref(), None);
        assert_eq!(normalise("a-b.io").as_deref(), Some("a-b.io"));
    }

    #[test]
    fn refuses_everything_else() {
        for raw in [
            "",
            "com",
            "localhost",
            "printer.local",
            "app.localhost",
            "router.home.arpa",
            "nas.lan",
            "site.test",
            "corp.internal",
            "127.0.0.1",
            "127.1",
            "0x7f.1",
            "[::1]",
            "::1",
            "2130706433",
            "example.com:8080",
            "example.com/favicon.ico",
            "example.com?x",
            "user@example.com",
            "example..com",
            "-bad.com",
            "bad-.com",
            "exa mple.com",
            "example.com%2f..",
            "under_score.com",
            &format!("{}.com", "a".repeat(64)),
            &format!("{}com", "abc.".repeat(70)),
        ] {
            assert_eq!(normalise(raw), None, "{raw:?}");
        }
    }
}
