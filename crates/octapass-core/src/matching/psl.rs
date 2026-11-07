//! Public Suffix List lookups over an embedded copy of the list.
//!
//! The list is kept as data and indexed on first use, instead of compiled into code: in the
//! browser's WASM module that is about 160 KB of text rather than several hundred KB of generated
//! functions.

use std::collections::HashSet;
use std::sync::OnceLock;

const LIST: &str = include_str!("../../data/public_suffix_list.dat");

struct Rules {
    /// Normal rules (`com`, `github.io`), and wildcard rules without their `*.` (`ck` for `*.ck`).
    exact: HashSet<String>,
    wildcard: HashSet<String>,
    /// Exception rules without their `!` (`www.ck`).
    exception: HashSet<String>,
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut rules = Rules {
            exact: HashSet::new(),
            wildcard: HashSet::new(),
            exception: HashSet::new(),
        };
        for line in LIST.lines() {
            let Some(rule) = line.split_whitespace().next() else {
                continue;
            };
            if rule.starts_with("//") {
                continue;
            }
            let (set, name) = if let Some(name) = rule.strip_prefix("*.") {
                (&mut rules.wildcard, name)
            } else if let Some(name) = rule.strip_prefix('!') {
                (&mut rules.exception, name)
            } else {
                (&mut rules.exact, rule)
            };
            // Hosts reach us in their ASCII (punycode) form, so internationalized rules are too.
            let name = if name.is_ascii() {
                name.to_string()
            } else {
                match idna::domain_to_ascii(name) {
                    Ok(ascii) => ascii,
                    Err(_) => continue,
                }
            };
            set.insert(name);
        }
        rules
    })
}

/// How many trailing labels of `labels` form the public suffix, by the list's algorithm: the
/// longest matching rule wins, exception rules beat everything, and an unlisted TLD is a suffix.
fn suffix_len(labels: &[&str]) -> usize {
    let rules = rules();
    for start in 0..labels.len() {
        let name = labels[start..].join(".");
        if rules.exception.contains(&name) {
            return labels.len() - start - 1;
        }
        // A wildcard here covers one more label than a normal rule here, so it's checked first.
        if start > 0 && rules.wildcard.contains(&name) {
            return labels.len() - start + 1;
        }
        if rules.exact.contains(&name) {
            return labels.len() - start;
        }
    }
    1
}

/// The registrable domain (public suffix plus one label) of a lowercase ASCII host, or `None`
/// when the host is itself a public suffix.
pub fn domain(host: &str) -> Option<&str> {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.iter().any(|label| label.is_empty()) {
        return None;
    }
    let keep = suffix_len(&labels) + 1;
    if keep > labels.len() {
        return None;
    }
    let skipped: usize = labels[..labels.len() - keep]
        .iter()
        .map(|label| label.len() + 1)
        .sum();
    Some(&host[skipped..])
}

#[cfg(test)]
mod tests {
    use super::domain;

    #[test]
    fn follows_the_list() {
        assert_eq!(domain("accounts.google.com"), Some("google.com"));
        assert_eq!(domain("google.com"), Some("google.com"));
        assert_eq!(domain("com"), None);
        assert_eq!(domain("www.bbc.co.uk"), Some("bbc.co.uk"));
        assert_eq!(domain("co.uk"), None);
        assert_eq!(domain("alice.github.io"), Some("alice.github.io"));
        assert_eq!(domain("github.io"), None);
        // Wildcard and exception rules: `*.ck` and `!www.ck`.
        assert_eq!(domain("a.b.ck"), Some("a.b.ck"));
        assert_eq!(domain("b.ck"), None);
        assert_eq!(domain("www.ck"), Some("www.ck"));
        assert_eq!(domain("x.www.ck"), Some("www.ck"));
        // An unlisted TLD counts as a suffix.
        assert_eq!(
            domain("shop.example.notarealtld"),
            Some("example.notarealtld")
        );
        // Internationalized rules match punycode hosts: 公司.cn.
        assert_eq!(domain("shop.xn--55qx5d.cn"), Some("shop.xn--55qx5d.cn"));
        assert_eq!(domain("a..com"), None);
    }

    /// Same answers as the `psl` crate, whose list snapshot this module embeds, except where that
    /// crate gets nested wildcards wrong: with `*.run.app`, `mtls.run.app` is itself a public suffix
    /// (no registrable domain), but `psl` answers `run.app`.
    #[test]
    fn matches_the_psl_crate() {
        let list = include_str!("../../data/public_suffix_list.dat");
        let mut hosts = vec![];
        for rule in list
            .lines()
            .filter(|line| !line.starts_with("//") && line.is_ascii())
        {
            let rule = rule.trim_start_matches(['*', '.', '!']);
            for prefix in ["", "a.", "x.a.", "www.", "y.www."] {
                hosts.push(format!("{prefix}{rule}"));
            }
        }
        hosts.extend(
            [
                "localhost",
                "example.notarealtld",
                "a.b.c.example.notarealtld",
            ]
            .map(String::from),
        );
        assert!(hosts.len() > 40_000);
        let mut psl_wrong = 0;
        for host in &hosts {
            if domain(host) == psl::domain_str(host) {
                continue;
            }
            let parent = host.split_once('.').unwrap().1;
            assert!(
                domain(host).is_none() && list.lines().any(|rule| rule == format!("*.{parent}")),
                "{host}"
            );
            psl_wrong += 1;
        }
        assert!(psl_wrong < 50);
    }
}
