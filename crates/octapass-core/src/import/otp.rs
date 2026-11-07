//! Authenticator exports: `otpauth://` links and Google Authenticator `otpauth-migration://`
//! links, one per line (what QR scanners and most authenticators can export).
//!
//! Each one-time code joins a login already in the vault when the issuer matches the login's
//! title or domain (and, if several do, the account name matches the username). Otherwise it
//! becomes a new login.

use serde::Deserialize;

use super::build::{Collector, LoginFields};
use super::{ImportResult, TotpUpdate};
use crate::matching::Site;
use crate::tools::otpauth::{OtpParams, parse_migration};

/// A login in the vault, as the caller knows it from the overview (plus the username from the
/// details, when it has them). `subtitle` stands in for the username otherwise.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExistingLogin {
    pub id: String,
    pub title: String,
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub subtitle: Option<String>,
    /// Logins that already have a one-time code are never changed.
    pub has_totp: bool,
    /// That code (an `otpauth://` link or a bare secret), so importing a backup again recognises
    /// the codes that are already in the vault instead of adding them twice.
    pub totp: Option<String>,
}

pub(super) fn parse(text: &str, existing: &[ExistingLogin]) -> ImportResult {
    let mut out = Collector::default();
    let mut taken: Vec<&str> = Vec::new();
    for (number, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l.trim())) {
        if line.is_empty() {
            continue;
        }
        let parsed = if line.to_ascii_lowercase().starts_with("otpauth-migration:") {
            parse_migration(line)
        } else {
            OtpParams::parse(line).and_then(|params| {
                line.to_ascii_lowercase()
                    .starts_with("otpauth://")
                    .then(|| vec![params])
                    .ok_or(crate::Error::InvalidTotp)
            })
        };
        let Ok(accounts) = parsed else {
            out.skip(Some(format!(
                "Line {number} skipped: not an otpauth:// link."
            )));
            continue;
        };
        for params in accounts {
            add(&params, existing, &mut taken, &mut out);
        }
    }
    out.finish()
}

fn add<'a>(
    params: &OtpParams,
    existing: &'a [ExistingLogin],
    taken: &mut Vec<&'a str>,
    out: &mut Collector,
) {
    let uri = params.to_uri();
    let label = params
        .issuer
        .clone()
        .or_else(|| params.account.clone())
        .unwrap_or_else(|| "One-time code".into());
    if let Some(login) = find_login(params, existing, taken) {
        taken.push(&login.id);
        let update = TotpUpdate {
            item_id: login.id.clone(),
            totp: uri.to_string(),
        };
        out.attach_code(update, params, label);
        return;
    }
    let fields = LoginFields {
        title: Some(label),
        username: params.account.clone(),
        totp: Some(uri.to_string()),
        ..LoginFields::default()
    };
    out.add_code(fields, params);
}

pub(super) fn find_login<'a>(
    params: &OtpParams,
    existing: &'a [ExistingLogin],
    taken: &[&str],
) -> Option<&'a ExistingLogin> {
    let issuer = params.issuer.as_deref()?;
    let issuer_key = key(issuer);
    // An issuer written as a domain ("github.com") compares by registrable domain.
    let issuer_domain = Site::parse(issuer).ok().and_then(|site| site.domain);
    if issuer_key.is_empty() {
        return None;
    }
    let matches_issuer = |login: &ExistingLogin| {
        key(&login.title) == issuer_key
            || login
                .urls
                .iter()
                .filter_map(|url| Site::parse(url).ok()?.domain)
                .any(|domain| {
                    issuer_domain.as_deref() == Some(&domain)
                        || domain
                            .split('.')
                            .next()
                            .is_some_and(|label| key(label) == issuer_key)
                })
    };
    let candidates = existing.iter().filter(|login| {
        !login.has_totp && !taken.contains(&login.id.as_str()) && matches_issuer(login)
    });
    // A login whose username is the code's account wins; one with another username never joins.
    let account = params.account.as_deref().map(|a| a.trim().to_lowercase());
    let (same, unknown): (Vec<&ExistingLogin>, Vec<&ExistingLogin>) = candidates
        .filter(|login| {
            let name = login.username.as_deref().or(login.subtitle.as_deref());
            match (name, &account) {
                (Some(name), Some(account)) => name.trim().to_lowercase() == *account,
                _ => true,
            }
        })
        .partition(|login| {
            account.is_some()
                && login
                    .username
                    .as_deref()
                    .or(login.subtitle.as_deref())
                    .is_some()
        });
    match (same.as_slice(), unknown.as_slice()) {
        ([only], _) | ([], [only]) => Some(only),
        _ => None,
    }
}

/// Lower-case letters and digits only: "Amazon Web Services" and "amazonwebservices" agree.
fn key(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::ItemDetails;

    const SECRET: &str = "JBSWY3DPEHPK3PXP";

    fn login(id: &str, title: &str, urls: &[&str], username: Option<&str>) -> ExistingLogin {
        ExistingLogin {
            id: id.into(),
            title: title.into(),
            urls: urls.iter().map(|u| u.to_string()).collect(),
            username: username.map(str::to_string),
            ..ExistingLogin::default()
        }
    }

    fn link(issuer: &str, account: &str) -> String {
        format!("otpauth://totp/{issuer}:{account}?secret={SECRET}&issuer={issuer}")
    }

    #[test]
    fn attaches_to_matching_logins_or_creates_new_ones() {
        let mut existing = [
            login(
                "gh",
                "My code host",
                &["https://github.com/login"],
                Some("octo"),
            ),
            login("aws1", "Amazon Web Services", &[], Some("root@example.com")),
            login("aws2", "AmazonWebServices", &[], Some("dev@example.com")),
            login("done", "Example", &["https://example.com"], None),
        ];
        existing[3].has_totp = true;
        let text = [
            link("GitHub", "octo"),
            link("AmazonWebServices", "dev@example.com"),
            link("Example", "me"),
            "not a link".into(),
            "".into(),
        ]
        .join("\n");
        let result = parse(&text, &existing);
        let attached: Vec<&str> = result
            .totp_updates
            .iter()
            .map(|u| u.item_id.as_str())
            .collect();
        assert_eq!(attached, ["gh", "aws2"]);
        assert!(
            result.totp_updates[0]
                .totp
                .starts_with("otpauth://totp/GitHub:octo?secret=")
        );
        assert_eq!(
            result.items.len(),
            1,
            "Example already has a code, so a new login is made"
        );
        assert_eq!(result.items[0].overview.title, "Example");
        let ItemDetails::Login(details) = &result.items[0].details else {
            panic!()
        };
        assert_eq!(details.username.as_deref(), Some("me"));
        assert_eq!(result.skipped, 1);
        assert_eq!(result.warnings, ["Line 4 skipped: not an otpauth:// link."]);
    }

    #[test]
    fn ambiguous_matches_make_new_logins() {
        let existing = [
            login("a", "Bank", &[], Some("x")),
            login("b", "Bank", &[], Some("y")),
        ];
        let result = parse(&link("Bank", "z"), &existing);
        assert!(result.totp_updates.is_empty());
        assert_eq!(result.items.len(), 1);
        // The same login never gets two codes from one import.
        let result = parse(
            &[link("Bank", "x"), link("Bank", "x")].join("\n"),
            &existing,
        );
        assert_eq!(result.totp_updates.len(), 1);
        assert_eq!(result.items.len(), 1);
    }

    #[test]
    fn domain_issuers_match_by_registrable_domain() {
        let existing = [login(
            "m",
            "Mail",
            &["https://accounts.example.co.uk"],
            None,
        )];
        let result = parse(&link("login.example.co.uk", "me"), &existing);
        assert_eq!(result.totp_updates.len(), 1);
    }

    #[test]
    fn google_authenticator_exports_and_hotp() {
        // One TOTP ("ACME") and one HOTP ("bob"), built like the tools::otpauth test payload.
        let payload = "otpauth-migration://offline?data=Ci8KCkhlbGxvId6tvu8SFUFDTUU6amFuZUBleGFtcGxlLmNvbRoEQUNNRSABKAEwAgojChQxMjM0NTY3ODkwMTIzNDU2Nzg5MBIDYm9iIAIoAjABOAkQARgB";
        let result = parse(payload, &[]);
        assert_eq!(result.items.len(), 2);
        let ItemDetails::Login(acme) = &result.items[0].details else {
            panic!()
        };
        assert!(acme.totp.as_deref().unwrap().contains("issuer=ACME"));
        let ItemDetails::Login(bob) = &result.items[1].details else {
            panic!()
        };
        assert!(bob.totp.as_deref().unwrap().starts_with("otpauth://hotp/"));
        assert!(bob.custom_fields.is_none());
        assert!(result.warnings.is_empty());
    }
}
