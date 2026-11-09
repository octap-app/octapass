//! The security dashboard: the web vault's `buildHealthReport` and recovery map
//! (`packages/vault-client/src/tools/health.ts` and `recovery.ts`) over the mobile vault's
//! health inputs, which replace each password by its group's strength and breach count, so no
//! password leaves the vault crate. The sites known to offer two-step sign-in or passkeys are the
//! signed lists of `octapass_core::health_data`: the bundled ones, or a newer file from the server.

use std::collections::{BTreeSet, HashMap, HashSet};

use octapass_core::health_data::{self, HealthData};

use octapass_mobile_vault::health::{HealthExpiry, HealthInputs, HealthLogin, HealthSettings};
use octapass_mobile_vault::model::{Item as StoredItem, ItemDraft as StoredDraft};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime};

use crate::api::{Method, Server};
use crate::error::Result;
use crate::items::is_valid_email;
use crate::list::compare_names;
use crate::vault::Ctx;

const WEAK_SCORE: u8 = 2;
// How much each problem scales an item's health; a breached password zeroes it.
const PENALTY_VERY_WEAK: f64 = 0.3;
const PENALTY_WEAK: f64 = 0.6;
const PENALTY_REUSED: f64 = 0.5;
const PENALTY_MISSING_2FA: f64 = 0.85;
const PENALTY_INSECURE_URL: f64 = 0.85;
/// A password this old is listed. A reminder, not a rule: a strong, unique password doesn't wear out.
const OLD_PASSWORD_DAYS: i64 = 365;
const EXPIRY_WARNING_DAYS: i64 = 60;
const LOW_BACKUP_CODES: u32 = 2;
/// How often the app asks about email breaches by itself; "Check again" asks at once.
const EMAIL_BREACH_CHECK_HOURS: i64 = 24;
const MAX_EMAIL_BREACH_ADDRESSES: usize = 50;
const SETTINGS_TITLE: &str = "Health settings";
/// The newest signed site lists this phone accepted, in the data folder.
const HEALTH_DATA_FILE: &str = "health-data.json";

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HealthEntry {
    pub item_id: String,
    pub vault_id: String,
    pub title: String,
    pub subtitle: Option<String>,
    /// Identifies this warning for `dismiss_health_warnings`; none on lists that aren't warnings.
    pub warning: Option<String>,
    /// The site's `/.well-known/change-password`, on warnings a new password fixes.
    pub change_password_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WeakPassword {
    pub entry: HealthEntry,
    /// 0–2.
    pub score: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BreachedPassword {
    pub entry: HealthEntry,
    /// Times the password appears in Pwned Passwords.
    pub count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RecoveryKind {
    Email,
    Phone,
}

/// An email account's own login, when the vault has it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecoveryAccount {
    pub entry: HealthEntry,
    pub two_step: bool,
}

/// An email or phone that can reset other logins.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecoveryContact {
    pub kind: RecoveryKind,
    /// As the first login that uses it wrote it.
    pub value: String,
    /// Never empty.
    pub logins: Vec<HealthEntry>,
    pub account: Option<RecoveryAccount>,
    /// A login links it to a masked email alias from this provider.
    pub alias_provider: Option<String>,
    /// The provider's id for that alias.
    pub alias_id: Option<String>,
    /// A login links it to this Identity item.
    pub identity_id: Option<String>,
}

/// A recovery email whose own login has no two-step sign-in: whoever gets into that inbox can
/// reset `accounts` logins.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnprotectedRecoveryEmail {
    pub entry: HealthEntry,
    pub email: String,
    pub accounts: u32,
}

/// A recovery email that email breach alerts found in a breach: whoever gets into that inbox can
/// reset `accounts` logins. The entry is the inbox's own login when the vault has it; otherwise
/// its item id is empty and its title is the address.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BreachedRecoveryEmail {
    pub entry: HealthEntry,
    pub email: String,
    pub accounts: u32,
    /// The breaches' titles, sorted.
    pub breaches: Vec<String>,
}

/// A password not changed for a year.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OldPassword {
    pub entry: HealthEntry,
    pub changed_at: String,
    pub age_days: u32,
}

/// A login with an `http://` website, other than this device or the local network.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct InsecureLogin {
    pub entry: HealthEntry,
    pub url: String,
}

/// A card, ID, passport, software licence or API credential that expired or expires within 60 days.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ExpiringItem {
    pub entry: HealthEntry,
    /// `YYYY-MM-DD`.
    pub expires_on: String,
    /// Negative once expired.
    pub days_left: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LowBackupCodes {
    pub entry: HealthEntry,
    pub unused: u32,
}

/// The account email or an alias, found in a breach by Have I Been Pwned.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EmailBreachFinding {
    pub address: String,
    pub name: String,
    pub title: String,
    pub domain: Option<String>,
    /// `YYYY-MM-DD`.
    pub breach_date: Option<String>,
    pub data_classes: Vec<String>,
    pub warning: String,
    /// Appeared since the check before the last one.
    pub is_new: bool,
}

/// A warning the user dismissed.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DismissedWarning {
    pub entry: HealthEntry,
    pub warning: String,
    /// `weak`, `reused`, `breached`, `old`, `missing2fa`, `passkeyAvailable`, `insecureUrl`,
    /// `expiring`, `backupCodes`, `recoveryNo2fa`, `recoveryBreached` or `emailBreach`.
    pub check: String,
}

/// What `check_email_breaches` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EmailBreachCheck {
    /// Alerts are off: nothing was sent.
    Off,
    /// Checked less than a day ago: nothing was sent.
    NotDue,
    Checked,
    /// A lookup failed; the last results stay.
    Failed,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct HealthReport {
    /// 0–100.
    pub score: u32,
    /// Logins that have a password.
    pub checked: u32,
    pub weak: Vec<WeakPassword>,
    /// Each group shares one password, the largest first.
    pub reused: Vec<Vec<HealthEntry>>,
    pub breached: Vec<BreachedPassword>,
    /// False when Pwned Passwords couldn't be reached; `breached` is then empty.
    pub breach_check_completed: bool,
    /// Logins for sites known to offer two-step sign-in, without a code or passkey saved.
    pub missing_2fa: Vec<HealthEntry>,
    /// The recovery map, the most used first.
    pub recovery: Vec<RecoveryContact>,
    pub recovery_no_2fa: Vec<UnprotectedRecoveryEmail>,
    /// Recovery emails found in a breach, the most used first. Not part of the score.
    pub recovery_breached: Vec<BreachedRecoveryEmail>,
    /// Passwords not changed for a year, the oldest first. Not part of the score.
    pub old: Vec<OldPassword>,
    /// Logins for sites that accept passkeys, without one saved. Not part of the score.
    pub passkey_available: Vec<HealthEntry>,
    pub insecure_urls: Vec<InsecureLogin>,
    /// The soonest first. Not part of the score.
    pub expiring: Vec<ExpiringItem>,
    /// Logins with saved backup codes and two or fewer unused. Not part of the score.
    pub low_backup_codes: Vec<LowBackupCodes>,
    /// Email breach alerts are on. Off by default.
    pub email_alerts_enabled: bool,
    /// The second opt-in: recovery emails that are neither the account email nor an alias are
    /// looked up too. Off by default, and off whenever alerts are.
    pub email_alerts_recovery_emails: bool,
    pub email_breaches_checked_at: Option<String>,
    pub email_breaches: Vec<EmailBreachFinding>,
    /// Left out of the lists above and of the score.
    pub dismissed: Vec<DismissedWarning>,
    pub generated_at: String,
}

/// The bundled registrable domains that offer authenticator codes or passkeys.
#[cfg(test)]
fn two_factor_domains() -> &'static BTreeSet<String> {
    &health_data::bundled().two_factor_domains
}

/// The bundled passkeys directory snapshot.
#[cfg(test)]
fn passkey_domains() -> &'static BTreeSet<String> {
    &health_data::bundled().passkey_domains
}

/// The URL of a website login, tolerating a missing scheme. Only `http` and `https`.
fn web_url(url: &str) -> Option<url::Url> {
    let text = url.trim();
    if text.is_empty() || text.chars().any(char::is_whitespace) {
        return None;
    }
    if let Some((scheme, rest)) = text.split_once(':')
        && is_scheme(scheme)
        && !rest.starts_with("//")
        && !rest.starts_with(|c: char| c.is_ascii_digit())
    {
        return None;
    }
    let with_scheme = match text.split_once("://") {
        Some((scheme, _)) if is_scheme(scheme) => text.to_owned(),
        _ => format!("https://{text}"),
    };
    url::Url::parse(&with_scheme)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"))
}

/// This device or the local network, where a site can't get a public certificate.
pub(crate) fn is_local_host(hostname: &str) -> bool {
    let host = hostname.trim().to_lowercase();
    let host = host.trim_end_matches('.').trim_matches(['[', ']']);
    if host == "localhost"
        || [".localhost", ".local", ".lan", ".home.arpa"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
    {
        return true;
    }
    if !host.contains('.') && !host.contains(':') {
        return true;
    }
    if host.contains(':') {
        return host == "::1"
            || host.starts_with("fc")
            || host.starts_with("fd")
            || ["fe8", "fe9", "fea", "feb"]
                .iter()
                .any(|prefix| host.starts_with(prefix));
    }
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

/// The first `http://` website in a login's URLs, unless it's on this device or the local network.
fn insecure_url<'a>(urls: &[&'a str]) -> Option<&'a str> {
    urls.iter().copied().find(|url| {
        web_url(url).is_some_and(|parsed| {
            parsed.scheme() == "http" && !is_local_host(parsed.host_str().unwrap_or_default())
        })
    })
}

/// The standard change-password address of a login's first website. Always `https` on the public
/// internet, even for an `http://` login.
pub(crate) fn change_password_url(urls: &[&str]) -> Option<String> {
    urls.iter().find_map(|url| {
        let parsed = web_url(url)?;
        let host = parsed.host_str()?;
        let scheme = if parsed.scheme() == "http" && is_local_host(host) {
            "http"
        } else {
            "https"
        };
        let port = parsed
            .port()
            .map_or_else(String::new, |port| format!(":{port}"));
        Some(format!(
            "{scheme}://{host}{port}/.well-known/change-password"
        ))
    })
}

/// The last day an expiry date is valid, as `YYYY-MM-DD`. Reads `MM/YY` and `MM/YYYY` (the end of
/// that month, as on a card), `YYYY-MM` and `YYYY-MM-DD`.
pub(crate) fn parse_expiry(text: &str) -> Option<Date> {
    let text = text.trim();
    let end_of_month = |year: i32, month: u8| {
        let month = Month::try_from(month).ok()?;
        Date::from_calendar_date(year, month, month.length(year)).ok()
    };
    let digits = |part: &str| {
        (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse::<i32>().ok())?
    };
    if let Some((month, year)) = text.split_once(['/', '-']) {
        let (month, year) = (month.trim(), year.trim());
        if month.len() <= 2 && matches!(year.len(), 2 | 4) {
            let year_number = digits(year)?;
            let year_number = if year.len() == 2 {
                2000 + year_number
            } else {
                year_number
            };
            return end_of_month(year_number, u8::try_from(digits(month)?).ok()?);
        }
    }
    if text.len() == 7 && text.as_bytes()[4] == b'-' {
        return end_of_month(digits(&text[..4])?, u8::try_from(digits(&text[5..])?).ok()?);
    }
    if text.len() >= 10 && text.is_char_boundary(10) {
        let day = &text[..10];
        if day.as_bytes()[4] == b'-' && day.as_bytes()[7] == b'-' {
            return Date::from_calendar_date(
                digits(&day[..4])?,
                Month::try_from(u8::try_from(digits(&day[5..7])?).ok()?).ok()?,
                u8::try_from(digits(&day[8..])?).ok()?,
            )
            .ok();
        }
    }
    None
}

fn iso_date(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// The hostname of a URL, tolerating a missing scheme; drops a leading `www.`.
pub(crate) fn hostname_of(url: &str) -> Option<String> {
    let text = url.trim();
    if text.is_empty() || text.chars().any(char::is_whitespace) {
        return None;
    }
    // Rejects mailto:, tel: and the like, but not `example.com:8443`.
    if let Some((scheme, rest)) = text.split_once(':')
        && is_scheme(scheme)
        && !rest.starts_with("//")
        && !rest.starts_with(|c: char| c.is_ascii_digit())
    {
        return None;
    }
    let with_scheme = match text.split_once("://") {
        Some((scheme, _)) if is_scheme(scheme) => text.to_owned(),
        _ => format!("https://{text}"),
    };
    let host = url::Url::parse(&with_scheme)
        .ok()?
        .host_str()?
        .to_lowercase();
    let host = host.trim_end_matches('.');
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then(|| host.to_owned())
}

fn is_scheme(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

#[rustfmt::skip]
const TWO_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in",
    "co.za", "org.za", "com.mx", "org.mx", "com.ar", "com.co", "com.pe", "com.cn", "net.cn", "org.cn",
    "com.hk", "com.sg", "com.tw", "com.tr", "com.my", "com.ph", "com.vn", "com.pk", "com.ng", "com.eg",
    "com.sa", "com.ua", "co.kr", "or.kr", "co.il", "org.il", "co.id", "or.id", "co.th", "in.th",
];

/// The registrable domain, approximated as the web vault's health report does it (not the
/// Public Suffix List, so both apps flag the same logins): `accounts.google.com` → `google.com`.
pub(crate) fn registrable_domain(hostname: &str) -> String {
    let host = hostname.trim().to_lowercase();
    let host = host.trim_end_matches('.');
    let ipv4 = host.split('.').count() == 4
        && host
            .split('.')
            .all(|part| (1..=3).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit()));
    if ipv4 || host.contains(':') {
        return host.to_owned();
    }
    let labels: Vec<&str> = host.split('.').collect();
    let last_two = labels[labels.len().saturating_sub(2)..].join(".");
    let take = if labels.len() > 2 && TWO_LABEL_SUFFIXES.contains(&last_two.as_str()) {
        3
    } else {
        2
    };
    labels[labels.len().saturating_sub(take)..].join(".")
}

/// Mail domains whose account lives on another site: a Gmail address signs in at google.com.
fn mail_sites_for(email: &str) -> Vec<String> {
    let domain = registrable_domain(email.rsplit_once('@').map_or(email, |(_, d)| d));
    let sites: &[&str] = match domain.as_str() {
        "gmail.com" | "googlemail.com" => &["google.com"],
        "outlook.com" | "hotmail.com" | "live.com" | "msn.com" => {
            &["live.com", "microsoft.com", "outlook.com"]
        }
        "yahoo.com" | "ymail.com" => &["yahoo.com"],
        "icloud.com" | "me.com" | "mac.com" => &["apple.com", "icloud.com"],
        "proton.me" | "protonmail.com" | "pm.me" => &["proton.me", "protonmail.com"],
        "gmx.com" | "gmx.net" | "gmx.de" => &["gmx.com", "gmx.net", "gmx.de"],
        "yandex.com" | "yandex.ru" => &["yandex.com", "yandex.ru"],
        "tuta.io" | "tutanota.com" => &["tuta.com", "tutanota.com"],
        _ => return vec![domain],
    };
    sites.iter().map(|s| (*s).to_owned()).collect()
}

/// Digits and a leading `+`, so spacing doesn't split a group.
fn normalize_phone(phone: &str) -> String {
    let trimmed = phone.trim();
    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    if trimmed.starts_with('+') {
        format!("+{digits}")
    } else {
        digits
    }
}

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn entry_of(login: &HealthLogin) -> HealthEntry {
    HealthEntry {
        item_id: login.item_id.clone(),
        vault_id: login.vault_id.clone(),
        title: login.title.clone(),
        subtitle: login.subtitle.clone(),
        warning: None,
        change_password_url: None,
    }
}

fn expiry_entry(row: &HealthExpiry) -> HealthEntry {
    HealthEntry {
        item_id: row.item_id.clone(),
        vault_id: row.vault_id.clone(),
        title: row.title.clone(),
        subtitle: row.subtitle.clone(),
        warning: None,
        change_password_url: None,
    }
}

/// Names a warning for dismissing it, as `warningKey` does in the web vault. `version` is what the
/// warning is about, so a new fact brings it back.
pub(crate) fn warning_key(check: &str, subject: &str, version: &str) -> String {
    format!("{check}:{subject}:{version}")
}

/// The same on every device, whichever way each one wrote the date.
fn password_version(login: &HealthLogin) -> String {
    login
        .password_date
        .as_deref()
        .and_then(|date| OffsetDateTime::parse(date, &Rfc3339).ok())
        .map_or_else(String::new, |date| date.unix_timestamp().to_string())
}

/// Collects warnings, leaving out the dismissed ones and remembering them for the report.
struct Warnings {
    keys: HashSet<String>,
    dismissed: Vec<DismissedWarning>,
}

impl Warnings {
    fn is_dismissed(&self, key: &str) -> bool {
        self.keys.contains(key)
    }

    /// The entry for a warning, or nothing when the user dismissed it.
    fn entry(&mut self, entry: HealthEntry, check: &str, key: String) -> Option<HealthEntry> {
        let entry = HealthEntry {
            warning: Some(key.clone()),
            ..entry
        };
        if !self.is_dismissed(&key) {
            return Some(entry);
        }
        self.dismissed.push(DismissedWarning {
            entry,
            warning: key,
            check: check.to_owned(),
        });
        None
    }

    fn login(&mut self, login: &HealthLogin, check: &str, version: &str) -> Option<HealthEntry> {
        let key = warning_key(check, &login.item_id, version);
        self.entry(entry_of(login), check, key)
    }

    /// A warning a new password fixes: it offers the site's change-password page.
    fn password(&mut self, login: &HealthLogin, check: &str) -> Option<HealthEntry> {
        let entry = self.login(login, check, &password_version(login))?;
        Some(HealthEntry {
            change_password_url: change_password_url(&urls(login)),
            ..entry
        })
    }
}

fn email_breach_findings(settings: &HealthSettings) -> Vec<EmailBreachFinding> {
    let Some(alerts) = settings.email_breach_alerts.as_ref() else {
        return Vec::new();
    };
    if alerts.get("enabled").and_then(Value::as_bool) != Some(true) {
        return Vec::new();
    }
    let previous = alerts.get("previous").and_then(Value::as_array);
    let known = |key: &str| {
        previous
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|text| text == key)
    };
    let text = |value: &Value, key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
    let results = alerts.get("found").and_then(Value::as_array);
    results
        .into_iter()
        .flatten()
        .flat_map(|result| {
            let address = text(result, "address").unwrap_or_default();
            let breaches = result.get("breaches").and_then(Value::as_array);
            breaches
                .into_iter()
                .flatten()
                .map(move |breach| (address.clone(), breach))
        })
        .map(|(address, breach)| {
            let name = text(breach, "name").unwrap_or_default();
            let warning = warning_key("emailBreach", &address.to_lowercase(), &name);
            EmailBreachFinding {
                title: text(breach, "title").unwrap_or_else(|| name.clone()),
                domain: text(breach, "domain"),
                breach_date: text(breach, "breachDate"),
                data_classes: breach
                    .get("dataClasses")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
                is_new: previous.is_some() && !known(&warning),
                warning,
                address,
                name,
            }
        })
        .collect()
}

/// Recovery emails among the findings (not dismissed), with the logins they can reset. The
/// version is the breaches, so a new one brings a dismissed warning back.
fn recovery_breaches(
    recovery: &[RecoveryContact],
    findings: &[EmailBreachFinding],
) -> Vec<BreachedRecoveryEmail> {
    let mut by_address: HashMap<String, BTreeSet<String>> = HashMap::new();
    for finding in findings {
        by_address
            .entry(normalize_email(&finding.address))
            .or_default()
            .insert(finding.title.clone());
    }
    let mut found: Vec<BreachedRecoveryEmail> = recovery
        .iter()
        .filter(|contact| contact.kind == RecoveryKind::Email)
        .filter_map(|contact| {
            let breaches: Vec<String> = by_address
                .get(&normalize_email(&contact.value))?
                .iter()
                .cloned()
                .collect();
            let warning = warning_key(
                "recoveryBreached",
                &contact.value.to_lowercase(),
                &breaches.join(","),
            );
            let entry = match &contact.account {
                Some(account) => HealthEntry {
                    warning: Some(warning),
                    change_password_url: None,
                    ..account.entry.clone()
                },
                None => HealthEntry {
                    item_id: String::new(),
                    vault_id: String::new(),
                    title: contact.value.clone(),
                    subtitle: None,
                    warning: Some(warning),
                    change_password_url: None,
                },
            };
            Some(BreachedRecoveryEmail {
                entry,
                email: contact.value.clone(),
                accounts: contact.logins.len() as u32,
                breaches,
            })
        })
        .collect();
    found.sort_by(|a, b| {
        b.accounts
            .cmp(&a.accounts)
            .then_with(|| compare_names(&a.email, &b.email))
    });
    found
}

fn has_two_step(login: &HealthLogin) -> bool {
    login.has_totp
        || login.has_passkey
        || login
            .two_factor_method
            .as_deref()
            .is_some_and(|method| method != "none")
}

fn urls(login: &HealthLogin) -> Vec<&str> {
    login
        .urls
        .as_ref()
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn on_sites(login: &HealthLogin, sites: &dyn Fn(&str) -> bool) -> bool {
    urls(login)
        .into_iter()
        .filter_map(hostname_of)
        .any(|host| sites(&registrable_domain(&host)))
}

fn lacks_second_factor(login: &HealthLogin, data: &HealthData) -> bool {
    login.item_type == "login"
        && !has_two_step(login)
        && on_sites(login, &|domain| data.two_factor_domains.contains(domain))
}

fn lacks_passkey(login: &HealthLogin, data: &HealthData) -> bool {
    login.item_type == "login"
        && !login.has_passkey
        && on_sites(login, &|domain| data.passkey_domains.contains(domain))
}

fn recovery_text(login: &HealthLogin, key: &str) -> Option<String> {
    login
        .recovery
        .as_ref()?
        .get(key)?
        .as_str()
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

struct Group {
    contact: RecoveryContact,
    ids: HashSet<String>,
}

/// Logins grouped by recovery email and phone, plus the emails whose own login lacks two-step
/// sign-in.
fn recovery_map(logins: &[&HealthLogin]) -> (Vec<RecoveryContact>, Vec<UnprotectedRecoveryEmail>) {
    let logins: Vec<&HealthLogin> = logins
        .iter()
        .copied()
        .filter(|login| login.item_type == "login")
        .collect();
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Group> = HashMap::new();
    let mut add = |kind: RecoveryKind, value: &str, login: &HealthLogin| {
        let key = match kind {
            RecoveryKind::Email => format!("email:{}", normalize_email(value)),
            RecoveryKind::Phone => format!("phone:{}", normalize_phone(value)),
        };
        let group = groups.entry(key.clone()).or_insert_with(|| {
            order.push(key);
            Group {
                contact: RecoveryContact {
                    kind,
                    value: value.trim().to_owned(),
                    logins: Vec::new(),
                    account: None,
                    alias_provider: None,
                    alias_id: None,
                    identity_id: None,
                },
                ids: HashSet::new(),
            }
        });
        if group.ids.insert(login.item_id.clone()) {
            group.contact.logins.push(entry_of(login));
        }
        let source_key = match kind {
            RecoveryKind::Email => "emailSource",
            RecoveryKind::Phone => "phoneSource",
        };
        let source = login.recovery.as_ref().and_then(|r| r.get(source_key));
        let field = |name: &str| source.and_then(|s| s.get(name)).and_then(Value::as_str);
        match field("kind") {
            Some("alias") if group.contact.alias_provider.is_none() => {
                group.contact.alias_provider = field("provider").map(str::to_owned);
                group.contact.alias_id = field("aliasId").map(str::to_owned);
            }
            Some("identity") if group.contact.identity_id.is_none() => {
                group.contact.identity_id = field("itemId").map(str::to_owned);
            }
            _ => {}
        }
    };
    for login in &logins {
        let email = recovery_text(login, "email");
        let phone = recovery_text(login, "phone");
        let username = login.username.as_deref().map(str::trim).unwrap_or_default();
        if let Some(email) = &email {
            add(RecoveryKind::Email, email, login);
        }
        // Sites send password resets to the email you sign in with, so it counts too.
        if !username.is_empty()
            && is_valid_email(username)
            && normalize_email(username) != normalize_email(email.as_deref().unwrap_or_default())
        {
            add(RecoveryKind::Email, username, login);
        }
        if let Some(phone) = &phone
            && !normalize_phone(phone).trim_start_matches('+').is_empty()
        {
            add(RecoveryKind::Phone, phone, login);
        }
    }

    let mut recovery = Vec::new();
    let mut unprotected = Vec::new();
    for key in order {
        let Some(Group { mut contact, .. }) = groups.remove(&key) else {
            continue;
        };
        if contact.kind == RecoveryKind::Email
            && let Some(account) = account_for(&contact.value, &logins)
        {
            contact
                .logins
                .retain(|entry| entry.item_id != account.item_id);
            let two_step = has_two_step(account);
            contact.account = Some(RecoveryAccount {
                entry: entry_of(account),
                two_step,
            });
            if !two_step && !contact.logins.is_empty() {
                unprotected.push(UnprotectedRecoveryEmail {
                    entry: entry_of(account),
                    email: contact.value.clone(),
                    accounts: contact.logins.len() as u32,
                });
            }
        }
        if !contact.logins.is_empty() {
            recovery.push(contact);
        }
    }
    recovery.sort_by(|a, b| {
        b.logins
            .len()
            .cmp(&a.logins.len())
            .then_with(|| compare_names(&a.value, &b.value))
    });
    unprotected.sort_by(|a, b| {
        b.accounts
            .cmp(&a.accounts)
            .then_with(|| compare_names(&a.email, &b.email))
    });
    (recovery, unprotected)
}

/// The email account's own login: signed in with that address (or its local part) on its mail
/// site.
fn account_for<'a>(email: &str, logins: &[&'a HealthLogin]) -> Option<&'a HealthLogin> {
    let address = normalize_email(email);
    let local = address.rsplit_once('@').map_or("", |(local, _)| local);
    let sites = mail_sites_for(&address);
    logins.iter().copied().find(|login| {
        let username = normalize_email(login.username.as_deref().unwrap_or_default());
        (username == address || username == local)
            && on_sites(login, &|domain| sites.iter().any(|site| site == domain))
    })
}

/// The report from the vault crate's health inputs (logins outside the trash), with the bundled
/// site lists.
#[cfg(test)]
pub(crate) fn build_report(inputs: &HealthInputs, now: OffsetDateTime) -> HealthReport {
    build_report_with(inputs, now, health_data::bundled())
}

/// The report with these site lists: the newest the phone has.
pub(crate) fn build_report_with(
    inputs: &HealthInputs,
    now: OffsetDateTime,
    data: &HealthData,
) -> HealthReport {
    let logins: Vec<&HealthLogin> = inputs.logins.iter().collect();
    let checked: Vec<(&HealthLogin, usize)> = logins
        .iter()
        .filter_map(|login| Some((*login, login.password_group?)))
        .collect();
    let mut by_group: HashMap<usize, Vec<&HealthLogin>> = HashMap::new();
    let mut group_order = Vec::new();
    for (login, group) in &checked {
        by_group
            .entry(*group)
            .or_insert_with(|| {
                group_order.push(*group);
                Vec::new()
            })
            .push(login);
    }
    let score_of = |group: usize| inputs.groups.get(group).map_or(0, |g| g.score);
    let breaches = |group: usize| {
        inputs.breach_check_completed.then(|| {
            inputs
                .groups
                .get(group)
                .and_then(|g| g.breach_count)
                .unwrap_or(0)
        })
    };
    let mut warnings = Warnings {
        keys: inputs.settings.dismissed.iter().cloned().collect(),
        dismissed: Vec::new(),
    };

    let mut weak = Vec::new();
    for (login, group) in &checked {
        let score = score_of(*group);
        if score <= WEAK_SCORE
            && let Some(entry) = warnings.password(login, "weak")
        {
            weak.push(WeakPassword { entry, score });
        }
    }
    let mut breached = Vec::new();
    for (login, group) in &checked {
        let Some(count) = breaches(*group).filter(|count| *count > 0) else {
            continue;
        };
        if let Some(entry) = warnings.password(login, "breached") {
            breached.push(BreachedPassword { entry, count });
        }
    }

    // A reused group is dismissed as a whole, and comes back whole when another login joins it.
    let mut groups: Vec<&Vec<&HealthLogin>> = group_order
        .iter()
        .map(|group| &by_group[group])
        .filter(|group| group.len() > 1)
        .collect();
    groups.sort_by_key(|group| std::cmp::Reverse(group.len()));
    let mut reused: Vec<Vec<HealthEntry>> = Vec::new();
    for group in groups {
        let keys: Vec<String> = group
            .iter()
            .map(|login| warning_key("reused", &login.item_id, &password_version(login)))
            .collect();
        if keys.iter().all(|key| warnings.is_dismissed(key)) {
            for login in group {
                warnings.password(login, "reused");
            }
            continue;
        }
        for key in &keys {
            warnings.keys.remove(key);
        }
        reused.push(
            group
                .iter()
                .filter_map(|login| warnings.password(login, "reused"))
                .collect(),
        );
    }

    let missing_2fa: Vec<HealthEntry> = logins
        .iter()
        .copied()
        .filter(|login| lacks_second_factor(login, data))
        .filter_map(|login| warnings.login(login, "missing2fa", ""))
        .collect();
    let insecure_urls: Vec<InsecureLogin> = logins
        .iter()
        .copied()
        .filter(|login| login.item_type == "login")
        .filter_map(|login| {
            let list = urls(login);
            let url = insecure_url(&list)?;
            let entry = warnings.login(login, "insecureUrl", url)?;
            Some(InsecureLogin {
                entry,
                url: url.to_owned(),
            })
        })
        .collect();

    let ids = |entries: Vec<&HealthEntry>| -> HashSet<String> {
        entries.into_iter().map(|e| e.item_id.clone()).collect()
    };
    let weak_ids = ids(weak.iter().map(|w| &w.entry).collect());
    let reused_ids = ids(reused.iter().flatten().collect());
    let breached_ids = ids(breached.iter().map(|b| &b.entry).collect());
    let missing_ids = ids(missing_2fa.iter().collect());
    let insecure_ids = ids(insecure_urls.iter().map(|i| &i.entry).collect());

    let mut total = 0.0;
    for (login, group) in &checked {
        let id = &login.item_id;
        let mut health = if breached_ids.contains(id) { 0.0 } else { 1.0 };
        if weak_ids.contains(id) {
            health *= if score_of(*group) <= 1 {
                PENALTY_VERY_WEAK
            } else {
                PENALTY_WEAK
            };
        }
        if reused_ids.contains(id) {
            health *= PENALTY_REUSED;
        }
        if missing_ids.contains(id) {
            health *= PENALTY_MISSING_2FA;
        }
        if insecure_ids.contains(id) {
            health *= PENALTY_INSECURE_URL;
        }
        total += health;
    }

    let mut old: Vec<OldPassword> = checked
        .iter()
        .filter_map(|(login, _)| {
            let changed_at = login.password_date.clone()?;
            let date = OffsetDateTime::parse(&changed_at, &Rfc3339).ok()?;
            let age = (now - date).whole_days();
            if age < OLD_PASSWORD_DAYS {
                return None;
            }
            let entry = warnings.password(login, "old")?;
            Some(OldPassword {
                entry,
                changed_at,
                age_days: u32::try_from(age).unwrap_or(u32::MAX),
            })
        })
        .collect();
    old.sort_by_key(|entry| std::cmp::Reverse(entry.age_days));

    let today = now.date();
    let mut expiring: Vec<ExpiringItem> = inputs
        .expiries
        .iter()
        .filter_map(|row| {
            let date = parse_expiry(&row.expiry)?;
            let left = (date.midnight() - today.midnight()).whole_days();
            if left > EXPIRY_WARNING_DAYS {
                return None;
            }
            let expires_on = iso_date(date);
            let key = warning_key("expiring", &row.item_id, &expires_on);
            let entry = warnings.entry(expiry_entry(row), "expiring", key)?;
            Some(ExpiringItem {
                entry,
                expires_on,
                days_left: i32::try_from(left).unwrap_or(i32::MIN),
            })
        })
        .collect();
    expiring.sort_by_key(|entry| entry.days_left);

    let low_backup_codes: Vec<LowBackupCodes> = logins
        .iter()
        .copied()
        .filter(|login| login.item_type == "login")
        .filter_map(|login| {
            let unused = login.backup_codes?.unused;
            if unused > LOW_BACKUP_CODES {
                return None;
            }
            let entry = warnings.login(login, "backupCodes", &unused.to_string())?;
            Some(LowBackupCodes { entry, unused })
        })
        .collect();

    let passkey_available: Vec<HealthEntry> = logins
        .iter()
        .copied()
        .filter(|login| lacks_passkey(login, data))
        .filter_map(|login| warnings.login(login, "passkeyAvailable", ""))
        .collect();

    let (recovery, recovery_no_2fa) = recovery_map(&logins);
    let recovery_no_2fa: Vec<UnprotectedRecoveryEmail> = recovery_no_2fa
        .into_iter()
        .filter_map(|mut item| {
            let key = warning_key(
                "recoveryNo2fa",
                &item.entry.item_id,
                &item.email.to_lowercase(),
            );
            let mut entry = item.entry.clone();
            if warnings.is_dismissed(&key) {
                entry.subtitle = Some(item.email.clone());
            }
            let kept = warnings.entry(entry, "recoveryNo2fa", key)?;
            item.entry.warning = kept.warning;
            Some(item)
        })
        .collect();

    let findings = email_breach_findings(&inputs.settings);
    let (dismissed_findings, email_breaches): (Vec<_>, Vec<_>) = findings
        .into_iter()
        .partition(|finding| warnings.is_dismissed(&finding.warning));
    for finding in dismissed_findings {
        warnings.dismissed.push(DismissedWarning {
            entry: HealthEntry {
                item_id: String::new(),
                vault_id: String::new(),
                title: finding.title,
                subtitle: Some(finding.address),
                warning: Some(finding.warning.clone()),
                change_password_url: None,
            },
            warning: finding.warning,
            check: "emailBreach".into(),
        });
    }
    let recovery_breached = recovery_breaches(&recovery, &email_breaches)
        .into_iter()
        .filter_map(|item| {
            let key = item.entry.warning.clone().unwrap_or_default();
            let mut entry = item.entry.clone();
            if warnings.is_dismissed(&key) {
                entry.subtitle = Some(item.email.clone());
            }
            warnings.entry(entry, "recoveryBreached", key)?;
            Some(item)
        })
        .collect();
    let alerts = inputs.settings.email_breach_alerts.as_ref();
    let alerts_on = alerts
        .and_then(|alerts| alerts.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    HealthReport {
        score: if checked.is_empty() {
            100
        } else {
            (total / checked.len() as f64 * 100.0).round() as u32
        },
        checked: checked.len() as u32,
        weak,
        reused,
        breached,
        breach_check_completed: inputs.breach_check_completed,
        missing_2fa,
        recovery,
        recovery_no_2fa,
        recovery_breached,
        old,
        passkey_available,
        insecure_urls,
        expiring,
        low_backup_codes,
        email_alerts_enabled: alerts_on,
        email_alerts_recovery_emails: alerts_on
            && alerts
                .and_then(|alerts| alerts.get("recoveryEmails"))
                .and_then(Value::as_bool)
                == Some(true),
        email_breaches_checked_at: alerts
            .and_then(|alerts| alerts.get("checkedAt"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        email_breaches,
        dismissed: warnings.dismissed,
        generated_at: now.format(&Rfc3339).expect("UTC times format as RFC 3339"),
    }
}

impl Ctx<'_> {
    fn settings_items(&self) -> Result<Vec<StoredItem>> {
        let mut items: Vec<StoredItem> = self
            .vault
            .live_items()?
            .into_iter()
            .filter(octapass_mobile_vault::health::is_health_settings)
            .collect();
        items.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        Ok(items)
    }

    /// Saves the settings to the oldest item and folds any conflict copy into it.
    fn save_settings(
        &self,
        personal_vault_id: &str,
        items: &[StoredItem],
        settings: &HealthSettings,
    ) -> Result<()> {
        let first = items.first();
        let vault_id = first.map_or_else(|| personal_vault_id.to_owned(), |i| i.vault_id.clone());
        let overview = first.map_or_else(
            || json!({ "schemaVersion": 1, "type": octapass_mobile_vault::health::HEALTH_SETTINGS_TYPE, "title": SETTINGS_TITLE }),
            |item| item.overview.clone(),
        );
        self.vault.save_item(StoredDraft {
            id: first.map(|item| item.id.clone()),
            vault_id,
            revision: first.map(|item| item.revision),
            overview,
            details: serde_json::to_value(settings).expect("settings serialize"),
        })?;
        for extra in items.iter().skip(1) {
            self.vault.delete_item(&extra.id)?;
        }
        Ok(())
    }

    /// Hides warnings on every device. Their keys come from the report.
    pub(crate) fn dismiss_health_warnings(
        &self,
        personal_vault_id: &str,
        warnings: &[String],
    ) -> Result<()> {
        let items = self.settings_items()?;
        let mut settings = read_settings(&items);
        for warning in warnings {
            if !settings.dismissed.contains(warning) {
                settings.dismissed.push(warning.clone());
            }
        }
        self.save_settings(personal_vault_id, &items, &settings)
    }

    pub(crate) fn restore_health_warnings(
        &self,
        personal_vault_id: &str,
        warnings: &[String],
    ) -> Result<()> {
        let items = self.settings_items()?;
        let mut settings = read_settings(&items);
        settings.dismissed.retain(|key| !warnings.contains(key));
        self.save_settings(personal_vault_id, &items, &settings)
    }

    /// The newest site lists on this phone (plan 06): a newer signed file from the account's
    /// server, asked for at most once a day, or the bundled lists. The file is public, so it's
    /// kept as is in the data folder, and checked against the pinned key whenever it's read.
    /// Local vaults have no server and keep the bundled lists.
    pub(crate) fn health_data(&self) -> HealthData {
        let path = self.vault.data_dir().join(HEALTH_DATA_FILE);
        let mut stored: Value = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_else(|| json!({}));
        let file = |stored: &Value| {
            stored
                .get("file")
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let checked_at = stored.get("checkedAt").and_then(Value::as_i64).unwrap_or(0);
        let local = self
            .vault
            .snapshot()
            .session
            .server_url
            .is_none_or(|url| url.starts_with("local:"));
        if !local && now - checked_at >= health_data::CHECK_HOURS * 3600 {
            let answer: Option<Value> = self.vault.access().ok().and_then(|access| {
                Server {
                    api: self.api,
                    access: &access,
                }
                .call(Method::Get, health_data::PATH, None::<&Value>)
                .ok()
            });
            if let Some(answer) = answer {
                // The signature covers the payload's bytes, which stay as they came in base64,
                // so the envelope's spacing doesn't matter.
                let text = answer.to_string();
                let in_use = health_data::newest(file(&stored).as_deref()).version;
                if health_data::verify(&text, in_use).is_ok() {
                    stored["file"] = json!(text);
                }
                stored["checkedAt"] = json!(now);
                // Best effort: without the file, the next report asks again.
                let _ = std::fs::write(&path, stored.to_string());
            }
        }
        health_data::newest(file(&stored).as_deref())
    }

    /// The second opt-in, while alerts are on: also look up the recovery emails that are neither
    /// the account email nor an alias. Either way the results are forgotten, so the next check
    /// holds exactly the addresses the user now agreed to.
    pub(crate) fn set_recovery_email_checks(
        &self,
        personal_vault_id: &str,
        enabled: bool,
    ) -> Result<()> {
        let items = self.settings_items()?;
        let mut settings = read_settings(&items);
        let on = settings
            .email_breach_alerts
            .as_ref()
            .and_then(|alerts| alerts.get("enabled"))
            .and_then(Value::as_bool)
            == Some(true);
        if !on {
            return Ok(());
        }
        settings.email_breach_alerts = Some(if enabled {
            json!({ "enabled": true, "recoveryEmails": true })
        } else {
            json!({ "enabled": true })
        });
        self.save_settings(personal_vault_id, &items, &settings)
    }

    /// Turning alerts off forgets their results.
    pub(crate) fn set_email_breach_alerts(
        &self,
        personal_vault_id: &str,
        enabled: bool,
    ) -> Result<()> {
        let items = self.settings_items()?;
        let mut settings = read_settings(&items);
        settings.email_breach_alerts = Some(json!({ "enabled": enabled }));
        self.save_settings(personal_vault_id, &items, &settings)
    }

    /// Looks the account email and aliases up, one at a time, when alerts are on and a day has
    /// passed (or `force`). **This sends the addresses to the server, which sends them to HIBP**,
    /// so it does nothing until the user opted in.
    pub(crate) fn check_email_breaches(
        &self,
        personal_vault_id: &str,
        account_email: Option<&str>,
        force: bool,
    ) -> Result<EmailBreachCheck> {
        let items = self.settings_items()?;
        let settings = read_settings(&items);
        let Some(alerts) = settings
            .email_breach_alerts
            .as_ref()
            .filter(|alerts| alerts.get("enabled").and_then(Value::as_bool) == Some(true))
        else {
            return Ok(EmailBreachCheck::Off);
        };
        let now = OffsetDateTime::now_utc();
        let checked_at = alerts
            .get("checkedAt")
            .and_then(Value::as_str)
            .and_then(|date| OffsetDateTime::parse(date, &Rfc3339).ok());
        if !force
            && checked_at.is_some_and(|date| (now - date).whole_hours() < EMAIL_BREACH_CHECK_HOURS)
        {
            return Ok(EmailBreachCheck::NotDue);
        }

        let recovery_emails = alerts.get("recoveryEmails").and_then(Value::as_bool) == Some(true);
        let mut addresses = breach_addresses(account_email, &self.vault.live_items()?);
        if recovery_emails {
            let logins = self.vault.recovery_logins()?;
            let (contacts, _) = recovery_map(&logins.iter().collect::<Vec<_>>());
            let mut seen: HashSet<String> = addresses.iter().map(|a| normalize_email(a)).collect();
            addresses.extend(
                contacts
                    .into_iter()
                    .filter(|contact| {
                        contact.kind == RecoveryKind::Email && contact.alias_provider.is_none()
                    })
                    .map(|contact| contact.value)
                    .filter(|address| seen.insert(normalize_email(address))),
            );
        }
        let access = self.vault.access()?;
        let server = Server {
            api: self.api,
            access: &access,
        };
        let mut found = Vec::new();
        for address in addresses.iter().take(MAX_EMAIL_BREACH_ADDRESSES) {
            let body = json!({ "email": address });
            let answer: Result<octapass_api::BreachEmailResponse> =
                server.call(Method::Post, "v1/health/breach-email", Some(&body));
            let Ok(answer) = answer else {
                return Ok(EmailBreachCheck::Failed);
            };
            if !answer.breaches.is_empty() {
                found.push(json!({ "address": address, "breaches": answer.breaches }));
            }
        }
        drop(access);

        let previous: Option<Vec<String>> = checked_at.map(|_| {
            email_breach_findings(&settings)
                .into_iter()
                .map(|finding| finding.warning)
                .collect()
        });
        let mut next = json!({
            "enabled": true,
            "checkedAt": now.format(&Rfc3339).expect("UTC times format as RFC 3339"),
            "found": found,
        });
        if recovery_emails {
            next["recoveryEmails"] = json!(true);
        }
        if let Some(previous) = previous {
            next["previous"] = json!(previous);
        }
        let items = self.settings_items()?;
        let mut settings = read_settings(&items);
        // Turned off while the check ran, or the second opt-in changed: the change wins, and
        // nothing found is kept.
        let now_alerts = settings.email_breach_alerts.as_ref();
        let still_on = now_alerts
            .and_then(|alerts| alerts.get("enabled"))
            .and_then(Value::as_bool)
            == Some(true)
            && (now_alerts
                .and_then(|alerts| alerts.get("recoveryEmails"))
                .and_then(Value::as_bool)
                == Some(true))
                == recovery_emails;
        if still_on {
            settings.email_breach_alerts = Some(next);
            self.save_settings(personal_vault_id, &items, &settings)?;
        }
        Ok(EmailBreachCheck::Checked)
    }
}

fn read_settings(items: &[StoredItem]) -> HealthSettings {
    octapass_mobile_vault::health::read_health_settings(items)
}

/// The account email and the masked email aliases the vault knows, each once.
fn breach_addresses(account_email: Option<&str>, items: &[StoredItem]) -> Vec<String> {
    let aliases = items.iter().filter_map(|item| {
        let recovery = item.details.get("recovery")?;
        let source = recovery.get("emailSource")?;
        (source.get("kind").and_then(Value::as_str) == Some("alias")).then_some(())?;
        recovery.get("email")?.as_str().map(str::to_owned)
    });
    let mut seen = HashSet::new();
    account_email
        .map(str::to_owned)
        .into_iter()
        .chain(aliases)
        .filter(|address| {
            let key = normalize_email(address);
            !key.is_empty() && seen.insert(key)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use octapass_mobile_vault::health::{BackupCodeCount, PasswordGroup};
    use serde_json::json;

    use super::*;

    fn login(id: &str, url: &str, group: Option<usize>) -> HealthLogin {
        HealthLogin {
            item_id: id.into(),
            vault_id: "v".into(),
            item_type: "login".into(),
            title: id.into(),
            subtitle: None,
            urls: Some(json!([url])),
            has_totp: false,
            has_passkey: false,
            two_factor_method: None,
            username: None,
            recovery: None,
            password_group: group,
            password_date: group.map(|_| "2026-09-01T00:00:00.000Z".into()),
            backup_codes: None,
        }
    }

    /// 2026-10-23 12:00 UTC, as in the web vault's tests.
    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_792_756_800).unwrap()
    }

    fn inputs(logins: Vec<HealthLogin>, groups: Vec<PasswordGroup>) -> HealthInputs {
        HealthInputs {
            logins,
            groups,
            breach_check_completed: true,
            expiries: Vec::new(),
            settings: HealthSettings::default(),
        }
    }

    fn strong() -> PasswordGroup {
        PasswordGroup {
            score: 4,
            breach_count: Some(0),
        }
    }

    #[test]
    fn the_web_vaults_site_list_is_read() {
        let domains = two_factor_domains();
        assert!(domains.contains("github.com") && domains.contains("1password.com"));
        assert!(domains.len() > 60);
        assert!(!domains.iter().any(|d| d.contains(' ') || d.is_empty()));
    }

    #[test]
    fn urls_reduce_like_the_web_vault() {
        assert_eq!(
            hostname_of("github.com/login").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            hostname_of("https://www.bbc.co.uk/").as_deref(),
            Some("bbc.co.uk")
        );
        assert_eq!(
            hostname_of("example.com:8443").as_deref(),
            Some("example.com")
        );
        assert_eq!(hostname_of("mailto:a@b.c"), None);
        assert_eq!(registrable_domain("accounts.google.com"), "google.com");
        assert_eq!(registrable_domain("news.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registrable_domain("10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn scores_reuse_breaches_and_missing_two_step() {
        let mut github = login("github", "https://github.com", Some(0));
        github.subtitle = Some("ada".into());
        let reused = login("forum", "https://forum.example", Some(0));
        let strong = login("bank", "https://bank.example", Some(1));
        let inputs = HealthInputs {
            logins: vec![github, reused, strong, login("note", "", None)],
            groups: vec![
                PasswordGroup {
                    score: 1,
                    breach_count: Some(3),
                },
                PasswordGroup {
                    score: 4,
                    breach_count: Some(0),
                },
            ],
            breach_check_completed: true,
            expiries: Vec::new(),
            settings: HealthSettings::default(),
        };
        let report = build_report(&inputs, now());
        assert_eq!(report.checked, 3);
        // github and forum: breached → 0; bank: 1.
        assert_eq!(report.score, 33);
        assert_eq!(report.weak.len(), 2);
        assert_eq!(report.reused.len(), 1);
        assert_eq!(report.breached[0].count, 3);
        assert_eq!(report.breached[0].entry.subtitle.as_deref(), Some("ada"));
        let missing: Vec<&str> = report
            .missing_2fa
            .iter()
            .map(|e| e.item_id.as_str())
            .collect();
        assert_eq!(missing, ["github"]);
    }

    #[test]
    fn the_recovery_map_finds_unprotected_inboxes() {
        let mut gmail = login("gmail", "https://accounts.google.com", None);
        gmail.username = Some("ada@gmail.com".into());
        let mut shop = login("shop", "https://shop.example", None);
        shop.username = Some("Ada@Gmail.com".into());
        shop.recovery = Some(
            json!({ "phone": "+1 555 0100", "phoneSource": { "kind": "identity", "itemId": "me" } }),
        );
        let mut bank = login("bank", "https://bank.example", None);
        bank.recovery = Some(json!({ "email": "ada@gmail.com", "phone": "+15550100" }));
        bank.two_factor_method = Some("sms".into());
        let inputs = HealthInputs {
            logins: vec![gmail, shop, bank],
            groups: Vec::new(),
            breach_check_completed: false,
            expiries: Vec::new(),
            settings: HealthSettings::default(),
        };
        let report = build_report(&inputs, now());
        assert_eq!(report.score, 100);
        let [phone, email] = &report.recovery[..] else {
            panic!("two contacts");
        };
        assert_eq!(email.kind, RecoveryKind::Email);
        assert_eq!(email.logins.len(), 2, "the inbox's own login isn't listed");
        assert!(!email.account.as_ref().unwrap().two_step);
        assert_eq!(phone.logins.len(), 2);
        assert_eq!(phone.identity_id.as_deref(), Some("me"));
        assert_eq!(report.recovery_no_2fa[0].accounts, 2);
        assert!(report.breached.is_empty() && !report.breach_check_completed);
    }

    #[test]
    fn the_passkey_directory_is_read() {
        let domains = passkey_domains();
        assert!(domains.contains("github.com") && domains.len() >= 300);
        assert!(!domains.iter().any(|d| d.contains(' ') || d.is_empty()));
    }

    #[test]
    fn urls_for_the_new_checks_match_the_web_vault() {
        assert_eq!(
            change_password_url(&["http://www.shop.example/login?x=1"]).as_deref(),
            Some("https://www.shop.example/.well-known/change-password")
        );
        assert_eq!(
            change_password_url(&["mailto:a@b.c", "example.com:8443/x"]).as_deref(),
            Some("https://example.com:8443/.well-known/change-password")
        );
        assert_eq!(
            change_password_url(&["http://192.168.1.1/admin"]).as_deref(),
            Some("http://192.168.1.1/.well-known/change-password")
        );
        assert_eq!(
            change_password_url(&["javascript:alert(1)", "file:///x"]),
            None
        );
        assert_eq!(
            insecure_url(&["https://a.example", "http://a.example"]),
            Some("http://a.example")
        );
        assert_eq!(
            insecure_url(&[
                "a.example",
                "http://10.0.0.8",
                "http://[::1]:3000",
                "http://printer"
            ]),
            None
        );
        for host in [
            "localhost",
            "nas.local",
            "127.0.0.1",
            "172.16.0.1",
            "[fd00::1]",
            "router",
        ] {
            assert!(is_local_host(host), "{host}");
        }
        for host in ["example.com", "8.8.8.8", "172.32.0.1", "[2606:4700::1]"] {
            assert!(!is_local_host(host), "{host}");
        }
    }

    #[test]
    fn expiry_dates_read_like_the_web_vault() {
        let iso = |text: &str| parse_expiry(text).map(iso_date);
        assert_eq!(iso("02/28").as_deref(), Some("2028-02-29"));
        assert_eq!(iso("2/2027").as_deref(), Some("2027-02-28"));
        assert_eq!(iso("12 / 26").as_deref(), Some("2026-12-31"));
        assert_eq!(iso("2027-04").as_deref(), Some("2027-04-30"));
        assert_eq!(iso("2027-04-15").as_deref(), Some("2027-04-15"));
        assert_eq!(iso("2027-04-15T00:00:00Z").as_deref(), Some("2027-04-15"));
        for bad in ["", "13/27", "00/27", "2027-13", "2027-02-30", "soon"] {
            assert_eq!(iso(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_new_checks_match_the_web_vault() {
        let shop = login("shop", "http://shop.example/login", Some(0));
        let router = login("router", "http://192.168.1.1", Some(1));
        let mut github = login("github", "https://github.com/login", None);
        github.backup_codes = Some(BackupCodeCount {
            total: 5,
            unused: 2,
        });
        let mut plenty = login("plenty", "https://plenty.example", None);
        plenty.backup_codes = Some(BackupCodeCount {
            total: 5,
            unused: 3,
        });
        let mut ancient = login("ancient", "https://safe.example", Some(2));
        ancient.password_date = Some("2024-10-23T12:00:00.000Z".into());
        let mut report_inputs = inputs(
            vec![shop, router, github, plenty, ancient],
            vec![strong(), strong(), strong()],
        );
        let expiry = |id: &str, expiry: &str| HealthExpiry {
            item_id: id.into(),
            vault_id: "v".into(),
            item_type: "card".into(),
            title: id.into(),
            subtitle: None,
            expiry: expiry.into(),
        };
        report_inputs.expiries = vec![
            expiry("later", "01/27"),
            expiry("soon", "10/26"),
            expiry("gone", "09/26"),
            expiry("exact", "2026-12-22"),
            expiry("blank", "nonsense"),
        ];
        let report = build_report(&report_inputs, now());
        assert_eq!(report.insecure_urls.len(), 1);
        assert_eq!(report.insecure_urls[0].entry.item_id, "shop");
        // Three checked; shop at 0.85.
        assert_eq!(report.score, 95);
        assert_eq!(report.low_backup_codes.len(), 1);
        assert_eq!(report.low_backup_codes[0].unused, 2);
        assert_eq!(report.passkey_available[0].item_id, "github");
        assert_eq!(report.old.len(), 1);
        assert_eq!(report.old[0].age_days, 730);
        let expiring: Vec<(&str, i32)> = report
            .expiring
            .iter()
            .map(|e| (e.entry.item_id.as_str(), e.days_left))
            .collect();
        assert_eq!(expiring, [("gone", -23), ("soon", 8), ("exact", 60)]);
    }

    #[test]
    fn dismissals_hide_warnings_until_the_fact_changes() {
        let weak_login = login("a", "https://a.example", Some(0));
        let group = PasswordGroup {
            score: 0,
            breach_count: Some(0),
        };
        let before = build_report(
            &inputs(vec![weak_login.clone()], vec![group.clone()]),
            now(),
        );
        let key = before.weak[0].entry.warning.clone().unwrap();
        assert_eq!(key, "weak:a:1788220800", "matches the web vault's key");

        let mut dismissed = inputs(vec![weak_login.clone()], vec![group.clone()]);
        dismissed.settings.dismissed = vec![key];
        let report = build_report(&dismissed, now());
        assert!(report.weak.is_empty());
        assert_eq!(report.score, 100);
        assert_eq!(report.dismissed[0].check, "weak");

        let mut changed = dismissed;
        changed.logins[0].password_date = Some("2026-10-01T00:00:00.000Z".into());
        assert_eq!(build_report(&changed, now()).weak.len(), 1);
    }

    #[test]
    fn a_reused_group_is_dismissed_whole_and_comes_back_whole() {
        let a = login("a", "https://a.example", Some(0));
        let b = login("b", "https://b.example", Some(0));
        let before = build_report(&inputs(vec![a.clone(), b.clone()], vec![strong()]), now());
        let keys: Vec<String> = before.reused[0]
            .iter()
            .map(|e| e.warning.clone().unwrap())
            .collect();
        let mut quiet = inputs(vec![a.clone(), b.clone()], vec![strong()]);
        quiet.settings.dismissed = keys.clone();
        let report = build_report(&quiet, now());
        assert!(report.reused.is_empty());
        assert_eq!(report.score, 100);
        assert_eq!(report.dismissed.len(), 2);

        let mut back = inputs(
            vec![a, b, login("c", "https://c.example", Some(0))],
            vec![strong()],
        );
        back.settings.dismissed = keys;
        let report = build_report(&back, now());
        assert_eq!(report.reused[0].len(), 3);
        assert!(report.dismissed.is_empty());
    }

    #[test]
    fn email_breaches_show_only_while_alerts_are_on() {
        let breach = json!({ "name": "Adobe", "title": "Adobe", "dataClasses": ["Passwords"] });
        let canva = json!({ "name": "Canva", "title": "Canva" });
        let found = json!([{ "address": "A@b.example", "breaches": [breach, canva] }]);
        let mut off = inputs(Vec::new(), Vec::new());
        off.settings.email_breach_alerts = Some(json!({ "enabled": false, "found": found }));
        let report = build_report(&off, now());
        assert!(!report.email_alerts_enabled && report.email_breaches.is_empty());

        let mut on = inputs(Vec::new(), Vec::new());
        on.settings.email_breach_alerts = Some(json!({
            "enabled": true,
            "checkedAt": "2026-10-23T00:00:00.000Z",
            "found": found,
            "previous": ["emailBreach:a@b.example:Adobe"],
        }));
        let report = build_report(&on, now());
        let names: Vec<(&str, bool)> = report
            .email_breaches
            .iter()
            .map(|finding| (finding.name.as_str(), finding.is_new))
            .collect();
        assert_eq!(names, [("Adobe", false), ("Canva", true)]);

        on.settings.dismissed = vec!["emailBreach:a@b.example:Adobe".into()];
        let report = build_report(&on, now());
        assert_eq!(report.email_breaches.len(), 1);
        assert_eq!(report.dismissed[0].check, "emailBreach");
        assert_eq!(
            report.dismissed[0].entry.subtitle.as_deref(),
            Some("A@b.example")
        );
    }

    #[test]
    fn only_the_account_email_and_aliases_are_checked() {
        let item = |recovery: Value| StoredItem {
            id: "i".into(),
            vault_id: "v".into(),
            revision: 1,
            created_at: String::new(),
            updated_at: String::new(),
            deleted_at: None,
            overview: json!({ "type": "login" }),
            details: json!({ "recovery": recovery }),
        };
        let items = [
            item(json!({ "email": "me@b.example", "emailSource": { "kind": "alias" } })),
            item(json!({ "email": "alias@relay.example", "emailSource": { "kind": "alias" } })),
            item(json!({ "email": "colleague@work.example" })),
            item(json!({ "email": "me@work.example", "emailSource": { "kind": "identity" } })),
        ];
        assert_eq!(
            breach_addresses(Some("Me@b.example"), &items),
            ["Me@b.example", "alias@relay.example"]
        );
    }
    fn recovery_vault() -> HealthInputs {
        let mut gmail = login("gmail", "https://mail.google.com", Some(0));
        gmail.username = Some("me@gmail.com".into());
        let mut shop = login("shop", "https://shop.example", Some(0));
        shop.recovery = Some(json!({ "email": "me@gmail.com" }));
        let mut bank = login("bank", "https://bank.example", Some(0));
        bank.recovery = Some(json!({ "email": "Me@Gmail.com" }));
        let mut forum = login("forum", "https://forum.example", Some(0));
        forum.username = Some("old@isp.example".into());
        inputs(vec![gmail, shop, bank, forum], vec![strong()])
    }

    fn breach(name: &str) -> Value {
        json!({ "name": name, "title": name, "dataClasses": ["Passwords"] })
    }

    #[test]
    fn breached_recovery_emails_list_the_logins_they_reset() {
        let mut vault = recovery_vault();
        vault.settings.email_breach_alerts = Some(json!({
            "enabled": true,
            "checkedAt": "2026-10-23T00:00:00.000Z",
            "found": [
                { "address": "me@gmail.com", "breaches": [breach("Zeta"), breach("Alpha")] },
                { "address": "old@isp.example", "breaches": [breach("Isp")] },
                { "address": "nobody@else.example", "breaches": [breach("Other")] },
            ],
        }));
        let report = build_report(&vault, now());
        let rows: Vec<(&str, &str, u32, Vec<String>)> = report
            .recovery_breached
            .iter()
            .map(|row| {
                (
                    row.entry.item_id.as_str(),
                    row.email.as_str(),
                    row.accounts,
                    row.breaches.clone(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                (
                    "gmail",
                    "me@gmail.com",
                    2,
                    vec!["Alpha".to_owned(), "Zeta".to_owned()]
                ),
                ("", "old@isp.example", 1, vec!["Isp".to_owned()]),
            ]
        );
        // The same keys as the web vault, so a dismissal holds on every device.
        assert_eq!(
            report.recovery_breached[0].entry.warning.as_deref(),
            Some("recoveryBreached:me@gmail.com:Alpha,Zeta")
        );
        assert_eq!(report.recovery_breached[1].entry.title, "old@isp.example");
        assert!(!report.email_alerts_recovery_emails);

        // Dismissed, it leaves the list; a new breach brings it back.
        vault.settings.dismissed = vec!["recoveryBreached:old@isp.example:Isp".into()];
        let report = build_report(&vault, now());
        assert_eq!(report.recovery_breached.len(), 1);
        let dismissed = report
            .dismissed
            .iter()
            .find(|d| d.check == "recoveryBreached")
            .unwrap();
        assert_eq!(dismissed.entry.subtitle.as_deref(), Some("old@isp.example"));

        // A dismissed breach finding doesn't count.
        vault.settings.dismissed = vec![
            "emailBreach:me@gmail.com:Zeta".into(),
            "emailBreach:me@gmail.com:Alpha".into(),
        ];
        let report = build_report(&vault, now());
        assert_eq!(report.recovery_breached.len(), 1);
        assert_eq!(report.recovery_breached[0].email, "old@isp.example");
    }

    #[test]
    fn the_second_opt_in_shows_only_while_alerts_are_on() {
        let mut vault = recovery_vault();
        vault.settings.email_breach_alerts =
            Some(json!({ "enabled": true, "recoveryEmails": true }));
        assert!(build_report(&vault, now()).email_alerts_recovery_emails);
        vault.settings.email_breach_alerts =
            Some(json!({ "enabled": false, "recoveryEmails": true }));
        let report = build_report(&vault, now());
        assert!(!report.email_alerts_recovery_emails && report.recovery_breached.is_empty());
    }

    #[test]
    fn the_report_uses_the_site_lists_it_is_given() {
        let vault = inputs(
            vec![login("new", "https://login.passkeys.example", Some(0))],
            vec![strong()],
        );
        let before = build_report(&vault, now());
        assert!(before.passkey_available.is_empty() && before.missing_2fa.is_empty());
        let data = HealthData {
            version: 99,
            issued_at: String::new(),
            passkey_domains: ["passkeys.example".to_owned()].into(),
            two_factor_domains: ["passkeys.example".to_owned()].into(),
        };
        let after = build_report_with(&vault, now(), &data);
        assert_eq!(after.passkey_available[0].item_id, "new");
        assert_eq!(after.missing_2fa[0].item_id, "new");
    }
}
