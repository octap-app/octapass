//! What the security dashboard needs, computed here so passwords stay in this process.
//!
//! The UI builds the report with the shared `buildHealthReport` from `packages/vault-client`. It
//! gets each login's row and, instead of the password, the index of its *password group* (logins
//! with the same password share one), with that group's strength score and breach count.

use std::collections::HashMap;

use octapass_core::tools::breach::{count_in_range, sha1_range};
use octapass_core::tools::strength;
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use crate::error::Result;
use crate::model::Item;
use crate::vault::Vault;

/// Dismissed warnings and email breach results live in one hidden item of this type.
pub const HEALTH_SETTINGS_TYPE: &str = "healthSettings";
/// What the expiry check covers. `idDocument` is a passport, driver's licence or national ID.
const EXPIRING_TYPES: [&str; 2] = ["card", "idDocument"];
/// Cards keep it in the first, IDs in the second.
const EXPIRY_FIELDS: [&str; 2] = ["expiry", "expiryDate"];

/// At most this many range requests in flight.
const BREACH_CONCURRENCY: usize = 4;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthInputs {
    pub logins: Vec<HealthLogin>,
    pub groups: Vec<PasswordGroup>,
    /// False when a breach lookup failed; then no group has a count.
    pub breach_check_completed: bool,
    /// Cards, IDs and passports with an expiry date.
    pub expiries: Vec<HealthExpiry>,
    pub settings: HealthSettings,
}

/// What the hidden settings items say, merged: see `packages/vault-client/src/tools/healthSettings.ts`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthSettings {
    pub schema_version: u32,
    pub dismissed: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_breach_alerts: Option<Value>,
}

impl Default for HealthSettings {
    fn default() -> Self {
        Self {
            schema_version: 1,
            dismissed: Vec::new(),
            email_breach_alerts: None,
        }
    }
}

/// Two devices saving at once leave a conflict copy: dismissals are a union, and the alerts come
/// from the newest save.
pub fn read_health_settings(items: &[Item]) -> HealthSettings {
    let mut found: Vec<&Item> = items
        .iter()
        .filter(|item| is_health_settings(item))
        .collect();
    found.sort_by(|a, b| a.updated_at.cmp(&b.updated_at));
    let mut settings = HealthSettings::default();
    for item in found {
        if let Some(keys) = item.details.get("dismissed").and_then(Value::as_array) {
            for key in keys.iter().filter_map(Value::as_str) {
                if !settings.dismissed.iter().any(|known| known == key) {
                    settings.dismissed.push(key.to_owned());
                }
            }
        }
        if let Some(alerts) = item.details.get("emailBreachAlerts") {
            settings.email_breach_alerts = Some(alerts.clone());
        }
    }
    settings
}

pub fn is_health_settings(item: &Item) -> bool {
    item.overview.get("type").and_then(Value::as_str) == Some(HEALTH_SETTINGS_TYPE)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthExpiry {
    pub item_id: String,
    pub vault_id: String,
    #[serde(rename = "type")]
    pub item_type: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    pub expiry: String,
}

/// How many backup codes a login has saved; never the codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BackupCodeCount {
    pub total: u32,
    pub unused: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthLogin {
    pub item_id: String,
    pub vault_id: String,
    #[serde(rename = "type")]
    pub item_type: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls: Option<Value>,
    pub has_totp: bool,
    pub has_passkey: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_factor_method: Option<String>,
    /// For the recovery map.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The recovery email and phone and where they came from; never the backup codes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<Value>,
    /// Index into `groups`; none when the login has no password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_group: Option<usize>,
    /// When the password was last set, or the item first saved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_codes: Option<BackupCodeCount>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordGroup {
    pub score: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breach_count: Option<u64>,
}

impl Vault {
    pub fn health_inputs(&self) -> Result<HealthInputs> {
        let items = self.live_items()?;
        let email = self.snapshot().session.email.unwrap_or_default();
        let user_inputs = [email.as_str(), email.split('@').next().unwrap_or_default()];

        let mut passwords: Vec<Zeroizing<String>> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        let mut logins = Vec::new();
        for item in items.iter().filter(|item| item.is_login_like()) {
            let password_group = item.detail("password").map(|password| {
                *index.entry(password.to_owned()).or_insert_with(|| {
                    passwords.push(Zeroizing::new(password.to_owned()));
                    passwords.len() - 1
                })
            });
            logins.push(login_row(item, password_group));
        }
        // The map's keys are plaintext passwords; drop them as soon as the groups exist.
        for (mut password, _) in index.drain() {
            zeroize::Zeroize::zeroize(&mut password);
        }

        let counts = self.breach_counts(&passwords);
        let groups = passwords
            .iter()
            .enumerate()
            .map(|(i, password)| PasswordGroup {
                score: strength::estimate(password, &user_inputs).score,
                breach_count: counts.as_ref().map(|counts| counts[i]),
            })
            .collect();
        Ok(HealthInputs {
            logins,
            groups,
            breach_check_completed: counts.is_some(),
            expiries: items.iter().filter_map(expiry_row).collect(),
            settings: read_health_settings(&items),
        })
    }

    /// The logins' rows for the recovery map alone: no passwords, no breach lookups.
    pub fn recovery_logins(&self) -> Result<Vec<HealthLogin>> {
        Ok(self
            .live_items()?
            .iter()
            .filter(|item| item.is_login_like())
            .map(|item| login_row(item, None))
            .collect())
    }

    /// One range request per distinct SHA-1 prefix. `None` if any lookup failed, so no partial
    /// result is shown.
    fn breach_counts(&self, passwords: &[Zeroizing<String>]) -> Option<Vec<u64>> {
        let ranges: Vec<_> = passwords
            .iter()
            .map(|password| sha1_range(password))
            .collect();
        let mut prefixes: Vec<&str> = ranges.iter().map(|range| range.prefix.as_str()).collect();
        prefixes.sort_unstable();
        prefixes.dedup();

        let mut bodies = HashMap::new();
        for chunk in prefixes.chunks(BREACH_CONCURRENCY) {
            let fetched: Vec<_> = std::thread::scope(|scope| {
                let requests: Vec<_> = chunk
                    .iter()
                    .map(|prefix| {
                        scope.spawn(move || {
                            (
                                *prefix,
                                self.http.pwned_range(self.pwned_passwords_url(), prefix),
                            )
                        })
                    })
                    .collect();
                requests.into_iter().map(|request| request.join()).collect()
            });
            for joined in fetched {
                let (prefix, body) = joined.ok()?;
                bodies.insert(prefix, body.ok()?);
            }
        }
        Some(
            ranges
                .iter()
                .map(|range| count_in_range(&range.suffix, &bodies[range.prefix.as_str()]))
                .collect(),
        )
    }
}

fn login_row(item: &Item, password_group: Option<usize>) -> HealthLogin {
    let overview = &item.overview;
    let text = |value: Option<&Value>| value.and_then(Value::as_str).map(str::to_owned);
    HealthLogin {
        item_id: item.id.clone(),
        vault_id: item.vault_id.clone(),
        item_type: text(overview.get("type")).unwrap_or_default(),
        title: item.title().to_owned(),
        subtitle: text(overview.get("subtitle"))
            .or_else(|| item.detail("username").map(str::to_owned)),
        urls: overview.get("urls").cloned(),
        has_totp: item.detail("totp").is_some(),
        has_passkey: item
            .details
            .get("passkeys")
            .and_then(Value::as_array)
            .is_some_and(|passkeys| !passkeys.is_empty()),
        two_factor_method: text(
            item.details
                .get("recovery")
                .and_then(|recovery| recovery.get("twoFactorMethod")),
        ),
        username: item.detail("username").map(str::to_owned),
        recovery: recovery_contacts(item),
        password_group,
        password_date: password_date(item),
        backup_codes: backup_code_count(item),
    }
}

/// The newest of an imported date and the password history, else when the item was first saved. A
/// plain edit of the item doesn't count.
fn password_date(item: &Item) -> Option<String> {
    item.detail("password")?;
    let imported = item.details.get("passwordChangedAt");
    let history = item
        .details
        .get("passwordHistory")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("changedAt"));
    let newest = imported
        .into_iter()
        .chain(history)
        .filter_map(Value::as_str)
        .filter_map(|text| Some((OffsetDateTime::parse(text, &Rfc3339).ok()?, text)))
        .max_by_key(|(date, _)| *date)
        .map(|(_, text)| text.to_owned());
    newest
        .or_else(|| {
            let created = item.overview.get("createdAt")?.as_str()?;
            Some(created.to_owned())
        })
        .or_else(|| Some(item.created_at.clone()))
}

fn backup_code_count(item: &Item) -> Option<BackupCodeCount> {
    let codes = item
        .details
        .get("recovery")?
        .get("backupCodes")?
        .as_array()?;
    let used = |code: &&Value| code.get("used").and_then(Value::as_bool).unwrap_or(false);
    (!codes.is_empty()).then(|| BackupCodeCount {
        total: codes.len() as u32,
        unused: codes.iter().filter(|code| !used(code)).count() as u32,
    })
}

fn expiry_row(item: &Item) -> Option<HealthExpiry> {
    let item_type = item.overview.get("type").and_then(Value::as_str)?;
    if !EXPIRING_TYPES.contains(&item_type) {
        return None;
    }
    let expiry = EXPIRY_FIELDS.iter().find_map(|field| item.detail(field))?;
    let overview = &item.overview;
    let text = |key: &str| overview.get(key).and_then(Value::as_str).map(str::to_owned);
    Some(HealthExpiry {
        item_id: item.id.clone(),
        vault_id: item.vault_id.clone(),
        item_type: text("type").unwrap_or_default(),
        title: item.title().to_owned(),
        subtitle: text("subtitle"),
        expiry: expiry.to_owned(),
    })
}

fn recovery_contacts(item: &Item) -> Option<Value> {
    let recovery = item.details.get("recovery")?.as_object()?;
    let kept: serde_json::Map<String, Value> = ["email", "emailSource", "phone", "phoneSource"]
        .into_iter()
        .filter_map(|key| Some((key.to_owned(), recovery.get(key)?.clone())))
        .collect();
    (!kept.is_empty()).then_some(Value::Object(kept))
}
