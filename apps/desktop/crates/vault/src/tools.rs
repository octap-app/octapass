//! Local tools that need the vault or the network: one-time codes, the breach check, the values
//! the quick-access window copies (natively, so they never pass through a web view), and what
//! auto-type needs to know about a login. Also reading QR codes from images, on the device.

use std::collections::HashMap;

use octapass_core::matching::MatchMode;
use octapass_core::tools::breach::{count_in_range, sha1_range};
use octapass_core::tools::qr;
pub use octapass_core::tools::qr::QrScan;
pub use octapass_core::tools::totp::TotpCode;
use octapass_core::tools::totp::totp_code;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{Item, now, require, unix_ms};
use crate::vault::{Vault, decrypt};

/// What the quick-access window can copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CopyField {
    Username,
    Password,
    /// The current one-time code.
    Code,
}

impl Vault {
    /// The code for an item's `totp` field at `at` (Unix milliseconds), or now.
    pub fn totp(&self, totp: &str, at: Option<u64>) -> Result<TotpCode> {
        let at = at.unwrap_or_else(|| unix_ms(now()));
        totp_code(totp, at / 1000).map_err(VaultError::from)
    }

    /// How often the password appears in Pwned Passwords. Only the first five hex characters of
    /// its SHA-1 leave the device.
    pub async fn check_breached(&self, password: &str) -> Result<u64> {
        let range = sha1_range(password);
        let body = pwned_range(&self.http, &self.config.pwned_passwords_url, &range.prefix).await?;
        Ok(count_in_range(&range.suffix, &body))
    }

    pub fn copy_value(&self, id: &str, field: CopyField) -> Result<Zeroizing<String>> {
        let item = self.with_unlocked(|unlocked| {
            decrypt(
                &unlocked.session,
                unlocked.cache.item(id).ok_or(ErrorCode::NotFound)?,
            )
        })?;
        let value = match field {
            CopyField::Username => item.detail("username").map(str::to_owned),
            CopyField::Password => item.detail("password").map(str::to_owned),
            CopyField::Code => match item.detail("totp") {
                Some(totp) => Some(self.totp(totp, None)?.code),
                None => None,
            },
        };
        value
            .map(Zeroizing::new)
            .ok_or_else(|| ErrorCode::NotFound.into())
    }
}

/// The text of every QR code in a PNG, JPEG, WebP or GIF image. `invalidImage` for anything else.
pub fn read_qr_codes(image: &[u8]) -> Result<Vec<String>> {
    qr::read_image(image).map_err(VaultError::from)
}

/// What scanned QR texts hold: one-time codes, parts of a Google Authenticator export, others.
pub fn summarize_qr_scans(texts: &[String]) -> QrScan {
    qr::summarize(texts)
}

/// Where a login may be auto-typed, and what to type: the overview's URLs and match modes, and
/// `details.autoType` (`{ sequence?, windowTitles? }`). No secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoTypeItem {
    pub id: String,
    /// `login` or `password`.
    pub item_type: String,
    pub title: String,
    pub urls: Vec<String>,
    pub url_match: HashMap<String, MatchMode>,
    pub window_titles: Vec<String>,
    /// The item's own sequence; `None` for the default.
    pub sequence: Option<String>,
}

impl AutoTypeItem {
    pub(crate) fn new(item: &Item) -> Self {
        let strings = |value: Option<&Value>| -> Vec<String> {
            value
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        let settings = item.details.get("autoType");
        Self {
            id: item.id.clone(),
            item_type: item
                .overview
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            title: item.title().to_owned(),
            urls: strings(item.overview.get("urls")),
            url_match: item
                .overview
                .get("urlMatch")
                .and_then(|modes| serde_json::from_value(modes.clone()).ok())
                .unwrap_or_default(),
            window_titles: strings(settings.and_then(|settings| settings.get("windowTitles"))),
            sequence: settings
                .and_then(|settings| settings.get("sequence"))
                .and_then(Value::as_str)
                .filter(|sequence| !sequence.trim().is_empty())
                .map(str::to_owned),
        }
    }
}

impl Vault {
    /// Every login and password item outside the trash, for the global auto-type shortcut to
    /// find the one that belongs to the focused window.
    pub fn auto_type_items(&self) -> Result<Vec<AutoTypeItem>> {
        Ok(self
            .live_items()?
            .iter()
            .filter(|item| item.is_login_like())
            .map(AutoTypeItem::new)
            .collect())
    }

    pub fn auto_type_item(&self, id: &str) -> Result<AutoTypeItem> {
        let item = self.get_item(id)?;
        require(
            item.is_login_like() && item.deleted_at.is_none(),
            ErrorCode::NotFound,
        )?;
        Ok(AutoTypeItem::new(&item))
    }
}

/// One Pwned Passwords range, padded (`Add-Padding`) so its size says nothing about the prefix.
pub(crate) async fn pwned_range(
    http: &reqwest::Client,
    base: &str,
    prefix: &str,
) -> Result<String> {
    let network = |error: reqwest::Error| {
        VaultError::new(
            ErrorCode::ServerUnreachable,
            error.without_url().to_string(),
        )
    };
    let response = http
        .get(format!("{}/range/{prefix}", base.trim_end_matches('/')))
        .header("add-padding", "true")
        .send()
        .await
        .map_err(network)?;
    if !response.status().is_success() {
        return Err(VaultError::new(
            ErrorCode::ServerUnreachable,
            format!("Pwned Passwords answered {}", response.status()),
        ));
    }
    response.text().await.map_err(network)
}
