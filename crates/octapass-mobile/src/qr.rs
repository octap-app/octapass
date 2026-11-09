//! QR codes and Wi-Fi networks (plan 01, plan 14), as the Tauri phone app did them: what an item
//! can show as a code, and the item a scanned code becomes.
//! Everything here runs on the phone; nothing is sent anywhere.
//!
//! Wi-Fi networks are the `wifi` item type. Older ones are a password or login item with a
//! custom field labelled `SSID`, and optionally `Security` (`WPA`, `WEP` or `None`) and `Hidden`
//! (`Yes`); they still get Connect and a code.

use octapass_core::item_fields::normalize_iban;
use octapass_core::tools::payment_qr::{self, EpcPayment};
use octapass_core::tools::wifi::{self, TagSecurity};
use url::Url;
use zeroize::Zeroizing;

use crate::items::{
    Address, CustomField, IdentityDetails, Item, ItemDetails, ItemDraft, ItemType, LoginDetails,
    StructuredDetails, WIFI_EAP_METHODS, WIFI_PHASE2, WifiDetails, has_password, is_enterprise,
    new_item_draft, structured,
};

const SSID_LABELS: [&str; 5] = [
    "ssid",
    "network",
    "network name",
    "wi-fi network",
    "wifi network",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WifiSecurity {
    Wpa,
    Wep,
    /// An open network.
    None,
    /// WPA2 or WPA3 Enterprise: each person signs in, so there's no code to join from. Connect
    /// needs the item's `WifiDetails` for the EAP settings.
    Enterprise,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WifiNetwork {
    pub ssid: String,
    pub password: Option<String>,
    pub security: WifiSecurity,
    pub hidden: bool,
}

/// What an item can show as a QR code. The label comes from the catalog: `phone.choices.<kind>`
/// (a custom field shows its own label).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct QrChoice {
    /// `wifi`, `password`, `both`, `totp`, `website`, `contact`, `notes`, `payment`, `iban`,
    /// `address-<n>` or `field-<n>`.
    pub id: String,
    /// `wifi`, `password`, `both`, `totp`, `website`, `contact`, `note`, `payment`, `iban`,
    /// `address` or `field`.
    pub kind: String,
    /// A custom field's own label, or a wallet address's label or network.
    pub label: Option<String>,
    pub text: String,
    /// Ask for Face ID / the passcode or the master password first (`confirmUser`).
    pub confirm: bool,
    /// Say that cameras can see the screen.
    pub warn: bool,
}

fn field(fields: &[CustomField], labels: &[&str]) -> Option<String> {
    fields
        .iter()
        .find(|f| labels.contains(&f.label.trim().to_lowercase().as_str()))
        .map(|f| f.value.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn security(value: Option<&str>, password: Option<&str>) -> WifiSecurity {
    match value.map(str::to_lowercase).as_deref() {
        Some("wep") => WifiSecurity::Wep,
        Some("none" | "open" | "nopass") => WifiSecurity::None,
        Some(v) if !v.is_empty() => WifiSecurity::Wpa,
        _ if password.is_some() => WifiSecurity::Wpa,
        _ => WifiSecurity::None,
    }
}

/// The network a Wi-Fi item describes, for Connect and its code.
pub(crate) fn network_of(wifi: &WifiDetails) -> Option<WifiNetwork> {
    if wifi.ssid.is_empty() {
        return None;
    }
    let security = match wifi.security.as_str() {
        "open" => WifiSecurity::None,
        "wep" => WifiSecurity::Wep,
        s if is_enterprise(s) => WifiSecurity::Enterprise,
        _ => WifiSecurity::Wpa,
    };
    Some(WifiNetwork {
        ssid: wifi.ssid.clone(),
        password: wifi
            .password
            .clone()
            .filter(|p| !p.is_empty() && has_password(&wifi.security)),
        security,
        hidden: wifi.hidden,
    })
}

/// Reads a security type as people, routers and other apps write it ("WPA2", "wpa2-personal",
/// "None", "SAE"), as the web vault's `parseWifiSecurity` does.
pub(crate) fn parse_wifi_security(text: Option<&str>, password: Option<&str>) -> Option<String> {
    let v: String = text
        .unwrap_or_default()
        .to_lowercase()
        .chars()
        .filter(|c| !matches!(c, ' ' | '_' | '.' | '/' | '-') && !c.is_whitespace())
        .collect();
    let kind = if v.is_empty() {
        if password.is_some_and(|p| !p.is_empty()) {
            "wpa2"
        } else {
            "open"
        }
    } else if [
        "none",
        "open",
        "nopass",
        "unsecured",
        "unsecure",
        "nosecurity",
    ]
    .contains(&v.as_str())
    {
        "open"
    } else if v.contains("enterprise") || v.contains("eap") || v.contains("8021x") {
        if v.contains('3') {
            "wpa3Enterprise"
        } else {
            "wpa2Enterprise"
        }
    } else if v.starts_with("wep") {
        "wep"
    } else if v == "sae" || v.starts_with("wpa3") {
        "wpa3"
    } else if v.starts_with("wpa2wpa3") || v.starts_with("wpa2sae") || v.starts_with("wpa3wpa2") {
        "wpa2Wpa3"
    } else if v.starts_with("wpawpa2") || v.starts_with("wpa1wpa2") {
        "wpaWpa2"
    } else if v.starts_with("wpa2") || ["psk", "wpapsk", "wpa2psk"].contains(&v.as_str()) {
        "wpa2"
    } else if v.starts_with("wpa") {
        "wpa"
    } else {
        return None;
    };
    Some(kind.into())
}

/// The Wi-Fi network a password or login's fields describe, if they do.
pub(crate) fn wifi_network(password: Option<&str>, fields: &[CustomField]) -> Option<WifiNetwork> {
    let ssid = field(fields, &SSID_LABELS)?;
    let password = password.filter(|p| !p.is_empty()).map(str::to_owned);
    Some(WifiNetwork {
        ssid,
        security: security(
            field(fields, &["security", "security type"]).as_deref(),
            password.as_deref(),
        ),
        password,
        hidden: matches!(
            field(fields, &["hidden", "hidden network"])
                .map(|v| v.to_lowercase())
                .as_deref(),
            Some("yes" | "true" | "1")
        ),
    })
}

fn escape_wifi(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '\\' | ';' | ',' | ':' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The `WIFI:` text phone cameras join from. Every WPA kind is `T:WPA`, which every camera
/// reads. Enterprise networks have none (each person signs in): the text is empty.
#[uniffi::export]
pub fn wifi_qr_text(network: WifiNetwork) -> String {
    let kind = match network.security {
        WifiSecurity::Wpa => "WPA",
        WifiSecurity::Wep => "WEP",
        WifiSecurity::None => "nopass",
        WifiSecurity::Enterprise => return String::new(),
    };
    let mut text = format!("WIFI:T:{kind};S:{};", escape_wifi(&network.ssid));
    if network.security != WifiSecurity::None
        && let Some(password) = &network.password
    {
        text.push_str(&format!("P:{};", escape_wifi(password)));
    }
    if network.hidden {
        text.push_str("H:true;");
    }
    text.push(';');
    text
}

/// What goes on an NFC tag so a phone joins by tapping it: the payload of one NDEF record of type
/// `wifiTagMimeType()`. `None` when the network can't go on a tag: WEP, WPA3-only and Enterprise,
/// which Android's tap-to-join doesn't read, or a name or password too long for a network.
#[uniffi::export]
pub fn wifi_tag_payload(
    ssid: String,
    security: String,
    password: Option<String>,
) -> Option<Vec<u8>> {
    let password = password.map(Zeroizing::new);
    let credential = wifi::wsc_credential(
        &ssid,
        TagSecurity::parse(&security)?,
        password.as_deref().map(String::as_str),
    )?;
    Some(credential.to_vec())
}

#[uniffi::export]
pub fn wifi_tag_mime_type() -> String {
    wifi::WSC_MIME_TYPE.to_owned()
}

/// Reads a scanned `WIFI:` code, with the `WPA2-EAP` fields Android writes for Enterprise
/// networks (`parseWifiQr` in the web vault).
pub(crate) fn parse_wifi_details(text: &str) -> Option<WifiDetails> {
    let rest = text.strip_prefix("WIFI:")?;
    let mut fields = std::collections::HashMap::new();
    let (mut key, mut value, mut in_value) = (String::new(), String::new(), false);
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek().is_some() => value.push(chars.next().expect("peeked")),
            ':' if !in_value => {
                key = std::mem::take(&mut value);
                in_value = true;
            }
            ';' => {
                if in_value {
                    fields.insert(key.to_uppercase(), std::mem::take(&mut value));
                }
                key.clear();
                value.clear();
                in_value = false;
            }
            c => value.push(c),
        }
    }
    let ssid = fields.get("S").filter(|s| !s.is_empty())?.clone();
    let password = fields.get("P").filter(|p| !p.is_empty()).cloned();
    let kind = fields.get("T").map(|t| t.to_uppercase());
    // `T:WPA` covers the whole WPA family; WPA2 is what a router most likely uses.
    let security = if kind.as_deref() == Some("WPA") {
        "wpa2".to_owned()
    } else {
        parse_wifi_security(kind.as_deref(), password.as_deref()).unwrap_or_else(|| "wpa2".into())
    };
    let mut wifi = WifiDetails {
        ssid,
        password: password.filter(|_| security != "open"),
        hidden: fields
            .get("H")
            .is_some_and(|h| h.eq_ignore_ascii_case("true")),
        ..WifiDetails::default()
    };
    if is_enterprise(&security) {
        let known = |key: &str, names: &[&str]| {
            fields
                .get(key)
                .map(|v| v.to_lowercase())
                .filter(|v| names.contains(&v.as_str()))
        };
        wifi.eap_method = known("E", &WIFI_EAP_METHODS);
        wifi.phase2 = known("PH2", &WIFI_PHASE2);
        wifi.username = fields.get("I").filter(|v| !v.is_empty()).cloned();
        wifi.identity = fields.get("A").filter(|v| !v.is_empty()).cloned();
    }
    wifi.security = security;
    Some(wifi)
}

/// Reads a scanned `WIFI:` code as a network.
#[cfg(test)]
pub(crate) fn parse_wifi(text: &str) -> Option<WifiNetwork> {
    network_of(&parse_wifi_details(text)?)
}

/// A new Wi-Fi item for a network, named after it.
fn wifi_draft(wifi: WifiDetails, vault_id: String) -> ItemDraft {
    ItemDraft {
        title: wifi.ssid.clone(),
        subtitle: Some(wifi.ssid.clone()),
        details: ItemDetails::Wifi { wifi },
        ..new_item_draft(ItemType::Wifi, vault_id)
    }
}

fn percent_decode(text: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", text.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

fn otpauth_draft(text: &str, vault_id: String) -> Option<ItemDraft> {
    let url = Url::parse(text).ok()?;
    let query = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty())
    };
    query("secret")?;
    let label = percent_decode(url.path().trim_start_matches('/'));
    let (label_issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (Some(issuer.trim().to_owned()), account.trim().to_owned()),
        None => (None, label.trim().to_owned()),
    };
    let issuer = query("issuer")
        .or(label_issuer.filter(|i| !i.is_empty()))
        .or_else(|| (!account.is_empty()).then(|| account.clone()))
        .unwrap_or_else(|| "One-time code".into());
    Some(ItemDraft {
        title: issuer,
        details: ItemDetails::Login {
            login: LoginDetails {
                username: (!account.is_empty()).then_some(account),
                totp: Some(text.into()),
                ..LoginDetails::default()
            },
        },
        ..new_item_draft(ItemType::Login, vault_id)
    })
}

fn unescape_vtext(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('n' | 'N') => {
                    chars.next();
                    out.push('\n');
                    continue;
                }
                Some(',' | ';' | '\\') => {
                    out.push(chars.next().expect("peeked"));
                    continue;
                }
                _ => {}
            }
        }
        out.push(c);
    }
    out
}

/// Splits on `;` that aren't escaped.
fn vcard_parts(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for c in value.chars() {
        if c == ';' && !escaped {
            parts.push(unescape_vtext(&std::mem::take(&mut current)));
            continue;
        }
        escaped = c == '\\' && !escaped;
        current.push(c);
    }
    parts.push(unescape_vtext(&current));
    parts
}

fn some(text: Option<&String>) -> Option<String> {
    text.filter(|t| !t.is_empty()).cloned()
}

fn vcard_draft(text: &str, vault_id: String) -> Option<ItemDraft> {
    // Folded lines continue with a space or tab.
    let unfolded = text
        .replace("\r\n ", "")
        .replace("\r\n\t", "")
        .replace("\n ", "")
        .replace("\n\t", "");
    let mut identity = IdentityDetails::default();
    let mut full_name = String::new();
    for line in unfolded.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.split(';').next().unwrap_or_default().to_uppercase();
        match name.as_str() {
            "FN" => full_name = unescape_vtext(value),
            "N" => {
                let parts = vcard_parts(value);
                identity.last_name = some(parts.first());
                identity.first_name = some(parts.get(1));
            }
            "EMAIL" if identity.email.is_none() => identity.email = Some(unescape_vtext(value)),
            "TEL" if identity.phone.is_none() => {
                let phone = unescape_vtext(value);
                let phone = match phone.get(..4) {
                    Some(prefix) if prefix.eq_ignore_ascii_case("tel:") => phone[4..].to_owned(),
                    _ => phone,
                };
                identity.phone = Some(phone);
            }
            "ADR" if identity.address.is_none() => {
                let parts = vcard_parts(value);
                let street = parts.get(2).cloned().unwrap_or_default();
                let mut lines = street.splitn(2, '\n');
                identity.address = Some(Address {
                    line1: lines.next().map(str::to_owned).filter(|l| !l.is_empty()),
                    line2: lines.next().map(str::to_owned).filter(|l| !l.is_empty()),
                    city: some(parts.get(3)),
                    region: some(parts.get(4)),
                    postal_code: some(parts.get(5)),
                    country: some(parts.get(6)),
                });
            }
            _ => {}
        }
    }
    let title = if full_name.is_empty() {
        [identity.first_name.clone(), identity.last_name.clone()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        full_name
    };
    if title.is_empty() {
        return None;
    }
    Some(ItemDraft {
        title,
        details: ItemDetails::Identity { identity },
        ..new_item_draft(ItemType::Identity, vault_id)
    })
}

/// The new item a scanned QR code becomes (plan 01): a Wi-Fi network, a login with one-time codes
/// (`otpauth://totp/…`) or a contact (vCard). `None` for anything else. Show the draft in the
/// editor, or save it as it is.
#[uniffi::export]
pub fn scanned_draft(text: String, vault_id: String) -> Option<ItemDraft> {
    if let Some(wifi) = parse_wifi_details(&text) {
        return Some(wifi_draft(wifi, vault_id));
    }
    let lower = text.get(..15).unwrap_or(&text).to_lowercase();
    if lower.starts_with("otpauth://totp/") {
        return otpauth_draft(&text, vault_id);
    }
    if lower.starts_with("begin:vcard") {
        return vcard_draft(&text, vault_id);
    }
    None
}

fn uri_component(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

/// The item's `otpauth://` URI, or one built from a bare secret, so another app can take over.
fn otpauth_uri(item: &Item, login: &LoginDetails) -> String {
    let totp = login.totp.as_deref().unwrap_or_default().trim();
    if totp.to_lowercase().starts_with("otpauth://") {
        return totp.into();
    }
    let issuer = &item.title;
    let account = login
        .username
        .as_deref()
        .filter(|u| !u.is_empty())
        .unwrap_or(issuer);
    let secret: String = totp
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    format!(
        "otpauth://totp/{}:{}?secret={secret}&issuer={}",
        uri_component(issuer),
        uri_component(account),
        uri_component(issuer)
    )
}

fn vtext(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace(',', "\\,")
        .replace(';', "\\;")
}

/// A vCard 4.0 with the identity's contact fields.
fn vcard(identity: &IdentityDetails) -> String {
    let first = identity.first_name.clone().unwrap_or_default();
    let last = identity.last_name.clone().unwrap_or_default();
    let mut lines = vec![
        "BEGIN:VCARD".to_owned(),
        "VERSION:4.0".to_owned(),
        format!("FN:{}", vtext(format!("{first} {last}").trim())),
        format!("N:{};{};;;", vtext(&last), vtext(&first)),
    ];
    if let Some(email) = identity.email.as_deref().filter(|e| !e.is_empty()) {
        lines.push(format!("EMAIL:{}", vtext(email)));
    }
    if let Some(phone) = identity.phone.as_deref().filter(|p| !p.is_empty()) {
        lines.push(format!("TEL:{}", vtext(phone)));
    }
    if let Some(a) = &identity.address {
        let parts = [
            &a.line1,
            &a.line2,
            &a.city,
            &a.region,
            &a.postal_code,
            &a.country,
        ];
        if parts
            .iter()
            .any(|p| p.as_deref().is_some_and(|p| !p.is_empty()))
        {
            let street = [&a.line1, &a.line2]
                .into_iter()
                .filter_map(|l| l.as_deref().filter(|l| !l.is_empty()))
                .collect::<Vec<_>>()
                .join("\n");
            let rest = [
                &street,
                &opt(&a.city),
                &opt(&a.region),
                &opt(&a.postal_code),
                &opt(&a.country),
            ]
            .map(|p| vtext(p))
            .join(";");
            lines.push(format!("ADR:;;{rest}"));
        }
    }
    if let Some(birth) = identity.birth_date.as_deref().filter(|b| !b.is_empty()) {
        lines.push(format!("BDAY:{}", birth.replace('-', "")));
    }
    lines.push("END:VCARD".into());
    lines.join("\r\n")
}

fn opt(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

fn choice(id: &str, kind: &str, text: String, secret: bool) -> QrChoice {
    QrChoice {
        id: id.into(),
        kind: kind.into(),
        label: None,
        text,
        confirm: secret,
        warn: secret,
    }
}

/// What an item can show as a QR code, the scan-to-act kinds first (plan 01): Wi-Fi joins,
/// contacts, one-time code setup, websites; otherwise the password or a field as text. Payment
/// cards never have one.
#[uniffi::export]
pub fn qr_choices(item: Item) -> Vec<QrChoice> {
    match &item.details {
        ItemDetails::Wifi { .. } => item.wifi.map(wifi_choices).unwrap_or_default(),
        ItemDetails::Login { login } | ItemDetails::Password { login } => {
            // An older Wi-Fi item, until it's moved to the Wi-Fi type.
            if let Some(network) = item.wifi.clone() {
                return wifi_choices(network);
            }
            let mut choices = Vec::new();
            if let Some(password) = login.password.as_deref().filter(|p| !p.is_empty()) {
                choices.push(choice("password", "password", password.into(), true));
                if let Some(username) = login.username.as_deref().filter(|u| !u.is_empty()) {
                    choices.push(choice(
                        "both",
                        "both",
                        format!("{username}\n{password}"),
                        true,
                    ));
                }
            }
            if login.totp.as_deref().is_some_and(|t| !t.is_empty()) {
                choices.push(choice("totp", "totp", otpauth_uri(&item, login), true));
            }
            if let Some(url) = item.urls.first() {
                choices.push(choice("website", "website", url.clone(), false));
            }
            choices
        }
        ItemDetails::Identity { identity } => {
            vec![choice("contact", "contact", vcard(identity), false)]
        }
        ItemDetails::SecureNote { note } if !note.notes.is_empty() => {
            vec![choice("notes", "note", note.notes.clone(), false)]
        }
        ItemDetails::Structured {
            item_type: ItemType::BankAccount,
            structured,
        } => bank_choices(structured),
        ItemDetails::Structured {
            item_type: ItemType::CryptoWallet,
            structured,
        } => wallet_choices(structured),
        _ => Vec::new(),
    }
}

/// What someone needs to pay this account, which isn't secret. The PIN never has a code.
fn bank_choices(bank: &StructuredDetails) -> Vec<QrChoice> {
    let Some(iban) = structured::value(bank, "iban") else {
        return Vec::new();
    };
    let plain = choice("iban", "iban", normalize_iban(iban), false);
    match bank_qr_text(bank.clone(), String::new(), String::new()) {
        Some(text) => vec![choice("payment", "payment", text, false), plain],
        None => vec![plain],
    }
}

/// The EPC QR text that asks a banking app to pay this account, with an optional amount in euros
/// (`12.50`) and reference. `None` when the IBAN isn't a SEPA one, the account has no holder's name,
/// or the amount or reference doesn't fit the format.
#[uniffi::export]
pub fn bank_qr_text(bank: StructuredDetails, amount: String, reference: String) -> Option<String> {
    payment_qr::epc_qr_text(&EpcPayment {
        name: structured::value(&bank, "accountHolder").unwrap_or_default(),
        iban: structured::value(&bank, "iban").unwrap_or_default(),
        bic: structured::value(&bank, "swift").unwrap_or_default(),
        amount: &amount,
        reference: &reference,
    })
}

/// Addresses only, never the seed phrase. A wallet's own fields have no code either: a seed could be
/// in one.
fn wallet_choices(wallet: &StructuredDetails) -> Vec<QrChoice> {
    wallet
        .addresses
        .iter()
        .enumerate()
        .filter_map(|(i, entry)| {
            let address = entry.address.trim();
            let text = payment_qr::address_uri(&entry.network, address)
                .or_else(|| payment_qr::looks_like_address(address).then(|| address.to_owned()))?;
            Some(QrChoice {
                label: Some(entry.label.clone().unwrap_or_else(|| entry.network.clone())),
                ..choice(&format!("address-{i}"), "address", text, false)
            })
        })
        .collect()
}

/// Wi-Fi passwords are meant to be shared at home: no confirmation for them. Enterprise ones
/// are people's own.
fn wifi_choices(network: WifiNetwork) -> Vec<QrChoice> {
    let password = network.password.clone();
    if network.security == WifiSecurity::Enterprise {
        return password
            .map(|p| vec![choice("password", "password", p, true)])
            .unwrap_or_default();
    }
    let mut choices = vec![choice("wifi", "wifi", wifi_qr_text(network), false)];
    if let Some(password) = password {
        choices.push(choice("password", "password", password, false));
    }
    choices
}

/// One-time codes found in scanned QR codes.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ScannedCode {
    /// The canonical `otpauth://` link, as a login's one-time code stores it. A secret.
    pub uri: String,
    pub issuer: Option<String>,
    pub account: Option<String>,
    /// Counter-based (HOTP): kept, but its codes can't be shown yet.
    pub counter_based: bool,
}

/// A Google Authenticator export split over several QR codes, some still to scan.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ExportBatch {
    pub id: i64,
    pub size: u32,
    /// The parts scanned so far, counted from 1 ("2 of 3").
    pub scanned: Vec<u32>,
}

/// What scanned QR texts hold (`summarize` in the core).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct QrScan {
    pub codes: Vec<ScannedCode>,
    pub incomplete: Vec<ExportBatch>,
    /// QR codes that aren't one-time codes (a website, Wi-Fi, a contact, …).
    pub other: u32,
    /// QR codes that look like one-time codes but can't be read.
    pub broken: u32,
}

/// The text of every QR code in a PNG, JPEG, WebP or GIF image (a photo, a screenshot), read on
/// the phone. Fails with `invalidImage` for anything else.
#[uniffi::export]
pub fn read_qr_codes(image: Vec<u8>) -> crate::Result<Vec<String>> {
    let image = zeroize::Zeroizing::new(image);
    Ok(octapass_mobile_vault::vault::read_qr_codes(&image)?)
}

/// Says what scanned QR texts hold, joining the parts of a split Google Authenticator export.
/// Pass every text scanned so far: scanning the same code twice changes nothing.
#[uniffi::export]
pub fn summarize_qr_scans(texts: Vec<String>) -> QrScan {
    let scan = octapass_mobile_vault::vault::summarize_qr_scans(&texts);
    QrScan {
        codes: scan
            .codes
            .into_iter()
            .map(|code| ScannedCode {
                uri: code.uri.to_string(),
                issuer: code.issuer,
                account: code.account,
                counter_based: code.counter_based,
            })
            .collect(),
        incomplete: scan
            .incomplete
            .into_iter()
            .map(|batch| ExportBatch {
                id: batch.id,
                size: batch.size,
                scanned: batch.scanned,
            })
            .collect(),
        other: scan.other as u32,
        broken: scan.broken as u32,
    }
}

#[cfg(test)]
mod payment_tests {
    use crate::items::ItemDetails;
    use crate::structured::{FieldValue, StructuredDetails, WalletAddress};

    use super::*;

    fn item(item_type: ItemType, structured: StructuredDetails) -> Item {
        Item {
            id: "i".into(),
            vault_id: "v".into(),
            revision: 1,
            created_at: String::new(),
            updated_at: String::new(),
            deleted_at: None,
            item_type: item_type.clone(),
            title: "T".into(),
            subtitle: None,
            urls: Vec::new(),
            url_match: std::collections::HashMap::new(),
            tags: Vec::new(),
            favorite: false,
            details: ItemDetails::Structured {
                item_type,
                structured,
            },
            attachments: Vec::new(),
            wifi: None,
            shown_created_at: None,
            shown_updated_at: None,
            last_used_at: None,
            password_changed_at: None,
            pinned: false,
            places: Vec::new(),
        }
    }

    fn values(pairs: &[(&str, &str)]) -> Vec<FieldValue> {
        pairs
            .iter()
            .map(|(key, value)| FieldValue {
                key: (*key).into(),
                value: (*value).into(),
            })
            .collect()
    }

    #[test]
    fn a_bank_account_offers_a_payment_code_and_never_the_pin() {
        let bank = StructuredDetails {
            values: values(&[
                ("iban", "DE89 3704 0044 0532 0130 00"),
                ("accountHolder", "Ada"),
                ("pin", "9876"),
            ]),
            ..StructuredDetails::default()
        };
        let choices = qr_choices(item(ItemType::BankAccount, bank.clone()));
        assert_eq!(
            choices.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            ["payment", "iban"]
        );
        assert!(
            choices
                .iter()
                .all(|c| !c.confirm && !c.text.contains("9876"))
        );
        assert_eq!(
            choices[0].text,
            "BCD\n002\n1\nSCT\n\nAda\nDE89370400440532013000"
        );
        assert_eq!(
            bank_qr_text(bank, "12.5".into(), "Rent".into()).unwrap(),
            "BCD\n002\n1\nSCT\n\nAda\nDE89370400440532013000\nEUR12.50\n\n\nRent"
        );
    }

    #[test]
    fn an_iban_outside_sepa_is_text_only() {
        let bank = StructuredDetails {
            values: values(&[
                ("iban", "JO94CBJO0010000000000131000302"),
                ("accountHolder", "Ada"),
            ]),
            ..StructuredDetails::default()
        };
        let choices = qr_choices(item(ItemType::BankAccount, bank));
        assert_eq!(
            choices.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            ["iban"]
        );
    }

    #[test]
    fn a_wallet_shows_addresses_and_nothing_else() {
        let seed = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let wallet = StructuredDetails {
            values: values(&[("seedPhrase", seed), ("passphrase", "p")]),
            addresses: vec![
                WalletAddress {
                    network: "bitcoin".into(),
                    address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".into(),
                    label: None,
                },
                WalletAddress {
                    network: "bitcoin".into(),
                    // Pasted in the wrong place: still no code.
                    address: seed.into(),
                    label: Some("oops".into()),
                },
            ],
            custom_fields: vec![CustomField {
                label: "Backup".into(),
                value: seed.into(),
                hidden: true,
            }],
            ..StructuredDetails::default()
        };
        let choices = qr_choices(item(ItemType::CryptoWallet, wallet));
        assert_eq!(choices.len(), 1);
        assert_eq!(
            choices[0].text,
            "bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        );
        assert!(choices.iter().all(|c| !c.text.contains("legal")));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn item(kind: &str, details: serde_json::Value) -> Item {
        Item::from(&octapass_mobile_vault::model::Item {
            id: "0190a6c4-7d00-7000-8000-000000000001".into(),
            vault_id: "v".into(),
            revision: 1,
            created_at: String::new(),
            updated_at: String::new(),
            deleted_at: None,
            overview: json!({ "type": kind, "title": "Home", "urls": ["https://router.local"] }),
            details,
        })
    }

    #[test]
    fn wifi_codes_round_trip_with_escapes() {
        let network = WifiNetwork {
            ssid: "My;Net".into(),
            password: Some("pa:ss\\".into()),
            security: WifiSecurity::Wpa,
            hidden: true,
        };
        let text = wifi_qr_text(network.clone());
        assert_eq!(text, "WIFI:T:WPA;S:My\\;Net;P:pa\\:ss\\\\;H:true;;");
        assert_eq!(parse_wifi(&text), Some(network));
        assert_eq!(
            parse_wifi("WIFI:S:Cafe;T:nopass;;").unwrap().security,
            WifiSecurity::None
        );
        assert_eq!(parse_wifi("WIFI:T:WPA;;"), None);
    }

    #[test]
    fn scanned_codes_become_drafts() {
        let wifi = scanned_draft("WIFI:T:WEP;S:Cafe;P:secret;;".into(), "v".into()).unwrap();
        let ItemDetails::Wifi { wifi: network } = &wifi.details else {
            panic!("a Wi-Fi item");
        };
        assert_eq!(wifi.title, "Cafe");
        assert_eq!(network.password.as_deref(), Some("secret"));
        assert_eq!(network.security, "wep");

        let eap = scanned_draft(
            "WIFI:T:WPA2-EAP;S:Office;E:PEAP;PH2:MSCHAPV2;I:ada;P:pw;;".into(),
            "v".into(),
        )
        .unwrap();
        let ItemDetails::Wifi { wifi: network } = &eap.details else {
            panic!("a Wi-Fi item");
        };
        assert_eq!(network.security, "wpa2Enterprise");
        assert_eq!(network.eap_method.as_deref(), Some("peap"));
        assert_eq!(network.phase2.as_deref(), Some("mschapv2"));
        assert_eq!(network.username.as_deref(), Some("ada"));

        let otp = scanned_draft(
            "otpauth://totp/GitHub:ada%40example.com?secret=JBSWY3DPEHPK3PXP".into(),
            "v".into(),
        )
        .unwrap();
        let ItemDetails::Login { login } = &otp.details else {
            panic!("a login");
        };
        assert_eq!(otp.title, "GitHub");
        assert_eq!(login.username.as_deref(), Some("ada@example.com"));

        let card = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ada Lovelace\r\nN:Lovelace;Ada;;;\r\nEMAIL:ada@example.com\r\nTEL:tel:+44 20\r\nADR:;;1 Main St\\nFlat 2;London;;N1;UK\r\nEND:VCARD";
        let contact = scanned_draft(card.into(), "v".into()).unwrap();
        let ItemDetails::Identity { identity } = &contact.details else {
            panic!("an identity");
        };
        assert_eq!(contact.title, "Ada Lovelace");
        assert_eq!(identity.phone.as_deref(), Some("+44 20"));
        let address = identity.address.clone().unwrap();
        assert_eq!(address.line2.as_deref(), Some("Flat 2"));
        assert_eq!(address.city.as_deref(), Some("London"));

        assert_eq!(scanned_draft("hello".into(), "v".into()), None);
        assert_eq!(scanned_draft("otpauth://totp/x".into(), "v".into()), None);
    }

    #[test]
    fn choices_follow_plan_01() {
        let wifi = item(
            "password",
            json!({ "password": "pw", "customFields": [{ "label": "SSID", "value": "Home", "hidden": false }] }),
        );
        let ids: Vec<(String, bool)> = qr_choices(wifi)
            .into_iter()
            .map(|c| (c.id, c.confirm))
            .collect();
        assert_eq!(ids, [("wifi".into(), false), ("password".into(), false)]);

        let typed = item(
            "wifi",
            json!({ "ssid": "Home", "security": "wpa3", "password": "pw123456" }),
        );
        let choices = qr_choices(typed);
        assert_eq!(choices[0].text, "WIFI:T:WPA;S:Home;P:pw123456;;");
        assert_eq!(choices.len(), 2);
        // Enterprise networks have no code to join from; the password is the user's own.
        let enterprise = item(
            "wifi",
            json!({ "ssid": "Office", "security": "wpa2Enterprise", "password": "mine" }),
        );
        let ids: Vec<(String, bool)> = qr_choices(enterprise)
            .into_iter()
            .map(|c| (c.id, c.confirm))
            .collect();
        assert_eq!(ids, [("password".into(), true)]);

        let login = item(
            "login",
            json!({ "username": "ada", "password": "pw", "totp": "jbsw y3dp ehpk 3pxp" }),
        );
        let choices = qr_choices(login);
        let ids: Vec<&str> = choices.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["password", "both", "totp", "website"]);
        assert!(choices[0].confirm && choices[0].warn);
        assert_eq!(
            choices[2].text,
            "otpauth://totp/Home:ada?secret=JBSWY3DPEHPK3PXP&issuer=Home"
        );

        assert!(qr_choices(item("card", json!({ "number": "4111" }))).is_empty());
        let contact = qr_choices(item(
            "identity",
            json!({ "firstName": "Ada", "lastName": "L" }),
        ));
        assert!(contact[0].text.contains("FN:Ada L\r\nN:L;Ada;;;"));
    }
}
