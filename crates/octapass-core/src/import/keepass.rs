//! KeePass 2 and KeePassXC: KDBX 3.1 and 4 databases (password and/or key file), KeePass's
//! unencrypted XML export, and the CSV exports of KeePassXC
//! (`Group,Title,Username,Password,URL,Notes,TOTP,Icon,Last Modified,Created`) and KeePass 2
//! (`Account,Login Name,Password,Web Site,Comments`).
//!
//! Databases and the XML export share one path. Entries become logins, or secure notes when they
//! only have notes. The group path below the root group becomes a tag, next to the entry's own
//! tags, and the Recycle Bin is left out. Other strings become custom fields, hidden when
//! protected. Earlier passwords in the entry history become password history. One-time code
//! setups from KeePassXC (`otp`), KeePass (`TimeOtp-*`) and older plugins (`TOTP Seed`) become the
//! login's TOTP. Attachments aren't imported.
//!
//! An entry's `UUID` is kept so importing the database again updates it, and its `Times`
//! (`CreationTime`, `LastModificationTime`, `LastAccessTime`) become its dates; `ExpiryTime`, when
//! `Expires` is on, is kept as an "Expires" field. Auto-type's default sequence and window titles
//! become the login's desktop auto-type settings. KeePassXC passkeys (`KPEX_PASSKEY_*` strings, as
//! KeePassXC's `src/browser/PasskeyUtils` writes them) become passkeys that can sign in. The
//! KeePassXC CSV's `Created` and `Last Modified` columns are dates too. Sources: KeePassXC's
//! `KdbxXmlReader.cpp` and `CsvExporter.cpp`, and KeePass's KDBX XML schema.

mod kdbx;
mod xml;

use std::collections::HashSet;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Map;
use zeroize::Zeroizing;

use super::build::{
    Collector, ItemMeta, LoginFields, clean, custom_field, extra_fields, rfc3339, skipped_row,
    split_tags, timestamp,
};
use super::csv_table::{CsvTable, invalid};
use super::{ImportError, ImportOptions, ImportResult, decode_text};
use crate::encoding::{b64_encode, base32_decode};
use crate::item::{CustomField, Passkey, PasswordHistoryEntry};
use crate::tools::otpauth::{OtpAlgorithm, OtpKind, OtpParams};
use xml::{Document, Entry, Field};

pub(super) fn parse(bytes: &[u8], options: &ImportOptions) -> Result<ImportResult, ImportError> {
    if bytes.starts_with(&kdbx::SIGNATURE) {
        let mut opened = kdbx::open(
            bytes,
            options.password.as_deref().map(String::as_str),
            options.key_file.as_deref().map(Vec::as_slice),
        )?;
        let damaged = || invalid("This KeePass database is damaged.");
        let xml = opened
            .xml
            .strip_prefix(b"\xef\xbb\xbf")
            .unwrap_or(&opened.xml);
        let text = std::str::from_utf8(xml).map_err(|_| damaged())?;
        let document = xml::parse(text, &mut opened.stream).ok_or_else(damaged)?;
        return Ok(convert(document));
    }
    let text = decode_text(bytes)?;
    if text.trim_start().starts_with('<') {
        let document = xml::parse(&text, &mut kdbx::InnerStream::None)
            .ok_or_else(|| invalid("This is not a KeePass XML export."))?;
        return Ok(convert(document));
    }
    parse_csv(&text)
}

fn convert(document: Document) -> ImportResult {
    let Document {
        groups,
        entries,
        recycle_bin,
    } = document;
    // Parents come before their children, so one pass finds every group's place.
    let mut binned_groups = vec![false; groups.len()];
    let mut paths: Vec<Option<String>> = Vec::with_capacity(groups.len());
    for (index, group) in groups.iter().enumerate() {
        let parent = group.parent.filter(|&p| p < index);
        binned_groups[index] =
            recycle_bin.as_ref() == Some(&group.uuid) || parent.is_some_and(|p| binned_groups[p]);
        // The root group is named after the database, so it isn't part of the tag.
        paths.push(parent.map(|p| match &paths[p] {
            Some(path) => format!("{path}/{}", group.name.trim()),
            None => group.name.trim().to_string(),
        }));
    }
    let mut out = Collector::default();
    let (mut binned, mut with_attachments) = (0, 0);
    for (index, entry) in entries.into_iter().enumerate() {
        if entry.group.is_some_and(|g| binned_groups[g]) {
            binned += 1;
            out.skip(None);
            continue;
        }
        with_attachments += usize::from(entry.attachments > 0);
        let mut tags: Vec<String> = entry
            .group
            .and_then(|g| clean(paths[g].as_deref()))
            .into_iter()
            .collect();
        tags.extend(split_tags(Some(&entry.tags)));
        out.add_login(login_fields(entry, tags), || {
            format!(
                "Entry {} skipped: no URL, username, password or notes.",
                index + 1
            )
        });
    }
    warn_binned(&mut out, binned);
    if with_attachments > 0 {
        out.warn(format!(
            "{} attachments, which weren't imported. Save them from KeePass and add them to the items in Octa Pass.",
            if with_attachments == 1 {
                "1 entry has".to_string()
            } else {
                format!("{with_attachments} entries have")
            }
        ));
    }
    out.finish()
}

/// Entries in the Recycle Bin are counted as skipped, with one line for all of them.
fn warn_binned(out: &mut Collector, binned: usize) {
    match binned {
        0 => {}
        1 => out.warn("1 entry in the Recycle Bin was left out."),
        n => out.warn(format!("{n} entries in the Recycle Bin were left out.")),
    }
}

fn login_fields(entry: Entry, tags: Vec<String>) -> LoginFields {
    let Entry {
        uuid,
        mut strings,
        created,
        modified,
        accessed,
        expires,
        expiry,
        history,
        auto_type,
        ..
    } = entry;
    let title = take(&mut strings, "Title");
    let username = take(&mut strings, "UserName");
    let password = take(&mut strings, "Password");
    let mut urls: Vec<String> = take(&mut strings, "URL").into_iter().collect();
    // KeePassXC's and Keepass2Android's additional URLs.
    let (more_urls, mut strings): (Vec<Field>, Vec<Field>) = strings
        .into_iter()
        .partition(|f| f.key == "KP2A_URL" || f.key.starts_with("KP2A_URL_"));
    urls.extend(more_urls.into_iter().map(|f| f.value));
    let notes = take(&mut strings, "Notes").map(|notes| notes.replace("\r\n", "\n"));
    let totp = take_totp(&mut strings, title.as_deref(), username.as_deref());
    let passkeys = take_passkey(&mut strings, created.as_deref())
        .into_iter()
        .collect();
    let mut custom_fields: Vec<CustomField> = strings
        .iter()
        .filter(|f| !f.value.is_empty())
        .map(|f| {
            let label = if f.key.trim().is_empty() {
                "Field"
            } else {
                &f.key
            };
            custom_field(label, &f.value, f.protected)
        })
        .collect();
    if expires && let Some(expiry) = expiry {
        custom_fields.push(custom_field("Expires", &expiry, false));
    }
    let password_history = password_history(&history, password.as_deref(), modified.clone());
    let mut details_extra = Map::new();
    let windows: Vec<serde_json::Value> = auto_type.windows.into_iter().map(Into::into).collect();
    if !auto_type.disabled && (auto_type.sequence.is_some() || !windows.is_empty()) {
        let mut settings = Map::new();
        if let Some(sequence) = auto_type.sequence {
            settings.insert("sequence".into(), sequence.into());
        }
        if !windows.is_empty() {
            settings.insert("windowTitles".into(), windows.into());
        }
        details_extra.insert("autoType".into(), settings.into());
    }
    LoginFields {
        title,
        urls,
        username,
        password,
        totp,
        notes,
        tags,
        custom_fields,
        password_history,
        passkeys,
        details_extra,
        meta: ItemMeta {
            created_at: created,
            updated_at: modified,
            last_used_at: accessed,
            source_id: Some(uuid),
        },
        ..LoginFields::default()
    }
}

/// A KeePassXC passkey (`KPEX_PASSKEY_*`), removing its strings. Without a relying party or key
/// the strings stay as custom fields.
fn take_passkey(fields: &mut Vec<Field>, created: Option<&str>) -> Option<Passkey> {
    let get = |key: &str| {
        fields
            .iter()
            .find(|f| f.key == key)
            .map(|f| f.value.trim().to_string())
    };
    let rp_id = get("KPEX_PASSKEY_RELYING_PARTY").filter(|rp| !rp.is_empty())?;
    let pem = get("KPEX_PASSKEY_PRIVATE_KEY_PEM")?;
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = Zeroizing::new(STANDARD.decode(body.trim()).ok()?);
    let mut extra = Map::new();
    extra.insert(
        "credentialId".into(),
        get("KPEX_PASSKEY_CREDENTIAL_ID")?.into(),
    );
    extra.insert(
        "userHandle".into(),
        get("KPEX_PASSKEY_USER_HANDLE").unwrap_or_default().into(),
    );
    extra.insert("privateKey".into(), b64_encode(&der).into());
    extra.insert("signCount".into(), 0.into());
    let user_name = get("KPEX_PASSKEY_USERNAME").unwrap_or_default();
    fields.retain(|f| !f.key.starts_with("KPEX_PASSKEY_"));
    Some(Passkey {
        rp_id,
        user_name,
        created_at: created.map_or_else(|| rfc3339(0), str::to_string),
        extra,
    })
}

/// Removes the first string named `key` and returns its value.
fn take(fields: &mut Vec<Field>, key: &str) -> Option<String> {
    let index = fields.iter().position(|f| f.key == key)?;
    Some(fields.remove(index).value)
}

/// Earlier passwords, newest first. Each one's date is when the next version replaced it.
fn password_history(
    history: &[Entry],
    current: Option<&str>,
    modified: Option<String>,
) -> Vec<PasswordHistoryEntry> {
    let mut seen: HashSet<&str> = current.into_iter().collect();
    let mut out = Vec::new();
    let mut replaced_at = modified;
    for old in history.iter().rev() {
        let password = old
            .strings
            .iter()
            .find(|f| f.key == "Password")
            .map(|f| f.value.as_str())
            .filter(|p| !p.is_empty());
        if let Some(password) = password
            && seen.insert(password)
        {
            out.push(PasswordHistoryEntry {
                password: password.to_string(),
                changed_at: replaced_at
                    .clone()
                    .or_else(|| old.modified.clone())
                    .unwrap_or_else(|| rfc3339(0)),
                extra: Map::new(),
            });
        }
        replaced_at = old.modified.clone();
    }
    out
}

/// The one-time code setup as a TOTP or HOTP for the login, removing the strings it came from. A
/// setup Octa Pass can't compute (Steam) stays: as the `otp` value (which [`LoginFields`] keeps as
/// a hidden field, with a warning) or as the original strings.
fn take_totp(
    fields: &mut Vec<Field>,
    title: Option<&str>,
    username: Option<&str>,
) -> Option<String> {
    let uri = |mut params: OtpParams| {
        params.issuer = clean(title);
        params.account = clean(username);
        params.to_uri().to_string()
    };
    if let Some(otp) = take(fields, "otp") {
        if otp.trim().to_ascii_lowercase().starts_with("otpauth://") {
            return Some(otp);
        }
        // KeeOtp, and KeePassXC before 2.6: `key=…&size=…&step=…`.
        return Some(key_value_otp(&otp).map(uri).unwrap_or(otp));
    }
    if let Some(params) = time_otp(fields) {
        fields.retain(|f| !f.key.starts_with("TimeOtp-"));
        return Some(uri(params));
    }
    if let Some(params) = hmac_otp(fields) {
        fields.retain(|f| !f.key.starts_with("HmacOtp-"));
        return Some(uri(params));
    }
    // KeeTrayTOTP and KeePassXC before 2.6: a base32 seed and `period;digits` (`S` for Steam).
    let get = |key: &str| fields.iter().find(|f| f.key == key).map(|f| f.value.trim());
    let seed = base32_decode(get("TOTP Seed")?)?;
    let (period, digits) = get("TOTP Settings").unwrap_or("30;6").split_once(';')?;
    let digits = digits.split(';').next()?;
    let params = totp(
        seed,
        OtpAlgorithm::Sha1,
        digits.parse().ok()?,
        period.parse().ok()?,
    )?;
    fields.retain(|f| f.key != "TOTP Seed" && f.key != "TOTP Settings");
    Some(uri(params))
}

/// KeePass 2.47+'s own fields: `TimeOtp-Secret-Base32` (or `-Hex`, `-Base64`, or UTF-8
/// `TimeOtp-Secret`), `TimeOtp-Length`, `TimeOtp-Period` and `TimeOtp-Algorithm`.
fn time_otp(fields: &[Field]) -> Option<OtpParams> {
    let get = |key: &str| fields.iter().find(|f| f.key == key).map(|f| f.value.trim());
    let secret = otp_secret(fields, "TimeOtp-Secret")?;
    let algorithm = match get("TimeOtp-Algorithm") {
        None | Some("HMAC-SHA-1") => OtpAlgorithm::Sha1,
        Some("HMAC-SHA-256") => OtpAlgorithm::Sha256,
        Some("HMAC-SHA-512") => OtpAlgorithm::Sha512,
        Some(_) => return None,
    };
    totp(
        secret,
        algorithm,
        get("TimeOtp-Length").map_or(Some(6), |d| d.parse().ok())?,
        get("TimeOtp-Period").map_or(Some(30), |p| p.parse().ok())?,
    )
}

/// KeePass's HOTP fields: `HmacOtp-Secret` (or `-Hex`, `-Base32`, `-Base64`) and `HmacOtp-Counter`,
/// always six digits of HMAC-SHA-1.
fn hmac_otp(fields: &[Field]) -> Option<OtpParams> {
    let get = |key: &str| fields.iter().find(|f| f.key == key).map(|f| f.value.trim());
    hotp(
        otp_secret(fields, "HmacOtp-Secret")?,
        OtpAlgorithm::Sha1,
        6,
        get("HmacOtp-Counter").map_or(Some(0), |c| c.parse().ok())?,
    )
}

/// The secret KeePass keeps under `prefix`, in one of its four encodings.
fn otp_secret(fields: &[Field], prefix: &str) -> Option<Vec<u8>> {
    let get = |suffix: &str| {
        let key = format!("{prefix}{suffix}");
        fields.iter().find(|f| f.key == key).map(|f| f.value.trim())
    };
    if let Some(secret) = get("-Base32") {
        base32_decode(secret)
    } else if let Some(secret) = get("-Hex") {
        let digits: Vec<u8> = secret
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        kdbx::hex_decode(&digits)
    } else if let Some(secret) = get("-Base64") {
        STANDARD.decode(secret).ok()
    } else {
        Some(get("")?.as_bytes().to_vec())
    }
}

/// `key=JBSWY3DP&size=6&step=30&otpHashMode=Sha256&encoding=base32&type=Totp`, or `type=Hotp` with
/// a `counter`.
fn key_value_otp(text: &str) -> Option<OtpParams> {
    let pairs: Vec<(String, String)> = text
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((
                key.trim().to_ascii_lowercase(),
                percent_decode(value.trim()),
            ))
        })
        .collect();
    let get = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.to_ascii_lowercase())
    };
    let kind = get("type");
    if kind
        .as_deref()
        .is_some_and(|kind| kind != "totp" && kind != "hotp")
    {
        return None;
    }
    let key = pairs.iter().find(|(k, _)| k == "key")?.1.as_str();
    let secret = match get("encoding").as_deref() {
        None | Some("base32") => base32_decode(key)?,
        Some("base64") => STANDARD.decode(key).ok()?,
        Some("hex") => kdbx::hex_decode(key.as_bytes())?,
        Some("utf8" | "utf-8") => key.as_bytes().to_vec(),
        Some(_) => return None,
    };
    let algorithm = match get("otphashmode").as_deref() {
        None | Some("sha1") => OtpAlgorithm::Sha1,
        Some("sha256") => OtpAlgorithm::Sha256,
        Some("sha512") => OtpAlgorithm::Sha512,
        Some(_) => return None,
    };
    let digits = get("size").map_or(Some(6), |d| d.parse().ok())?;
    if kind.as_deref() == Some("hotp") {
        let counter = get("counter").map_or(Some(0), |c| c.parse().ok())?;
        return hotp(secret, algorithm, digits, counter);
    }
    totp(
        secret,
        algorithm,
        digits,
        get("step").map_or(Some(30), |p| p.parse().ok())?,
    )
}

fn hotp(secret: Vec<u8>, algorithm: OtpAlgorithm, digits: u32, counter: u64) -> Option<OtpParams> {
    let usable = !secret.is_empty() && (6..=8).contains(&digits);
    usable.then(|| OtpParams {
        kind: OtpKind::Hotp { counter },
        secret: Zeroizing::new(secret),
        algorithm,
        digits,
        issuer: None,
        account: None,
    })
}

fn totp(secret: Vec<u8>, algorithm: OtpAlgorithm, digits: u32, period: u64) -> Option<OtpParams> {
    let usable = !secret.is_empty() && (6..=8).contains(&digits) && (1..=3600).contains(&period);
    usable.then(|| OtpParams {
        kind: OtpKind::Totp { period },
        secret: Zeroizing::new(secret),
        algorithm,
        digits,
        issuer: None,
        account: None,
    })
}

/// `%XX` escapes, as KeeOtp writes `=` padding; anything else is left as it is.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = (bytes[i] == b'%')
            .then(|| kdbx::hex_decode(bytes.get(i + 1..i + 3)?))
            .flatten();
        match escaped {
            Some(byte) => {
                out.extend(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_csv(text: &str) -> Result<ImportResult, ImportError> {
    let table = CsvTable::parse(text, b',')?;
    if table.has(&["group"]) && table.has(&["title"]) && table.has(&["password"]) {
        Ok(keepassxc_csv(table))
    } else if table.has(&["account"]) && table.has(&["login name"]) && table.has(&["password"]) {
        Ok(keepass_csv(CsvTable::parse(
            &unescape_backslashes(text),
            b',',
        )?))
    } else {
        Err(invalid(
            "This is not a KeePass export: choose a .kdbx database, a KeePass XML export, or a KeePassXC or KeePass CSV export.",
        ))
    }
}

/// KeePassXC: `Group` is the path from the root group (`Root/Work/Email`).
fn keepassxc_csv(mut table: CsvTable) -> ImportResult {
    let group = table.take(&["group"]);
    let title = table.take(&["title"]);
    let username = table.take(&["username"]);
    let password = table.take(&["password"]);
    let url = table.take(&["url"]);
    let notes = table.take(&["notes"]);
    let totp = table.take(&["totp"]);
    let tags = table.take(&["tags"]);
    let modified = table.take(&["last modified"]);
    let created = table.take(&["created"]);
    // An icon number: how KeePassXC draws the entry.
    table.ignore(&["icon"]);
    let mut out = Collector::default();
    let mut binned = 0;
    for row in &table.rows {
        let path: Vec<&str> = row
            .get(group)
            .unwrap_or_default()
            .split('/')
            .skip(1)
            .collect();
        if path.first().map(|g| g.trim()) == Some("Recycle Bin") {
            binned += 1;
            out.skip(None);
            continue;
        }
        let mut row_tags: Vec<String> = clean(Some(&path.join("/"))).into_iter().collect();
        row_tags.extend(split_tags(row.get(tags)));
        let fields = LoginFields {
            title: row.get(title).map(str::to_string),
            urls: row.get(url).map(str::to_string).into_iter().collect(),
            username: row.get(username).map(str::to_string),
            password: row.get(password).map(str::to_string),
            totp: row.get(totp).map(str::to_string),
            notes: row.get(notes).map(str::to_string),
            tags: row_tags,
            custom_fields: extra_fields(table.extras(row)),
            meta: ItemMeta {
                created_at: timestamp(row.get(created)),
                updated_at: timestamp(row.get(modified)),
                ..ItemMeta::default()
            },
            ..LoginFields::default()
        };
        out.add_login(fields, || skipped_row(row.line));
    }
    warn_binned(&mut out, binned);
    out.finish()
}

/// KeePass's 1.x CSV escapes `"` and `\` inside quoted fields with a backslash; this rewrites
/// them as standard CSV (`""` and `\`). Doubled quotes pass through unchanged.
fn unescape_backslashes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut quoted = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                out.push_str("\"\"");
            }
            '\\' if quoted && chars.peek() == Some(&'\\') => {
                chars.next();
                out.push('\\');
            }
            '"' => {
                quoted = !quoted;
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// KeePass 2's "KeePass CSV (1.x)" export.
fn keepass_csv(mut table: CsvTable) -> ImportResult {
    let title = table.take(&["account"]);
    let username = table.take(&["login name"]);
    let password = table.take(&["password"]);
    let url = table.take(&["web site"]);
    let notes = table.take(&["comments"]);
    let mut out = Collector::default();
    for row in &table.rows {
        let fields = LoginFields {
            title: row.get(title).map(str::to_string),
            urls: row.get(url).map(str::to_string).into_iter().collect(),
            username: row.get(username).map(str::to_string),
            password: row.get(password).map(str::to_string),
            notes: row.get(notes).map(str::to_string),
            custom_fields: extra_fields(table.extras(row)),
            ..LoginFields::default()
        };
        out.add_login(fields, || skipped_row(row.line));
    }
    out.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(key: &str, value: &str) -> Field {
        Field {
            key: key.into(),
            value: value.into(),
            protected: false,
        }
    }

    fn totp_of(fields: &[(&str, &str)]) -> (Option<String>, Vec<String>) {
        let mut fields: Vec<Field> = fields.iter().map(|(k, v)| field(k, v)).collect();
        let totp = take_totp(&mut fields, Some("Site"), Some("me"));
        (totp, fields.into_iter().map(|f| f.key).collect())
    }

    #[test]
    fn auto_type_passkeys_and_dates() {
        let xml = r#"<KeePassFile><Root><Group><UUID>cm9vdA==</UUID><Name>Root</Name>
            <Entry><UUID>AQIDBA==</UUID>
              <Times><CreationTime>2020-01-01T00:00:00Z</CreationTime><LastModificationTime>2021-01-01T00:00:00Z</LastModificationTime>
                <LastAccessTime>2022-01-01T00:00:00Z</LastAccessTime><Expires>True</Expires><ExpiryTime>2030-01-01T00:00:00Z</ExpiryTime></Times>
              <String><Key>Title</Key><Value>Bank</Value></String>
              <String><Key>UserName</Key><Value>me</Value></String>
              <String><Key>KPEX_PASSKEY_CREDENTIAL_ID</Key><Value>Y3JlZA</Value></String>
              <String><Key>KPEX_PASSKEY_PRIVATE_KEY_PEM</Key><Value Protected="False">-----BEGIN PRIVATE KEY-----
AAEC
-----END PRIVATE KEY-----</Value></String>
              <String><Key>KPEX_PASSKEY_RELYING_PARTY</Key><Value>bank.example</Value></String>
              <String><Key>KPEX_PASSKEY_USERNAME</Key><Value>me@bank.example</Value></String>
              <String><Key>KPEX_PASSKEY_USER_HANDLE</Key><Value>dXNlcg</Value></String>
              <AutoType><Enabled>True</Enabled><DefaultSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultSequence>
                <Association><Window>Bank - *</Window><KeystrokeSequence /></Association></AutoType>
            </Entry></Group></Root></KeePassFile>"#;
        let result = parse(xml.as_bytes(), &ImportOptions::default()).unwrap();
        let item = &result.items[0];
        assert_eq!(
            item.overview.created_at.as_deref(),
            Some("2020-01-01T00:00:00Z")
        );
        assert_eq!(
            item.overview.updated_at.as_deref(),
            Some("2021-01-01T00:00:00Z")
        );
        assert_eq!(
            item.overview.last_used_at.as_deref(),
            Some("2022-01-01T00:00:00Z")
        );
        assert_eq!(item.overview.imported_from.as_ref().unwrap().id, "AQIDBA==");
        let crate::item::ItemDetails::Login(login) = &item.details else {
            panic!()
        };
        assert_eq!(
            login.extra["autoType"],
            serde_json::json!({ "sequence": "{USERNAME}{TAB}{PASSWORD}{ENTER}", "windowTitles": ["Bank - *"] })
        );
        let passkey = &login.passkeys.as_ref().unwrap()[0];
        assert_eq!(
            (passkey.rp_id.as_str(), passkey.user_name.as_str()),
            ("bank.example", "me@bank.example")
        );
        assert_eq!(passkey.created_at, "2020-01-01T00:00:00Z");
        let record =
            crate::passkey::PasskeyRecord::from_item(passkey).expect("a passkey that can sign in");
        assert_eq!(
            (record.credential_id.as_str(), record.private_key.as_str()),
            ("Y3JlZA", "AAEC")
        );
        let labels: Vec<&str> = login
            .custom_fields
            .iter()
            .flatten()
            .map(|f| f.label.as_str())
            .collect();
        assert_eq!(labels, ["Expires"], "the passkey's strings aren't fields");
    }

    #[test]
    fn one_time_code_setups() {
        let link = "otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP";
        assert_eq!(totp_of(&[("otp", link)]).0.as_deref(), Some(link));
        let (keeotp, rest) = totp_of(&[
            (
                "otp",
                "key=JBSWY3DPEHPK3PXP%3d%3d&size=8&step=60&otpHashMode=Sha512",
            ),
            ("Other", "x"),
        ]);
        assert_eq!(
            keeotp.as_deref(),
            Some(
                "otpauth://totp/Site:me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8&period=60&issuer=Site"
            )
        );
        assert_eq!(rest, ["Other"]);
        // KeeOtp's HOTP, and KeePass's own fields, become counter-based codes.
        let hotp = "key=JBSWY3DPEHPK3PXP&type=Hotp&counter=3";
        assert_eq!(
            totp_of(&[("otp", hotp)]).0.as_deref(),
            Some(
                "otpauth://hotp/Site:me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&counter=3&issuer=Site"
            )
        );
        let (own, rest) = totp_of(&[
            ("HmacOtp-Secret-Base32", "JBSWY3DPEHPK3PXP"),
            ("HmacOtp-Counter", "12"),
            ("Other", "x"),
        ]);
        assert_eq!(
            own.as_deref(),
            Some(
                "otpauth://hotp/Site:me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&counter=12&issuer=Site"
            )
        );
        assert_eq!(rest, ["Other"]);

        let (keepass, rest) = totp_of(&[
            ("TimeOtp-Secret-Hex", "48656c6c 6f21deadbeef"),
            ("TimeOtp-Period", "45"),
            ("TimeOtp-Algorithm", "HMAC-SHA-256"),
        ]);
        assert!(
            keepass
                .unwrap()
                .contains("secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=45")
        );
        assert!(rest.is_empty());
        let (utf8, _) = totp_of(&[("TimeOtp-Secret", "Hello!\u{de}")]);
        assert!(utf8.unwrap().contains("secret=JBSWY3DPEHBZ4&"));
        // Settings Octa Pass can't compute stay as fields.
        let (unusable, rest) = totp_of(&[
            ("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP"),
            ("TimeOtp-Algorithm", "HMAC-MD5"),
        ]);
        assert_eq!(unusable, None);
        assert_eq!(rest.len(), 2);

        let (seed, rest) = totp_of(&[("TOTP Seed", "JBSWY3DPEHPK3PXP"), ("TOTP Settings", "30;7")]);
        assert!(seed.unwrap().contains("digits=7&period=30"));
        assert!(rest.is_empty());
        let (steam, rest) =
            totp_of(&[("TOTP Seed", "JBSWY3DPEHPK3PXP"), ("TOTP Settings", "30;S")]);
        assert_eq!(steam, None);
        assert_eq!(rest.len(), 2);
    }

    #[test]
    fn history_dates_are_when_a_password_was_replaced() {
        let version = |password: &str, modified: &str| Entry {
            strings: vec![field("Password", password)],
            modified: Some(modified.into()),
            ..Entry::default()
        };
        let history = [
            version("a", "2020-01-01T00:00:00Z"),
            version("", "2021-01-01T00:00:00Z"),
            version("b", "2022-01-01T00:00:00Z"),
            version("c", "2023-01-01T00:00:00Z"),
        ];
        let entries = password_history(&history, Some("c"), Some("2024-01-01T00:00:00Z".into()));
        let pairs: Vec<(&str, &str)> = entries
            .iter()
            .map(|e| (e.password.as_str(), e.changed_at.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [("b", "2023-01-01T00:00:00Z"), ("a", "2021-01-01T00:00:00Z")]
        );
    }

    #[test]
    fn backslash_escaped_csv() {
        assert_eq!(
            unescape_backslashes("\"a\\\"b\",\"c\\\\\",\"d\"\"e\",f\\\"g\n"),
            "\"a\"\"b\",\"c\\\",\"d\"\"e\",f\\\"g\n"
        );
    }

    #[test]
    fn percent_escapes() {
        assert_eq!(percent_decode("AB%3D%3d%zz%"), "AB==%zz%");
    }
}
