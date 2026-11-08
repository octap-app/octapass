//! Importing a file again: items that are already in the vault are updated instead of copied.
//!
//! An imported item matches an item in the vault by the id the other app gave it
//! ([`ImportedFrom`]), or else as a duplicate: a login with the same site and username (or the
//! same title, when it has neither), a card with the same number, an identity with the same
//! title, name, email, phone and address, a note with the same title and text, a Wi-Fi network
//! with the same name, a bank account with the same title and IBAN or account number, an API
//! credential with the same title, host and username, a licence with the same title and key, an ID
//! document with the same kind and number, a wallet with the same title and first address, a
//! database with the same host, port, database and username, a custom item with the same title and
//! template. The file's values win for the fields it has; what only Octa Pass holds (files, recovery
//! info, fields the file doesn't have, earlier passwords) is kept. A password that changed goes into
//! the password history. Items that would come out the same aren't written at all.
//!
//! Octa Pass's own exports ([`restore`]) keep their items' ids, so an item matches the vault's item
//! with the same id first, in any vault, and the newer of the two wins.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{ImportOptions, ImportResult, build};
use crate::item::{Item, ItemOverview, ItemType};

/// An item already in the vault, as the vault holds it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExistingItem {
    pub id: String,
    pub overview: ItemOverview,
    pub details: Value,
    /// The item's vault. With [`ImportOptions::vault_id`], only the items of that vault are compared,
    /// except that an Octa Pass export also finds its own items, by id, in every vault (it holds
    /// every vault, and an import goes into one). Without it, every item counts as in the target.
    #[serde(default)]
    pub vault_id: Option<String>,
    /// When the item last changed in the vault (the sync record's `updatedAt`, RFC 3339). An Open
    /// Pass export doesn't replace an item that changed after the export was made.
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// The items of `options` in the vault the import goes into.
pub(super) fn in_target(options: &ImportOptions) -> impl Iterator<Item = &ExistingItem> {
    options
        .existing_items
        .iter()
        .filter(|item| is_in_target(item, options))
}

fn is_in_target(item: &ExistingItem, options: &ImportOptions) -> bool {
    match (&options.vault_id, &item.vault_id) {
        (Some(target), Some(vault)) => target == vault,
        _ => true,
    }
}

/// The vault's items, typed, with what makes each a duplicate worked out once (not once for
/// every imported item: a vault and a file can each hold thousands).
struct Known<'a> {
    items: Vec<(&'a str, Item)>,
    keys: Vec<Option<String>>,
}

impl<'a> Known<'a> {
    fn new(existing: impl IntoIterator<Item = &'a ExistingItem>) -> Self {
        let items: Vec<(&str, Item)> = existing
            .into_iter()
            .filter_map(|e| {
                let item = Item::from_parts(e.overview.clone(), e.details.clone()).ok()?;
                Some((e.id.as_str(), item))
            })
            .collect();
        let keys = items.iter().map(|(_, item)| duplicate_key(item)).collect();
        Self { items, keys }
    }
}

/// An item in the vault that the import changes: save `item` as the new version of `item_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemUpdate {
    pub item_id: String,
    pub item: Item,
}

/// Moves the items of `result` that match `existing` out of `items`, into `updates` (or counts
/// them as `unchanged`). `source` is the import source's name; `now` dates a replaced password
/// when the file doesn't say when it changed.
pub(super) fn reconcile<'a>(
    result: &mut ImportResult,
    existing: impl IntoIterator<Item = &'a ExistingItem>,
    source: &str,
    now: &str,
) {
    let known = Known::new(existing);
    let mut claimed = vec![false; known.items.len()];
    let mut new_items = Vec::new();
    for item in std::mem::take(&mut result.items) {
        let Some(at) = find_match(&item, &known, &claimed, source, true) else {
            new_items.push(item);
            continue;
        };
        claimed[at] = true;
        let (id, current) = &known.items[at];
        match merge(current, &item, now) {
            Some(merged) if &merged == current => result.unchanged += 1,
            Some(merged) => result.updates.push(ItemUpdate {
                item_id: (*id).to_owned(),
                item: merged,
            }),
            None => new_items.push(item),
        }
    }
    result.items = new_items;
}

/// [`reconcile`] for authenticator backups, whose items are one-time codes (and the notes of
/// codes that joined a login). A code is only ever the same item by the app's id: two codes for
/// the same account name are different codes. A code whose secret is already on a login in the
/// vault (`known`: the logins' codes, from [`super::ExistingLogin::totp`] and from `existing`)
/// isn't added again, and counts as unchanged; so does a code for a login already in the vault
/// (`totp_updates`). [`ImportResult::codes`] follows the items and codes that remain.
pub(super) fn reconcile_codes<'a>(
    result: &mut ImportResult,
    existing: impl IntoIterator<Item = &'a ExistingItem>,
    known: &[&str],
    source: &str,
    now: &str,
) {
    let vault = Known::new(existing);
    let existing = &vault.items;
    let mut secrets: Vec<Vec<u8>> = known.iter().filter_map(|t| secret_key(t)).collect();
    secrets.extend(existing.iter().flat_map(|(_, item)| item_secrets(item)));
    let known = |item: &Item| item_secrets(item).iter().any(|s| secrets.contains(s));
    let mut claimed = vec![false; existing.len()];
    let mut kept = Vec::new();
    let mut new_index = Vec::with_capacity(result.items.len());
    for item in std::mem::take(&mut result.items) {
        let code = matches!(
            item.overview.item_type,
            ItemType::Login | ItemType::Password
        );
        let found = find_match(&item, &vault, &claimed, source, !code);
        let merged = found.and_then(|at| Some((at, merge(&existing[at].1, &item, now)?)));
        match merged {
            Some((at, merged)) => {
                claimed[at] = true;
                if merged == existing[at].1 {
                    result.unchanged += 1;
                } else {
                    result.updates.push(ItemUpdate {
                        item_id: existing[at].0.to_owned(),
                        item: merged,
                    });
                }
                new_index.push(None);
            }
            None if code && known(&item) => {
                result.unchanged += 1;
                new_index.push(None);
            }
            None => {
                new_index.push(Some(kept.len()));
                kept.push(item);
            }
        }
    }
    result.items = kept;
    let mut update_index = Vec::with_capacity(result.totp_updates.len());
    let mut updates = Vec::new();
    for update in std::mem::take(&mut result.totp_updates) {
        if secret_key(&update.totp).is_some_and(|s| secrets.contains(&s)) {
            result.unchanged += 1;
            update_index.push(None);
        } else {
            update_index.push(Some(updates.len()));
            updates.push(update);
        }
    }
    result.totp_updates = updates;
    result.codes.retain_mut(|code| {
        let item = code.item.map(|i| new_index.get(i).copied().flatten());
        let update = code.update.map(|u| update_index.get(u).copied().flatten());
        match (item, update) {
            (Some(Some(i)), _) => code.item = Some(i),
            (_, Some(Some(u))) => code.update = Some(u),
            _ => return false,
        }
        true
    });
}

/// The secret of a one-time code: an `otpauth://` link (of any kind) or a bare secret, decoded
/// from base32 when it is base32, so `JBSW Y3DP` and `jbswy3dp` agree.
pub(super) fn secret_key(totp: &str) -> Option<Vec<u8>> {
    let totp = totp.trim();
    let secret = if totp.to_ascii_lowercase().starts_with("otpauth") {
        url::Url::parse(totp)
            .ok()?
            .query_pairs()
            .find(|(key, _)| key.eq_ignore_ascii_case("secret"))?
            .1
            .into_owned()
    } else {
        totp.to_owned()
    };
    let secret: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect();
    if secret.is_empty() {
        return None;
    }
    Some(
        crate::encoding::base32_decode(&secret)
            .unwrap_or_else(|| secret.to_lowercase().into_bytes()),
    )
}

/// The secrets of a login's code and of the codes it keeps as hidden fields (HOTP, Steam, …).
fn item_secrets(item: &Item) -> Vec<Vec<u8>> {
    let crate::item::ItemDetails::Login(login) = &item.details else {
        return Vec::new();
    };
    let fields = login.custom_fields.iter().flatten();
    login
        .totp
        .iter()
        .chain(
            fields
                .filter(|f| f.value.trim_start().starts_with("otpauth"))
                .map(|f| &f.value),
        )
        .filter_map(|totp| secret_key(totp))
        .collect()
}

/// Where an item of an Octa Pass export comes from, for [`restore`].
pub(super) struct Exported<'a> {
    /// Its id in the export, which is its id in the vault it was exported from.
    pub id: &'a str,
    /// When it last changed before the export (the export's `updatedAt`).
    pub updated_at: &'a str,
}

/// Where an item of an Octa Pass export goes.
#[derive(Debug)]
pub(super) enum Restored {
    /// Not in the vault yet.
    New(Item),
    /// The vault's item `item_id`. `update` is its new version, `None` when it stays as it is;
    /// `kept` when that's because it changed in the vault after the export was made. `newer` when
    /// the vault's item changed after the export at all: then its files aren't brought back either.
    Existing {
        item_id: String,
        update: Option<Item>,
        kept: bool,
        newer: bool,
        /// The vault item's own files, to tell which of the export's it already has.
        details: Value,
    },
}

/// [`reconcile`] for an Octa Pass export. An exported item is the vault's item with the same id,
/// in any vault, or else a duplicate in the target vault as for other files (so a file imported
/// into another account is recognised the second time). The newer version wins: an item that
/// changed in the vault after the export stays as it is; otherwise the export's version replaces
/// it whole, keeping the vault's files and password history (and the vault's password in it, when
/// the export's differs). Recovery info pointing at an exported item that's already in the vault
/// is pointed at the vault's item.
pub(super) fn restore(
    mut items: Vec<Item>,
    exported: &[Exported<'_>],
    options: &ImportOptions,
    now: &str,
) -> Vec<Restored> {
    let known = Known::new(&options.existing_items);
    // Only typed vault items are candidates: `known` skipped the rest, so map back by id.
    let meta: HashMap<&str, &ExistingItem> = options
        .existing_items
        .iter()
        .map(|e| (e.id.as_str(), e))
        .collect();
    let mut claimed = vec![false; known.items.len()];
    let mut found: Vec<Option<usize>> = vec![None; items.len()];
    let by_id: HashMap<&str, usize> = known
        .items
        .iter()
        .enumerate()
        .map(|(at, (id, _))| (*id, at))
        .collect();
    for (i, entry) in exported.iter().enumerate() {
        if let Some(&at) = by_id.get(entry.id)
            && !claimed[at]
        {
            claimed[at] = true;
            found[i] = Some(at);
        }
    }
    // Duplicates only in the target vault, and only once every item had its own id's turn.
    for (at, (id, _)) in known.items.iter().enumerate() {
        if !meta.get(id).is_some_and(|e| is_in_target(e, options)) {
            claimed[at] = true;
        }
    }
    for (i, item) in items.iter().enumerate() {
        if found[i].is_some() {
            continue;
        }
        if let Some(at) = find_match(item, &known, &claimed, "octapass", true) {
            claimed[at] = true;
            found[i] = Some(at);
        }
    }

    let (sources, targets): (Vec<String>, Vec<String>) = exported
        .iter()
        .zip(&found)
        .filter_map(|(entry, at)| Some((entry.id.to_owned(), known.items[(*at)?].0.to_owned())))
        .filter(|(source, target)| source != target)
        .unzip();
    super::relink(&mut items, &sources, &targets);

    items
        .into_iter()
        .zip(exported)
        .zip(found)
        .map(|((item, entry), at)| {
            let Some(at) = at else {
                return Restored::New(item);
            };
            let (id, current) = &known.items[at];
            let existing = meta[id];
            let Some(merged) = replace(current, &item, now) else {
                return Restored::New(item);
            };
            let newer_in_vault = existing
                .updated_at
                .as_deref()
                .and_then(instant)
                .zip(instant(entry.updated_at))
                .is_some_and(|(vault, export)| vault > export);
            let same = &merged == current;
            Restored::Existing {
                item_id: (*id).to_owned(),
                update: (!same && !newer_in_vault).then_some(merged),
                kept: !same && newer_in_vault,
                newer: newer_in_vault,
                details: existing.details.clone(),
            }
        })
        .collect()
}

/// An RFC 3339 time as its UTC second and the nanoseconds after it, so that two changes in the
/// same second still come in order (sync records keep milliseconds).
fn instant(text: &str) -> Option<(String, u32)> {
    let second = build::timestamp(Some(text))?;
    let fraction: String = text
        .trim()
        .get(19..)
        .and_then(|rest| rest.strip_prefix('.'))
        .map(|rest| {
            rest.chars()
                .take_while(char::is_ascii_digit)
                .take(9)
                .collect()
        })
        .unwrap_or_default();
    let nanos = format!("{fraction:0<9}").parse().ok()?;
    Some((second, nanos))
}

/// Whether the vault item's `details` already hold the export's file `id` (its attachment id
/// where it was exported, so the same item restored), or a file with the same name and size.
pub(super) fn has_file(details: &Value, id: &str, name: &str, size: u64) -> bool {
    details
        .get("attachments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|file| {
            file.get("id").and_then(Value::as_str) == Some(id)
                || file.get("name").and_then(Value::as_str) == Some(name)
                    && file.get("size").and_then(Value::as_u64) == Some(size)
        })
}

/// The export's item as the new version of the vault's: the export's fields, with the vault's
/// files and password history, and the vault's password added to it when the export's differs.
fn replace(current: &Item, exported: &Item, now: &str) -> Option<Item> {
    let kept = object(serde_json::to_value(&current.details).ok()?);
    let overview = object(serde_json::to_value(&exported.overview).ok()?);
    let mut details = object(serde_json::to_value(&exported.details).ok()?);
    details.remove("attachments");
    if let Some(files) = kept.get("attachments") {
        details.insert("attachments".into(), files.clone());
    }
    if let Some(history) = kept.get("passwordHistory") {
        let merged = union(
            details.get("passwordHistory").unwrap_or(&Value::Null),
            Some(history),
            |a, b| a.get("password") == b.get("password"),
        );
        details.insert("passwordHistory".into(), merged);
    }
    if current.overview.item_type == exported.overview.item_type {
        keep_old_password(current, &mut details, &overview, now);
    }
    let overview: ItemOverview = serde_json::from_value(Value::Object(overview)).ok()?;
    Item::from_parts(overview, Value::Object(details)).ok()
}

fn find_match(
    item: &Item,
    known: &Known<'_>,
    claimed: &[bool],
    source: &str,
    duplicates: bool,
) -> Option<usize> {
    let existing = &known.items;
    let open = |at: &usize| !claimed[*at];
    // A file recognised as another app's export (generic CSV) carries that app's name.
    let mine = item.overview.imported_from.as_ref();
    let source = mine.map_or(source, |from| from.source.as_str());
    if let Some(from) = mine {
        let by_id = (0..existing.len()).filter(open).find(|&at| {
            existing[at]
                .1
                .overview
                .imported_from
                .as_ref()
                .is_some_and(|other| other.source == source && other.id == from.id)
                && same_kind(&existing[at].1, item)
        });
        if by_id.is_some() || !duplicates {
            return by_id;
        }
    }
    if !duplicates {
        return None;
    }
    let key = duplicate_key(item)?;
    (0..existing.len()).filter(open).find(|&at| {
        let other = &existing[at].1;
        // Another item from the same app is a different item there, however alike.
        let other_item_there = other.overview.imported_from.as_ref().is_some_and(|theirs| {
            theirs.source == source && mine.is_none_or(|m| m.id != theirs.id)
        });
        !other_item_there && known.keys[at].as_ref() == Some(&key)
    })
}

/// One app item can become several here (a login and a card in one CXF item), all with its id.
fn same_kind(a: &Item, b: &Item) -> bool {
    let login = |item: &Item| {
        matches!(
            item.overview.item_type,
            ItemType::Login | ItemType::Password
        )
    };
    a.overview.item_type == b.overview.item_type || login(a) && login(b)
}

/// What makes two items the same thing, or `None` when the item has too little to tell.
fn duplicate_key(item: &Item) -> Option<String> {
    let value = serde_json::to_value(&item.details).ok()?;
    let text = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(|v| v.trim().to_lowercase())
            .unwrap_or_default()
    };
    // Keys, certificates and fingerprints are case-sensitive.
    let exact = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(|v| v.trim().to_owned())
            .unwrap_or_default()
    };
    let title = item.overview.title.trim().to_lowercase();
    match item.overview.item_type {
        ItemType::Login | ItemType::Password => {
            let site = item
                .overview
                .urls
                .iter()
                .flatten()
                .find_map(|url| origin(url))
                .unwrap_or_default();
            let username = text("username");
            if site.is_empty() && username.is_empty() {
                // Nothing else to go on: a login with only a password or fields, by its title.
                Some(format!(
                    "login-title\n{}",
                    item.overview.title.trim().to_lowercase()
                ))
            } else {
                Some(format!("login\n{site}\n{username}"))
            }
        }
        ItemType::Card => {
            let digits: String = text("number")
                .chars()
                .filter(char::is_ascii_digit)
                .collect();
            (!digits.is_empty()).then(|| format!("card\n{digits}"))
        }
        ItemType::Identity => {
            // Some apps keep a lone address or phone number as an identity, so the title counts.
            let line1 = value
                .pointer("/address/line1")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_lowercase();
            let key = [
                item.overview.title.trim().to_lowercase(),
                text("firstName"),
                text("lastName"),
                text("email"),
                text("phone"),
                line1,
            ]
            .join("\n");
            Some(format!("identity\n{key}"))
        }
        // Network names are case-sensitive.
        ItemType::Wifi => {
            let ssid = value
                .get("ssid")
                .and_then(Value::as_str)
                .unwrap_or_default();
            (!ssid.is_empty()).then(|| format!("wifi\n{ssid}"))
        }
        ItemType::SecureNote => Some(format!(
            "note\n{}\n{}",
            item.overview.title.trim().to_lowercase(),
            text("notes")
        )),
        ItemType::BankAccount => {
            let plain = |value: String| value.replace([' ', '-'], "");
            let number = Some(plain(text("iban")))
                .filter(|number| !number.is_empty())
                .unwrap_or_else(|| plain(text("accountNumber")));
            (!number.is_empty()).then(|| format!("bank\n{title}\n{number}"))
        }
        ItemType::ApiCredential => Some(format!(
            "api\n{title}\n{}\n{}",
            text("host"),
            text("username")
        )),
        ItemType::SoftwareLicense => {
            let key = text("licenseKey");
            (!key.is_empty()).then(|| format!("license\n{title}\n{key}"))
        }
        ItemType::IdDocument => {
            let number = text("number");
            (!number.is_empty()).then(|| format!("id\n{}\n{number}", text("documentType")))
        }
        ItemType::CryptoWallet => {
            // Never the seed phrase: this key is compared, but it shouldn't hold more than it needs.
            let address = value
                .pointer("/addresses/0/address")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or_default();
            (!address.is_empty()).then(|| format!("wallet\n{title}\n{address}"))
        }
        ItemType::Database => {
            let host = text("host");
            (!host.is_empty()).then(|| {
                format!(
                    "database\n{host}\n{}\n{}\n{}",
                    text("port"),
                    text("database"),
                    text("username")
                )
            })
        }
        ItemType::Custom => Some(format!("custom\n{title}\n{}", text("templateName"))),
        ItemType::CustomTemplate => Some(format!("template\n{title}")),
        // A file's text with whatever wraps it: `Some` only when there's something to compare.
        ItemType::Document => Some(format!("document\n{title}\n{}", text("notes"))),
        // The key itself (type and base64, not the comment), else its fingerprint.
        ItemType::SshKey => {
            let public: Vec<String> = exact("publicKey")
                .split_whitespace()
                .take(2)
                .map(str::to_owned)
                .collect();
            let fingerprint = exact("fingerprint");
            match (public.len(), fingerprint.is_empty()) {
                (2, _) => Some(format!("ssh\n{}", public.join(" "))),
                (_, false) => Some(format!("ssh-fingerprint\n{fingerprint}")),
                _ => None,
            }
        }
        // A project's stage; an environment without either by its title.
        ItemType::Environment => {
            let (project, stage) = (text("project"), text("stage"));
            Some(if project.is_empty() && stage.is_empty() {
                format!("environment-title\n{title}")
            } else {
                format!("environment\n{project}\n{stage}")
            })
        }
        ItemType::Certificate => {
            let pem: String = exact("certificate").split_whitespace().collect();
            (!pem.is_empty()).then(|| format!("certificate\n{pem}"))
        }
        // By what's public about it; a key that's only a secret has nothing safe to tell it by.
        ItemType::Key => {
            let public: String = exact("publicKey").split_whitespace().collect();
            let fingerprint = exact("fingerprint");
            if !public.is_empty() {
                Some(format!("key\n{public}"))
            } else {
                (!fingerprint.is_empty()).then(|| format!("key-fingerprint\n{fingerprint}"))
            }
        }
        _ => None,
    }
}

/// `https://example.com` for `https://Example.com/login?x`; the app for `android://…@com.app/`.
fn origin(url: &str) -> Option<String> {
    let url = url.trim();
    let parsed = url::Url::parse(url)
        .or_else(|_| url::Url::parse(&format!("https://{url}")))
        .ok()?;
    let host = parsed.host_str()?.trim_start_matches("www.").to_lowercase();
    let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    Some(format!("{}://{host}{port}", parsed.scheme()))
}

/// The vault's item with the file's values on top. `None` when the result isn't a valid item.
fn merge(current: &Item, imported: &Item, now: &str) -> Option<Item> {
    let mut overview = object(serde_json::to_value(&current.overview).ok()?);
    let mut details = object(serde_json::to_value(&current.details).ok()?);
    let new_overview = object(serde_json::to_value(&imported.overview).ok()?);
    let new_details = object(serde_json::to_value(&imported.details).ok()?);
    if current.overview.item_type != imported.overview.item_type {
        // The other app changed the item's kind: take it whole, keeping only the files.
        let files = details.remove("attachments");
        overview = new_overview;
        details = new_details;
        if let Some(files) = files {
            details.insert("attachments".into(), files);
        }
    } else {
        for (key, value) in new_overview {
            let merged = match key.as_str() {
                // The vault's websites first, so each site keeps the address and mode it has
                // here; repeats of a site go below.
                "urls" => union(
                    overview.get(&key).unwrap_or(&Value::Null),
                    Some(&value),
                    |a, b| a == b,
                ),
                // The file's modes on top, as for any field.
                "urlMatch" => {
                    let mut modes = overview.get(&key).cloned().map(object).unwrap_or_default();
                    modes.extend(object(value));
                    Value::Object(modes)
                }
                "tags" => union(&value, overview.get(&key), |a, b| a == b),
                _ => value,
            };
            overview.insert(key, merged);
        }
        // Apps write one site differently (a trailing slash, `/login`, `http`, `www.`).
        crate::matching::websites::dedupe_overview_json(&mut overview);
        for (key, value) in new_details {
            let merged = match key.as_str() {
                // Files only change through the attachment calls.
                "attachments" => continue,
                // A file with the address as one line (a CSV) keeps the vault's parts of it.
                "address"
                    if details
                        .get(&key)
                        .is_some_and(|old| same_address(old, &value)) =>
                {
                    continue;
                }
                // Labels are what names a field, also on a custom item.
                "customFields" | "fields" => union(&value, details.get(&key), |a, b| {
                    a.get("label") == b.get("label")
                }),
                "addresses" => union(&value, details.get(&key), |a, b| {
                    a.get("address") == b.get("address")
                }),
                "passkeys" => union(&value, details.get(&key), |a, b| {
                    a.get("credentialId").is_some()
                        && a.get("credentialId") == b.get("credentialId")
                        || a.get("rpId") == b.get("rpId") && a.get("userName") == b.get("userName")
                }),
                "passwordHistory" => union(&value, details.get(&key), |a, b| {
                    a.get("password") == b.get("password")
                }),
                _ => value,
            };
            details.insert(key, merged);
        }
        keep_old_password(current, &mut details, &overview, now);
    }
    let changed = Value::Object(overview.clone())
        != serde_json::to_value(&current.overview).ok()?
        || Value::Object(details.clone()) != serde_json::to_value(&current.details).ok()?;
    if changed && imported.overview.updated_at.is_none() {
        // Changed now, by this import: the sync record's date is the right one to show.
        overview.remove("updatedAt");
    }
    let overview: ItemOverview = serde_json::from_value(Value::Object(overview)).ok()?;
    Item::from_parts(overview, Value::Object(details)).ok()
}

/// Whether two addresses read the same as one line (`line1, line2, postcode city region, country`,
/// as the CSV export writes it), however their parts are split.
fn same_address(a: &Value, b: &Value) -> bool {
    let text = |address: &Value| {
        let part = |key: &str| address.get(key).and_then(Value::as_str).unwrap_or_default();
        [
            part("line1"),
            part("line2"),
            part("postalCode"),
            part("city"),
            part("region"),
            part("country"),
        ]
        .join(" ")
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
    };
    text(a) == text(b)
}

/// When the file has a new password, the vault's one goes into the history (newest first),
/// dated when the file says the password changed.
fn keep_old_password(
    current: &Item,
    details: &mut Map<String, Value>,
    overview: &Map<String, Value>,
    now: &str,
) {
    if !matches!(
        current.overview.item_type,
        ItemType::Login | ItemType::Password | ItemType::Wifi | ItemType::Database
    ) {
        return;
    }
    let old = serde_json::to_value(&current.details)
        .ok()
        .and_then(|d| d.get("password").cloned());
    let Some(Value::String(old)) = old else {
        return;
    };
    if details.get("password").and_then(Value::as_str) == Some(old.as_str()) {
        return;
    }
    let history = details
        .entry("passwordHistory")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(entries) = history else {
        return;
    };
    if entries
        .iter()
        .any(|entry| entry.get("password").and_then(Value::as_str) == Some(old.as_str()))
    {
        return;
    }
    let changed_at = details
        .get("passwordChangedAt")
        .or_else(|| overview.get("updatedAt"))
        .and_then(Value::as_str)
        .unwrap_or(now)
        .to_owned();
    let Some(Value::Array(entries)) = details.get_mut("passwordHistory") else {
        return;
    };
    entries.insert(
        0,
        serde_json::json!({ "password": old, "changedAt": changed_at }),
    );
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// The file's list, then the vault's entries that aren't in it.
fn union(new: &Value, old: Option<&Value>, same: impl Fn(&Value, &Value) -> bool) -> Value {
    let mut list = new.as_array().cloned().unwrap_or_default();
    for entry in old.and_then(Value::as_array).into_iter().flatten() {
        if !list.iter().any(|kept| same(kept, entry)) {
            list.push(entry.clone());
        }
    }
    Value::Array(list)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn item(value: Value) -> Item {
        serde_json::from_value(value).unwrap()
    }

    fn existing(id: &str, value: Value) -> ExistingItem {
        ExistingItem {
            id: id.into(),
            overview: serde_json::from_value(value["overview"].clone()).unwrap(),
            details: value["details"].clone(),
            vault_id: None,
            updated_at: None,
        }
    }

    fn firefox_login(id: &str, password: &str) -> Value {
        json!({
            "overview": {
                "title": "example.com", "type": "login", "urls": ["https://www.example.com"], "subtitle": "alice",
                "updatedAt": "2025-01-01T00:00:00Z", "importedFrom": { "source": "firefox", "id": id }
            },
            "details": { "username": "alice", "password": password, "passwordChangedAt": "2025-01-01T00:00:00Z" }
        })
    }

    #[test]
    fn same_id_updates_and_keeps_the_old_password() {
        let mut stored = firefox_login("{1}", "old");
        stored["overview"]["tags"] = json!(["work"]);
        stored["details"]["recovery"] = json!({ "email": "a@b.test" });
        stored["details"]["attachments"] =
            json!([{ "id": "f", "name": "a.txt", "type": "", "size": 1, "key": "AQ" }]);
        let mut result = ImportResult {
            items: vec![item(firefox_login("{1}", "new"))],
            ..ImportResult::default()
        };
        reconcile(
            &mut result,
            &[existing("i1", stored)],
            "firefox",
            "2026-10-24T00:00:00Z",
        );
        assert!(result.items.is_empty());
        assert_eq!(result.updates.len(), 1);
        let update = serde_json::to_value(&result.updates[0]).unwrap();
        assert_eq!(update["itemId"], "i1");
        let details = &update["item"]["details"];
        assert_eq!(details["password"], "new");
        assert_eq!(
            details["passwordHistory"],
            json!([{ "password": "old", "changedAt": "2025-01-01T00:00:00Z" }])
        );
        assert_eq!(details["recovery"]["email"], "a@b.test");
        assert_eq!(details["attachments"][0]["id"], "f");
        assert_eq!(update["item"]["overview"]["tags"], json!(["work"]));
    }

    #[test]
    fn the_same_file_again_changes_nothing() {
        let imported = item(firefox_login("{1}", "pw"));
        let stored = existing("i1", serde_json::to_value(&imported).unwrap());
        let mut result = ImportResult {
            items: vec![imported],
            ..ImportResult::default()
        };
        reconcile(&mut result, &[stored], "firefox", "now");
        assert_eq!(
            (result.items.len(), result.updates.len(), result.unchanged),
            (0, 0, 1)
        );
    }

    #[test]
    fn duplicates_match_without_an_id() {
        let chrome = json!({
            "overview": { "title": "Example", "type": "login", "urls": ["https://example.com/login"] },
            "details": { "username": "Alice", "password": "pw", "notes": "kept" }
        });
        let mut result = ImportResult {
            items: vec![
                item(firefox_login("{1}", "pw")),
                item(firefox_login("{2}", "other")),
            ],
            ..ImportResult::default()
        };
        reconcile(&mut result, &[existing("c", chrome)], "firefox", "now");
        assert_eq!(result.updates.len(), 1, "one match per item in the vault");
        let update = &result.updates[0];
        assert_eq!(update.item_id, "c");
        let value = serde_json::to_value(&update.item).unwrap();
        assert_eq!(value["details"]["notes"], "kept");
        assert_eq!(value["overview"]["importedFrom"]["id"], "{1}");
        assert_eq!(result.items.len(), 1);
    }

    #[test]
    fn other_items_from_the_same_app_are_not_duplicates() {
        let mut result = ImportResult {
            items: vec![item(firefox_login("{2}", "pw"))],
            ..ImportResult::default()
        };
        reconcile(
            &mut result,
            &[existing("i1", firefox_login("{1}", "pw"))],
            "firefox",
            "now",
        );
        assert_eq!((result.items.len(), result.updates.len()), (1, 0));
    }

    #[test]
    fn wifi_networks_match_by_name_and_keep_old_passwords() {
        let network = |password: &str| {
            json!({
                "overview": { "title": "Home", "type": "wifi", "subtitle": "Casa" },
                "details": { "ssid": "Casa", "security": "wpa2", "password": password }
            })
        };
        let mut result = ImportResult {
            items: vec![item(network("new"))],
            ..ImportResult::default()
        };
        reconcile(
            &mut result,
            &[existing("w", network("old"))],
            "cxf",
            "2026-10-24T00:00:00Z",
        );
        let value = serde_json::to_value(&result.updates[0].item).unwrap();
        assert_eq!(
            value["details"]["passwordHistory"],
            json!([{ "password": "old", "changedAt": "2026-10-24T00:00:00Z" }])
        );
    }

    #[test]
    fn new_types_match_as_duplicates_and_keep_their_lists() {
        fn typed(kind: &str, details: Value) -> Value {
            json!({ "overview": { "title": "Item", "type": kind }, "details": details })
        }
        for (kind, stored, imported, same) in [
            (
                "bankAccount",
                json!({ "iban": "DE89 3704 0044 0532 0130 00", "pin": "1" }),
                json!({ "iban": "de89370400440532013000", "pin": "2" }),
                true,
            ),
            (
                "bankAccount",
                json!({ "accountNumber": "1" }),
                json!({ "accountNumber": "2" }),
                false,
            ),
            (
                "apiCredential",
                json!({ "host": "a.example", "username": "u", "key": "1" }),
                json!({ "host": "A.example", "username": "U", "key": "2" }),
                true,
            ),
            (
                "softwareLicense",
                json!({ "licenseKey": "AAAA" }),
                json!({ "licenseKey": "aaaa", "version": "2" }),
                true,
            ),
            (
                "idDocument",
                json!({ "documentType": "passport", "number": "X1" }),
                json!({ "documentType": "passport", "number": "X1", "country": "JO" }),
                true,
            ),
            (
                "idDocument",
                json!({ "documentType": "passport", "number": "X1" }),
                json!({ "documentType": "nationalId", "number": "X1" }),
                false,
            ),
            (
                "cryptoWallet",
                json!({ "addresses": [{ "network": "bitcoin", "address": "bc1" }] }),
                json!({ "addresses": [{ "network": "bitcoin", "address": "bc1" }], "walletName": "W" }),
                true,
            ),
            (
                "database",
                json!({ "host": "db", "port": "5432", "username": "u" }),
                json!({ "host": "db", "port": "5433", "username": "u" }),
                false,
            ),
            (
                "custom",
                json!({ "templateName": "Locker", "fields": [{ "label": "Row", "value": "1", "kind": "text" }] }),
                json!({ "templateName": "Locker", "fields": [{ "label": "Row", "value": "2", "kind": "text" }] }),
                true,
            ),
        ] {
            let mut result = ImportResult {
                items: vec![item(typed(kind, imported.clone()))],
                ..ImportResult::default()
            };
            reconcile(
                &mut result,
                &[existing("x", typed(kind, stored.clone()))],
                "keeper",
                "now",
            );
            assert_eq!(
                result.updates.len() == 1,
                same,
                "{kind}: {stored} {imported}"
            );
            assert_eq!(
                result.items.len() == 1,
                !same,
                "{kind}: {stored} {imported}"
            );
        }
    }

    #[test]
    fn nothing_to_tell_new_types_apart_by_is_no_match() {
        for kind in [
            "bankAccount",
            "softwareLicense",
            "idDocument",
            "cryptoWallet",
            "database",
            "sshKey",
            "certificate",
            "key",
        ] {
            let empty = json!({ "overview": { "title": "Item", "type": kind }, "details": {} });
            assert_eq!(duplicate_key(&item(empty)), None, "{kind}");
        }
    }

    #[test]
    fn times_in_the_same_second_still_come_in_order() {
        let at = |text| instant(text).unwrap();
        assert_eq!(
            at("2026-03-01T10:00:00.120Z"),
            at("2026-03-01T10:00:00.12Z")
        );
        assert!(at("2026-03-01T10:00:00.121Z") > at("2026-03-01T10:00:00.12Z"));
        assert!(at("2026-03-01T10:00:01Z") > at("2026-03-01T10:00:00.999Z"));
        assert_eq!(
            at("2026-03-01T12:00:00.5+02:00"),
            at("2026-03-01T10:00:00.500Z")
        );
        assert!(instant("not a date").is_none());
    }

    #[test]
    fn developer_items_and_documents_match_as_duplicates() {
        let pairs = [
            (
                json!({ "overview": { "title": "Server", "type": "sshKey" }, "details": { "publicKey": "ssh-ed25519 AAAAC3Nz me@laptop" } }),
                json!({ "overview": { "title": "Other name", "type": "sshKey" }, "details": { "publicKey": "ssh-ed25519 AAAAC3Nz\n" } }),
            ),
            (
                json!({ "overview": { "title": "API", "type": "environment" }, "details": { "project": "api", "stage": "Production", "variables": [] } }),
                json!({ "overview": { "title": "api (production)", "type": "environment" }, "details": { "project": "API", "stage": "production", "variables": [] } }),
            ),
            (
                json!({ "overview": { "title": "localhost", "type": "certificate" }, "details": { "certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----" } }),
                json!({ "overview": { "title": "dev cert", "type": "certificate" }, "details": { "certificate": "-----BEGIN CERTIFICATE-----\r\nMIIB\r\n-----END CERTIFICATE-----\r\n" } }),
            ),
            (
                json!({ "overview": { "title": "Signing", "type": "key" }, "details": { "publicKey": "-----BEGIN PUBLIC KEY-----\nMCow\n-----END PUBLIC KEY-----" } }),
                json!({ "overview": { "title": "JWT key", "type": "key" }, "details": { "publicKey": "-----BEGIN PUBLIC KEY-----\nMCow\n-----END PUBLIC KEY-----\n" } }),
            ),
            (
                json!({ "overview": { "title": "Lease", "type": "document" }, "details": { "notes": "Signed" } }),
                json!({ "overview": { "title": "lease", "type": "document" }, "details": { "notes": "Signed", "attachments": [] } }),
            ),
        ];
        for (a, b) in pairs {
            let key = duplicate_key(&item(a.clone()));
            assert!(key.is_some(), "{a}");
            assert_eq!(key, duplicate_key(&item(b)), "{a}");
        }
        // Different keys, stages and documents stay apart.
        let ssh = |public: &str| {
            item(
                json!({ "overview": { "title": "k", "type": "sshKey" }, "details": { "publicKey": public } }),
            )
        };
        assert_ne!(
            duplicate_key(&ssh("ssh-ed25519 AAAA")),
            duplicate_key(&ssh("ssh-ed25519 BBBB"))
        );
        let env = |stage: &str| {
            item(
                json!({ "overview": { "title": "e", "type": "environment" }, "details": { "project": "api", "stage": stage, "variables": [] } }),
            )
        };
        assert_ne!(
            duplicate_key(&env("staging")),
            duplicate_key(&env("production"))
        );
    }

    #[test]
    fn wallets_keep_addresses_and_databases_keep_old_passwords() {
        let wallet = |address: &str| {
            json!({
                "overview": { "title": "W", "type": "cryptoWallet", "importedFrom": { "source": "cxf", "id": "1" } },
                "details": { "seedPhrase": "words", "addresses": [{ "network": "bitcoin", "address": address }] }
            })
        };
        let mut result = ImportResult {
            items: vec![item(wallet("new"))],
            ..ImportResult::default()
        };
        reconcile(&mut result, &[existing("w", wallet("old"))], "cxf", "now");
        let value = serde_json::to_value(&result.updates[0].item).unwrap();
        assert_eq!(value["details"]["addresses"][0]["address"], "new");
        assert_eq!(value["details"]["addresses"][1]["address"], "old");

        let database = |password: &str| {
            json!({
                "overview": { "title": "D", "type": "database" },
                "details": { "host": "db", "password": password }
            })
        };
        let mut result = ImportResult {
            items: vec![item(database("new"))],
            ..ImportResult::default()
        };
        reconcile(
            &mut result,
            &[existing("d", database("old"))],
            "keeper",
            "2026-10-24T00:00:00Z",
        );
        let value = serde_json::to_value(&result.updates[0].item).unwrap();
        assert_eq!(
            value["details"]["passwordHistory"],
            json!([{ "password": "old", "changedAt": "2026-10-24T00:00:00Z" }])
        );
    }

    #[test]
    fn one_site_from_three_apps_is_one_website() {
        use crate::import::{ImportOptions, ImportSource, import_file};
        let vault = json!({
            "overview": { "title": "Saasify", "type": "login", "urls": ["https://saasify.example.com"],
                          "urlMatch": { "https://saasify.example.com": "host" } },
            "details": { "username": "ada", "password": "pw" }
        });
        let mut stored = existing("s", vault);
        for (source, file) in [
            (
                ImportSource::Chrome,
                "name,url,username,password\nSaasify,https://saasify.example.com/,ada,pw\n",
            ),
            (
                ImportSource::Firefox,
                "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n\
                 https://saasify.example.com/login,ada,pw,,,{1},1700000000000,1700000000000,1700000000000\n",
            ),
        ] {
            let options = ImportOptions {
                existing_items: vec![stored.clone()],
                now: Some("2026-11-05T00:00:00Z".into()),
                ..ImportOptions::default()
            };
            let result = import_file(source, file.as_bytes(), &options).unwrap();
            assert!(result.items.is_empty(), "{source:?} matched the login");
            if let Some(update) = result.updates.first() {
                let value = serde_json::to_value(&update.item).unwrap();
                stored = existing("s", value);
            }
            let overview = serde_json::to_value(&stored.overview).unwrap();
            assert_eq!(
                overview["urls"],
                json!(["https://saasify.example.com"]),
                "{source:?}"
            );
            assert_eq!(
                overview["urlMatch"],
                json!({ "https://saasify.example.com": "host" }),
                "{source:?}"
            );
        }
    }

    #[test]
    fn new_websites_join_after_the_vaults() {
        let stored = json!({
            "overview": { "title": "A", "type": "login", "urls": ["https://a.example/login"], "importedFrom": { "source": "bitwarden-json", "id": "1" } },
            "details": { "username": "ada", "password": "pw" }
        });
        let imported = json!({
            "overview": { "title": "A", "type": "login",
                          "urls": ["https://b.example", "http://www.a.example", "^x$"],
                          "urlMatch": { "http://www.a.example": "never", "^x$": "regex" },
                          "importedFrom": { "source": "bitwarden-json", "id": "1" } },
            "details": { "username": "ada", "password": "pw" }
        });
        let mut result = ImportResult {
            items: vec![item(imported)],
            ..ImportResult::default()
        };
        reconcile(
            &mut result,
            &[existing("a", stored)],
            "bitwarden-json",
            "now",
        );
        let value = serde_json::to_value(&result.updates[0].item).unwrap();
        assert_eq!(
            value["overview"]["urls"],
            json!(["https://a.example/login", "https://b.example", "^x$"])
        );
        assert_eq!(value["overview"]["urlMatch"], json!({ "^x$": "regex" }));
    }

    #[test]
    fn a_change_without_a_date_drops_the_old_date() {
        let stored = json!({
            "overview": { "title": "Card", "type": "card", "updatedAt": "2020-01-01T00:00:00Z" },
            "details": { "number": "4111 1111 1111 1111", "cvv": "123" }
        });
        let imported = json!({
            "overview": { "title": "Card", "type": "card" },
            "details": { "number": "4111111111111111", "cvv": "456" }
        });
        let mut result = ImportResult {
            items: vec![item(imported)],
            ..ImportResult::default()
        };
        reconcile(&mut result, &[existing("c", stored)], "dashlane", "now");
        let value = serde_json::to_value(&result.updates[0].item).unwrap();
        assert_eq!(value["details"]["cvv"], "456");
        assert!(value["overview"].get("updatedAt").is_none());
    }
}
