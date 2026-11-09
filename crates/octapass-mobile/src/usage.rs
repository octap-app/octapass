//! How often and when each item was used, for the Frequently used and Recently used lists, and
//! the sidebar's lists that keep an order of their own (`packages/vault-client/src/usage.ts`).
//!
//! The uses live in one hidden `usageStats` item in the personal vault, encrypted like the rest
//! of the vault, so they follow the account to its other devices. Using an item never writes the
//! item itself. A use is copying one of its fields, filling it in, or opening its website; uses
//! wait a few seconds and are saved together.

use std::collections::HashMap;

use octapass_mobile_vault::model::{Item as StoredItem, ItemDraft as StoredDraft};
use serde_json::{Map, Value, json};

use crate::error::Result;
use crate::items::ItemSummary;
use crate::list::{ListSort, compare_names, matches_query, millis, sort_items};
use crate::vault::Ctx;

pub const USAGE_STATS_TYPE: &str = "usageStats";
/// The hidden item's title. Nobody sees it.
const USAGE_STATS_TITLE: &str = "Usage";
/// How long uses wait before they're saved, so a burst of copies is one write.
pub(crate) const USAGE_SAVE_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
/// The most items it remembers. The least recently used are forgotten first.
const MAX_USAGE_ENTRIES: usize = 500;
/// How many items the smart lists show.
pub const SMART_LIST_LIMIT: usize = 50;

/// The sidebar's lists that put items in an order of their own. Pinned and Favourites are
/// filters (`ItemFilter`), sorted like any list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum SmartList {
    /// Newest first, by the sync record's date.
    Created,
    /// The most uses first, then the latest use. Items never used aren't in it.
    Frequent,
    /// The latest use first. Items never used aren't in it.
    Used,
    /// The latest change first.
    Changed,
}

impl SmartList {
    /// Its name in the web vault's URLs and the catalogs: `created`, `frequent`, `used`, `changed`.
    pub fn name(self) -> &'static str {
        match self {
            SmartList::Created => "created",
            SmartList::Frequent => "frequent",
            SmartList::Used => "used",
            SmartList::Changed => "changed",
        }
    }
}

/// The name of a smart list (`created`, …), for the list keys the apps share with the web vault.
#[uniffi::export]
pub fn smart_list_name(list: SmartList) -> String {
    list.name().to_owned()
}

/// One item's uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ItemUse {
    pub count: u64,
    /// RFC 3339.
    pub last_used_at: String,
}

pub(crate) type Usage = HashMap<String, ItemUse>;

fn later(a: &str, b: &str) -> String {
    if millis(b) > millis(a) { b } else { a }.to_owned()
}

fn read_use(value: &Value) -> Option<ItemUse> {
    let count = value.get("count")?.as_f64()?;
    let last_used_at = value.get("lastUsedAt")?.as_str()?;
    (count.is_finite() && count >= 1.0 && millis(last_used_at) > 0).then(|| ItemUse {
        count: count as u64,
        last_used_at: last_used_at.to_owned(),
    })
}

pub(crate) fn is_usage_stats(item: &StoredItem) -> bool {
    item.overview.get("type").and_then(Value::as_str) == Some(USAGE_STATS_TYPE)
}

/// Merges every live usage item: two devices saving at once leave a conflict copy. Each item
/// keeps the higher count and the later use. Entries that don't read as uses are left out.
pub(crate) fn read_usage(items: &[StoredItem]) -> Usage {
    let mut merged = Usage::new();
    for item in items
        .iter()
        .filter(|item| is_usage_stats(item) && item.deleted_at.is_none())
    {
        let Some(entries) = item.details.get("items").and_then(Value::as_object) else {
            continue;
        };
        for (id, value) in entries {
            let Some(found) = read_use(value) else {
                continue;
            };
            merged
                .entry(id.clone())
                .and_modify(|known| {
                    known.count = known.count.max(found.count);
                    known.last_used_at = later(&known.last_used_at, &found.last_used_at);
                })
                .or_insert(found);
        }
    }
    merged
}

/// `usage` with `uses` added: counts add up, and the last use is the later one.
pub(crate) fn add_uses(usage: &mut Usage, uses: &Usage) {
    for (id, found) in uses {
        usage
            .entry(id.clone())
            .and_modify(|known| {
                known.count += found.count;
                known.last_used_at = later(&known.last_used_at, &found.last_used_at);
            })
            .or_insert_with(|| found.clone());
    }
}

/// At most `limit` entries, keeping the most recently used.
fn prune(usage: Usage, limit: usize) -> Usage {
    if usage.len() <= limit {
        return usage;
    }
    let mut entries: Vec<(String, ItemUse)> = usage.into_iter().collect();
    entries.sort_by(|(a, x), (b, y)| {
        millis(&y.last_used_at)
            .cmp(&millis(&x.last_used_at))
            .then_with(|| a.cmp(b))
    });
    entries.truncate(limit);
    entries.into_iter().collect()
}

fn usage_json(usage: &Usage) -> Value {
    let mut ids: Vec<&String> = usage.keys().collect();
    ids.sort();
    Value::Object(
        ids.into_iter()
            .map(|id| {
                let found = &usage[id];
                (
                    id.clone(),
                    json!({ "count": found.count, "lastUsedAt": found.last_used_at }),
                )
            })
            .collect::<Map<String, Value>>(),
    )
}

/// The items a smart list shows, in its order, at most `limit` of them (`smartListItems`).
/// `items` are the vault's items, not the trash or settings. Equal places fall back to the name,
/// then the id.
pub(crate) fn smart_list_items(
    mut items: Vec<ItemSummary>,
    list: SmartList,
    usage: &Usage,
    limit: usize,
) -> Vec<ItemSummary> {
    match list {
        SmartList::Created => sort_items(&mut items, ListSort::Newest),
        SmartList::Changed => sort_items(&mut items, ListSort::Changed),
        SmartList::Frequent | SmartList::Used => {
            items.retain(|item| usage.contains_key(&item.id));
            let by_name = |a: &ItemSummary, b: &ItemSummary| {
                compare_names(&a.title, &b.title).then_with(|| a.id.cmp(&b.id))
            };
            let last = |item: &ItemSummary| millis(&usage[&item.id].last_used_at);
            items.sort_by(|a, b| {
                let order = if list == SmartList::Frequent {
                    usage[&b.id].count.cmp(&usage[&a.id].count)
                } else {
                    std::cmp::Ordering::Equal
                };
                order
                    .then_with(|| last(b).cmp(&last(a)))
                    .then_with(|| by_name(a, b))
            });
        }
    }
    items.truncate(limit);
    items
}

/// What a smart list shows, then only those that match `query`: a search there looks through
/// what the list shows.
pub(crate) fn smart_list(
    items: Vec<ItemSummary>,
    list: SmartList,
    usage: &Usage,
    query: Option<&str>,
) -> Vec<ItemSummary> {
    let shown = smart_list_items(items, list, usage, SMART_LIST_LIMIT);
    match query.map(str::trim).filter(|query| !query.is_empty()) {
        Some(query) => shown
            .into_iter()
            .filter(|item| matches_query(item, query))
            .collect(),
        None => shown,
    }
}

impl Ctx<'_> {
    fn usage_items(&self) -> Result<Vec<StoredItem>> {
        let mut items: Vec<StoredItem> = self
            .vault
            .live_items()?
            .into_iter()
            .filter(is_usage_stats)
            .collect();
        items.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        Ok(items)
    }

    /// What the vault says about uses.
    pub(crate) fn usage(&self) -> Result<Usage> {
        Ok(read_usage(&self.usage_items()?))
    }

    /// Adds `uses` to the oldest usage item, or a new one in the personal vault, and folds any
    /// conflict copy into it.
    pub(crate) fn save_uses(&self, personal_vault_id: &str, uses: &Usage) -> Result<()> {
        let items = self.usage_items()?;
        let mut usage = read_usage(&items);
        add_uses(&mut usage, uses);
        let usage = prune(usage, MAX_USAGE_ENTRIES);
        let first = items.first();
        let mut details = first
            .and_then(|item| item.details.as_object().cloned())
            .unwrap_or_default();
        details.insert("schemaVersion".into(), json!(1));
        details.insert("items".into(), usage_json(&usage));
        self.vault.save_item(StoredDraft {
            id: first.map(|item| item.id.clone()),
            vault_id: first.map_or_else(|| personal_vault_id.to_owned(), |i| i.vault_id.clone()),
            revision: first.map(|item| item.revision),
            overview: first.map_or_else(
                || json!({ "schemaVersion": 1, "type": USAGE_STATS_TYPE, "title": USAGE_STATS_TITLE }),
                |item| item.overview.clone(),
            ),
            details: Value::Object(details),
        })?;
        for extra in items.iter().skip(1) {
            self.vault.delete_item(&extra.id)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::items::ItemType;

    fn stored(id: &str, created_at: &str, entries: Value) -> StoredItem {
        StoredItem {
            id: id.into(),
            vault_id: "p".into(),
            revision: 1,
            created_at: created_at.into(),
            updated_at: created_at.into(),
            deleted_at: None,
            overview: json!({ "schemaVersion": 1, "type": USAGE_STATS_TYPE, "title": "Usage" }),
            details: json!({ "schemaVersion": 1, "items": entries }),
        }
    }

    fn uses(pairs: &[(&str, u64, &str)]) -> Usage {
        pairs
            .iter()
            .map(|(id, count, at)| {
                (
                    (*id).to_owned(),
                    ItemUse {
                        count: *count,
                        last_used_at: (*at).to_owned(),
                    },
                )
            })
            .collect()
    }

    fn row(id: &str, title: &str, created: &str, changed: &str) -> ItemSummary {
        ItemSummary {
            id: id.into(),
            vault_id: "v".into(),
            item_type: ItemType::Login,
            title: title.into(),
            subtitle: None,
            urls: Vec::new(),
            tags: Vec::new(),
            favorite: false,
            has_totp: false,
            has_passkey: false,
            attachment_count: 0,
            created_at: created.into(),
            updated_at: changed.into(),
            deleted_at: None,
            site: None,
            icon_domain: None,
            project: None,
            stage: None,
            variable_keys: Vec::new(),
            pinned: false,
            places: Vec::new(),
        }
    }

    fn titles(items: &[ItemSummary]) -> Vec<&str> {
        items.iter().map(|item| item.title.as_str()).collect()
    }

    #[test]
    fn conflict_copies_merge_to_the_higher_count_and_the_later_use() {
        let a = stored(
            "x",
            "2026-01-01T00:00:00Z",
            json!({ "a": { "count": 3, "lastUsedAt": "2026-10-01T00:00:00Z" }, "bad": { "count": 0, "lastUsedAt": "2026-10-01T00:00:00Z" } }),
        );
        let b = stored(
            "y",
            "2026-01-02T00:00:00Z",
            json!({ "a": { "count": 1, "lastUsedAt": "2026-10-05T00:00:00Z" }, "b": { "count": 2, "lastUsedAt": "never" } }),
        );
        let mut gone = stored(
            "z",
            "2026-01-03T00:00:00Z",
            json!({ "c": { "count": 9, "lastUsedAt": "2026-10-05T00:00:00Z" } }),
        );
        gone.deleted_at = Some("2026-10-06T00:00:00Z".into());
        assert_eq!(
            read_usage(&[a, b, gone]),
            uses(&[("a", 3, "2026-10-05T00:00:00Z")])
        );
    }

    #[test]
    fn uses_add_up_and_the_oldest_are_forgotten_past_the_limit() {
        let mut usage = uses(&[("a", 2, "2026-10-01T00:00:00Z")]);
        add_uses(
            &mut usage,
            &uses(&[
                ("a", 1, "2026-10-03T00:00:00Z"),
                ("b", 1, "2026-10-02T00:00:00Z"),
            ]),
        );
        assert_eq!(
            usage,
            uses(&[
                ("a", 3, "2026-10-03T00:00:00Z"),
                ("b", 1, "2026-10-02T00:00:00Z"),
            ])
        );
        let kept = prune(usage, 1);
        assert_eq!(kept.keys().collect::<Vec<_>>(), vec!["a"]);
    }

    #[test]
    fn smart_lists_follow_the_web_vault() {
        let old = row("1", "Old", "2025-01-01T00:00:00Z", "2026-10-09T00:00:00Z");
        let mid = row("2", "Mid", "2026-03-01T00:00:00Z", "2026-03-01T00:00:00Z");
        let recent = row(
            "3",
            "Recent",
            "2026-10-01T00:00:00Z",
            "2026-10-01T00:00:00Z",
        );
        let unused = row(
            "4",
            "Unused",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        );
        let items = vec![old, mid, recent, unused];
        let usage = uses(&[
            ("1", 1, "2026-11-03T00:00:00Z"),
            ("2", 5, "2026-10-01T00:00:00Z"),
            ("3", 5, "2026-10-20T00:00:00Z"),
            ("gone", 50, "2026-11-04T00:00:00Z"),
        ]);
        let list = |which| smart_list_items(items.clone(), which, &usage, SMART_LIST_LIMIT);
        assert_eq!(
            titles(&list(SmartList::Created)),
            ["Recent", "Mid", "Unused", "Old"]
        );
        assert_eq!(
            titles(&list(SmartList::Changed)),
            ["Old", "Recent", "Mid", "Unused"]
        );
        assert_eq!(titles(&list(SmartList::Frequent)), ["Recent", "Mid", "Old"]);
        assert_eq!(titles(&list(SmartList::Used)), ["Old", "Recent", "Mid"]);
        assert_eq!(
            titles(&smart_list_items(
                items.clone(),
                SmartList::Created,
                &usage,
                2
            )),
            ["Recent", "Mid"]
        );
        assert_eq!(
            titles(&smart_list(
                items.clone(),
                SmartList::Used,
                &usage,
                Some(" rec ")
            )),
            ["Recent"]
        );
    }

    #[test]
    fn names_match_the_web_vault() {
        assert_eq!(
            [
                SmartList::Created,
                SmartList::Frequent,
                SmartList::Used,
                SmartList::Changed
            ]
            .map(SmartList::name),
            ["created", "frequent", "used", "changed"]
        );
    }
}
