//! An account's encrypted vaults and items, kept in step with `GET /v1/sync`.

use octapass_api::{ItemRecord, SyncResponse, VaultRecord};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultCache {
    pub vaults: Vec<VaultRecord>,
    pub items: Vec<ItemRecord>,
}

impl VaultCache {
    /// The `since` parameter for the next sync.
    pub fn since(&self) -> Vec<(String, u64)> {
        self.vaults
            .iter()
            .map(|vault| (vault.id.clone(), vault.revision))
            .collect()
    }

    pub fn vault(&self, id: &str) -> Option<&VaultRecord> {
        self.vaults.iter().find(|vault| vault.id == id)
    }

    pub fn item(&self, id: &str) -> Option<&ItemRecord> {
        self.items.iter().find(|item| item.id == id)
    }

    /// Applies a sync response. The server returns every vault the account can still access,
    /// items changed since the revisions we sent (all items for vaults we didn't send), and
    /// tombstones for items purged from the trash. Returns whether anything changed.
    pub fn apply(&mut self, response: SyncResponse) -> bool {
        let before = self.clone();
        self.items.retain(|item| {
            response
                .vaults
                .iter()
                .any(|vault| vault.id == item.vault_id)
        });
        for deleted in &response.deleted {
            self.items
                .retain(|item| !(item.id == deleted.item_id && item.vault_id == deleted.vault_id));
        }
        for record in response.items {
            match self.items.iter_mut().find(|item| item.id == record.id) {
                Some(existing) if existing.revision > record.revision => {}
                Some(existing) => *existing = record,
                None => self.items.push(record),
            }
        }
        self.vaults = response.vaults;
        *self != before
    }

    /// Puts a record the server returned (a `409` body) in place of ours.
    pub fn upsert(&mut self, record: ItemRecord) {
        match self.items.iter_mut().find(|item| item.id == record.id) {
            Some(existing) => *existing = record,
            None => self.items.push(record),
        }
    }
}

#[cfg(test)]
mod tests {
    use octapass_api::{DeletedItem, VaultRole, VaultType};

    use super::*;

    fn vault(id: &str, revision: u64) -> VaultRecord {
        VaultRecord {
            id: id.into(),
            vault_type: VaultType::Personal,
            revision,
            wrapped_vault_key: "k".into(),
            role: VaultRole::Owner,
            key_id: None,
            grant: None,
            org_id: None,
        }
    }

    fn item(id: &str, vault_id: &str, revision: u64) -> ItemRecord {
        ItemRecord {
            id: id.into(),
            vault_id: vault_id.into(),
            revision,
            encrypted_item_key: "k".into(),
            overview: format!("o{revision}"),
            details: "d".into(),
            updated_at: "t".into(),
            deleted_at: None,
        }
    }

    fn sync(
        vaults: Vec<VaultRecord>,
        items: Vec<ItemRecord>,
        deleted: Vec<DeletedItem>,
    ) -> SyncResponse {
        SyncResponse {
            vaults,
            items,
            deleted,
            has_more: false,
        }
    }

    #[test]
    fn the_first_sync_fills_the_cache() {
        let mut cache = VaultCache::default();
        assert!(cache.since().is_empty());
        assert!(cache.apply(sync(
            vec![vault("v", 2)],
            vec![item("a", "v", 1), item("b", "v", 2)],
            vec![]
        )));
        assert_eq!(cache.since(), [("v".to_owned(), 2)]);
        assert_eq!(cache.items.len(), 2);
        assert!(
            !cache.apply(sync(vec![vault("v", 2)], vec![], vec![])),
            "nothing new"
        );
    }

    #[test]
    fn later_syncs_update_add_and_purge() {
        let mut cache = VaultCache::default();
        cache.apply(sync(
            vec![vault("v", 2)],
            vec![item("a", "v", 1), item("b", "v", 2)],
            vec![],
        ));
        let purged = DeletedItem {
            vault_id: "v".into(),
            item_id: "b".into(),
            revision: 4,
        };
        assert!(cache.apply(sync(
            vec![vault("v", 4)],
            vec![item("a", "v", 3), item("c", "v", 4)],
            vec![purged]
        )));
        assert_eq!(cache.item("a").unwrap().overview, "o3");
        assert!(cache.item("b").is_none());
        assert!(cache.item("c").is_some());
    }

    #[test]
    fn an_older_record_never_replaces_a_newer_one() {
        let mut cache = VaultCache::default();
        cache.apply(sync(vec![vault("v", 5)], vec![item("a", "v", 5)], vec![]));
        cache.apply(sync(vec![vault("v", 5)], vec![item("a", "v", 4)], vec![]));
        assert_eq!(cache.item("a").unwrap().revision, 5);
    }

    #[test]
    fn losing_access_to_a_vault_drops_its_items() {
        let mut cache = VaultCache::default();
        cache.apply(sync(
            vec![vault("v", 1), vault("w", 1)],
            vec![item("a", "v", 1), item("b", "w", 1)],
            vec![],
        ));
        assert!(cache.apply(sync(vec![vault("v", 1)], vec![], vec![])));
        assert!(cache.vault("w").is_none());
        assert!(cache.item("b").is_none());
        assert!(cache.item("a").is_some());
    }

    #[test]
    fn upsert_replaces_or_adds() {
        let mut cache = VaultCache::default();
        cache.upsert(item("a", "v", 1));
        cache.upsert(item("a", "v", 2));
        assert_eq!(cache.items.len(), 1);
        assert_eq!(cache.item("a").unwrap().revision, 2);
    }
}
