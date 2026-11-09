//! Nearby: the places in the vault and the items at each, the place the computer is at first.
//! Worked out here by the core (`octapass_core::places`): `here` never leaves this computer.

use octapass_core::places::{self, Here, NearbyPlace, PlaceData, PlaceEntry, PlacedItem};

use super::Vault;
use crate::error::Result;
use octapass_api::VaultType;

use crate::model::ItemSummary;

/// The places and the items that can be at them, each by name, out of every row.
fn inputs(rows: &[ItemSummary]) -> (Vec<PlaceEntry>, Vec<PlacedItem>) {
    let mut live: Vec<&ItemSummary> = rows.iter().filter(|row| row.deleted_at.is_none()).collect();
    live.sort_by(|a, b| {
        a.title
            .to_lowercase()
            .cmp(&b.title.to_lowercase())
            .then_with(|| a.id.cmp(&b.id))
    });
    let entries = live
        .iter()
        .filter(|row| row.item_type == places::PLACE_TYPE)
        .map(|row| PlaceEntry {
            id: row.id.clone(),
            vault_id: Some(row.vault_id.clone()),
            place: row
                .place
                .clone()
                .and_then(|value| serde_json::from_value::<PlaceData>(value).ok()),
        })
        .collect();
    let items = live.iter().map(|row| placed(row)).collect();
    (entries, items)
}

fn placed(row: &ItemSummary) -> PlacedItem {
    PlacedItem {
        id: row.id.clone(),
        item_type: row.item_type.clone(),
        places: row.places.clone(),
        subtitle: row.subtitle.clone(),
    }
}

impl Vault {
    /// Every place with its items, the places the computer is at first (`VaultService.nearby`).
    pub fn nearby(&self, here: &Here) -> Result<Vec<NearbyPlace>> {
        let (entries, items) = inputs(&self.list_items()?);
        Ok(places::nearby_list(&entries, &items, here))
    }

    /// The place to offer a new item to, if the computer is at one its readers can all see.
    pub fn suggest_place(&self, item_id: &str, here: &Here) -> Result<Option<String>> {
        let rows = self.list_items()?;
        let Some(row) = rows
            .iter()
            .find(|row| row.id == item_id && row.deleted_at.is_none())
        else {
            return Ok(None);
        };
        let personal = self
            .list_vaults()?
            .iter()
            .any(|vault| vault.id == row.vault_id && vault.vault_type == VaultType::Personal);
        let (entries, items) = inputs(&rows);
        Ok(places::suggested_place(
            &entries,
            &items,
            here,
            &placed(row),
            &row.vault_id,
            personal,
        ))
    }
}
