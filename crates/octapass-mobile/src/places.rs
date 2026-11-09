//! Nearby (plan 01): places saved in the vault, the items at each, and which place the phone is
//! at, worked out here by the core (`octapass_core::places`). The app passes in what it knows
//! ([`Here`]: the Wi-Fi network it's on, one location reading taken while it's open); none of it
//! leaves the phone. Places are `place` items, encrypted like any other and kept out of item lists.

use std::sync::Arc;

use octapass_core::places::{self, PlaceData, PlaceEntry, PlacedItem};
use octapass_mobile_vault::model::{Item as StoredItem, ItemDraft as StoredDraft};
use serde_json::{Map, Value, json};

use crate::error::{ErrorCode, Result, VaultError};
use crate::items::{Item, ItemSummary, ItemType, item_draft};
use crate::list::compare_names;
use crate::sharing::VaultType;
use crate::vault::OctaPassVault;

/// A place: a name, and how to tell the phone is there.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct Place {
    pub id: String,
    pub vault_id: String,
    /// Pass it back in the draft, like an item's.
    pub revision: u64,
    pub name: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    /// Metres around the point; the default (150) when none was saved.
    pub radius: f64,
    /// Wi-Fi network names (SSIDs): being on one means being here.
    pub networks: Vec<String>,
    pub notes: Option<String>,
}

/// What `savePlace` takes. No `id` for a new place.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct PlaceDraft {
    pub id: Option<String>,
    pub vault_id: String,
    pub revision: Option<u64>,
    pub name: String,
    /// Both or neither.
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    /// Kept within 25 m to 10 km; `None` is the default.
    pub radius: Option<f64>,
    pub networks: Vec<String>,
    pub notes: Option<String>,
}

/// Where the phone is, as far as it can tell. Both parts are optional.
#[derive(Debug, Clone, Default, PartialEq, uniffi::Record)]
pub struct Here {
    /// The Wi-Fi network the phone is on (where the system says).
    pub networks: Vec<String>,
    /// One reading, taken while the app is open: never in the background.
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    /// Metres.
    pub accuracy: Option<f64>,
}

impl From<&Here> for places::Here {
    fn from(here: &Here) -> Self {
        let position = match (here.latitude, here.longitude) {
            (Some(latitude), Some(longitude)) => Some(places::Position {
                latitude,
                longitude,
                accuracy: here.accuracy,
            }),
            _ => None,
        };
        places::Here {
            networks: here.networks.clone(),
            position,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HereBy {
    /// The phone is on one of the place's networks.
    Wifi,
    /// The phone's location is within the place's radius.
    Location,
}

/// The items of one type at a place, by name.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct NearbySection {
    pub item_type: ItemType,
    pub items: Vec<ItemSummary>,
}

/// A place in the Nearby list.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct NearbyPlace {
    pub place: Place,
    /// Set when the phone is at this place: "Now nearby".
    pub here: Option<HereBy>,
    /// Metres from the phone, when both points are known.
    pub distance: Option<f64>,
    /// In the lists' type order.
    pub sections: Vec<NearbySection>,
}

fn place_of(item: &StoredItem) -> Place {
    let data = place_data(item);
    Place {
        id: item.id.clone(),
        vault_id: item.vault_id.clone(),
        revision: item.revision,
        name: item
            .overview
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        latitude: data.point().map(|p| p.latitude),
        longitude: data.point().map(|p| p.longitude),
        radius: data.radius(),
        networks: data.networks,
        notes: item
            .details
            .get("notes")
            .and_then(Value::as_str)
            .filter(|n| !n.is_empty())
            .map(str::to_owned),
    }
}

fn place_data(item: &StoredItem) -> PlaceData {
    item.overview
        .get(places::PLACE_FIELD)
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

fn is_place(item: &StoredItem) -> bool {
    item.overview.get("type").and_then(Value::as_str) == Some(places::PLACE_TYPE)
}

fn by_name(a: &str, b: &str, a_id: &str, b_id: &str) -> std::cmp::Ordering {
    compare_names(a, b).then_with(|| a_id.cmp(b_id))
}

/// The places and items to hand the core, each by name, and the summaries to show.
fn inputs(
    stored: &[StoredItem],
) -> (
    Vec<&StoredItem>,
    Vec<PlaceEntry>,
    Vec<ItemSummary>,
    Vec<PlacedItem>,
) {
    let mut live: Vec<&StoredItem> = stored
        .iter()
        .filter(|item| item.deleted_at.is_none())
        .collect();
    let title = |item: &StoredItem| {
        item.overview
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    live.sort_by(|a, b| by_name(&title(a), &title(b), &a.id, &b.id));
    let place_items: Vec<&StoredItem> =
        live.iter().copied().filter(|item| is_place(item)).collect();
    let entries = place_items
        .iter()
        .map(|item| PlaceEntry {
            id: item.id.clone(),
            vault_id: Some(item.vault_id.clone()),
            place: Some(place_data(item)),
        })
        .collect();
    let summaries: Vec<ItemSummary> = live
        .iter()
        .filter(|item| !is_place(item))
        .map(|item| ItemSummary::from(*item))
        .collect();
    let placed = summaries.iter().map(placed).collect();
    (place_items, entries, summaries, placed)
}

fn placed(summary: &ItemSummary) -> PlacedItem {
    PlacedItem {
        id: summary.id.clone(),
        item_type: summary.item_type.name().to_owned(),
        places: summary.places.clone(),
        subtitle: summary.subtitle.clone(),
    }
}

/// The Nearby list from the vault's items (`OctaPassVault::nearby`).
pub(crate) fn nearby_from(stored: &[StoredItem], here: &Here) -> Vec<NearbyPlace> {
    let (place_items, entries, summaries, placed_items) = inputs(stored);
    places::nearby_list(&entries, &placed_items, &here.into())
        .into_iter()
        .filter_map(|entry| {
            let item = place_items.iter().find(|item| item.id == entry.id)?;
            let sections = entry
                .sections
                .into_iter()
                .map(|section| NearbySection {
                    item_type: ItemType::parse(&section.item_type),
                    items: section
                        .items
                        .iter()
                        .filter_map(|id| summaries.iter().find(|s| &s.id == id).cloned())
                        .collect(),
                })
                .collect();
            Some(NearbyPlace {
                place: place_of(item),
                here: entry.here.map(|by| match by {
                    places::HereBy::Wifi => HereBy::Wifi,
                    places::HereBy::Location => HereBy::Location,
                }),
                distance: entry.distance,
                sections,
            })
        })
        .collect()
}

/// The place to offer item `id` to, from the vault's items (`OctaPassVault::suggested_place`).
pub(crate) fn suggestion_from(
    stored: &[StoredItem],
    id: &str,
    personal: bool,
    here: &Here,
) -> Option<Place> {
    let (place_items, entries, summaries, placed_items) = inputs(stored);
    let summary = summaries.iter().find(|summary| summary.id == id)?;
    let chosen = places::suggested_place(
        &entries,
        &placed_items,
        &here.into(),
        &placed(summary),
        &summary.vault_id,
        personal,
    )?;
    place_items
        .iter()
        .find(|item| item.id == chosen)
        .map(|item| place_of(item))
}

/// A draft's overview `place` object and details, checked by the core.
fn place_json(draft: &PlaceDraft, stored: Option<&StoredItem>) -> Result<(Value, Value)> {
    let name = draft.name.trim();
    if name.is_empty() {
        return Err(VaultError::new(
            ErrorCode::InvalidInput,
            "a place needs a name",
        ));
    }
    let mut data = stored.map(place_data).unwrap_or_default();
    data.latitude = draft.latitude;
    data.longitude = draft.longitude;
    data.radius = draft.radius;
    data.networks = draft.networks.clone();
    let data = data.cleaned().map_err(|_| {
        VaultError::new(
            ErrorCode::InvalidInput,
            "latitude and longitude go together, within ±90 and ±180",
        )
    })?;
    let mut overview: Map<String, Value> = stored
        .and_then(|item| item.overview.as_object().cloned())
        .unwrap_or_default();
    overview.insert(
        "schemaVersion".into(),
        json!(octapass_core::item::SCHEMA_VERSION),
    );
    overview.insert("type".into(), json!(places::PLACE_TYPE));
    overview.insert("title".into(), json!(name));
    overview.insert(
        places::PLACE_FIELD.into(),
        serde_json::to_value(&data).expect("a place serializes"),
    );
    let mut details: Map<String, Value> = stored
        .and_then(|item| item.details.as_object().cloned())
        .unwrap_or_default();
    details.insert(
        "schemaVersion".into(),
        json!(octapass_core::item::SCHEMA_VERSION),
    );
    match draft
        .notes
        .as_deref()
        .map(str::trim)
        .filter(|notes| !notes.is_empty())
    {
        Some(notes) => details.insert("notes".into(), json!(notes)),
        None => details.remove("notes"),
    };
    Ok((Value::Object(overview), Value::Object(details)))
}

#[uniffi::export]
impl OctaPassVault {
    /// Every place, by name (the Places manager).
    pub async fn places(self: Arc<Self>) -> Result<Vec<Place>> {
        self.run(|this| {
            let stored = this.visible_items()?;
            let (place_items, ..) = inputs(&stored);
            Ok(place_items.into_iter().map(place_of).collect())
        })
        .await
    }

    /// Saves a new place or an edit of one. A place in a shared or family vault is seen by
    /// everyone in it: apps warn before saving one with a location there.
    pub async fn save_place(self: Arc<Self>, draft: PlaceDraft) -> Result<Place> {
        self.run(move |this| {
            let stored = match &draft.id {
                Some(id) => {
                    let item = this.vault.get_item(id)?;
                    if !is_place(&item) {
                        return Err(ErrorCode::NotFound.into());
                    }
                    Some(item)
                }
                None => None,
            };
            let (overview, details) = place_json(&draft, stored.as_ref())?;
            let saved = this.vault.save_item(StoredDraft {
                id: draft.id.clone(),
                vault_id: draft.vault_id.clone(),
                revision: draft.revision,
                overview,
                details,
            })?;
            this.refresh_pending();
            Ok(place_of(&saved))
        })
        .await
    }

    /// Moves a place to the trash. Its items stay; they just aren't listed under it.
    pub async fn delete_place(self: Arc<Self>, id: String) -> Result<()> {
        self.run(move |this| {
            if !is_place(&this.vault.get_item(&id)?) {
                return Err(ErrorCode::NotFound.into());
            }
            this.vault.delete_item(&id)?;
            this.refresh_pending();
            Ok(())
        })
        .await
    }

    /// Nearby: every place with its items, the places the phone is at first, then the others
    /// nearest first when the location is known (places without a point after them, by name).
    pub async fn nearby(self: Arc<Self>, here: Here) -> Result<Vec<NearbyPlace>> {
        self.run(move |this| Ok(nearby_from(&this.visible_items()?, &here)))
            .await
    }

    /// The place to offer a newly saved item to ("You're at Office. Add this item to it?"): one
    /// the phone is at, that everyone who sees the item can see, and that it isn't at yet.
    pub async fn suggested_place(
        self: Arc<Self>,
        item_id: String,
        here: Here,
    ) -> Result<Option<Place>> {
        self.run(move |this| {
            let stored = this.visible_items()?;
            let vault_id = match stored.iter().find(|item| item.id == item_id) {
                Some(item) => item.vault_id.clone(),
                None => return Ok(None),
            };
            let personal = this
                .vaults()?
                .iter()
                .any(|vault| vault.id == vault_id && vault.vault_type == VaultType::Personal);
            Ok(suggestion_from(&stored, &item_id, personal, &here))
        })
        .await
    }

    /// Adds the item to a place, or takes it off one ("Add to a place").
    pub async fn set_item_place(
        self: Arc<Self>,
        item_id: String,
        place_id: String,
        linked: bool,
    ) -> Result<Item> {
        self.run(move |this| {
            let item = this.item(&item_id)?;
            let places = places::with_place(&item.places, &place_id, linked);
            let mut draft = item_draft(item);
            draft.places = Some(places);
            this.save(&draft)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(id: &str, vault: &str, overview: Value) -> StoredItem {
        StoredItem {
            id: id.into(),
            vault_id: vault.into(),
            revision: 1,
            created_at: "2026-11-01T00:00:00Z".into(),
            updated_at: "2026-11-01T00:00:00Z".into(),
            deleted_at: None,
            overview,
            details: json!({ "schemaVersion": 1 }),
        }
    }

    fn vault_items() -> Vec<StoredItem> {
        vec![
            stored(
                "p-home",
                "personal",
                json!({ "type": "place", "title": "Home", "place": { "networks": ["Home"] } }),
            ),
            stored(
                "p-office",
                "personal",
                json!({ "type": "place", "title": "Office", "place": { "latitude": 51.5, "longitude": -0.12 } }),
            ),
            stored(
                "p-lab",
                "team",
                json!({ "type": "place", "title": "Lab", "place": { "networks": ["Lab"] } }),
            ),
            stored(
                "door",
                "personal",
                json!({ "type": "secureNote", "title": "Door code", "places": ["p-home"] }),
            ),
            stored(
                "alarm",
                "personal",
                json!({ "type": "secureNote", "title": "Alarm", "places": ["p-home"] }),
            ),
            stored(
                "printer",
                "personal",
                json!({ "type": "login", "title": "Printer", "places": ["p-office"] }),
            ),
            stored(
                "router",
                "personal",
                json!({ "type": "wifi", "title": "Router", "subtitle": "Home" }),
            ),
            stored(
                "shared",
                "team",
                json!({ "type": "login", "title": "Lab VPN" }),
            ),
        ]
    }

    #[test]
    fn nearby_lists_the_place_here_first_with_its_items_by_type_and_name() {
        let here = Here {
            networks: vec!["Home".into()],
            ..Here::default()
        };
        let list = nearby_from(&vault_items(), &here);
        let names: Vec<&str> = list.iter().map(|p| p.place.name.as_str()).collect();
        assert_eq!(names, ["Home", "Lab", "Office"]);
        assert_eq!(list[0].here, Some(HereBy::Wifi));
        let home: Vec<(ItemType, Vec<&str>)> = list[0]
            .sections
            .iter()
            .map(|s| {
                (
                    s.item_type.clone(),
                    s.items.iter().map(|i| i.title.as_str()).collect(),
                )
            })
            .collect();
        assert_eq!(
            home,
            [
                (ItemType::SecureNote, vec!["Alarm", "Door code"]),
                (ItemType::Wifi, vec!["Router"])
            ]
        );
        // By location: the office comes first, with its distance.
        let at_office = Here {
            latitude: Some(51.5005),
            longitude: Some(-0.12),
            accuracy: Some(20.0),
            ..Here::default()
        };
        let list = nearby_from(&vault_items(), &at_office);
        assert_eq!(list[0].place.name, "Office");
        assert_eq!(list[0].here, Some(HereBy::Location));
        assert!((list[0].distance.unwrap() - 55.6).abs() < 1.0);
    }

    #[test]
    fn a_shared_item_is_offered_only_places_in_its_vault() {
        let on = |ssid: &str| Here {
            networks: vec![ssid.into()],
            ..Here::default()
        };
        assert_eq!(
            suggestion_from(&vault_items(), "printer", true, &on("Home")).map(|p| p.name),
            Some("Home".into())
        );
        assert_eq!(
            suggestion_from(&vault_items(), "shared", false, &on("Home")),
            None
        );
        assert_eq!(
            suggestion_from(&vault_items(), "shared", false, &on("Lab")).map(|p| p.name),
            Some("Lab".into())
        );
        assert_eq!(
            suggestion_from(&vault_items(), "door", true, &on("Home")),
            None,
            "already there"
        );
        assert_eq!(
            suggestion_from(&vault_items(), "printer", true, &Here::default()),
            None
        );
    }

    #[test]
    fn drafts_are_checked_and_keep_what_they_dont_know() {
        let draft = PlaceDraft {
            id: None,
            vault_id: "personal".into(),
            revision: None,
            name: "  Cabin ".into(),
            latitude: Some(10.1234567),
            longitude: Some(20.0),
            radius: Some(5.0),
            networks: vec!["Cabin".into(), "Cabin".into(), "".into()],
            notes: Some("  ".into()),
        };
        let (overview, details) = place_json(&draft, None).unwrap();
        assert_eq!(overview["title"], "Cabin");
        assert_eq!(
            overview["place"],
            json!({ "latitude": 10.123457, "longitude": 20.0, "radius": 25.0, "networks": ["Cabin"] })
        );
        assert!(details.get("notes").is_none());
        let old = stored(
            "p",
            "personal",
            json!({ "type": "place", "title": "Old", "floor": 3, "place": { "networks": ["X"], "beacon": "b" } }),
        );
        let (overview, _) = place_json(
            &PlaceDraft {
                latitude: None,
                longitude: None,
                networks: vec![],
                ..draft.clone()
            },
            Some(&old),
        )
        .unwrap();
        assert_eq!(overview["floor"], 3);
        assert_eq!(overview["place"], json!({ "radius": 25.0, "beacon": "b" }));
        assert!(
            place_json(
                &PlaceDraft {
                    longitude: None,
                    ..draft.clone()
                },
                None
            )
            .is_err()
        );
        assert!(
            place_json(
                &PlaceDraft {
                    name: " ".into(),
                    ..draft
                },
                None
            )
            .is_err()
        );
    }
}
