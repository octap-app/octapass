//! Nearby (plan 01): places saved in the vault, and the items that belong to each, listed with the
//! place the device is at first.
//!
//! A place is an item of type `place`, kept out of item lists like the other setting types. Its
//! overview's `place` object holds an optional point (latitude, longitude), a radius and the names
//! of its Wi-Fi networks; its details hold a note. Any item links to places by listing their ids
//! in its overview's `places`. Everything here is inside the end-to-end encrypted item, and
//! working out which place the device is at happens here, on the device: the server never sees a
//! place, a coordinate or a network name (plan 03, *Nearby*).
//!
//! The device tells [`nearby_list`] where it is ([`Here`]): the Wi-Fi networks it's connected to,
//! and, when the user allows it, one reading of its location. A place is *here* when one of its
//! networks is connected, or when the reading falls within its radius.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// The item type of a place.
pub const PLACE_TYPE: &str = "place";
/// The overview field that holds a place's point, radius and networks.
pub const PLACE_FIELD: &str = "place";
/// The overview field, on any item, that lists the ids of the places it belongs to.
pub const PLACES_FIELD: &str = "places";

/// The radius a place gets when none is set: about a building and its car park.
pub const DEFAULT_RADIUS: f64 = 150.0;
/// The smallest radius kept: a phone's location is rarely closer than this.
pub const MIN_RADIUS: f64 = 25.0;
/// The largest radius kept: a campus or a small town.
pub const MAX_RADIUS: f64 = 10_000.0;
/// How much of a reading's uncertainty counts in its favour, at most. A rough reading (a computer
/// placed by its IP address, a few kilometres) mustn't make every place in town nearby.
pub const MAX_ACCURACY_SLACK: f64 = 500.0;
/// The most networks a place keeps.
pub const MAX_NETWORKS: usize = 20;
/// The longest network name: SSIDs are at most 32 bytes.
const MAX_SSID_BYTES: usize = 32;

/// The mean Earth radius (IUGG), in metres.
const EARTH_RADIUS: f64 = 6_371_008.8;

/// The order type sections come in, as in the web vault's lists (`TYPE_SECTION_ORDER` in
/// `packages/vault-client/src/listOrder.ts`). Types from a newer client follow, by name.
pub const TYPE_SECTION_ORDER: [&str; 20] = [
    "login",
    "password",
    "card",
    "identity",
    "secureNote",
    "wifi",
    "sshKey",
    "certificate",
    "key",
    "document",
    "environment",
    "bankAccount",
    "idDocument",
    "cryptoWallet",
    "apiCredential",
    "database",
    "softwareLicense",
    "custom",
    "customTemplate",
    "maskedEmailProvider",
];

/// Item types that hold settings rather than things to list (`HIDDEN_ITEM_TYPES` in
/// `packages/vault-client/src/items.ts`, plus shared vaults' name records). Nearby never lists them
/// under a place.
pub const HIDDEN_TYPES: [&str; 8] = [
    "maskedEmailProvider",
    "healthSettings",
    "equivalentDomains",
    "usageStats",
    "customTemplate",
    "fileSafe",
    "vaultInfo",
    PLACE_TYPE,
];

/// A point on Earth, in degrees (WGS 84, as every location API gives it).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Point {
    pub latitude: f64,
    pub longitude: f64,
}

impl Point {
    /// Whether the point is a real place: finite, latitude within ±90° and longitude within ±180°.
    pub fn is_valid(&self) -> bool {
        self.latitude.is_finite()
            && self.longitude.is_finite()
            && (-90.0..=90.0).contains(&self.latitude)
            && (-180.0..=180.0).contains(&self.longitude)
    }
}

/// The great-circle distance between two points, in metres (haversine, on a sphere: within 0.5%
/// of the ellipsoid, a metre or so at a place's scale).
pub fn distance(a: Point, b: Point) -> f64 {
    let (la1, la2) = (a.latitude.to_radians(), b.latitude.to_radians());
    let d_lat = la2 - la1;
    let d_lon = (b.longitude - a.longitude).to_radians();
    let h = (d_lat / 2.0).sin().powi(2) + la1.cos() * la2.cos() * (d_lon / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS * h.sqrt().min(1.0).asin()
}

/// A place's overview `place` object: where it is and which networks are its own. Every field is
/// optional, so a place can be just a name with items (listed, never *here*), a network, a point,
/// or both. Fields this version doesn't know are kept in `extra`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaceData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    /// Metres around the point. Missing means [`DEFAULT_RADIUS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radius: Option<f64>,
    /// Wi-Fi network names (SSIDs), exactly as broadcast: being connected to one means being here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PlaceData {
    /// The point, when both coordinates are set and valid.
    pub fn point(&self) -> Option<Point> {
        let point = Point {
            latitude: self.latitude?,
            longitude: self.longitude?,
        };
        point.is_valid().then_some(point)
    }

    /// The radius in metres: the saved one within [`MIN_RADIUS`]..[`MAX_RADIUS`], or the default.
    pub fn radius(&self) -> f64 {
        match self.radius {
            Some(radius) if radius.is_finite() => radius.clamp(MIN_RADIUS, MAX_RADIUS),
            _ => DEFAULT_RADIUS,
        }
    }

    /// The place as editors should save it: both coordinates or neither (rounded to 6 decimals,
    /// about 10 cm, which is all a phone can tell), the radius within its bounds and rounded to a
    /// metre, and the network names without empty, duplicate or over-long ones. Fails with
    /// [`Error::InvalidItem`] when only one coordinate is set or they aren't a real point.
    pub fn cleaned(&self) -> Result<PlaceData> {
        let (latitude, longitude) = match (self.latitude, self.longitude) {
            (None, None) => (None, None),
            (Some(latitude), Some(longitude)) => {
                if !(Point {
                    latitude,
                    longitude,
                })
                .is_valid()
                {
                    return Err(Error::InvalidItem);
                }
                (Some(round6(latitude)), Some(round6(longitude)))
            }
            _ => return Err(Error::InvalidItem),
        };
        let radius = match self.radius {
            Some(radius) if radius.is_finite() => {
                Some(radius.clamp(MIN_RADIUS, MAX_RADIUS).round())
            }
            _ => None,
        };
        let mut seen = HashSet::new();
        let networks = self
            .networks
            .iter()
            .filter(|ssid| !ssid.trim().is_empty() && ssid.len() <= MAX_SSID_BYTES)
            .filter(|ssid| seen.insert(ssid.as_str()))
            .take(MAX_NETWORKS)
            .cloned()
            .collect();
        Ok(PlaceData {
            latitude,
            longitude,
            radius,
            networks,
            extra: self.extra.clone(),
        })
    }
}

fn schema_version() -> u32 {
    crate::item::SCHEMA_VERSION
}

fn round6(degrees: f64) -> f64 {
    (degrees * 1e6).round() / 1e6
}

/// The details of a `place` item.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaceDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One reading of the device's location.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Position {
    pub latitude: f64,
    pub longitude: f64,
    /// How far off the reading may be, in metres (the radius of 68% confidence that iOS, Android
    /// and browsers report).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accuracy: Option<f64>,
}

/// Where the device is, as far as it can tell. Both parts are optional: without either, every
/// place is listed and none is *here*.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Here {
    /// The Wi-Fi networks the device is connected to (usually one).
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<Position>,
}

/// Why a place is *here*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HereBy {
    /// The device is connected to one of the place's networks.
    Wifi,
    /// The device's location is within the place's radius.
    Location,
}

/// A place to list: its item id, and its overview's `place` object (missing for a place that is
/// only a name). Other fields are ignored, so a list's summary of the place item can be passed as is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaceEntry {
    pub id: String,
    /// The vault the place is in, for [`suggested_place`]. Not needed by [`nearby_list`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<PlaceData>,
}

/// An item to file under its places: its id, type, the places it links to, and its subtitle (a
/// Wi-Fi item's network name). Other fields are ignored, like [`PlaceEntry`]'s.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacedItem {
    pub id: String,
    #[serde(rename = "type")]
    pub item_type: String,
    #[serde(default)]
    pub places: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
}

/// The items of one type at a place, in the order they were given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NearbySection {
    #[serde(rename = "type")]
    pub item_type: String,
    pub items: Vec<String>,
}

/// A place in the Nearby list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NearbyPlace {
    pub id: String,
    /// Set when the device is at this place, and how it knows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub here: Option<HereBy>,
    /// Metres from the device's location to the place's point, when both are known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distance: Option<f64>,
    /// Its items, a section per type, in [`TYPE_SECTION_ORDER`].
    pub sections: Vec<NearbySection>,
}

/// The networks a place is known by: its own, and those of the Wi-Fi items linked to it.
fn networks_of<'a>(
    id: &str,
    place: Option<&'a PlaceData>,
    items: &'a [PlacedItem],
) -> HashSet<&'a str> {
    let own = place
        .map(|place| place.networks.iter().map(String::as_str))
        .into_iter()
        .flatten();
    let linked = items
        .iter()
        .filter(|item| item.item_type == "wifi" && item.places.iter().any(|one| one == id))
        .filter_map(|item| item.subtitle.as_deref());
    own.chain(linked).filter(|ssid| !ssid.is_empty()).collect()
}

/// Whether the device is at `place` (with `networks`, from [`networks_of`]), and how: a connected
/// network wins over the location. A reading counts when the place's circle and the reading's
/// own circle of uncertainty (at most [`MAX_ACCURACY_SLACK`]) touch.
pub fn here_at(place: &PlaceData, networks: &HashSet<&str>, here: &Here) -> Option<HereBy> {
    if here
        .networks
        .iter()
        .any(|ssid| networks.contains(ssid.as_str()))
    {
        return Some(HereBy::Wifi);
    }
    let (point, position) = (place.point()?, here.position?);
    let at = Point {
        latitude: position.latitude,
        longitude: position.longitude,
    };
    if !at.is_valid() {
        return None;
    }
    let slack = position
        .accuracy
        .filter(|a| a.is_finite() && *a > 0.0)
        .unwrap_or(0.0)
        .min(MAX_ACCURACY_SLACK);
    (distance(point, at) <= place.radius() + slack).then_some(HereBy::Location)
}

fn section_rank(item_type: &str) -> (usize, &str) {
    match TYPE_SECTION_ORDER.iter().position(|one| *one == item_type) {
        Some(index) => (index, ""),
        None => (TYPE_SECTION_ORDER.len(), item_type),
    }
}

/// The Nearby list: every place, those the device is at first (a connected network before a
/// location), then the others; each with its items in a section per type. When the device's
/// location is known, each group is ordered nearest first, and places without a point follow.
///
/// Places and items keep the order they're given in within those rules (and when the location
/// is unknown), so callers pass them sorted by name the way their lists sort names. An item is at a place when it links to it, and a
/// Wi-Fi item is also at every place that names its network. Places and the other
/// [`HIDDEN_TYPES`] are never listed as items, and an item linked to a place that isn't in `places` (deleted, or in a vault this
/// account can't open) just isn't shown there.
pub fn nearby_list(places: &[PlaceEntry], items: &[PlacedItem], here: &Here) -> Vec<NearbyPlace> {
    let index: HashMap<&str, usize> = places
        .iter()
        .enumerate()
        .map(|(i, place)| (place.id.as_str(), i))
        .collect();
    let mut sections: Vec<Vec<NearbySection>> = vec![Vec::new(); places.len()];
    let network_sets: Vec<HashSet<&str>> = places
        .iter()
        .map(|place| networks_of(&place.id, place.place.as_ref(), items))
        .collect();

    for item in items.iter().filter(|item| !HIDDEN_TYPES.contains(&item.item_type.as_str())) {
        let mut at: Vec<usize> = item
            .places
            .iter()
            .filter_map(|id| index.get(id.as_str()).copied())
            .collect();
        if let (true, Some(ssid)) = (item.item_type == "wifi", item.subtitle.as_deref()) {
            at.extend(
                network_sets
                    .iter()
                    .enumerate()
                    .filter(|(_, set)| set.contains(ssid))
                    .map(|(i, _)| i),
            );
        }
        at.sort_unstable();
        at.dedup();
        for place in at {
            let list = &mut sections[place];
            match list
                .iter_mut()
                .find(|section| section.item_type == item.item_type)
            {
                Some(section) => section.items.push(item.id.clone()),
                None => list.push(NearbySection {
                    item_type: item.item_type.clone(),
                    items: vec![item.id.clone()],
                }),
            }
        }
    }

    let mut listed: Vec<(usize, NearbyPlace)> = places
        .iter()
        .zip(sections)
        .zip(&network_sets)
        .enumerate()
        .map(|(order, ((entry, mut sections), networks))| {
            sections.sort_by(|a, b| section_rank(&a.item_type).cmp(&section_rank(&b.item_type)));
            let data = entry.place.clone().unwrap_or_default();
            let distance = match (data.point(), here.position) {
                (Some(point), Some(at)) => {
                    let at = Point {
                        latitude: at.latitude,
                        longitude: at.longitude,
                    };
                    at.is_valid().then(|| distance(point, at))
                }
                _ => None,
            };
            let place = NearbyPlace {
                id: entry.id.clone(),
                here: here_at(&data, networks, here),
                distance,
                sections,
            };
            (order, place)
        })
        .collect();

    let rank = |place: &NearbyPlace| match place.here {
        Some(HereBy::Wifi) => 0,
        Some(HereBy::Location) => 1,
        None => 2,
    };
    // Within each rank the nearest come first; places without a distance (no point, or no
    // reading) follow, and ties keep the order given.
    listed.sort_by(|(a_order, a), (b_order, b)| {
        let (x, y) = (
            a.distance.unwrap_or(f64::INFINITY),
            b.distance.unwrap_or(f64::INFINITY),
        );
        rank(a)
            .cmp(&rank(b))
            .then(x.partial_cmp(&y).unwrap_or(Ordering::Equal))
            .then(a_order.cmp(b_order))
    });
    listed.into_iter().map(|(_, place)| place).collect()
}

/// The place to offer a new item to ("You're at Office. Add this item to it?"): the first place
/// the device is at, in [`nearby_list`]'s order, that everyone who can see the item can see too.
/// That is a place in the item's own vault, or, for an item in the personal vault (`personal`),
/// any place: the item's only reader can open every place listed. `None` when the device isn't at
/// a place, which includes knowing neither its network nor its location, or when the item
/// already belongs to the place.
pub fn suggested_place(
    places: &[PlaceEntry],
    items: &[PlacedItem],
    here: &Here,
    item: &PlacedItem,
    item_vault: &str,
    personal: bool,
) -> Option<String> {
    if HIDDEN_TYPES.contains(&item.item_type.as_str()) || (here.networks.is_empty() && here.position.is_none()) {
        return None;
    }
    let visible: Vec<PlaceEntry> = places
        .iter()
        .filter(|place| personal || place.vault_id.as_deref() == Some(item_vault))
        .cloned()
        .collect();
    nearby_list(&visible, items, here)
        .into_iter()
        .take_while(|place| place.here.is_some())
        .find(|place| !item.places.contains(&place.id))
        .map(|place| place.id)
}

/// `ids` with `place` added (once) or removed, for an item's overview `places`.
pub fn with_place(ids: &[String], place: &str, linked: bool) -> Vec<String> {
    let mut out: Vec<String> = ids
        .iter()
        .filter(|id| id.as_str() != place)
        .cloned()
        .collect();
    if linked {
        out.push(place.to_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFICE: Point = Point {
        latitude: 51.507_351,
        longitude: -0.127_758,
    };

    fn place(id: &str, point: Option<Point>, radius: Option<f64>, networks: &[&str]) -> PlaceEntry {
        PlaceEntry {
            id: id.into(),
            vault_id: Some("personal".into()),
            place: Some(PlaceData {
                latitude: point.map(|p| p.latitude),
                longitude: point.map(|p| p.longitude),
                radius,
                networks: networks.iter().map(|s| (*s).into()).collect(),
                extra: Map::new(),
            }),
        }
    }

    fn item(id: &str, item_type: &str, places: &[&str]) -> PlacedItem {
        PlacedItem {
            id: id.into(),
            item_type: item_type.into(),
            places: places.iter().map(|s| (*s).into()).collect(),
            subtitle: None,
        }
    }

    fn wifi(id: &str, ssid: &str, places: &[&str]) -> PlacedItem {
        PlacedItem {
            subtitle: Some(ssid.into()),
            ..item(id, "wifi", places)
        }
    }

    /// A point `metres` north of `from` (a degree of latitude is the same length everywhere on a sphere).
    fn north(from: Point, metres: f64) -> Point {
        Point {
            latitude: from.latitude + (metres / EARTH_RADIUS).to_degrees(),
            longitude: from.longitude,
        }
    }

    fn at(point: Point, accuracy: Option<f64>) -> Here {
        Here {
            networks: vec![],
            position: Some(Position {
                latitude: point.latitude,
                longitude: point.longitude,
                accuracy,
            }),
        }
    }

    fn ids(list: &[NearbyPlace]) -> Vec<&str> {
        list.iter().map(|place| place.id.as_str()).collect()
    }

    #[test]
    fn distance_matches_known_ones() {
        assert_eq!(distance(OFFICE, OFFICE), 0.0);
        // London to Paris (Notre-Dame): about 343.5 km.
        let paris = Point {
            latitude: 48.853,
            longitude: 2.3499,
        };
        assert!(
            (distance(OFFICE, paris) - 343_500.0).abs() < 1_500.0,
            "{}",
            distance(OFFICE, paris)
        );
        assert!((distance(OFFICE, north(OFFICE, 150.0)) - 150.0).abs() < 0.01);
        // Across the antimeridian, and between the poles.
        let west = Point {
            latitude: 0.0,
            longitude: 179.999,
        };
        let east = Point {
            latitude: 0.0,
            longitude: -179.999,
        };
        assert!((distance(west, east) - 222.4).abs() < 1.0);
        let poles = distance(
            Point {
                latitude: 90.0,
                longitude: 0.0,
            },
            Point {
                latitude: -90.0,
                longitude: 0.0,
            },
        );
        assert!((poles - std::f64::consts::PI * EARTH_RADIUS).abs() < 1.0);
    }

    #[test]
    fn a_reading_on_the_radius_is_here_and_a_metre_past_it_isnt() {
        let office = place("office", Some(OFFICE), Some(100.0), &[]);
        let list = |here: &Here| nearby_list(std::slice::from_ref(&office), &[], here)[0].here;
        assert_eq!(list(&at(north(OFFICE, 99.9), None)), Some(HereBy::Location));
        assert_eq!(
            list(&at(north(OFFICE, 100.0 - 1e-6), None)),
            Some(HereBy::Location)
        );
        assert_eq!(list(&at(north(OFFICE, 101.0), None)), None);
        // The reading's own uncertainty counts in its favour…
        assert_eq!(
            list(&at(north(OFFICE, 140.0), Some(50.0))),
            Some(HereBy::Location)
        );
        // …but never more than MAX_ACCURACY_SLACK: a city-wide guess isn't being here.
        assert_eq!(list(&at(north(OFFICE, 700.0), Some(5_000.0))), None);
        assert_eq!(
            list(&at(north(OFFICE, 590.0), Some(5_000.0))),
            Some(HereBy::Location)
        );
        // Nonsense readings don't count.
        assert_eq!(
            list(&at(
                Point {
                    latitude: 91.0,
                    longitude: 0.0
                },
                None
            )),
            None
        );
        assert_eq!(
            list(&at(
                Point {
                    latitude: f64::NAN,
                    longitude: 0.0
                },
                None
            )),
            None
        );
    }

    #[test]
    fn the_radius_defaults_and_stays_in_bounds() {
        let data = |radius| PlaceData {
            radius,
            ..PlaceData::default()
        };
        assert_eq!(data(None).radius(), DEFAULT_RADIUS);
        assert_eq!(data(Some(f64::NAN)).radius(), DEFAULT_RADIUS);
        assert_eq!(data(Some(1.0)).radius(), MIN_RADIUS);
        assert_eq!(data(Some(1e9)).radius(), MAX_RADIUS);
        let office = place("office", Some(OFFICE), None, &[]);
        assert!(
            nearby_list(
                std::slice::from_ref(&office),
                &[],
                &at(north(OFFICE, 149.0), None)
            )[0]
            .here
            .is_some()
        );
        assert!(
            nearby_list(&[office], &[], &at(north(OFFICE, 151.0), None))[0]
                .here
                .is_none()
        );
    }

    #[test]
    fn a_connected_network_makes_a_place_here_exactly_as_named() {
        let home = place("home", None, None, &["Home 5G"]);
        let here = |ssid: &str| Here {
            networks: vec![ssid.into()],
            position: None,
        };
        assert_eq!(
            nearby_list(std::slice::from_ref(&home), &[], &here("Home 5G"))[0].here,
            Some(HereBy::Wifi)
        );
        // SSIDs are case-sensitive bytes: "home 5g" is another network.
        assert_eq!(
            nearby_list(std::slice::from_ref(&home), &[], &here("home 5g"))[0].here,
            None
        );
        assert_eq!(
            nearby_list(std::slice::from_ref(&home), &[], &here("Home"))[0].here,
            None
        );
        // A Wi-Fi item linked to the place lends it its network.
        let bare = place("cabin", None, None, &[]);
        let items = [wifi("w", "Cabin", &["cabin"])];
        assert_eq!(
            nearby_list(std::slice::from_ref(&bare), &items, &here("Cabin"))[0].here,
            Some(HereBy::Wifi)
        );
        // The network wins even when the location says the place is far away.
        let both = place("office", Some(OFFICE), None, &["Office"]);
        let far = Here {
            networks: vec!["Office".into()],
            position: at(north(OFFICE, 5_000.0), None).position,
        };
        let listed = nearby_list(&[both], &[], &far);
        assert_eq!(listed[0].here, Some(HereBy::Wifi));
        assert!((listed[0].distance.unwrap() - 5_000.0).abs() < 0.1);
    }

    #[test]
    fn items_are_filed_by_type_in_the_list_order() {
        let office = place("office", None, None, &["Office"]);
        let items = [
            item("doc", "document", &["office"]),
            item("printer", "login", &["office"]),
            item("alarm", "secureNote", &["office"]),
            item("door", "secureNote", &["office"]),
            item("vpn", "login", &["office"]),
            item("new", "holoKey", &["office"]),
            item("odd", "aardvark", &["office"]),
            item("elsewhere", "login", &[]),
            wifi("guest", "Office", &[]),
            item("self", PLACE_TYPE, &["office"]),
            item("token", "maskedEmailProvider", &["office"]),
        ];
        let listed = nearby_list(&[office], &items, &Here::default());
        let sections: Vec<(&str, Vec<&str>)> = listed[0]
            .sections
            .iter()
            .map(|s| {
                (
                    s.item_type.as_str(),
                    s.items.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            sections,
            [
                ("login", vec!["printer", "vpn"]),
                ("secureNote", vec!["alarm", "door"]),
                // Wi-Fi on the place's network is there without a link.
                ("wifi", vec!["guest"]),
                ("document", vec!["doc"]),
                // Types this version doesn't know come last, by name.
                ("aardvark", vec!["odd"]),
                ("holoKey", vec!["new"]),
            ]
        );
    }

    #[test]
    fn places_here_come_first_then_the_rest_in_the_order_given() {
        let places = [
            place("attic", None, None, &[]),
            place("bakery", Some(north(OFFICE, 2_000.0)), Some(3_000.0), &[]),
            place("cafe", Some(north(OFFICE, 50.0)), None, &[]),
            place("depot", Some(north(OFFICE, 20_000.0)), None, &[]),
            place("office", None, None, &["Office"]),
        ];
        let here = Here {
            networks: vec!["Office".into()],
            position: at(OFFICE, Some(10.0)).position,
        };
        let listed = nearby_list(&places, &[], &here);
        assert_eq!(ids(&listed), ["office", "cafe", "bakery", "depot", "attic"]);
        assert_eq!(
            listed.iter().map(|p| p.here).collect::<Vec<_>>(),
            [
                Some(HereBy::Wifi),
                Some(HereBy::Location),
                Some(HereBy::Location),
                None,
                None
            ]
        );
        // Not knowing where the device is lists every place, none here, in the order given.
        let nowhere = nearby_list(&places, &[], &Here::default());
        assert_eq!(
            ids(&nowhere),
            ["attic", "bakery", "cafe", "depot", "office"]
        );
        assert!(
            nowhere
                .iter()
                .all(|p| p.here.is_none() && p.distance.is_none())
        );
    }

    #[test]
    fn with_a_location_the_other_places_come_nearest_first_and_those_without_a_point_last() {
        let places = [
            place("attic", None, None, &[]),
            place("bakery", Some(north(OFFICE, 2_000.0)), None, &[]),
            place("cafe", Some(north(OFFICE, 900.0)), None, &[]),
            place("depot", Some(north(OFFICE, 2_000.0)), None, &[]),
            place("elm", None, None, &["Elm"]),
            place("ferry", Some(north(OFFICE, 40_000.0)), None, &[]),
            place("office", Some(OFFICE), None, &[]),
        ];
        let listed = nearby_list(&places, &[], &at(OFFICE, None));
        // Here first; then nearest first, a tie (bakery, depot) in the order given; then the
        // places without a point, in the order given.
        assert_eq!(
            ids(&listed),
            ["office", "cafe", "bakery", "depot", "ferry", "attic", "elm"]
        );
        assert!((listed[1].distance.unwrap() - 900.0).abs() < 0.1);
        assert_eq!(listed[5].distance, None);
        // Only a network, no location: no distances, so the name order the caller gave.
        let wifi_only = nearby_list(
            &places,
            &[],
            &Here {
                networks: vec!["Elm".into()],
                position: None,
            },
        );
        assert_eq!(
            ids(&wifi_only),
            ["elm", "attic", "bakery", "cafe", "depot", "ferry", "office"]
        );
    }

    #[test]
    fn a_new_item_is_offered_the_place_the_device_is_at_if_its_readers_can_see_it() {
        let shared = PlaceEntry {
            vault_id: Some("team".into()),
            ..place("lab", None, None, &["Lab"])
        };
        let places = [
            place("home", None, None, &["Home"]),
            shared,
            place("office", Some(OFFICE), None, &["Office"]),
        ];
        let new = item("new", "login", &[]);
        let on = |ssid: &str| Here {
            networks: vec![ssid.into()],
            position: None,
        };
        assert_eq!(
            suggested_place(&places, &[], &on("Home"), &new, "personal", true).as_deref(),
            Some("home")
        );
        // A personal item can join a place in a shared vault: its only reader sees both.
        assert_eq!(
            suggested_place(&places, &[], &on("Lab"), &new, "personal", true).as_deref(),
            Some("lab")
        );
        // A shared item is only offered places in its own vault.
        assert_eq!(
            suggested_place(&places, &[], &on("Home"), &new, "team", false),
            None
        );
        assert_eq!(
            suggested_place(&places, &[], &on("Lab"), &new, "team", false).as_deref(),
            Some("lab")
        );
        // By location too; and nothing when the device isn't at a place or can't tell.
        assert_eq!(
            suggested_place(
                &places,
                &[],
                &at(north(OFFICE, 30.0), Some(20.0)),
                &new,
                "personal",
                true
            )
            .as_deref(),
            Some("office")
        );
        assert_eq!(
            suggested_place(
                &places,
                &[],
                &at(north(OFFICE, 3_000.0), None),
                &new,
                "personal",
                true
            ),
            None
        );
        assert_eq!(
            suggested_place(&places, &[], &Here::default(), &new, "personal", true),
            None
        );
        // Not a place it's already at, and never a place for a place.
        let linked = item("new", "login", &["home"]);
        assert_eq!(
            suggested_place(&places, &[], &on("Home"), &linked, "personal", true),
            None
        );
        assert_eq!(
            suggested_place(
                &places,
                &[],
                &on("Home"),
                &item("p", PLACE_TYPE, &[]),
                "personal",
                true
            ),
            None
        );
    }

    #[test]
    fn an_item_can_be_at_several_places_once_each_and_dangling_links_are_ignored() {
        let places = [
            place("home", None, None, &["Home"]),
            place("office", None, None, &[]),
        ];
        let items = [
            item("vpn", "login", &["home", "office", "home", "gone"]),
            wifi("router", "Home", &["home"]),
        ];
        let listed = nearby_list(&places, &items, &Here::default());
        assert_eq!(
            listed[0].sections,
            [
                NearbySection {
                    item_type: "login".into(),
                    items: vec!["vpn".into()]
                },
                NearbySection {
                    item_type: "wifi".into(),
                    items: vec!["router".into()]
                }
            ]
        );
        assert_eq!(
            listed[1].sections,
            [NearbySection {
                item_type: "login".into(),
                items: vec!["vpn".into()]
            }]
        );
    }

    #[test]
    fn places_are_cleaned_for_saving() {
        let raw = PlaceData {
            latitude: Some(51.507_351_49),
            longitude: Some(-0.127_758_4),
            radius: Some(149.6),
            networks: vec![
                "Office".into(),
                "".into(),
                "  ".into(),
                "Office".into(),
                "x".repeat(33),
                "Guest".into(),
            ],
            extra: Map::new(),
        };
        let clean = raw.cleaned().unwrap();
        assert_eq!(
            (clean.latitude, clean.longitude, clean.radius),
            (Some(51.507_351), Some(-0.127_758), Some(150.0))
        );
        assert_eq!(clean.networks, ["Office", "Guest"]);
        assert_eq!(
            PlaceData {
                radius: Some(3.0),
                ..PlaceData::default()
            }
            .cleaned()
            .unwrap()
            .radius,
            Some(MIN_RADIUS)
        );
        assert_eq!(
            PlaceData {
                latitude: Some(1.0),
                ..PlaceData::default()
            }
            .cleaned(),
            Err(Error::InvalidItem)
        );
        assert_eq!(
            PlaceData {
                latitude: Some(95.0),
                longitude: Some(0.0),
                ..PlaceData::default()
            }
            .cleaned(),
            Err(Error::InvalidItem)
        );
        assert_eq!(
            PlaceData::default().cleaned().unwrap(),
            PlaceData::default()
        );
    }

    #[test]
    fn json_round_trips_and_keeps_unknown_fields() {
        let json =
            serde_json::json!({ "latitude": 1.5, "longitude": 2.5, "networks": ["A"], "floor": 3 });
        let data: PlaceData = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            data.point(),
            Some(Point {
                latitude: 1.5,
                longitude: 2.5
            })
        );
        assert_eq!(serde_json::to_value(&data).unwrap(), json);
        // A list summary passes as is: unknown fields are ignored.
        let entry: PlaceEntry = serde_json::from_value(
            serde_json::json!({ "id": "p", "type": "place", "title": "Home", "place": json }),
        )
        .unwrap();
        assert_eq!(entry.place.unwrap().networks, ["A"]);
        let item: PlacedItem = serde_json::from_value(
            serde_json::json!({ "id": "i", "type": "login", "title": "VPN", "favorite": false }),
        )
        .unwrap();
        assert!(item.places.is_empty());
        let out = serde_json::to_value(NearbyPlace {
            id: "p".into(),
            here: Some(HereBy::Wifi),
            distance: None,
            sections: vec![],
        })
        .unwrap();
        assert_eq!(
            out,
            serde_json::json!({ "id": "p", "here": "wifi", "sections": [] })
        );
    }

    #[test]
    fn links_are_added_once_and_removed() {
        let ids = vec!["a".to_owned(), "b".to_owned()];
        assert_eq!(with_place(&ids, "c", true), ["a", "b", "c"]);
        assert_eq!(with_place(&ids, "a", true), ["b", "a"]);
        assert_eq!(with_place(&ids, "a", false), ["b"]);
        assert_eq!(with_place(&ids, "z", false), ["a", "b"]);
    }
}
