//! Nearby: which place the device is at, and the items at each place, worked out here on the
//! device (`octapass_core::places`).

use octapass_core::places::{self, Here, PlaceData, PlaceEntry, PlacedItem};
use wasm_bindgen::prelude::*;

use crate::{from_js, js_error, options_from_js, to_js};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
/** A place item's overview `place`: an optional point, its radius in metres (default 150) and its Wi-Fi network names. */
export type PlaceData = { latitude?: number; longitude?: number; radius?: number; networks?: string[]; [field: string]: unknown };
/** A place to list: a place item's summary will do. */
export type PlaceEntry = { id: string; vaultId?: string; place?: PlaceData; [field: string]: unknown };
/** An item to file under its places: an item summary will do. `subtitle` is a Wi-Fi item's network name. */
export type PlacedItem = { id: string; type: string; places?: string[]; subtitle?: string; [field: string]: unknown };
/** Where the device is: the networks it's connected to, and one location reading (accuracy in metres). */
export type Here = { networks?: string[]; position?: { latitude: number; longitude: number; accuracy?: number } };
export type HereBy = "wifi" | "location";
export type NearbySection = { type: string; items: string[] };
/** `here`: the device is at this place, and how it knows. `distance`: metres from the device, when both points are known. */
export type NearbyPlace = { id: string; here?: HereBy; distance?: number; sections: NearbySection[] };
"#;

/// Every place, those the device is at first, then the others nearest first when the location is
/// known (places without a point last), each with its items in a section per type. Places and
/// items otherwise keep the order given: pass them sorted by name.
#[wasm_bindgen(js_name = nearbyList, unchecked_return_type = "NearbyPlace[]")]
pub fn nearby_list(
    #[wasm_bindgen(unchecked_param_type = "PlaceEntry[]")] places: JsValue,
    #[wasm_bindgen(unchecked_param_type = "PlacedItem[]")] items: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Here | undefined")] here: JsValue,
) -> Result<JsValue, JsValue> {
    let places: Vec<PlaceEntry> = from_js(places, "places")?;
    let items: Vec<PlacedItem> = from_js(items, "items")?;
    let here: Here = options_from_js(here, "here")?;
    to_js(&places::nearby_list(&places, &items, &here))
}

/// The place to offer a new item to ("You're at Office. Add this item to it?"), or `undefined`:
/// the first place the device is at that everyone who sees the item can see (a place in its own
/// vault, or any place for an item in the personal vault), and that it isn't at already.
#[wasm_bindgen(js_name = suggestedPlace)]
pub fn suggested_place(
    #[wasm_bindgen(unchecked_param_type = "PlaceEntry[]")] places: JsValue,
    #[wasm_bindgen(unchecked_param_type = "PlacedItem[]")] items: JsValue,
    #[wasm_bindgen(unchecked_param_type = "Here | undefined")] here: JsValue,
    #[wasm_bindgen(unchecked_param_type = "PlacedItem")] item: JsValue,
    item_vault: String,
    personal: bool,
) -> Result<Option<String>, JsValue> {
    let places: Vec<PlaceEntry> = from_js(places, "places")?;
    let items: Vec<PlacedItem> = from_js(items, "items")?;
    let here: Here = options_from_js(here, "here")?;
    let item: PlacedItem = from_js(item, "item")?;
    Ok(places::suggested_place(
        &places,
        &items,
        &here,
        &item,
        &item_vault,
        personal,
    ))
}

/// A place as editors save it: both coordinates or neither, the radius within 25 m to 10 km, the
/// network names without empty or repeated ones. Throws `invalid_item` for half a point or one
/// that isn't on Earth.
#[wasm_bindgen(js_name = cleanPlace, unchecked_return_type = "PlaceData")]
pub fn clean_place(
    #[wasm_bindgen(unchecked_param_type = "PlaceData")] place: JsValue,
) -> Result<JsValue, JsValue> {
    let place: PlaceData = from_js(place, "place")?;
    to_js(&place.cleaned().map_err(js_error)?)
}

/// Metres between two points (latitude, longitude in degrees).
#[wasm_bindgen(js_name = placeDistance)]
pub fn place_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    places::distance(
        places::Point {
            latitude: lat1,
            longitude: lon1,
        },
        places::Point {
            latitude: lat2,
            longitude: lon2,
        },
    )
}
