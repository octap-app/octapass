//! The save inbox (plan 03, *Saving while locked*): sealing what the user saves while the vault is
//! locked, and opening and merging it at the next unlock. The inbox itself is JSON the host keeps on
//! this device; these functions take it and return the new JSON.

use octapass_core::inbox::{self, Inbox, InboxEntry, OpenedEntry, VaultLogin};
use octapass_core::matching::MatchOptions;
use octapass_core::session;
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

use crate::account::Session;
use crate::{from_js, js_error, now_ms, options_from_js, to_js};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
export type InboxKind = "login" | "identity" | "card" | "apiKey";
/** One thing saved while locked. `details` holds an address, card or API key form, for the client to merge. */
export type InboxEntry = { kind: InboxKind; url: string; savedAt: number; username?: string; password?: string; title?: string; details?: unknown };
export type OpenedInboxEntry = InboxEntry & { id: string };
/** `unreadable`: entries these keys can't open (sealed to another key, or damaged); they never will. */
export type OpenedInbox = { entries: OpenedInboxEntry[]; unreadable: string[] };
/** A login in the vault for the merge: `{ id, urls, urlMatch }` from the overview, `username` and `password` from the details. */
export type InboxVaultLogin = { id: string; urls?: string[]; urlMatch?: Record<string, MatchMode>; username?: string; password?: string };
/** Apply `passwords` in order, one save each. No `itemId`: a new login, tagged for review. */
export type InboxLoginMerge = { itemId?: string; entryIds: string[]; url: string; username?: string; title?: string; passwords: string[] };
export type InboxMergePlan = { logins: InboxLoginMerge[]; duplicates: string[] };
"#;

/// The most entries an inbox holds.
#[wasm_bindgen(js_name = inboxCap)]
pub fn inbox_cap() -> usize {
    inbox::CAP
}

/// Whether a locked device can save to this inbox now: a key is pinned and there's room.
#[wasm_bindgen(js_name = inboxAccepts)]
pub fn inbox_accepts(inbox: &str) -> bool {
    Inbox::from_json(inbox).is_ok_and(|inbox| inbox.accepts())
}

/// Seals `entry` into the inbox for `owner` (the account id, or the local vault's id). Needs no
/// unlocked session. Throws `invalid_key` with no pinned key, `key_mismatch` when it's another
/// vault's, `inbox_full` at the cap.
#[wasm_bindgen(js_name = inboxAdd)]
pub fn inbox_add(
    inbox: &str,
    owner: &str,
    #[wasm_bindgen(unchecked_param_type = "InboxEntry")] entry: JsValue,
) -> Result<String, JsValue> {
    let mut stored = Inbox::from_json(inbox).map_err(js_error)?;
    let entry: InboxEntry = from_js(entry, "entry")?;
    stored
        .add(owner, &entry, now_ms(), &mut OsRng)
        .map_err(js_error)?;
    Ok(stored.to_json())
}

/// Removes merged entries.
#[wasm_bindgen(js_name = inboxRemove)]
pub fn inbox_remove(inbox: &str, ids: Vec<String>) -> Result<String, JsValue> {
    let mut stored = Inbox::from_json(inbox).map_err(js_error)?;
    stored.remove(&ids);
    Ok(stored.to_json())
}

/// What to do with the login entries: see `octapass_core::inbox::plan_login_merge` for the rules.
#[wasm_bindgen(js_name = planInboxMerge, unchecked_return_type = "InboxMergePlan")]
pub fn plan_inbox_merge(
    #[wasm_bindgen(unchecked_param_type = "OpenedInboxEntry[]")] entries: JsValue,
    #[wasm_bindgen(unchecked_param_type = "InboxVaultLogin[]")] logins: JsValue,
    #[wasm_bindgen(unchecked_param_type = "MatchOptions | undefined")] options: JsValue,
) -> Result<JsValue, JsValue> {
    let entries: Vec<OpenedEntry> = from_js(entries, "entries")?;
    let logins: Vec<VaultLogin> = from_js(logins, "logins")?;
    let options: MatchOptions = options_from_js(options, "options")?;
    to_js(&inbox::plan_login_merge(&entries, &logins, &options))
}

/// Pins the session's own public keys as the inbox key. Returns the new inbox JSON.
pub(crate) fn pin(session: &session::Session, inbox: &str, owner: &str) -> Result<String, JsValue> {
    let mut stored = Inbox::from_json(inbox).map_err(js_error)?;
    stored.pin(session, owner).map_err(js_error)?;
    Ok(stored.to_json())
}

pub(crate) fn open(
    session: &session::Session,
    inbox: &str,
    owner: &str,
) -> Result<JsValue, JsValue> {
    let stored = Inbox::from_json(inbox).map_err(js_error)?;
    to_js(&stored.open(session, owner).map_err(js_error)?)
}

#[wasm_bindgen]
impl Session {
    /// Pins this account's own public keys as its inbox key, at every unlock. Returns the inbox JSON.
    #[wasm_bindgen(js_name = inboxPin)]
    pub fn inbox_pin(&self, inbox: &str, owner: &str) -> Result<String, JsValue> {
        pin(&self.inner, inbox, owner)
    }

    /// Opens every entry, oldest first.
    #[wasm_bindgen(js_name = inboxOpen, unchecked_return_type = "OpenedInbox")]
    pub fn inbox_open(&self, inbox: &str, owner: &str) -> Result<JsValue, JsValue> {
        open(&self.inner, inbox, owner)
    }
}
