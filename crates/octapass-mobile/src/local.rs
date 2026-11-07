//! What this phone keeps outside the encrypted store, none of it secret: the app's settings,
//! and per account the fingerprints the user compared with other people and which item each
//! share link was made from (the web vault keeps the same in IndexedDB). Written atomically next
//! to the store.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};
use crate::list::{ListArrangement, ListGrouping, ListSort};

const SETTINGS_FILE: &str = "settings.json";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
#[serde(rename_all = "camelCase")]
pub enum ThemePreference {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
#[serde(rename_all = "camelCase")]
pub enum LanguagePreference {
    /// The phone's language, if the app has it, else English.
    #[default]
    System,
    En,
    Ar,
}

/// The web vault's settings (`apps/web/src/app/settings.tsx`) plus the list order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub theme: ThemePreference,
    pub language: LanguagePreference,
    /// Minutes of inactivity before the vault locks: 1, 5, 15, 30, 60 or 240; 0 locks only when
    /// the app is closed.
    pub auto_lock_minutes: u32,
    /// Lock as soon as the app goes to the background.
    pub lock_on_background: bool,
    #[serde(with = "sort_name")]
    pub list_sort: ListSort,
    #[serde(with = "grouping_name")]
    pub list_grouping: ListGrouping,
    /// Each list's own sort and grouping, by view (`listArrangement` / `setListArrangement`).
    #[uniffi(default)]
    pub list_arrangements: HashMap<String, ListArrangement>,
    /// Lists show two or more logins for the same website as one row.
    #[uniffi(default = true)]
    pub combine_sites: bool,
    /// Website icons through the user's server (plan 04). Off means no requests, and clears the
    /// icons kept on this phone.
    #[uniffi(default = true)]
    pub show_site_icons: bool,
    /// Offer to save a network the phone joins that isn't in the vault.
    #[uniffi(default = true)]
    pub wifi_offers: bool,
    /// Send one-time codes to a paired watch while the vault is unlocked (`watchPayload`). This
    /// phone's choice, never synced.
    #[uniffi(default = false)]
    pub show_codes_on_watch: bool,
    /// The app-open gate (plan 03, per device, never synced): opening the app asks for the
    /// device lock where it's set up. Off: the master password instead.
    #[uniffi(default = true)]
    pub device_auth_on_open: bool,
    /// Stay unlocked while logged in to this phone (plan 18, per device, never synced): the app
    /// opens without a prompt while the phone is unlocked, with no lock timer and no lock in the
    /// background; filling doesn't ask. Needs a passcode; without one the phone locks as before.
    /// On for new installs; see [`load_settings`] for existing ones.
    #[uniffi(default = true)]
    pub stay_unlocked: bool,
}

/// The web vault's choices for `autoLockMinutes`.
pub const AUTO_LOCK_CHOICES: [u32; 7] = [1, 5, 15, 30, 60, 240, 0];

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: ThemePreference::System,
            language: LanguagePreference::System,
            auto_lock_minutes: 15,
            lock_on_background: false,
            list_sort: ListSort::Name,
            list_grouping: ListGrouping::Type,
            list_arrangements: HashMap::new(),
            combine_sites: true,
            show_site_icons: true,
            wifi_offers: true,
            show_codes_on_watch: false,
            device_auth_on_open: true,
            stay_unlocked: true,
        }
    }
}

pub(crate) mod sort_name {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::list::ListSort;

    const NAMES: [(ListSort, &str); 5] = [
        (ListSort::Name, "name"),
        (ListSort::NameDesc, "nameDesc"),
        (ListSort::Newest, "newest"),
        (ListSort::Oldest, "oldest"),
        (ListSort::Changed, "changed"),
    ];

    pub fn serialize<S: Serializer>(value: &ListSort, serializer: S) -> Result<S::Ok, S::Error> {
        let name = NAMES
            .iter()
            .find(|(v, _)| v == value)
            .map_or("name", |(_, n)| n);
        serializer.serialize_str(name)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<ListSort, D::Error> {
        let name = String::deserialize(deserializer)?;
        Ok(NAMES
            .iter()
            .find(|(_, n)| *n == name)
            .map_or(ListSort::Name, |(v, _)| *v))
    }
}

pub(crate) mod grouping_name {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::list::ListGrouping;

    const NAMES: [(ListGrouping, &str); 5] = [
        (ListGrouping::Type, "type"),
        (ListGrouping::Letter, "letter"),
        (ListGrouping::Vault, "vault"),
        (ListGrouping::Project, "project"),
        (ListGrouping::None, "none"),
    ];

    pub fn serialize<S: Serializer>(
        value: &ListGrouping,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let name = NAMES
            .iter()
            .find(|(v, _)| v == value)
            .map_or("type", |(_, n)| n);
        serializer.serialize_str(name)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ListGrouping, D::Error> {
        let name = String::deserialize(deserializer)?;
        Ok(NAMES
            .iter()
            .find(|(_, n)| *n == name)
            .map_or(ListGrouping::Type, |(v, _)| *v))
    }
}

/// What this phone remembers for one account.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AccountNotes {
    /// Account id → the fingerprint digits the user compared with its owner.
    pub verified: BTreeMap<String, String>,
    /// Share link id → the item it was made from.
    pub share_links: BTreeMap<String, String>,
}

fn io_error(error: std::io::Error) -> VaultError {
    VaultError::unexpected(format!("storage: {error}"))
}

fn read<T: DeserializeOwned + Default>(path: &Path) -> T {
    // A damaged file only loses preferences: start over rather than fail.
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(io_error)?;
    }
    let temporary = path.with_extension("json.tmp");
    let mut file = fs::File::create(&temporary).map_err(io_error)?;
    file.write_all(&serde_json::to_vec_pretty(value).expect("plain data serializes"))
        .and_then(|()| file.sync_all())
        .map_err(io_error)?;
    fs::rename(&temporary, path).map_err(io_error)
}

/// The settings, with plan 18's migration: a phone that never saved settings gets stay unlocked
/// (the new default). A settings file from before it existed keeps the lock: the file holds every
/// value at once, so a lock time or background lock at its default can't be told from one the
/// user picked, and the reading that doesn't relax a picked lock wins (plan 18 History).
pub(crate) fn load_settings(dir: &Path) -> Settings {
    let Ok(bytes) = fs::read(dir.join(SETTINGS_FILE)) else {
        return Settings::default();
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        // Damaged: the preferences start over, but a lock the user may have picked stays.
        return Settings {
            stay_unlocked: false,
            ..Settings::default()
        };
    };
    let decided = json.get("stayUnlocked").is_some();
    let mut settings: Settings = serde_json::from_value(json).unwrap_or_default();
    if !decided {
        settings.stay_unlocked = false;
    }
    settings
}

pub(crate) fn save_settings(dir: &Path, settings: &Settings) -> Result<()> {
    write(&dir.join(SETTINGS_FILE), settings)
}

fn notes_path(dir: &Path, account_tag: &str) -> PathBuf {
    dir.join(format!("{account_tag}.notes.json"))
}

pub(crate) fn load_notes(dir: &Path, account_tag: &str) -> AccountNotes {
    read(&notes_path(dir, account_tag))
}

pub(crate) fn update_notes(
    dir: &Path,
    account_tag: &str,
    change: impl FnOnce(&mut AccountNotes),
) -> Result<()> {
    let mut notes = load_notes(dir, account_tag);
    change(&mut notes);
    write(&notes_path(dir, account_tag), &notes)
}

/// On sign-out and account deletion.
pub(crate) fn forget_notes(dir: &Path, account_tag: &str) {
    let _ = fs::remove_file(notes_path(dir, account_tag));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_default_like_the_web_vault_and_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_settings(dir.path()), Settings::default());
        let settings = Settings {
            theme: ThemePreference::Dark,
            language: LanguagePreference::Ar,
            auto_lock_minutes: 5,
            lock_on_background: true,
            list_sort: ListSort::NameDesc,
            list_grouping: ListGrouping::Letter,
            list_arrangements: HashMap::from([(
                "login".to_owned(),
                ListArrangement {
                    sort: ListSort::Newest,
                    grouping: ListGrouping::None,
                },
            )]),
            combine_sites: false,
            show_site_icons: false,
            wifi_offers: false,
            show_codes_on_watch: true,
            device_auth_on_open: false,
            stay_unlocked: false,
        };
        save_settings(dir.path(), &settings).unwrap();
        assert_eq!(load_settings(dir.path()), settings);
        let json = std::fs::read_to_string(dir.path().join(SETTINGS_FILE)).unwrap();
        assert!(
            json.contains("\"listSort\": \"nameDesc\"") && json.contains("\"autoLockMinutes\": 5")
        );
        // Settings saved before a field existed get its default.
        std::fs::write(dir.path().join(SETTINGS_FILE), r#"{"theme":"dark"}"#).unwrap();
        let older = load_settings(dir.path());
        assert!(older.show_site_icons && older.combine_sites && older.list_arrangements.is_empty());
        assert!(
            !older.show_codes_on_watch,
            "nothing reaches a watch until it's turned on"
        );
        assert!(
            !older.stay_unlocked,
            "settings saved before plan 18 keep their lock"
        );
        std::fs::write(dir.path().join(SETTINGS_FILE), "{ broken").unwrap();
        assert_eq!(
            load_settings(dir.path()),
            Settings {
                stay_unlocked: false,
                ..Settings::default()
            }
        );
    }

    #[test]
    fn stay_unlocked_reaches_new_installs_and_keeps_a_picked_lock() {
        // Plan 18: never saved, so nothing was picked.
        let dir = tempfile::tempdir().unwrap();
        assert!(load_settings(dir.path()).stay_unlocked);
        // A lock changed from the defaults is kept.
        std::fs::write(
            dir.path().join(SETTINGS_FILE),
            r#"{"autoLockMinutes":1,"lockOnBackground":true}"#,
        )
        .unwrap();
        let picked = load_settings(dir.path());
        assert!(
            !picked.stay_unlocked && picked.auto_lock_minutes == 1 && picked.lock_on_background
        );
        // At the defaults, it can't be told from a picked lock: kept too.
        std::fs::write(
            dir.path().join(SETTINGS_FILE),
            r#"{"autoLockMinutes":15,"lockOnBackground":false,"theme":"dark"}"#,
        )
        .unwrap();
        assert!(!load_settings(dir.path()).stay_unlocked);
        // Once chosen, the choice is read as it is.
        for on in [true, false] {
            let settings = Settings {
                stay_unlocked: on,
                ..Settings::default()
            };
            save_settings(dir.path(), &settings).unwrap();
            assert_eq!(load_settings(dir.path()).stay_unlocked, on);
        }
    }

    #[test]
    fn notes_are_per_account() {
        let dir = tempfile::tempdir().unwrap();
        update_notes(dir.path(), "a", |notes| {
            notes.verified.insert("acc".into(), "0412".into());
        })
        .unwrap();
        assert_eq!(load_notes(dir.path(), "a").verified["acc"], "0412");
        assert!(load_notes(dir.path(), "b").verified.is_empty());
        forget_notes(dir.path(), "a");
        assert!(load_notes(dir.path(), "a").verified.is_empty());
    }
}
