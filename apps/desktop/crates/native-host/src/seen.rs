//! Which browsers the Octa Pass extension has reached this app from, kept in the app's data
//! folder (the App Group container on the Mac). The desktop apps offer the extension until one
//! has: an extension that has never talked to the bridge is most likely not installed, and the
//! sandboxed Mac app can't look in the browsers' profiles to find out.
//!
//! Only the browser's name and when it first came, for this computer. Never synced, no secrets,
//! and written once per browser, not on every request.

use std::io;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// The file in the app's data folder.
pub const FILE: &str = "browser-extension.json";

/// One browser the extension has come from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeenBrowser {
    /// As the bridge knows it: "Google Chrome", "Microsoft Edge", "Firefox" (`browsers::KNOWN`).
    pub browser: String,
    /// Seconds since 1970.
    pub first_seen: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Record {
    browsers: Vec<SeenBrowser>,
}

/// The bridge answers on several threads at once; one write at a time keeps each browser.
static WRITING: Mutex<()> = Mutex::new(());

/// The browsers the extension has come from, oldest first. Empty when it never has, or the file
/// can't be read.
pub fn read(dir: &Path) -> Vec<SeenBrowser> {
    read_record(dir).browsers
}

fn read_record(dir: &Path) -> Record {
    std::fs::read(dir.join(FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Notes that the extension in `browser` reached the bridge. True the first time for that
/// browser, when the file is written; after that it's only read.
pub fn record(dir: &Path, browser: &str) -> io::Result<bool> {
    let _writing = WRITING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut record = read_record(dir);
    if record.browsers.iter().any(|seen| seen.browser == browser) {
        return Ok(false);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default();
    record.browsers.push(SeenBrowser {
        browser: browser.to_owned(),
        first_seen: now,
    });
    std::fs::create_dir_all(dir)?;
    // Whole or not at all: written beside it, then renamed over it.
    let path = dir.join(FILE);
    let partial = dir.join(format!("{FILE}.partial"));
    std::fs::write(
        &partial,
        serde_json::to_vec_pretty(&record).expect("the record serializes"),
    )?;
    std::fs::rename(&partial, &path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_each_browser_once() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path()).is_empty());
        assert!(record(dir.path(), "Google Chrome").unwrap());
        assert!(!record(dir.path(), "Google Chrome").unwrap());
        assert!(record(dir.path(), "Firefox").unwrap());
        let seen = read(dir.path());
        assert_eq!(
            seen.iter()
                .map(|one| one.browser.as_str())
                .collect::<Vec<_>>(),
            ["Google Chrome", "Firefox"]
        );
        assert!(seen[0].first_seen > 0);
        assert!(!dir.path().join(format!("{FILE}.partial")).exists());
    }

    #[test]
    fn the_file_is_what_the_apps_read() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), "Microsoft Edge").unwrap();
        let file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join(FILE)).unwrap()).unwrap();
        assert_eq!(file["browsers"][0]["browser"], "Microsoft Edge");
        assert!(file["browsers"][0]["firstSeen"].as_u64().unwrap() > 0);
    }

    #[test]
    fn a_damaged_file_starts_again() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), b"not json").unwrap();
        assert!(read(dir.path()).is_empty());
        assert!(record(dir.path(), "Brave").unwrap());
        assert_eq!(read(dir.path())[0].browser, "Brave");
    }
}
