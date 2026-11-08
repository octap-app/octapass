//! The native messaging host manifests the desktop app installs for the current user, so Chrome,
//! Edge, Brave, Chromium and Firefox can start `octapass-native-host` for the Octa Pass
//! extension, and removes again.
//!
//! - macOS and Linux: a JSON file in each browser's per-user `NativeMessagingHosts` folder.
//! - Windows: the JSON file in the app's data folder, registered under
//!   `HKCU\Software\<browser>\NativeMessagingHosts\app.octap.desktop`.
//!
//! Only browsers that have a profile folder (or registry key) on this machine get one.

use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

pub const HOST_NAME: &str = "app.octap.desktop";

// PUBLISH: replace the Edge placeholder with the Edge Add-ons ID once the extension is listed there
// (the store assigns it). A placeholder isn't a well-formed ID, so it never matches a caller and never
// reaches a manifest: until it's filled in, release builds don't accept the Edge store extension.
/// The Chrome Web Store listing's ID.
pub const CHROME_WEB_STORE_ID: &str = "jainmncaocgdhknhcjkdbbbmahllbjol";
/// The Edge Add-ons listing's ID (Edge gives its store its own IDs).
pub const EDGE_ADD_ONS_ID: &str = "PLACEHOLDER:edge-add-ons-id";
/// The `browser_specific_settings.gecko.id` the extension is signed with on addons.mozilla.org.
pub const AMO_ID: &str = "octa-pass@octap.app";

/// From the development key in the extension's `manifest.json` (`key`, see
/// `apps/desktop/README.md`). Debug builds only.
pub const DEV_CHROME_ID: &str = "oojckfebkmiogiahdggohbdnndbfcjnm";
/// The development builds' Firefox ID: the same as the store's, which the extension chooses itself
/// (`browser_specific_settings.gecko.id`).
pub const DEV_FIREFOX_ID: &str = AMO_ID;

/// The Chromium extension IDs this build allows.
#[cfg(not(debug_assertions))]
pub const CHROME_EXTENSION_IDS: &[&str] = &[CHROME_WEB_STORE_ID, EDGE_ADD_ONS_ID];
#[cfg(debug_assertions)]
pub const CHROME_EXTENSION_IDS: &[&str] = &[CHROME_WEB_STORE_ID, EDGE_ADD_ONS_ID, DEV_CHROME_ID];
/// The Firefox extension IDs this build allows.
#[cfg(not(debug_assertions))]
pub const FIREFOX_EXTENSION_IDS: &[&str] = &[AMO_ID];
#[cfg(debug_assertions)]
pub const FIREFOX_EXTENSION_IDS: &[&str] = &[DEV_FIREFOX_ID];

/// Extension IDs a self-distributed build allows on top of the store IDs, set when it is built:
/// `OCTAPASS_EXTRA_EXTENSION_IDS=<Chromium ID>,<Firefox ID>,…` (debug and release alike). For
/// someone who builds the app and loads their own build of the extension, which no store has
/// given an ID. Any unpacked extension can claim a Chromium ID through its manifest `key`, so a
/// build with extras trusts every unpacked extension the user installs with that key.
pub const EXTRA_EXTENSION_IDS: &str = match option_env!("OCTAPASS_EXTRA_EXTENSION_IDS") {
    Some(ids) => ids,
    None => "",
};

fn listed(ids: &'static str) -> impl Iterator<Item = &'static str> {
    ids.split(',').map(str::trim).filter(|id| !id.is_empty())
}

/// Chromium IDs are 32 letters from `a` to `p`.
pub fn is_chrome_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
}

/// Firefox IDs are `{uuid}` or email-like (`name@domain`).
pub fn is_firefox_id(id: &str) -> bool {
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || b"-._".contains(&byte);
    if let Some(uuid) = id.strip_prefix('{').and_then(|rest| rest.strip_suffix('}')) {
        return uuid.len() == 36
            && uuid
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-');
    }
    match id.split_once('@') {
        Some((name, domain)) => {
            !domain.is_empty() && name.bytes().all(allowed) && domain.bytes().all(allowed)
        }
        None => false,
    }
}

/// The allowed Chromium IDs that are filled in.
pub fn chrome_extension_ids() -> impl Iterator<Item = &'static str> {
    CHROME_EXTENSION_IDS
        .iter()
        .copied()
        .chain(listed(EXTRA_EXTENSION_IDS))
        .filter(|id| is_chrome_id(id))
}

/// The allowed Firefox IDs that are filled in.
pub fn firefox_extension_ids() -> impl Iterator<Item = &'static str> {
    FIREFOX_EXTENSION_IDS
        .iter()
        .copied()
        .chain(listed(EXTRA_EXTENSION_IDS))
        .filter(|id| is_firefox_id(id))
}

/// `ids`, with the development ID `dev` too when `development`.
fn with_development(
    ids: impl Iterator<Item = &'static str>,
    development: bool,
    dev: &'static str,
) -> Vec<&'static str> {
    let mut ids: Vec<_> = ids.collect();
    if development && !ids.contains(&dev) {
        ids.push(dev);
    }
    ids
}

/// The allowed Chromium IDs, and the development one when `development`: what a development build
/// of the native Mac app allows, whose Rust library is always built for release (plan 19). The
/// app's Swift code says which it is; a release build of it passes `false`.
pub fn allowed_chrome_ids(development: bool) -> Vec<&'static str> {
    with_development(chrome_extension_ids(), development, DEV_CHROME_ID)
}

/// The allowed Firefox IDs, and the development one when `development` (as [`allowed_chrome_ids`]).
pub fn allowed_firefox_ids(development: bool) -> Vec<&'static str> {
    with_development(firefox_extension_ids(), development, DEV_FIREFOX_ID)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    Chromium,
    Edge,
    Brave,
    Firefox,
}

impl Browser {
    pub const ALL: [Browser; 5] = [
        Browser::Chrome,
        Browser::Chromium,
        Browser::Edge,
        Browser::Brave,
        Browser::Firefox,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Browser::Chrome => "Chrome",
            Browser::Chromium => "Chromium",
            Browser::Edge => "Edge",
            Browser::Brave => "Brave",
            Browser::Firefox => "Firefox",
        }
    }

    /// The manifest for this browser, pointing at `host` (an absolute path).
    pub fn manifest(self, host: &Path) -> Value {
        self.manifest_with(host, false)
    }

    /// The manifest, allowing the development extension too when `development`
    /// ([`allowed_chrome_ids`]).
    pub fn manifest_with(self, host: &Path, development: bool) -> Value {
        let mut manifest = json!({
            "name": HOST_NAME,
            "description": "Octa Pass desktop app",
            "path": host,
            "type": "stdio",
        });
        if self == Browser::Firefox {
            manifest["allowed_extensions"] = json!(allowed_firefox_ids(development));
        } else {
            let origins: Vec<String> = allowed_chrome_ids(development)
                .into_iter()
                .map(|id| format!("chrome-extension://{id}/"))
                .collect();
            manifest["allowed_origins"] = json!(origins);
        }
        manifest
    }

    /// The browser's per-user folder, relative to the home folder.
    #[cfg(target_os = "macos")]
    fn profile_dir(self) -> &'static str {
        match self {
            Browser::Chrome => "Library/Application Support/Google/Chrome",
            Browser::Chromium => "Library/Application Support/Chromium",
            Browser::Edge => "Library/Application Support/Microsoft Edge",
            Browser::Brave => "Library/Application Support/BraveSoftware/Brave-Browser",
            Browser::Firefox => "Library/Application Support/Mozilla",
        }
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    fn profile_dir(self) -> &'static str {
        match self {
            Browser::Chrome => ".config/google-chrome",
            Browser::Chromium => ".config/chromium",
            Browser::Edge => ".config/microsoft-edge",
            Browser::Brave => ".config/BraveSoftware/Brave-Browser",
            Browser::Firefox => ".mozilla",
        }
    }

    #[cfg(not(windows))]
    fn hosts_dir(self) -> &'static str {
        match self {
            Browser::Firefox if cfg!(not(target_os = "macos")) => "native-messaging-hosts",
            _ => "NativeMessagingHosts",
        }
    }

    /// `HKCU` key whose `NativeMessagingHosts` subkey the browser reads.
    #[cfg(windows)]
    fn registry_key(self) -> &'static str {
        match self {
            Browser::Chrome => r"Software\Google\Chrome",
            Browser::Chromium => r"Software\Chromium",
            Browser::Edge => r"Software\Microsoft\Edge",
            Browser::Brave => r"Software\BraveSoftware\Brave-Browser",
            Browser::Firefox => r"Software\Mozilla",
        }
    }
}

/// Where this user's browsers and the app keep their files.
#[derive(Debug, Clone)]
pub struct Locations {
    pub home: PathBuf,
    /// The desktop app's data folder (Windows keeps the manifests there).
    pub data_dir: PathBuf,
    /// Where apps are installed (`/Applications`): on macOS, Firefox counts as present when its
    /// app is there even before it has made `Mozilla` in Application Support.
    pub applications: PathBuf,
}

impl Locations {
    /// This user's home folder and the app's data folder.
    pub fn for_user() -> Option<Self> {
        Some(Self {
            home: crate::ipc::user_home()?,
            data_dir: crate::ipc::data_dir()?,
            applications: PathBuf::from("/Applications"),
        })
    }

    #[cfg(not(windows))]
    fn manifest_path(&self, browser: Browser) -> PathBuf {
        self.home
            .join(browser.profile_dir())
            .join(browser.hosts_dir())
            .join(format!("{HOST_NAME}.json"))
    }

    /// The browser's folder for native messaging hosts, made if the browser is on this machine
    /// (its profile folder is there). `false` when it isn't. The folder is made without looking
    /// at the profile folder first: the sandboxed Mac app may reach only this folder (plan 19).
    #[cfg(not(windows))]
    fn hosts_folder(&self, browser: Browser) -> io::Result<bool> {
        let folder = self
            .home
            .join(browser.profile_dir())
            .join(browser.hosts_dir());
        match std::fs::create_dir(&folder) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(folder.is_dir()),
            // Firefox on a Mac makes `Mozilla` only when something needs it; its profiles are in
            // `Firefox`. With Firefox installed, make the folder it reads manifests from.
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && self.firefox_without_folder(browser) =>
            {
                std::fs::create_dir_all(&folder)?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Firefox (release, Developer Edition or Nightly) is in the applications folder, on macOS.
    #[cfg(not(windows))]
    fn firefox_without_folder(&self, browser: Browser) -> bool {
        cfg!(target_os = "macos")
            && browser == Browser::Firefox
            && [
                "Firefox.app",
                "Firefox Developer Edition.app",
                "Firefox Nightly.app",
            ]
            .iter()
            .any(|app| self.applications.join(app).is_dir())
    }

    #[cfg(windows)]
    fn manifest_path(&self, browser: Browser) -> PathBuf {
        self.data_dir
            .join("native-messaging")
            .join(format!("{}.json", browser.name().to_lowercase()))
    }
}

/// Installs the manifest for every browser present. Returns the browsers it installed for.
pub fn install(locations: &Locations, host: &Path) -> io::Result<Vec<Browser>> {
    install_with(locations, host, false)
}

/// [`install`], allowing the development extension too when `development`
/// ([`allowed_chrome_ids`]).
pub fn install_with(
    locations: &Locations,
    host: &Path,
    development: bool,
) -> io::Result<Vec<Browser>> {
    if !host.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the host path must be absolute",
        ));
    }
    let mut installed = Vec::new();
    for browser in Browser::ALL {
        if platform::install(locations, browser, host, development)? {
            installed.push(browser);
        }
    }
    Ok(installed)
}

/// Removes every manifest the app installed. Returns the browsers it removed it from.
pub fn uninstall(locations: &Locations) -> io::Result<Vec<Browser>> {
    let mut removed = Vec::new();
    for browser in Browser::ALL {
        if platform::uninstall(locations, browser)? {
            removed.push(browser);
        }
    }
    Ok(removed)
}

/// The browsers that currently have the manifest.
pub fn installed(locations: &Locations) -> Vec<Browser> {
    Browser::ALL
        .into_iter()
        .filter(|browser| platform::is_installed(locations, *browser))
        .collect()
}

fn write_manifest(path: &Path, manifest: &Value) -> io::Result<()> {
    std::fs::create_dir_all(path.parent().expect("manifest paths have a folder"))?;
    let json = serde_json::to_vec_pretty(manifest).expect("JSON values serialize");
    std::fs::write(path, json)
}

fn remove_file(path: &Path) -> io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;

    pub fn install(
        locations: &Locations,
        browser: Browser,
        host: &Path,
        development: bool,
    ) -> io::Result<bool> {
        if !locations.hosts_folder(browser)? {
            return Ok(false);
        }
        write_manifest(
            &locations.manifest_path(browser),
            &browser.manifest_with(host, development),
        )?;
        Ok(true)
    }

    pub fn uninstall(locations: &Locations, browser: Browser) -> io::Result<bool> {
        remove_file(&locations.manifest_path(browser))
    }

    pub fn is_installed(locations: &Locations, browser: Browser) -> bool {
        locations.manifest_path(browser).is_file()
    }
}

#[cfg(windows)]
mod platform {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};

    use super::*;

    fn host_key(browser: Browser) -> String {
        format!(
            r"{}\NativeMessagingHosts\{HOST_NAME}",
            browser.registry_key()
        )
    }

    pub fn install(
        locations: &Locations,
        browser: Browser,
        host: &Path,
        development: bool,
    ) -> io::Result<bool> {
        let user = RegKey::predef(HKEY_CURRENT_USER);
        if user
            .open_subkey_with_flags(browser.registry_key(), KEY_READ)
            .is_err()
        {
            return Ok(false);
        }
        let path = locations.manifest_path(browser);
        write_manifest(&path, &browser.manifest_with(host, development))?;
        let (key, _) = user.create_subkey(host_key(browser))?;
        key.set_value("", &path.as_os_str())?;
        Ok(true)
    }

    pub fn uninstall(locations: &Locations, browser: Browser) -> io::Result<bool> {
        let user = RegKey::predef(HKEY_CURRENT_USER);
        let removed = match user.delete_subkey_all(host_key(browser)) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        Ok(remove_file(&locations.manifest_path(browser))? || removed)
    }

    pub fn is_installed(_: &Locations, browser: Browser) -> bool {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(host_key(browser), KEY_READ)
            .is_ok()
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    fn locations() -> (tempfile::TempDir, Locations) {
        let home = tempfile::tempdir().unwrap();
        let locations = Locations {
            home: home.path().to_owned(),
            data_dir: home.path().join("data"),
            applications: home.path().join("Applications"),
        };
        (home, locations)
    }

    #[test]
    fn manifests_allow_only_the_octa_pass_extension() {
        let host = Path::new("/Applications/Octa Pass.app/Contents/MacOS/octapass-native-host");
        let chrome = Browser::Chrome.manifest(host);
        assert_eq!(chrome["name"], HOST_NAME);
        assert_eq!(chrome["type"], "stdio");
        assert_eq!(chrome["path"], host.to_str().unwrap());
        assert_eq!(
            chrome["allowed_origins"],
            json!([
                "chrome-extension://jainmncaocgdhknhcjkdbbbmahllbjol/",
                "chrome-extension://oojckfebkmiogiahdggohbdnndbfcjnm/"
            ])
        );
        assert!(chrome.get("allowed_extensions").is_none());
        let firefox = Browser::Firefox.manifest(host);
        assert_eq!(
            firefox["allowed_extensions"],
            json!(["octa-pass@octap.app"])
        );
        assert!(firefox.get("allowed_origins").is_none());
    }

    #[test]
    fn extra_ids_are_split_by_kind() {
        let extras = "oojckfebkmiogiahdggohbdnndbfcjnm, octapass@example.com,,not an id";
        let chrome: Vec<_> = listed(extras).filter(|id| is_chrome_id(id)).collect();
        let firefox: Vec<_> = listed(extras).filter(|id| is_firefox_id(id)).collect();
        assert_eq!(chrome, ["oojckfebkmiogiahdggohbdnndbfcjnm"]);
        assert_eq!(firefox, ["octapass@example.com"]);
    }

    #[test]
    fn placeholders_are_never_allowed() {
        assert!(!is_chrome_id(EDGE_ADD_ONS_ID) && !is_firefox_id(EDGE_ADD_ONS_ID));
        let built_in = |id: &&str| !listed(EXTRA_EXTENSION_IDS).any(|extra| extra == *id);
        assert_eq!(
            chrome_extension_ids().filter(built_in).collect::<Vec<_>>(),
            [CHROME_WEB_STORE_ID, DEV_CHROME_ID]
        );
        assert_eq!(
            firefox_extension_ids().filter(built_in).collect::<Vec<_>>(),
            [DEV_FIREFOX_ID]
        );
        assert!(is_firefox_id("{6f2e9a1c-3b4d-4e5f-8a9b-0c1d2e3f4a5b}"));
        assert!(!is_chrome_id("OOJCKFEBKMIOGIAHDGGOHBDNNDBFCJNM"));
        assert!(!is_chrome_id("oojckfebkmiogiahdggohbdnndbfcjnz"));
        assert!(!is_firefox_id("x@") && !is_firefox_id("x@a/b") && !is_firefox_id("x"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn firefox_in_applications_gets_its_folder_made() {
        let (_home, locations) = locations();
        let host = locations.home.join("app/octapass-native-host");
        // Installed but never made `Mozilla` in Application Support: the folder is made for it.
        std::fs::create_dir_all(locations.applications.join("Firefox.app")).unwrap();
        assert_eq!(install(&locations, &host).unwrap(), [Browser::Firefox]);
        assert!(locations.manifest_path(Browser::Firefox).is_file());
    }

    #[test]
    fn installs_only_for_browsers_on_this_machine_and_uninstalls() {
        let (_home, locations) = locations();
        let host = locations.home.join("app/octapass-native-host");
        assert!(install(&locations, &host).unwrap().is_empty());

        for browser in [Browser::Chrome, Browser::Firefox] {
            std::fs::create_dir_all(locations.home.join(browser.profile_dir())).unwrap();
        }
        assert_eq!(
            install(&locations, &host).unwrap(),
            [Browser::Chrome, Browser::Firefox]
        );
        assert_eq!(installed(&locations), [Browser::Chrome, Browser::Firefox]);
        let written: Value = serde_json::from_slice(
            &std::fs::read(locations.manifest_path(Browser::Chrome)).unwrap(),
        )
        .unwrap();
        assert_eq!(written["path"], host.to_str().unwrap());
        assert!(
            locations
                .manifest_path(Browser::Firefox)
                .ends_with(format!("{}/{HOST_NAME}.json", Browser::Firefox.hosts_dir()))
        );

        // Installing again replaces in place.
        assert_eq!(install(&locations, &host).unwrap().len(), 2);
        assert_eq!(
            uninstall(&locations).unwrap(),
            [Browser::Chrome, Browser::Firefox]
        );
        assert!(installed(&locations).is_empty());
        assert!(uninstall(&locations).unwrap().is_empty());
        assert!(
            locations.home.join(Browser::Chrome.profile_dir()).is_dir(),
            "the browser's folder stays"
        );
    }

    #[test]
    fn a_development_app_allows_the_development_extension() {
        let host = Path::new("/Applications/Octa Pass.app/Contents/MacOS/octapass-native-host");
        let chrome = Browser::Chrome.manifest_with(host, true);
        let origin = format!("chrome-extension://{DEV_CHROME_ID}/");
        let origins = chrome["allowed_origins"].as_array().unwrap();
        assert_eq!(origins.iter().filter(|o| **o == json!(origin)).count(), 1);
        let firefox = Browser::Firefox.manifest_with(host, true);
        assert!(
            firefox["allowed_extensions"]
                .as_array()
                .unwrap()
                .contains(&json!(DEV_FIREFOX_ID))
        );
        assert!(allowed_chrome_ids(true).contains(&DEV_CHROME_ID));
        assert_eq!(
            allowed_chrome_ids(false),
            chrome_extension_ids().collect::<Vec<_>>()
        );

        let (_home, locations) = locations();
        std::fs::create_dir_all(locations.home.join(Browser::Chrome.profile_dir())).unwrap();
        assert_eq!(
            install_with(&locations, host, true).unwrap(),
            [Browser::Chrome]
        );
        let written: Value = serde_json::from_slice(
            &std::fs::read(locations.manifest_path(Browser::Chrome)).unwrap(),
        )
        .unwrap();
        assert!(
            written["allowed_origins"]
                .as_array()
                .unwrap()
                .contains(&json!(origin))
        );
    }

    #[test]
    fn the_host_path_must_be_absolute() {
        let (_home, locations) = locations();
        assert!(install(&locations, Path::new("octapass-native-host")).is_err());
    }
}
