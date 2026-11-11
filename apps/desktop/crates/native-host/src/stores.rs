//! Where the desktop app sends someone to get the Octa Pass extension for a browser. Chrome,
//! Chromium and Brave install from the Chrome Web Store, Edge from Edge Add-ons (the Chrome Web
//! Store until it's listed there), Firefox from addons.mozilla.org. The Mac app keeps the same table in Swift
//! (`apps/macos/OctaPassMac/BrowserExtensionOffer.swift`).

use crate::manifests::Browser;

/// The Chrome Web Store listing (`manifests::CHROME_WEB_STORE_ID`).
pub const CHROME_WEB_STORE_PAGE: &str =
    "https://chromewebstore.google.com/detail/octa-pass/jainmncaocgdhknhcjkdbbbmahllbjol";
/// The addons.mozilla.org listing (`manifests::AMO_ID`).
pub const FIREFOX_ADD_ONS_PAGE: &str = "https://addons.mozilla.org/firefox/addon/octa-pass/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    ChromeWebStore,
    EdgeAddOns,
    FirefoxAddOns,
}

impl Store {
    /// For the UI: `chrome`, `edge` or `firefox`.
    pub fn id(self) -> &'static str {
        match self {
            Store::ChromeWebStore => "chrome",
            Store::EdgeAddOns => "edge",
            Store::FirefoxAddOns => "firefox",
        }
    }

    // PUBLISH: give Edge Add-ons its own listing once the extension is there (with its ID in
    // `manifests`). Until then Edge installs from the Chrome Web Store, whose ID the host accepts.
    pub fn page(self) -> &'static str {
        match self {
            Store::ChromeWebStore | Store::EdgeAddOns => CHROME_WEB_STORE_PAGE,
            Store::FirefoxAddOns => FIREFOX_ADD_ONS_PAGE,
        }
    }
}

impl Browser {
    /// The store this browser installs the extension from.
    pub fn store(self) -> Store {
        match self {
            Browser::Chrome | Browser::Chromium | Browser::Brave => Store::ChromeWebStore,
            Browser::Edge => Store::EdgeAddOns,
            Browser::Firefox => Store::FirefoxAddOns,
        }
    }

    /// By [`Browser::name`]: "Chrome", "Edge", …
    pub fn from_name(name: &str) -> Option<Browser> {
        Browser::ALL
            .into_iter()
            .find(|browser| browser.name() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_browser_has_its_store() {
        assert_eq!(Browser::Brave.store(), Store::ChromeWebStore);
        assert_eq!(Browser::Edge.store().id(), "edge");
        assert_eq!(Browser::Firefox.store().id(), "firefox");
        assert_eq!(Browser::from_name("Edge"), Some(Browser::Edge));
        assert_eq!(Browser::from_name("Safari"), None);
    }

    #[test]
    fn each_browser_goes_to_a_listing() {
        assert_eq!(Browser::Chrome.store().page(), CHROME_WEB_STORE_PAGE);
        assert_eq!(Browser::Brave.store().page(), CHROME_WEB_STORE_PAGE);
        // No Edge Add-ons listing yet: Edge installs from the Chrome Web Store.
        assert_eq!(Browser::Edge.store().page(), CHROME_WEB_STORE_PAGE);
        assert_eq!(Browser::Firefox.store().page(), FIREFOX_ADD_ONS_PAGE);
        assert!(CHROME_WEB_STORE_PAGE.ends_with(crate::manifests::CHROME_WEB_STORE_ID));
    }
}
