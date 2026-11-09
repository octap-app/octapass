//! Where the desktop app sends someone to get the Octa Pass extension for a browser. Chrome,
//! Chromium and Brave install from the Chrome Web Store, Edge from Edge Add-ons, Firefox from
//! addons.mozilla.org. The Mac app keeps the same table in Swift
//! (`apps/macos/OctaPassMac/BrowserExtensionOffer.swift`).

use crate::manifests::Browser;

/// The extension's page on the website: how to get it while it's in no store.
pub const EXTENSION_PAGE: &str = "https://octap.app/docs/platforms/browser-extension/";

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

    // PUBLISH: replace each with the listing's address once the extension is listed (with the IDs
    // in `manifests`). Until then every store is the website's page for the extension.
    pub fn page(self) -> &'static str {
        match self {
            Store::ChromeWebStore | Store::EdgeAddOns | Store::FirefoxAddOns => EXTENSION_PAGE,
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
    fn no_listing_is_made_up() {
        // No store lists the extension yet, so every browser goes to the website's page.
        for browser in Browser::ALL {
            assert_eq!(browser.store().page(), EXTENSION_PAGE);
        }
    }
}
