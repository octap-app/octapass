//! The browsers that may start the host, and who signs each one.

use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub struct KnownBrowser {
    /// Named in the unlock prompt: "unlock Octa Pass in Google Chrome".
    pub name: &'static str,
    /// The executable's file name; on macOS it sits in `<Name>.app/Contents/MacOS`.
    pub executable: &'static str,
    /// Who signs it: the Apple team ID on macOS, the Authenticode signer's name on Windows.
    /// `None` for builds no vendor signs (Chromium), which only development builds accept there.
    pub signer: Option<&'static str>,
}

const fn browser(
    name: &'static str,
    executable: &'static str,
    signer: Option<&'static str>,
) -> KnownBrowser {
    KnownBrowser {
        name,
        executable,
        signer,
    }
}

#[cfg(target_os = "macos")]
mod table {
    use super::{KnownBrowser, browser};

    const GOOGLE: Option<&str> = Some("EQHXZ8M8AV");
    const MICROSOFT: Option<&str> = Some("UBF8T346G9");
    const BRAVE: Option<&str> = Some("KL8N8XSYF4");

    pub const KNOWN: &[KnownBrowser] = &[
        browser("Google Chrome", "Google Chrome", GOOGLE),
        browser("Google Chrome Beta", "Google Chrome Beta", GOOGLE),
        browser("Google Chrome Dev", "Google Chrome Dev", GOOGLE),
        browser("Google Chrome Canary", "Google Chrome Canary", GOOGLE),
        browser("Chromium", "Chromium", None),
        browser("Microsoft Edge", "Microsoft Edge", MICROSOFT),
        browser("Microsoft Edge Beta", "Microsoft Edge Beta", MICROSOFT),
        browser("Microsoft Edge Dev", "Microsoft Edge Dev", MICROSOFT),
        browser("Microsoft Edge Canary", "Microsoft Edge Canary", MICROSOFT),
        browser("Brave", "Brave Browser", BRAVE),
        browser("Brave Beta", "Brave Browser Beta", BRAVE),
        browser("Brave Nightly", "Brave Browser Nightly", BRAVE),
        browser("Firefox", "firefox", Some("43AQ936H96")),
        browser("Vivaldi", "Vivaldi", Some("4XF3XNRN6Y")),
        browser("Opera", "Opera", Some("A2P9LX4JPN")),
        browser("Arc", "Arc", Some("S6N382Y83G")),
    ];
}

#[cfg(windows)]
mod table {
    use super::{KnownBrowser, browser};

    // Chromium is also `chrome.exe`; unsigned, it fails Chrome's signature check.
    pub const KNOWN: &[KnownBrowser] = &[
        browser("Google Chrome", "chrome.exe", Some("Google LLC")),
        browser(
            "Microsoft Edge",
            "msedge.exe",
            Some("Microsoft Corporation"),
        ),
        browser("Brave", "brave.exe", Some("Brave Software, Inc.")),
        browser("Firefox", "firefox.exe", Some("Mozilla Corporation")),
        browser("Vivaldi", "vivaldi.exe", Some("Vivaldi Technologies AS")),
        browser("Opera", "opera.exe", Some("Opera Norway AS")),
        browser(
            "Arc",
            "Arc.exe",
            Some("The Browser Company of New York Inc."),
        ),
    ];
}

#[cfg(not(any(target_os = "macos", windows)))]
mod table {
    use super::{KnownBrowser, browser};

    // Linux has no code signatures; release builds require a root-owned system install instead.
    pub const KNOWN: &[KnownBrowser] = &[
        browser("Google Chrome", "chrome", None),
        browser("Chromium", "chromium", None),
        browser("Chromium", "chromium-browser", None),
        browser("Microsoft Edge", "msedge", None),
        browser("Brave", "brave", None),
        browser("Firefox", "firefox", None),
        browser("Firefox", "firefox-bin", None),
        browser("Firefox", "firefox-esr", None),
        browser("Vivaldi", "vivaldi-bin", None),
        browser("Opera", "opera", None),
    ];
}

pub use table::KNOWN;

/// The known browser whose executable is at `path`, if any.
pub fn identify(path: &Path) -> Option<&'static KnownBrowser> {
    let name = path.file_name()?.to_str()?;
    if cfg!(target_os = "macos") && !in_app_bundle(path) {
        return None;
    }
    KNOWN.iter().find(|browser| {
        if cfg!(windows) {
            browser.executable.eq_ignore_ascii_case(name)
        } else {
            browser.executable == name
        }
    })
}

/// `<Name>.app/Contents/MacOS/<executable>`.
fn in_app_bundle(path: &Path) -> bool {
    let mut folders = path.ancestors().skip(1).map(Path::file_name);
    folders.next() == Some(Some("MacOS".as_ref()))
        && folders.next() == Some(Some("Contents".as_ref()))
        && folders
            .next()
            .flatten()
            .is_some_and(|bundle| bundle.to_string_lossy().ends_with(".app"))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn browsers_are_known_by_their_executable_in_their_bundle() {
        let chrome = identify(Path::new(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ))
        .unwrap();
        assert_eq!(chrome.name, "Google Chrome");
        assert_eq!(chrome.signer, Some("EQHXZ8M8AV"));
        let firefox = identify(Path::new(
            "/Users/a/Applications/Firefox Nightly.app/Contents/MacOS/firefox",
        ))
        .unwrap();
        assert_eq!(firefox.name, "Firefox");
        assert_eq!(
            identify(Path::new("/x/Chromium.app/Contents/MacOS/Chromium"))
                .unwrap()
                .signer,
            None
        );
    }

    #[test]
    fn anything_else_is_not_a_browser() {
        for path in [
            "/usr/local/bin/Google Chrome",
            "/tmp/Google Chrome",
            "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome Helper",
            "/Applications/Terminal.app/Contents/MacOS/Terminal",
            "/bin/zsh",
            "/",
        ] {
            assert_eq!(identify(Path::new(path)), None, "{path}");
        }
    }
}
