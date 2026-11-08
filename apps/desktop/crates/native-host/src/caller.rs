//! Which extension launched the host. Browsers only start a host for the extensions its manifest
//! allows; the host checks again, so a manifest edited by someone else can't widen access.

use crate::manifests::{allowed_chrome_ids, allowed_firefox_ids};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// Chrome, Edge, Brave and other Chromium browsers pass `chrome-extension://<id>/`.
    Chromium { id: String },
    /// Firefox passes the manifest path, then the extension id.
    Firefox { id: String },
}

impl Caller {
    /// Reads the caller from the host's command-line arguments (without the program name).
    pub fn from_args<I: IntoIterator<Item = String>>(args: I) -> Option<Self> {
        let args: Vec<String> = args.into_iter().collect();
        if let Some(origin) = args
            .iter()
            .find_map(|arg| arg.strip_prefix("chrome-extension://"))
        {
            let id = origin.trim_end_matches('/');
            return Some(Caller::Chromium { id: id.to_owned() });
        }
        match args.as_slice() {
            [manifest, id, ..] if manifest.ends_with(".json") => {
                Some(Caller::Firefox { id: id.clone() })
            }
            _ => None,
        }
    }

    pub fn is_allowed(&self) -> bool {
        self.is_allowed_with(false)
    }

    /// Also the development extension when `development` (`manifests::allowed_chrome_ids`).
    pub fn is_allowed_with(&self, development: bool) -> bool {
        match self {
            Caller::Chromium { id } => allowed_chrome_ids(development).contains(&id.as_str()),
            Caller::Firefox { id } => allowed_firefox_ids(development).contains(&id.as_str()),
        }
    }

    /// Parses an origin as [`Caller::origin`] spells it.
    pub fn from_origin(origin: &str) -> Option<Self> {
        if let Some(id) = origin.strip_prefix("chrome-extension://") {
            return Some(Caller::Chromium {
                id: id.trim_end_matches('/').to_owned(),
            });
        }
        origin
            .strip_prefix("moz-extension://")
            .map(|id| Caller::Firefox { id: id.to_owned() })
    }

    /// The origin the app sees, in the browser's own spelling.
    pub fn origin(&self) -> String {
        match self {
            Caller::Chromium { id } => format!("chrome-extension://{id}/"),
            Caller::Firefox { id } => format!("moz-extension://{id}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifests::{CHROME_WEB_STORE_ID, DEV_CHROME_ID, DEV_FIREFOX_ID, EDGE_ADD_ONS_ID};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn chromium_browsers_pass_the_origin() {
        let id = DEV_CHROME_ID;
        let caller = Caller::from_args(args(&[&format!("chrome-extension://{id}/")])).unwrap();
        assert!(caller.is_allowed());
        assert_eq!(caller.origin(), format!("chrome-extension://{id}/"));
        // Chrome on Windows adds the parent window handle.
        let windows = Caller::from_args(args(&[
            &format!("chrome-extension://{id}/"),
            "--parent-window=0",
        ]))
        .unwrap();
        assert_eq!(windows, caller);
    }

    #[test]
    fn firefox_passes_the_manifest_path_and_the_id() {
        let caller = Caller::from_args(args(&[
            "/Users/a/Library/Application Support/Mozilla/NativeMessagingHosts/app.octap.desktop.json",
            DEV_FIREFOX_ID,
        ]))
        .unwrap();
        assert!(caller.is_allowed());
    }

    #[test]
    fn origins_round_trip() {
        for caller in [
            Caller::Chromium {
                id: DEV_CHROME_ID.into(),
            },
            Caller::Firefox {
                id: DEV_FIREFOX_ID.into(),
            },
        ] {
            assert_eq!(Caller::from_origin(&caller.origin()), Some(caller));
        }
        assert_eq!(Caller::from_origin("https://example.com"), None);
    }

    #[test]
    fn other_extensions_and_direct_runs_are_refused() {
        let other = Caller::from_args(args(&[
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
        ]))
        .unwrap();
        assert!(!other.is_allowed());
        let other = Caller::from_args(args(&["/x/manifest.json", "evil@example.com"])).unwrap();
        assert!(!other.is_allowed());
        // The Chrome Web Store listing is allowed; an unfilled store ID matches nothing, even
        // spelled exactly.
        let store =
            Caller::from_origin(&format!("chrome-extension://{CHROME_WEB_STORE_ID}/")).unwrap();
        assert!(store.is_allowed());
        let placeholder =
            Caller::from_origin(&format!("chrome-extension://{EDGE_ADD_ONS_ID}/")).unwrap();
        assert!(!placeholder.is_allowed());
        assert!(!placeholder.is_allowed_with(true));
        assert!(
            !Caller::from_origin("chrome-extension://abcdefghijklmnopabcdefghijklmnop/")
                .unwrap()
                .is_allowed_with(true)
        );
        assert!(
            Caller::from_origin(&format!("chrome-extension://{DEV_CHROME_ID}/"))
                .unwrap()
                .is_allowed_with(true)
        );
        assert_eq!(Caller::from_args(args(&[])), None);
        assert_eq!(Caller::from_args(args(&["--help"])), None);
    }
}
