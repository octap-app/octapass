//! Which relying party a page may act for (WebAuthn §5.1.3 step 8, §5.1.4 step 6).
//!
//! The `rpId` must be the origin's host or a registrable-domain suffix of it, checked against the
//! Public Suffix List, so `login.example.com` may use `example.com` but no page may use
//! `github.io` or `co.uk`. Origins must be `https`, or `http://localhost` for development.
//!
//! TODO(matching): use `matching::site::registrable_domain` once the URL matching module is
//! merged, so autofill and passkeys share one PSL lookup.

use serde::Deserialize;

use crate::error::{Error, Result};

/// Where a WebAuthn request comes from, as the host (extension, app) observed it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Caller {
    /// The origin of the document that called `navigator.credentials`, e.g. `https://example.com`.
    pub origin: String,
    /// The top-level page's origin, when the call comes from an iframe.
    #[serde(default)]
    pub top_origin: Option<String>,
    /// The user allowed this cross-origin frame to use passkeys.
    #[serde(default)]
    pub frame_allowed: bool,
}

/// Who wrote `clientDataJSON` (WebAuthn §5.8.1). That decides what the authenticator checks and
/// what it signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientData {
    /// A page (browser extension, web views): the core checks the `rpId` against the caller's
    /// origin and writes `clientDataJSON`.
    Web(Caller),
    /// The SHA-256 of the `clientDataJSON` the platform wrote after verifying the calling app or
    /// browser itself (iOS `ASPasskeyCredentialRequest`, Android Credential Manager). Only the
    /// hash is signed, and responses carry an empty `clientDataJSON` for the platform to fill in.
    /// With no origin to check against, the request must name its `rpId`, and a public suffix is
    /// still refused.
    Hash([u8; 32]),
}

impl From<Caller> for ClientData {
    fn from(caller: Caller) -> Self {
        Self::Web(caller)
    }
}

impl ClientData {
    /// Checks the requested `rpId`: against the caller's origin for a page, on its own for the
    /// platform.
    pub(crate) fn relying(&self, rp_id: Option<&str>) -> Result<Relying> {
        match self {
            Self::Web(caller) => caller.relying(rp_id),
            Self::Hash(_) => {
                let rp_id = rp_id
                    .ok_or(Error::InvalidPasskeyRequest)?
                    .to_ascii_lowercase();
                // A Chromium extension's own passkey (the Octa Pass extension's Unlock with Touch
                // ID), and the browser has checked the origin (plan 05). The page asks for its ID,
                // but Chrome hands authenticators its origin instead, `chrome-extension://<id>`
                // (`MaybeGetRelyingPartyIdOverride`): that is the RP ID it hashes and checks.
                let extension = rp_id.strip_prefix("chrome-extension://").unwrap_or(&rp_id);
                if is_chromium_extension_id(extension) {
                    return Ok(Relying {
                        origin: format!("chrome-extension://{extension}"),
                        rp_id,
                        top_origin: None,
                    });
                }
                if !is_domain(&rp_id) || crate::matching::psl::domain(&rp_id).is_none() {
                    return Err(Error::PasskeyRpMismatch);
                }
                // Only used as a new login's URL: the platform's client data has the real origin.
                Ok(Relying {
                    origin: format!("https://{rp_id}"),
                    rp_id,
                    top_origin: None,
                })
            }
        }
    }
}

/// A request that passed the origin checks: what goes into `clientDataJSON` and the rpIdHash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Relying {
    pub rp_id: String,
    pub origin: String,
    /// `Some` only for a cross-origin frame.
    pub top_origin: Option<String>,
}

impl Caller {
    /// Checks the caller against the requested `rpId` (defaulting to the origin's host).
    pub(crate) fn relying(&self, rp_id: Option<&str>) -> Result<Relying> {
        let origin = Origin::parse(&self.origin)?;
        let top_origin = match &self.top_origin {
            Some(top) => {
                let top = Origin::parse(top)?;
                (top != origin).then(|| top.to_string())
            }
            None => None,
        };
        if top_origin.is_some() && !self.frame_allowed {
            return Err(Error::PasskeyFrameNotAllowed);
        }
        let rp_id = match rp_id {
            Some(rp_id) => rp_id.to_ascii_lowercase(),
            None => origin.host.clone(),
        };
        if !may_use_rp_id(&origin.host, &rp_id) {
            return Err(Error::PasskeyRpMismatch);
        }
        Ok(Relying {
            rp_id,
            origin: origin.to_string(),
            top_origin,
        })
    }
}

fn may_use_rp_id(host: &str, rp_id: &str) -> bool {
    if !is_domain(rp_id) {
        return false;
    }
    if host == rp_id {
        return true;
    }
    let is_suffix = host
        .strip_suffix(rp_id)
        .is_some_and(|rest| rest.ends_with('.'));
    // A public suffix (`com`, `github.io`) has no registrable domain of its own.
    is_suffix && crate::matching::psl::domain(rp_id).is_some()
}

/// A tuple origin: scheme, host and port, serialized the way browsers do (default port omitted).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    https: bool,
    host: String,
    port: Option<u16>,
}

impl Origin {
    fn parse(text: &str) -> Result<Self> {
        let invalid = Error::PasskeyRpMismatch;
        let (scheme, rest) = text.split_once("://").ok_or(invalid)?;
        let https = match scheme.to_ascii_lowercase().as_str() {
            "https" => true,
            "http" => false,
            _ => return Err(invalid),
        };
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) => {
                let port: u16 = port.parse().map_err(|_| invalid)?;
                let default = if https { 443 } else { 80 };
                (host, (port != default).then_some(port))
            }
            None => (rest, None),
        };
        let host = host.to_ascii_lowercase();
        // IP addresses and anything with a path, user info or brackets are not valid here.
        if !is_domain(&host) {
            return Err(invalid);
        }
        if !https && host != "localhost" {
            return Err(invalid);
        }
        Ok(Self { https, host, port })
    }
}

impl core::fmt::Display for Origin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let scheme = if self.https { "https" } else { "http" };
        write!(f, "{scheme}://{}", self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

/// A lower-case ASCII domain (browsers hand us IDNs as punycode), not an IP address.
/// A Chromium extension ID: 32 letters from `a` to `p`.
fn is_chromium_extension_id(name: &str) -> bool {
    name.len() == 32 && name.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

fn is_domain(name: &str) -> bool {
    let labels_ok = name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    let last = name.rsplit('.').next().unwrap_or_default();
    labels_ok && !last.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(origin: &str) -> Caller {
        Caller {
            origin: origin.into(),
            top_origin: None,
            frame_allowed: false,
        }
    }

    fn rp(origin: &str, rp_id: Option<&str>) -> Result<String> {
        caller(origin).relying(rp_id).map(|relying| relying.rp_id)
    }

    #[test]
    fn rp_id_is_the_host_or_a_registrable_suffix() {
        assert_eq!(rp("https://example.com", None).unwrap(), "example.com");
        assert_eq!(
            rp("https://Example.COM", Some("EXAMPLE.com")).unwrap(),
            "example.com"
        );
        assert_eq!(
            rp("https://login.example.com", Some("example.com")).unwrap(),
            "example.com"
        );
        assert_eq!(
            rp("https://a.b.example.co.uk:8443", Some("b.example.co.uk")).unwrap(),
            "b.example.co.uk"
        );
        assert_eq!(
            rp("https://user.github.io", None).unwrap(),
            "user.github.io"
        );
        assert_eq!(rp("http://localhost:5173", None).unwrap(), "localhost");
    }

    #[test]
    fn foreign_and_public_suffix_rp_ids_are_refused() {
        for (origin, rp_id) in [
            ("https://example.com", "example.org"),
            ("https://example.com", "login.example.com"),
            ("https://notexample.com", "example.com"),
            ("https://example.com", "com"),
            ("https://example.co.uk", "co.uk"),
            ("https://user.github.io", "github.io"),
            ("https://example.com", "example.com."),
            ("https://example.com", ""),
        ] {
            assert_eq!(
                rp(origin, Some(rp_id)).unwrap_err(),
                Error::PasskeyRpMismatch,
                "{origin} {rp_id}"
            );
        }
    }

    #[test]
    fn only_secure_origins() {
        for origin in [
            "http://example.com",
            "ftp://example.com",
            "https://127.0.0.1",
            "https://[::1]",
            "https://example.com/path",
            "https://user@example.com",
            "https://example.com:99999",
            "example.com",
            "",
        ] {
            assert_eq!(
                rp(origin, None).unwrap_err(),
                Error::PasskeyRpMismatch,
                "{origin}"
            );
        }
    }

    #[test]
    fn origins_serialize_like_browsers() {
        let origin = |text: &str| caller(text).relying(None).unwrap().origin;
        assert_eq!(origin("HTTPS://Example.com:443"), "https://example.com");
        assert_eq!(
            origin("https://example.com:8443"),
            "https://example.com:8443"
        );
        assert_eq!(origin("http://localhost:80"), "http://localhost");
    }

    #[test]
    fn platform_client_data_needs_a_registrable_rp_id() {
        let platform = ClientData::Hash([7; 32]);
        let relying = platform.relying(Some("Login.Example.com")).unwrap();
        assert_eq!(relying.rp_id, "login.example.com");
        assert_eq!(relying.origin, "https://login.example.com");
        assert_eq!(relying.top_origin, None);
        assert_eq!(
            platform.relying(None).unwrap_err(),
            Error::InvalidPasskeyRequest
        );
        for rp_id in [
            "com",
            "co.uk",
            "github.io",
            "localhost",
            "127.0.0.1",
            "example.com.",
            "exa mple.com",
            "",
        ] {
            assert_eq!(
                platform.relying(Some(rp_id)).unwrap_err(),
                Error::PasskeyRpMismatch,
                "{rp_id}"
            );
        }
        assert_eq!(
            ClientData::from(caller("https://login.example.com"))
                .relying(Some("example.com"))
                .unwrap(),
            caller("https://login.example.com")
                .relying(Some("example.com"))
                .unwrap()
        );
    }

    #[test]
    fn platform_client_data_takes_a_chromium_extension_id() {
        let platform = ClientData::Hash([7; 32]);
        let relying = platform
            .relying(Some("oojckfebkmiogiahdggohbdnndbfcjnm"))
            .unwrap();
        assert_eq!(relying.rp_id, "oojckfebkmiogiahdggohbdnndbfcjnm");
        assert_eq!(
            relying.origin,
            "chrome-extension://oojckfebkmiogiahdggohbdnndbfcjnm"
        );
        // What Chrome actually hands an authenticator: the extension's origin.
        let relying = platform
            .relying(Some("chrome-extension://oojckfebkmiogiahdggohbdnndbfcjnm"))
            .unwrap();
        assert_eq!(
            relying.rp_id,
            "chrome-extension://oojckfebkmiogiahdggohbdnndbfcjnm"
        );
        assert_eq!(
            relying.origin,
            "chrome-extension://oojckfebkmiogiahdggohbdnndbfcjnm"
        );
        // Near misses, and a page claiming an extension's ID, are still refused.
        for rp_id in [
            "oojckfebkmiogiahdggohbdnndbfcjn",
            "oojckfebkmiogiahdggohbdnndbfcjnz",
            "oojckfebkmiogiahdggohbdnndbfcjnm.",
            "chrome-extension://oojckfebkmiogiahdggohbdnndbfcjnm/",
            "chrome-extension://example.com",
            "moz-extension://oojckfebkmiogiahdggohbdnndbfcjnm",
        ] {
            assert_eq!(
                platform.relying(Some(rp_id)).unwrap_err(),
                Error::PasskeyRpMismatch,
                "{rp_id}"
            );
        }
        assert_eq!(
            rp(
                "https://example.com",
                Some("oojckfebkmiogiahdggohbdnndbfcjnm")
            )
            .unwrap_err(),
            Error::PasskeyRpMismatch
        );
    }

    #[test]
    fn cross_origin_frames_need_permission() {
        let mut frame = Caller {
            origin: "https://pay.example".into(),
            top_origin: Some("https://shop.example".into()),
            frame_allowed: false,
        };
        assert_eq!(
            frame.relying(None).unwrap_err(),
            Error::PasskeyFrameNotAllowed
        );
        frame.frame_allowed = true;
        let relying = frame.relying(None).unwrap();
        assert_eq!(relying.top_origin.as_deref(), Some("https://shop.example"));

        let same_origin = Caller {
            top_origin: Some("https://pay.example:443".into()),
            frame_allowed: false,
            ..frame
        };
        assert_eq!(same_origin.relying(None).unwrap().top_origin, None);
    }
}
