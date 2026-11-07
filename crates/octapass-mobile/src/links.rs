//! One-time share links (plan 06), as `packages/vault-client/src/remote/shareLinks.ts` and the
//! web vault's link addresses (`apps/web/src/lib/shareLinks.ts`) do them. The item snapshot is
//! encrypted here under a random key that only ever travels in the link's `#` fragment:
//! `https://<web vault>/s/<id>#<key>`, plus `?server=<origin>` for a server other than the
//! default.

use octapass_api::{CreateShareLinkResponse, ShareLinkResponse, ShareLinksResponse};
use octapass_core::item::Item as CoreItem;
use octapass_core::sharing::share_link;
use rand_core::OsRng;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::api::{Api, Method, Server, not_found, secure_origin, segment};
use crate::error::{ErrorCode, Result, VaultError};
use crate::items::{ItemDetails, ItemType, details_of};
use crate::local;
use crate::vault::Ctx;

const MIN_HOURS: u32 = 1;
const MAX_HOURS: u32 = 30 * 24;
const MAX_VIEWS: u32 = 100;

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareLinkOptions {
    /// 1 to 720 (30 days).
    pub expires_in_hours: u32,
    /// 1 to 100.
    pub max_views: u32,
    /// Also needed to open the link; send it separately.
    pub passphrase: Option<String>,
}

/// A new link. `key` belongs only in the fragment of `url`, which browsers never send.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CreatedShareLink {
    pub id: String,
    pub key: String,
    pub expires_at: String,
    /// The address to send.
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareLinkInfo {
    pub id: String,
    /// The item it was made from, while it still exists in this vault.
    pub item_id: Option<String>,
    pub item_title: Option<String>,
    pub expires_at: String,
    pub max_views: u32,
    pub views: u32,
    pub passphrase_required: bool,
    pub created_at: String,
}

/// What fetching a link returned. Fetching used up one view.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareLinkEnvelope {
    pub ciphertext: String,
    pub passphrase_required: bool,
    pub expires_at: String,
    pub views_left: u32,
}

/// A link's parts, from its address.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareLinkAddress {
    pub id: String,
    /// Empty when the fragment is missing, say the link was cut short.
    pub key: String,
    /// Empty when the link names a server that isn't HTTPS: such a link isn't opened at all.
    pub server_url: String,
}

/// A shared item, decrypted on this phone.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SharedItem {
    pub item_type: ItemType,
    pub title: String,
    pub subtitle: Option<String>,
    pub urls: Vec<String>,
    pub details: ItemDetails,
}

fn origin(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .map(|url| url.origin().ascii_serialization())
}

/// The address of a new link made on `server_url`.
pub(crate) fn share_link_url(
    web_vault_url: &str,
    id: &str,
    key: &str,
    server_url: &str,
    default_server_url: &str,
) -> Result<String> {
    let mut url = url::Url::parse(web_vault_url)
        .and_then(|base| base.join(&format!("/s/{}", segment(id))))
        .map_err(|_| VaultError::unexpected("invalid web vault address"))?;
    if origin(server_url) != origin(default_server_url)
        && let Some(server) = origin(server_url)
    {
        url.query_pairs_mut().append_pair("server", &server);
    }
    url.set_fragment(Some(key));
    Ok(url.to_string())
}

/// Reads a share link's address (from a tap, a scan or the clipboard). `None` when it isn't one.
#[uniffi::export]
pub fn parse_share_link_url(url: String, default_server_url: String) -> Option<ShareLinkAddress> {
    let parsed = url::Url::parse(url.trim()).ok()?;
    let mut path = parsed.path_segments()?;
    if path.next() != Some("s") {
        return None;
    }
    let id = path.next().filter(|id| !id.is_empty())?;
    let id = url::form_urlencoded::parse(format!("i={id}").as_bytes())
        .next()
        .map(|(_, id)| id.into_owned())?;
    let named = parsed
        .query_pairs()
        .find(|(name, _)| name == "server")
        .map(|(_, value)| value.into_owned());
    Some(ShareLinkAddress {
        id,
        key: parsed.fragment().unwrap_or_default().to_owned(),
        server_url: match named {
            Some(server) => secure_origin(&server).unwrap_or_default(),
            None => default_server_url,
        },
    })
}

fn timestamp(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).expect("UTC times format as RFC 3339")
}

/// The item as it is now, without its old passwords, the favourite and pinned flags or attachments (their
/// files can't be opened from a link): a copy of the current secret, not its history.
fn shareable(overview: &Value, details: &Value) -> Result<CoreItem> {
    let mut overview = overview.clone();
    let mut details = details.clone();
    if let Some(fields) = overview.as_object_mut() {
        fields.remove("favorite");
        fields.remove("pinned");
    }
    if let Some(fields) = details.as_object_mut() {
        fields.remove("passwordHistory");
        fields.remove("attachments");
    }
    let overview = serde_json::from_value(overview)
        .map_err(|_| VaultError::unexpected("invalid item overview"))?;
    Ok(CoreItem::from_parts(overview, details)?)
}

impl Ctx<'_> {
    /// Encrypts a snapshot of the item for a link. With a passphrase this runs Argon2id.
    pub fn create_share_link(
        &self,
        item_id: &str,
        options: &ShareLinkOptions,
    ) -> Result<CreatedShareLink> {
        if !(MIN_HOURS..=MAX_HOURS).contains(&options.expires_in_hours)
            || !(1..=MAX_VIEWS).contains(&options.max_views)
        {
            return Err(VaultError::new(
                ErrorCode::InvalidInput,
                "share links last 1 hour to 30 days and allow 1 to 100 views",
            ));
        }
        let item = self.vault.get_item(item_id)?;
        if item.deleted_at.is_some() {
            return Err(ErrorCode::NotFound.into());
        }
        let snapshot = shareable(&item.overview, &item.details)?;
        let passphrase = options
            .passphrase
            .as_deref()
            .filter(|p| !p.is_empty())
            .map(|p| Zeroizing::new(p.to_owned()));
        let link = share_link::create(
            &snapshot,
            passphrase.as_deref().map(String::as_str),
            &mut OsRng,
        )?;
        let expires_at =
            OffsetDateTime::now_utc() + Duration::hours(options.expires_in_hours.into());
        let access = self.vault.access()?;
        let created: CreateShareLinkResponse = Server {
            api: self.api,
            access: &access,
        }
        .post(
            "v1/share-links",
            &json!({
                "ciphertext": link.ciphertext,
                "expiresAt": timestamp(expires_at),
                "maxViews": options.max_views,
                "passphraseRequired": link.passphrase_required,
            }),
        )?;
        local::update_notes(access.data_dir(), access.account_tag(), |notes| {
            notes.share_links.insert(created.id.clone(), item_id.into());
        })?;
        let url = share_link_url(
            self.web_vault_url,
            &created.id,
            &link.key,
            &access.server_url(),
            self.default_server_url,
        )?;
        self.sharing_changed();
        Ok(CreatedShareLink {
            id: created.id,
            key: link.key,
            expires_at: created.expires_at,
            url,
        })
    }

    pub fn list_share_links(&self) -> Result<Vec<ShareLinkInfo>> {
        let access = self.vault.access()?;
        let response: ShareLinksResponse = Server {
            api: self.api,
            access: &access,
        }
        .get("v1/share-links")?;
        let mut sources = local::load_notes(access.data_dir(), access.account_tag()).share_links;
        // Links the server no longer has were used up, expired or revoked elsewhere.
        let before = sources.len();
        sources.retain(|id, _| response.links.iter().any(|link| link.id == *id));
        if sources.len() != before {
            local::update_notes(access.data_dir(), access.account_tag(), |notes| {
                notes.share_links = sources.clone();
            })?;
        }
        Ok(response
            .links
            .into_iter()
            .map(|link| {
                let item = sources
                    .get(&link.id)
                    .and_then(|item_id| self.vault.get_item(item_id).ok());
                ShareLinkInfo {
                    item_title: item.as_ref().map(|item| item.title().to_owned()),
                    item_id: item.map(|item| item.id),
                    id: link.id,
                    expires_at: link.expires_at,
                    max_views: link.max_views,
                    views: link.views,
                    passphrase_required: link.passphrase_required,
                    created_at: link.created_at,
                }
            })
            .collect())
    }

    pub fn revoke_share_link(&self, id: &str) -> Result<()> {
        let access = self.vault.access()?;
        let deleted = Server {
            api: self.api,
            access: &access,
        }
        .delete(&format!("v1/share-links/{}", segment(id)));
        match deleted {
            // Already gone: used up or expired meanwhile, which is what revoking wanted.
            Err(error) if !not_found(&error) => return Err(error),
            _ => {}
        }
        local::update_notes(access.data_dir(), access.account_tag(), |notes| {
            notes.share_links.remove(id);
        })?;
        self.sharing_changed();
        Ok(())
    }
}

/// Works signed out. Counts a view; fails with `notFound` once a link is used up, expired or
/// revoked.
pub(crate) fn fetch_share_link(api: &Api, server_url: &str, id: &str) -> Result<ShareLinkEnvelope> {
    let origin = secure_origin(server_url).ok_or(ErrorCode::InsecureServerUrl)?;
    let url = format!("{origin}/v1/share-links/{}", segment(id));
    let envelope: ShareLinkResponse = api.json(Method::Get, &url, None, None::<&()>)?;
    Ok(ShareLinkEnvelope {
        ciphertext: envelope.ciphertext,
        passphrase_required: envelope.passphrase_required,
        expires_at: envelope.expires_at,
        views_left: envelope.views_left,
    })
}

/// Decrypts on this phone. Fails with `wrongPassphrase` or `invalidShareLink`.
pub(crate) fn open_share_link(
    ciphertext: &str,
    key: &str,
    passphrase: Option<&str>,
) -> Result<SharedItem> {
    if key.is_empty() {
        return Err(ErrorCode::InvalidShareLink.into());
    }
    let item = share_link::open(ciphertext, key, passphrase.filter(|p| !p.is_empty()))?;
    let overview = serde_json::to_value(&item.overview).expect("items serialize");
    let details = serde_json::to_value(&item.details).expect("items serialize");
    let text = |key: &str| overview.get(key).and_then(Value::as_str).map(str::to_owned);
    let item_type = text("type").unwrap_or_default();
    Ok(SharedItem {
        title: text("title").unwrap_or_default(),
        subtitle: text("subtitle"),
        urls: overview
            .get("urls")
            .and_then(Value::as_array)
            .map(|urls| {
                urls.iter()
                    .filter_map(|u| u.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        details: details_of(&item_type, &details),
        item_type: ItemType::parse(&item_type),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: &str = "https://vault.octap.app";

    #[test]
    fn addresses_match_the_web_vault() {
        let url = share_link_url(
            "https://vault.octap.app",
            "AbC_d-e",
            "k3y-in_the-fragment",
            "https://vault.octap.app/",
            DEFAULT,
        )
        .unwrap();
        assert_eq!(
            url,
            "https://vault.octap.app/s/AbC_d-e#k3y-in_the-fragment"
        );
        assert_eq!(
            parse_share_link_url(url, DEFAULT.into()),
            Some(ShareLinkAddress {
                id: "AbC_d-e".into(),
                key: "k3y-in_the-fragment".into(),
                server_url: DEFAULT.into()
            })
        );
        let other = share_link_url(
            "https://vault.octap.app",
            "x",
            "k",
            "https://vault.example.org/",
            DEFAULT,
        )
        .unwrap();
        assert_eq!(
            other,
            "https://vault.octap.app/s/x?server=https%3A%2F%2Fvault.example.org#k"
        );
        assert_eq!(
            parse_share_link_url(other, DEFAULT.into())
                .unwrap()
                .server_url,
            "https://vault.example.org"
        );
        let insecure = "https://vault.octap.app/s/x?server=http%3A%2F%2Fevil.example#k";
        assert_eq!(
            parse_share_link_url(insecure.into(), DEFAULT.into())
                .unwrap()
                .server_url,
            ""
        );
        let local = "https://v/s/x?server=http://localhost:8080#k";
        assert_eq!(
            parse_share_link_url(local.into(), DEFAULT.into())
                .unwrap()
                .server_url,
            "http://localhost:8080"
        );
        assert_eq!(
            parse_share_link_url("https://v/s/x".into(), DEFAULT.into())
                .unwrap()
                .key,
            ""
        );
        assert_eq!(
            parse_share_link_url("https://v/items/x".into(), DEFAULT.into()),
            None
        );
    }

    #[test]
    fn links_carry_a_snapshot_without_history_or_files() {
        let item = shareable(
            &json!({ "schemaVersion": 1, "type": "login", "title": "GitHub", "favorite": true }),
            &json!({ "schemaVersion": 1, "password": "pw", "passwordHistory": [{ "password": "old", "changedAt": "t" }], "attachments": [{ "id": "a", "name": "n", "type": "", "size": 1, "key": "k" }] }),
        )
        .unwrap();
        let link = share_link::create(&item, None, &mut OsRng).unwrap();
        let shared = open_share_link(&link.ciphertext, &link.key, None).unwrap();
        assert_eq!(shared.title, "GitHub");
        let ItemDetails::Login { login } = shared.details else {
            panic!("a login");
        };
        assert_eq!(login.password.as_deref(), Some("pw"));
        assert!(login.password_history.is_empty());
        assert_eq!(
            open_share_link(&link.ciphertext, "", None)
                .unwrap_err()
                .code(),
            ErrorCode::InvalidShareLink
        );
    }
}
