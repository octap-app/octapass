//! The save inbox (plan 03, *Saving while locked*): what the user saves while the vault is locked
//! (a login from a sign-in form, an address, a card, an API key) waits here, sealed to the account's
//! own public keys, until the next unlock opens it and merges it into the vault.
//!
//! The vault key only exists after an unlock, so a locked device can't encrypt into the vault. It
//! can seal to a public key, though, and only the private keys open what it sealed: the device can
//! add to its inbox while locked, but can't read the inbox back.
//!
//! ```text
//! entry_key  = 32 random bytes, one per entry
//! sealed_key = the sealed box (`sharing::seal`, hybrid X25519 + ML-KEM-768) of entry_key
//!              to the pinned inbox key, context "inbox:{owner}"
//! body       = envelope(entry_key, entry JSON, context "inbox-entry:{owner}:{entry_id}")
//! sealed     = sealed_key "." body            (both base64url)
//! ```
//!
//! `owner` is the account id, or a local vault's personal vault id: an entry sealed for one vault
//! never opens as another's.
//!
//! **The inbox key** is pinned at unlock from the private keys themselves ([`InboxKey::for_session`]),
//! never from an account bundle the server sent: its X25519 half is the account's encryption key and
//! its ML-KEM half is the account's ML-KEM key (checked against the signed key record at unlock).
//! An account without an ML-KEM key yet, and a local vault, which has none, use one derived from the
//! account key (ASK): `seed = HKDF-SHA256(ikm = ASK, salt = "", info = "openpass/v1/inbox-pq")`, 64
//! bytes. Nothing new is stored for it, and opening tries both, so entries sealed before the account
//! got its own ML-KEM key still open. Every unlock pins the key again, so a substituted key lasts at
//! most until then, and what was sealed to it doesn't open.
//!
//! **Limits**: at most [`CAP`] entries, each at most [`MAX_ENTRY_LEN`] bytes of JSON. A full inbox
//! refuses new entries ([`Error::InboxFull`]) rather than dropping old ones, so filling it can't push
//! out what the user saved.
//!
//! **Merging** logins is [`plan_login_merge`]; addresses, cards and API keys are merged by the
//! client with the rules its save prompts already use.

use std::collections::{HashMap, HashSet};

use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::account::{new_id, parse_id};
use crate::encoding::{b64_decode_array, b64_encode};
use crate::envelope::{Context, open_b64, seal_b64};
use crate::error::{Error, Result};
use crate::kdf::normalize_email;
use crate::keys::SymmetricKey;
use crate::matching::site::Site;
use crate::matching::{MatchMode, MatchOptions, match_items, other_parts};
use crate::session::Session;
use crate::sharing::pq::{PqKeyPair, PqPublicKey, SEED_LEN};
use crate::sharing::seal::{Opener, SealContext, open_key, seal_key_hybrid};

/// The most entries an inbox holds. Fifty covers a long day of sign-ins on a locked browser, and
/// keeps a flood from a locked device small: each one is a single review at the next unlock.
pub const CAP: usize = 50;
/// The most JSON one entry may hold: an API key is up to 8,192 characters, a card or an address far
/// less.
pub const MAX_ENTRY_LEN: usize = 16 * 1024;
const KEY_VERSION: u8 = 1;

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InboxKind {
    Login,
    Identity,
    Card,
    ApiKey,
}

/// One thing the user saved while locked, as it's sealed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxEntry {
    pub kind: InboxKind,
    /// The page (or `androidapp://` package) it was typed into.
    pub url: String,
    /// Unix milliseconds. Entries merge oldest first.
    pub saved_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// A name for a new login (an app's name on Android); by default, the website's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// What an address, card or API key form held, for the client to merge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// The public keys entries are sealed to, pinned at unlock. Public: readable while locked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxKey {
    pub version: u8,
    /// The account id, or a local vault's personal vault id.
    pub owner: String,
    /// X25519, base64url.
    pub public_enc_key: String,
    /// ML-KEM-768, base64url.
    pub public_pq_key: String,
}

impl InboxKey {
    /// The inbox key of an unlocked session, from its private keys.
    pub fn for_session(session: &Session, owner: &str) -> Result<Self> {
        let owner = parse_id(owner)?;
        let derived;
        let pq = match session.pq_keys() {
            Some(pq) => pq,
            None => {
                derived = derived_pq(session.ask())?;
                &derived
            }
        };
        Ok(Self {
            version: KEY_VERSION,
            owner,
            public_enc_key: b64_encode(&session.key_pairs().public_enc_key()),
            public_pq_key: pq.public_key().to_b64(),
        })
    }

    /// The keys to seal to, if this key is for `owner` and well formed.
    fn recipient(&self, owner: &str) -> Result<([u8; 32], PqPublicKey)> {
        if self.version != KEY_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if parse_id(&self.owner)? != parse_id(owner)? {
            return Err(Error::KeyMismatch);
        }
        let x25519 = b64_decode_array(&self.public_enc_key).map_err(|_| Error::InvalidKey)?;
        Ok((x25519, PqPublicKey::from_b64(&self.public_pq_key)?))
    }
}

/// The ML-KEM key of an account that has none of its own (every local vault).
fn derived_pq(ask: &SymmetricKey) -> Result<PqKeyPair> {
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    Hkdf::<Sha256>::new(None, ask.as_bytes())
        .expand(b"openpass/v1/inbox-pq", seed.as_mut())
        .map_err(|_| Error::InvalidKey)?;
    PqKeyPair::from_seed(seed.as_ref())
}

/// One sealed entry. Only its id is readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEntry {
    pub id: String,
    pub sealed: String,
}

/// An entry after the unlock opened it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedEntry {
    pub id: String,
    #[serde(flatten)]
    pub entry: InboxEntry,
}

/// What [`Inbox::open`] found.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedInbox {
    pub entries: Vec<OpenedEntry>,
    /// Entries these keys can't open (sealed to another key, or damaged). They never will.
    pub unreadable: Vec<String>,
}

/// The inbox as a client stores it, as JSON: on this device only, never synced.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Inbox {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<InboxKey>,
    #[serde(default)]
    pub entries: Vec<SealedEntry>,
}

impl Inbox {
    pub fn from_json(text: &str) -> Result<Self> {
        if text.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(text).map_err(|_| Error::InvalidItem)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("an inbox serializes")
    }

    /// Whether a locked device can save to it now: a key is pinned and there's room.
    pub fn accepts(&self) -> bool {
        self.key.is_some() && self.entries.len() < CAP
    }

    /// Pins the session's inbox key. True when it changed (or there was none).
    pub fn pin(&mut self, session: &Session, owner: &str) -> Result<bool> {
        let key = InboxKey::for_session(session, owner)?;
        let changed = self.key.as_ref() != Some(&key);
        self.key = Some(key);
        Ok(changed)
    }

    /// Seals `entry` to the pinned key, for `owner`. Returns the new entry's id.
    ///
    /// Fails with [`Error::InvalidKey`] when no key is pinned, [`Error::KeyMismatch`] when the
    /// pinned key is another vault's, and [`Error::InboxFull`] at [`CAP`].
    pub fn add(
        &mut self,
        owner: &str,
        entry: &InboxEntry,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<String> {
        let key = self.key.as_ref().ok_or(Error::InvalidKey)?;
        let (x25519, pq) = key.recipient(owner)?;
        if self.entries.len() >= CAP {
            return Err(Error::InboxFull);
        }
        let plaintext = Zeroizing::new(serde_json::to_vec(entry).map_err(|_| Error::InvalidItem)?);
        if plaintext.len() > MAX_ENTRY_LEN {
            return Err(Error::InvalidItem);
        }
        let owner = parse_id(owner)?;
        let id = new_id(now_ms, rng);
        let entry_key = SymmetricKey::generate(rng);
        let sealed_key = seal_key_hybrid(
            &x25519,
            &pq,
            &SealContext::Inbox { owner: &owner },
            &entry_key,
            rng,
        )?;
        let body = seal_b64(&entry_key, &entry_context(&owner, &id), &plaintext, rng)?;
        self.entries.push(SealedEntry {
            id: id.clone(),
            sealed: format!("{sealed_key}.{body}"),
        });
        Ok(id)
    }

    /// Opens every entry with the session's private keys, oldest first.
    pub fn open(&self, session: &Session, owner: &str) -> Result<OpenedInbox> {
        let owner = parse_id(owner)?;
        let derived = derived_pq(session.ask())?;
        let mut openers = vec![Opener {
            x25519: session.key_pairs().encryption_key(),
            pq: Some(&derived),
        }];
        if let Some(pq) = session.pq_keys() {
            openers.insert(
                0,
                Opener {
                    x25519: session.key_pairs().encryption_key(),
                    pq: Some(pq),
                },
            );
        }
        let mut opened = OpenedInbox::default();
        for sealed in &self.entries {
            match open_entry(&openers, &owner, sealed) {
                Some(entry) => opened.entries.push(OpenedEntry {
                    id: sealed.id.clone(),
                    entry,
                }),
                None => opened.unreadable.push(sealed.id.clone()),
            }
        }
        opened.entries.sort_by_key(|e| e.entry.saved_at);
        Ok(opened)
    }

    /// Removes entries once they're merged (or can never be).
    pub fn remove(&mut self, ids: &[String]) {
        let ids: HashSet<&String> = ids.iter().collect();
        self.entries.retain(|e| !ids.contains(&e.id));
    }
}

fn entry_context<'a>(owner: &'a str, id: &'a str) -> Context<'a> {
    Context::InboxEntry {
        owner,
        entry_id: id,
    }
}

fn open_entry(openers: &[Opener<'_>], owner: &str, sealed: &SealedEntry) -> Option<InboxEntry> {
    let (sealed_key, body) = sealed.sealed.split_once('.')?;
    let id = parse_id(&sealed.id).ok()?;
    let context = SealContext::Inbox { owner };
    let entry_key = openers
        .iter()
        .find_map(|opener| open_key(*opener, &context, sealed_key).ok())?;
    let plaintext = open_b64(&entry_key, &entry_context(owner, &id), body).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

// ---------- Merging logins ----------

/// A login in the vault, as the merge needs it: a whole `{ id, ...overview }` with the details'
/// `username` and `password` added will do.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultLogin {
    pub id: String,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub url_match: HashMap<String, MatchMode>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// One login to write. Apply `passwords` in order, one save each, so every password but the last
/// lands in the password history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginMerge {
    /// The login to update; none for a new login, which is tagged for review ("Unconfirmed").
    pub item_id: Option<String>,
    /// The entries this write uses up.
    pub entry_ids: Vec<String>,
    pub url: String,
    pub username: Option<String>,
    pub title: Option<String>,
    /// Oldest first; the last one ends up current.
    pub passwords: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MergePlan {
    pub logins: Vec<LoginMerge>,
    /// Entries that add nothing: the vault (or a newer entry) already has that password.
    pub duplicates: Vec<String>,
}

const ANDROID_APP: &str = "androidapp://";

fn same_user(a: Option<&str>, b: Option<&str>) -> bool {
    normalize_email(a.unwrap_or("")) == normalize_email(b.unwrap_or(""))
}

/// The logins `url` matches, best first: the core's matching for websites, the exact package for an
/// Android app.
fn logins_for<'a>(
    url: &str,
    logins: &'a [VaultLogin],
    options: &MatchOptions,
) -> Vec<&'a VaultLogin> {
    if url.starts_with(ANDROID_APP) {
        return logins
            .iter()
            .filter(|login| {
                login
                    .urls
                    .iter()
                    .any(|saved| saved.eq_ignore_ascii_case(url))
            })
            .collect();
    }
    let candidates: Vec<_> = logins.iter().map(candidate).collect();
    let by_id: HashMap<&str, &VaultLogin> = logins.iter().map(|l| (l.id.as_str(), l)).collect();
    match_items(url, &candidates, options)
        .map(|found| {
            found
                .iter()
                .filter_map(|m| by_id.get(m.id.as_str()).copied())
                .collect()
        })
        .unwrap_or_default()
}

fn candidate(login: &VaultLogin) -> crate::matching::Candidate {
    crate::matching::Candidate {
        id: login.id.clone(),
        urls: login.urls.clone(),
        url_match: login.url_match.clone(),
    }
}

/// A login for another part of `url`'s site already has this username and password: it's saved.
fn other_part_has(entry: &InboxEntry, logins: &[VaultLogin], options: &MatchOptions) -> bool {
    let candidates: Vec<_> = logins.iter().map(candidate).collect();
    let Ok(parts) = other_parts(&entry.url, &candidates, options) else {
        return false;
    };
    parts.iter().any(|part| {
        logins.iter().any(|login| {
            login.id == part.id
                && login.password == entry.password
                && same_user(login.username.as_deref(), entry.username.as_deref())
        })
    })
}

/// Where a login entry goes: an existing login, or a new one for this host and username.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Target {
    Existing(String),
    New(String, String),
}

/// What to do with the login entries (others are left to the client), by these rules:
///
/// - **An existing login** with the entry's site (as autofill matches it) and username gets the
///   entry's password; the old one goes into its history. A confirmed login stays confirmed: an
///   entry never adds the review mark to it, the same rule as a suggested-password draft on a
///   confirmed login. One already marked for review stays marked.
/// - **Otherwise a new login**, which the client tags for review ("Unconfirmed").
/// - **Exact duplicates are dropped**: an entry whose password is already the login's (or, with no
///   login on this part of the site, a login's for another part of it with the same username), or
///   that a newer entry for the same login repeats.
/// - Several entries for one login apply oldest first, so the newest ends up current and the
///   others are in the history.
pub fn plan_login_merge(
    entries: &[OpenedEntry],
    logins: &[VaultLogin],
    options: &MatchOptions,
) -> MergePlan {
    let mut order: Vec<Target> = Vec::new();
    let mut groups: HashMap<Target, Vec<&OpenedEntry>> = HashMap::new();
    let mut plan = MergePlan::default();
    let mut sorted: Vec<&OpenedEntry> = entries
        .iter()
        .filter(|e| e.entry.kind == InboxKind::Login)
        .collect();
    sorted.sort_by_key(|e| e.entry.saved_at);
    for opened in sorted {
        // Nothing to save (a client never seals one; dropped all the same).
        if opened.entry.password.as_deref().is_none_or(str::is_empty) {
            plan.duplicates.push(opened.id.clone());
            continue;
        }
        let entry = &opened.entry;
        let existing = logins_for(&entry.url, logins, options)
            .into_iter()
            .find(|login| same_user(login.username.as_deref(), entry.username.as_deref()));
        let target = match existing {
            Some(login) => Target::Existing(login.id.clone()),
            None if other_part_has(entry, logins, options) => {
                plan.duplicates.push(opened.id.clone());
                continue;
            }
            None => Target::New(
                site_key(&entry.url),
                normalize_email(entry.username.as_deref().unwrap_or("")),
            ),
        };
        if !groups.contains_key(&target) {
            order.push(target.clone());
        }
        groups.entry(target).or_default().push(opened);
    }
    for target in order {
        let group = &groups[&target];
        let current = match &target {
            Target::Existing(id) => logins
                .iter()
                .find(|l| &l.id == id)
                .and_then(|l| l.password.clone()),
            Target::New(..) => None,
        };
        // Newest first: the first time a password is seen is its newest entry; older repeats are duplicates.
        let mut seen = HashSet::new();
        let mut kept: Vec<&OpenedEntry> = Vec::new();
        for opened in group.iter().rev() {
            let password = opened.entry.password.clone().unwrap_or_default();
            if seen.insert(password) {
                kept.push(opened);
            } else {
                plan.duplicates.push(opened.id.clone());
            }
        }
        kept.reverse();
        // The oldest change can't be to the password the login already has.
        if let Some(first) = kept.first()
            && first.entry.password == current
        {
            plan.duplicates.push(first.id.clone());
            kept.remove(0);
        }
        let Some(first) = kept.first() else { continue };
        plan.logins.push(LoginMerge {
            item_id: match &target {
                Target::Existing(id) => Some(id.clone()),
                Target::New(..) => None,
            },
            entry_ids: kept.iter().map(|e| e.id.clone()).collect(),
            url: first.entry.url.clone(),
            username: first.entry.username.clone().filter(|u| !u.is_empty()),
            title: first.entry.title.clone(),
            passwords: kept
                .iter()
                .filter_map(|e| e.entry.password.clone())
                .collect(),
        });
    }
    plan
}

/// The host a new login is grouped by: without `www.`, or the whole address for an app.
fn site_key(url: &str) -> String {
    match Site::parse(url) {
        Ok(site) => site
            .host
            .strip_prefix("www.")
            .unwrap_or(&site.host)
            .to_string(),
        Err(_) => url.trim().to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::sharing::test_support;

    const OWNER: &str = "0192f0c8-1c2d-7a00-8000-0000000000a1";
    const OTHER: &str = "0192f0c8-1c2d-7a00-8000-0000000000b1";
    const NOW: u64 = 1_793_836_800_000;

    fn login(url: &str, username: Option<&str>, password: &str, at: u64) -> InboxEntry {
        InboxEntry {
            kind: InboxKind::Login,
            url: url.into(),
            saved_at: at,
            username: username.map(Into::into),
            password: Some(password.into()),
            title: None,
            details: None,
        }
    }

    fn pinned(session: &Session) -> Inbox {
        let mut inbox = Inbox::default();
        assert!(inbox.pin(session, OWNER).unwrap());
        inbox
    }

    #[test]
    fn seals_while_locked_and_opens_at_unlock() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let session = test_support::account(&mut rng);
        let mut inbox = pinned(&session);
        assert!(
            !inbox.pin(&session, OWNER).unwrap(),
            "the same keys pin the same key"
        );
        // What a locked device holds: the JSON, and no session.
        let mut stored = Inbox::from_json(&inbox.to_json()).unwrap();
        let entry = login("https://shop.example/login", Some("maya"), "typed", NOW);
        let id = stored.add(OWNER, &entry, NOW, &mut rng).unwrap();
        let json = stored.to_json();
        assert!(
            !json.contains("typed") && !json.contains("shop.example") && !json.contains("maya")
        );

        inbox = Inbox::from_json(&json).unwrap();
        let opened = inbox.open(&session, OWNER).unwrap();
        assert_eq!(
            opened.entries,
            vec![OpenedEntry {
                id: id.clone(),
                entry
            }]
        );
        assert!(opened.unreadable.is_empty());
        inbox.remove(&[id]);
        assert!(inbox.entries.is_empty());
    }

    #[test]
    fn uses_the_hybrid_box_with_or_without_an_account_ml_kem_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let mut session = test_support::account(&mut rng);
        // No ML-KEM key of its own (a local vault, or an account before its first key record).
        let derived_key = InboxKey::for_session(&session, OWNER).unwrap();
        let mut inbox = pinned(&session);
        inbox
            .add(
                OWNER,
                &login("https://a.example", None, "one", NOW),
                NOW,
                &mut rng,
            )
            .unwrap();
        let sealed_key = inbox.entries[0].sealed.split_once('.').unwrap().0;
        assert_eq!(
            crate::encoding::b64_decode(sealed_key).unwrap().len(),
            crate::sharing::seal::HYBRID_SEALED_LEN
        );

        // The account gets its ML-KEM key: the inbox key follows it, and the older entry still opens.
        session.set_pq_keys(PqKeyPair::generate(&mut rng));
        assert!(inbox.pin(&session, OWNER).unwrap());
        assert_ne!(inbox.key.as_ref(), Some(&derived_key));
        assert_eq!(
            inbox.key.as_ref().unwrap().public_pq_key,
            session.pq_keys().unwrap().public_key().to_b64()
        );
        inbox
            .add(
                OWNER,
                &login("https://b.example", None, "two", NOW + 1),
                NOW + 1,
                &mut rng,
            )
            .unwrap();
        let opened = inbox.open(&session, OWNER).unwrap();
        assert_eq!(opened.entries.len(), 2);
    }

    #[test]
    fn refuses_a_missing_or_wrong_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let session = test_support::account(&mut rng);
        let entry = login("https://shop.example", Some("maya"), "pw", NOW);
        // Nothing pinned: nothing to seal to.
        let mut empty = Inbox::default();
        assert!(!empty.accepts());
        assert_eq!(
            empty.add(OWNER, &entry, NOW, &mut rng).err(),
            Some(Error::InvalidKey)
        );

        // A key pinned for another vault is refused.
        let mut inbox = pinned(&session);
        assert_eq!(
            inbox.add(OTHER, &entry, NOW, &mut rng).err(),
            Some(Error::KeyMismatch)
        );

        // Garbage in place of the keys is refused, and so is a low-order X25519 key.
        let mut forged = inbox.clone();
        forged.key.as_mut().unwrap().public_pq_key = b64_encode(&[7u8; 32]);
        assert_eq!(
            forged.add(OWNER, &entry, NOW, &mut rng).err(),
            Some(Error::InvalidKey)
        );
        let mut low_order = inbox.clone();
        low_order.key.as_mut().unwrap().public_enc_key = b64_encode(&[0u8; 32]);
        assert_eq!(
            low_order.add(OWNER, &entry, NOW, &mut rng).err(),
            Some(Error::InvalidKey)
        );
        let mut future = inbox.clone();
        future.key.as_mut().unwrap().version = 2;
        assert_eq!(
            future.add(OWNER, &entry, NOW, &mut rng).err(),
            Some(Error::UnsupportedVersion)
        );

        // A key swapped for someone else's (well formed, but not this account's): what's sealed to
        // it doesn't open here, and the next unlock pins the right key again.
        let stranger = test_support::account(&mut rng);
        let mut swapped = Inbox {
            key: Some(InboxKey::for_session(&stranger, OWNER).unwrap()),
            entries: Vec::new(),
        };
        let lost = swapped.add(OWNER, &entry, NOW, &mut rng).unwrap();
        let opened = swapped.open(&session, OWNER).unwrap();
        assert!(opened.entries.is_empty());
        assert_eq!(opened.unreadable, vec![lost]);
        assert!(swapped.pin(&session, OWNER).unwrap());
        assert_eq!(swapped.key, inbox.key);

        // An entry opens only for its own vault, and only under its own id.
        inbox.add(OWNER, &entry, NOW, &mut rng).unwrap();
        assert_eq!(inbox.open(&session, OTHER).unwrap().unreadable.len(), 1);
        let mut moved = inbox.clone();
        moved.entries[0].id = new_id(NOW, &mut rng);
        assert_eq!(moved.open(&session, OWNER).unwrap().unreadable.len(), 1);
    }

    #[test]
    fn stops_at_the_cap() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let session = test_support::account(&mut rng);
        let mut inbox = pinned(&session);
        for n in 0..CAP as u64 {
            inbox
                .add(
                    OWNER,
                    &login("https://a.example", None, "pw", NOW + n),
                    NOW,
                    &mut rng,
                )
                .unwrap();
        }
        assert!(!inbox.accepts());
        assert_eq!(
            inbox
                .add(
                    OWNER,
                    &login("https://a.example", None, "late", NOW),
                    NOW,
                    &mut rng
                )
                .err(),
            Some(Error::InboxFull)
        );
        assert_eq!(inbox.entries.len(), CAP);
        let mut huge = login("https://a.example", None, "pw", NOW);
        huge.password = Some("x".repeat(MAX_ENTRY_LEN));
        inbox.remove(&[inbox.entries[0].id.clone()]);
        assert_eq!(
            inbox.add(OWNER, &huge, NOW, &mut rng).err(),
            Some(Error::InvalidItem)
        );
    }

    fn opened(id: &str, entry: InboxEntry) -> OpenedEntry {
        OpenedEntry {
            id: id.into(),
            entry,
        }
    }

    fn vault_login(id: &str, url: &str, username: &str, password: &str) -> VaultLogin {
        VaultLogin {
            id: id.into(),
            urls: vec![url.into()],
            url_match: HashMap::new(),
            username: Some(username.into()),
            password: Some(password.into()),
        }
    }

    #[test]
    fn merges_a_new_login() {
        let entries = [opened(
            "e1",
            login("https://www.shop.example/join", Some("maya"), "new", NOW),
        )];
        let plan = plan_login_merge(&entries, &[], &MatchOptions::default());
        assert_eq!(
            plan.logins,
            vec![LoginMerge {
                item_id: None,
                entry_ids: vec!["e1".into()],
                url: "https://www.shop.example/join".into(),
                username: Some("maya".into()),
                title: None,
                passwords: vec!["new".into()],
            }]
        );
        assert!(plan.duplicates.is_empty());
    }

    #[test]
    fn updates_the_login_with_that_site_and_username() {
        let logins = [
            vault_login("other-user", "https://shop.example", "sam", "x"),
            vault_login("shop", "https://shop.example", "Maya", "old"),
        ];
        let entries = [opened(
            "e1",
            login("https://shop.example/login", Some("maya"), "new", NOW),
        )];
        let plan = plan_login_merge(&entries, &logins, &MatchOptions::default());
        assert_eq!(plan.logins.len(), 1);
        assert_eq!(plan.logins[0].item_id.as_deref(), Some("shop"));
        assert_eq!(plan.logins[0].passwords, vec!["new".to_string()]);
    }

    #[test]
    fn drops_exact_duplicates() {
        let logins = [
            vault_login("shop", "https://shop.example", "maya", "same"),
            vault_login("mail", "https://mail.other.example", "maya", "there"),
        ];
        let entries = [
            // The vault has it already.
            opened(
                "vault",
                login("https://shop.example", Some("maya"), "same", NOW),
            ),
            // Two entries for one new login, the same password twice.
            opened(
                "first",
                login("https://new.example", Some("sam"), "pw", NOW + 1),
            ),
            opened(
                "again",
                login("https://new.example/x", Some("SAM"), "pw", NOW + 2),
            ),
            // Saved already for another part of the site (filled from "other parts of …").
            opened(
                "part",
                login(
                    "https://login.other.example",
                    Some("maya"),
                    "there",
                    NOW + 3,
                ),
            ),
        ];
        let plan = plan_login_merge(&entries, &logins, &MatchOptions::default());
        let mut duplicates = plan.duplicates.clone();
        duplicates.sort();
        assert_eq!(duplicates, vec!["first", "part", "vault"]);
        assert_eq!(plan.logins.len(), 1);
        assert_eq!(plan.logins[0].entry_ids, vec!["again".to_string()]);
        assert_eq!(plan.logins[0].item_id, None);
    }

    #[test]
    fn several_passwords_for_one_login_keep_history_newest_last() {
        let logins = [vault_login("shop", "https://shop.example", "maya", "p0")];
        let entries = [
            opened(
                "c",
                login("https://shop.example", Some("maya"), "p1", NOW + 3),
            ),
            opened(
                "a",
                login("https://shop.example", Some("maya"), "p1", NOW + 1),
            ),
            opened(
                "b",
                login("https://shop.example", Some("maya"), "p2", NOW + 2),
            ),
            opened(
                "d",
                login("https://shop.example", Some("maya"), "p0", NOW + 4),
            ),
        ];
        let plan = plan_login_merge(&entries, &logins, &MatchOptions::default());
        assert_eq!(plan.duplicates, vec!["a".to_string()]);
        assert_eq!(plan.logins[0].passwords, vec!["p2", "p1", "p0"]);
        assert_eq!(plan.logins[0].entry_ids, vec!["b", "c", "d"]);
    }

    #[test]
    fn android_apps_match_their_package_only() {
        let logins = [vault_login(
            "app",
            "androidapp://com.example.app",
            "maya",
            "old",
        )];
        let entries = [
            opened(
                "same",
                login("androidapp://com.example.app", Some("maya"), "new", NOW),
            ),
            opened(
                "other",
                login(
                    "androidapp://com.example.other",
                    Some("maya"),
                    "new",
                    NOW + 1,
                ),
            ),
        ];
        let plan = plan_login_merge(&entries, &logins, &MatchOptions::default());
        assert_eq!(plan.logins.len(), 2);
        assert_eq!(plan.logins[0].item_id.as_deref(), Some("app"));
        assert_eq!(plan.logins[1].item_id, None);
    }

    #[test]
    fn leaves_other_kinds_to_the_client_and_drops_empty_passwords() {
        let mut card = login("https://shop.example", None, "", NOW);
        card.kind = InboxKind::Card;
        card.password = None;
        let entries = [
            opened("card", card),
            opened("empty", login("https://shop.example", None, "", NOW)),
        ];
        let plan = plan_login_merge(&entries, &[], &MatchOptions::default());
        assert!(plan.logins.is_empty());
        assert_eq!(plan.duplicates, vec!["empty".to_string()]);
    }
}
