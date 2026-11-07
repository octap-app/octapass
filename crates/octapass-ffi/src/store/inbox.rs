//! Saving while locked (plan 03, *Saving while locked*): the store's save inbox, a JSON file next to
//! it (`<store>.inbox`) that never syncs. While the store is locked, the Autofill service seals a
//! login into it with the account's own public keys, pinned there at the last unlock; it can't read
//! it back. The next unlock, by the app or by an autofill screen, pins the keys again, opens the
//! entries and merges them into the store by the core's rules (`octapass_core::inbox`): a new login
//! tagged "Unconfirmed" for review; a new password on the login with that site and username, the old
//! one going into its history and its tags left as they are; exact duplicates dropped.
//!
//! The inbox is read and written under the store's own file lock, so the app and the services never
//! lose each other's entries.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use octapass_core::inbox::{
    Inbox, InboxEntry, InboxKind, LoginMerge, VaultLogin, plan_login_merge,
};
use octapass_core::item::ItemDetails;
use octapass_core::matching::user_equivalents;
use rand_core::OsRng;

use super::{LocalStore, StoreData, write_atomically};
use crate::error::{OctaPassError, Result};
use crate::items::{self, LoginDraft};
use crate::session::{Session, encrypt, live_items};
use crate::{now_ms, timestamp};

/// Tagged on what the inbox adds, as on the browser extension's drafts (plan 05).
pub const UNCONFIRMED_TAG: &str = "Unconfirmed";

/// What a merge did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, uniffi::Record)]
pub struct InboxMerge {
    /// New logins, tagged "Unconfirmed".
    pub added: u32,
    /// Logins that got a new password.
    pub updated: u32,
    /// Entries dropped: the store had them already, or they can never be opened.
    pub dropped: u32,
    /// Entries that couldn't be merged this time; they stay for the next unlock.
    pub failed: u32,
}

#[uniffi::export]
impl LocalStore {
    /// Whether a login can be saved while locked: an unlock here pinned the inbox key, and the
    /// inbox isn't full (50 entries).
    pub fn inbox_accepts(&self) -> bool {
        self.read_inbox().is_ok_and(|inbox| inbox.accepts())
    }

    /// Seals a login into the inbox, without unlocking (the Autofill service's Save). It's added to
    /// the vault at the next unlock. Fails when no unlock pinned a key yet, or the inbox is full.
    pub fn add_to_inbox(
        &self,
        url: String,
        username: Option<String>,
        password: String,
        title: Option<String>,
    ) -> Result<()> {
        if password.is_empty() {
            return Err(OctaPassError::InvalidItem);
        }
        let owner = self.inbox_owner()?;
        let entry = InboxEntry {
            kind: InboxKind::Login,
            url,
            saved_at: now_ms(),
            username: username.filter(|u| !u.is_empty()),
            password: Some(password),
            title: title.filter(|t| !t.trim().is_empty()),
            details: None,
        };
        let _lock = self.lock_file()?;
        let mut inbox = self.read_inbox()?;
        inbox.add(&owner, &entry, now_ms(), &mut OsRng)?;
        self.write_inbox(&inbox)
    }

    /// Pins this account's own public keys for the inbox, then merges what waits in it into the
    /// store. Call it at every unlock; the app uploads what it added on its next sync.
    pub fn merge_inbox(self: Arc<Self>, session: Arc<Session>) -> Result<InboxMerge> {
        self.check_account(&session)?;
        let owner = self.inbox_owner()?;
        let opened = {
            let _lock = self.lock_file()?;
            let mut inbox = self.read_inbox()?;
            if session.with(|core| Ok(inbox.pin(core, &owner)?))? {
                self.write_inbox(&inbox)?;
            }
            session.with(|core| Ok(inbox.open(core, &owner)?))?
        };
        if opened.entries.is_empty() && opened.unreadable.is_empty() {
            return Ok(InboxMerge::default());
        }
        let mut result = InboxMerge::default();
        // Sealed to a key that isn't this account's, or damaged: they'll never open.
        let mut done = opened.unreadable.clone();
        result.dropped += opened.unreadable.len() as u32;

        let (logins, options) = session.with_store(&self, |core, data| {
            let all = live_items(core, data);
            let options =
                user_equivalents(all.iter().filter_map(|(_, item)| match &item.details {
                    ItemDetails::EquivalentDomains(details) => Some(details),
                    _ => None,
                }));
            let logins = all
                .iter()
                .filter_map(|(stored, item)| {
                    let login = items::login_details(item)?;
                    let mut overview = serde_json::to_value(&item.overview).ok()?;
                    overview["id"] = stored.record.id.clone().into();
                    overview["username"] = login.username.clone().into();
                    overview["password"] = login.password.clone().into();
                    serde_json::from_value::<VaultLogin>(overview).ok()
                })
                .collect::<Vec<_>>();
            Ok((logins, options))
        })?;
        let plan = plan_login_merge(&opened.entries, &logins, &options);
        result.dropped += plan.duplicates.len() as u32;
        done.extend(plan.duplicates.iter().cloned());
        for merge in &plan.logins {
            match Self::apply(&self, &session, merge) {
                Ok(()) => {
                    done.extend(merge.entry_ids.iter().cloned());
                    if merge.item_id.is_some() {
                        result.updated += 1;
                    } else {
                        result.added += 1;
                    }
                }
                Err(_) => result.failed += merge.entry_ids.len() as u32,
            }
        }
        // Only logins are saved on a phone; anything else is left for a client that knows it.
        let _lock = self.lock_file()?;
        let mut inbox = self.read_inbox()?;
        inbox.remove(&done);
        self.write_inbox(&inbox)?;
        Ok(result)
    }
}

impl LocalStore {
    fn inbox_path(&self) -> PathBuf {
        let mut path = self.path.clone().into_os_string();
        path.push(".inbox");
        PathBuf::from(path)
    }

    fn read_inbox(&self) -> Result<Inbox> {
        match fs::read_to_string(self.inbox_path()) {
            Ok(text) => Ok(Inbox::from_json(&text)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Inbox::default()),
            Err(error) => Err(error.into()),
        }
    }

    fn write_inbox(&self, inbox: &Inbox) -> Result<()> {
        write_atomically(&self.inbox_path(), inbox.to_json().as_bytes())
    }

    /// The account id, or a local vault's personal vault id: both readable while locked.
    fn inbox_owner(&self) -> Result<String> {
        let data = self.data();
        owner_of(&data)
    }

    /// One save per password, oldest first, so all but the newest land in the password history.
    fn apply(store: &Arc<Self>, session: &Session, merge: &LoginMerge) -> Result<()> {
        let mut item_id = merge.item_id.clone();
        for password in &merge.passwords {
            let draft = LoginDraft {
                item_id: item_id.clone(),
                title: if item_id.is_none() {
                    merge.title.clone()
                } else {
                    None
                },
                url: if item_id.is_none() {
                    Some(merge.url.clone())
                } else {
                    None
                },
                username: if item_id.is_none() {
                    merge.username.clone()
                } else {
                    None
                },
                password: Some(password.clone()),
                totp: None,
            };
            item_id = Some(match &item_id {
                // An existing login keeps its tags: the inbox never adds or removes the review mark.
                Some(_) => session.save_login(store.clone(), draft)?,
                None => store.add_for_review(session, &draft)?,
            });
        }
        Ok(())
    }

    /// A new login from the inbox, tagged "Unconfirmed" for review.
    fn add_for_review(&self, session: &Session, draft: &LoginDraft) -> Result<String> {
        let now = timestamp(now_ms());
        let (vault_id, item_id, encrypted) = session.with_store(self, |core, data| {
            let mut item = items::new_login(draft)?;
            item.overview.tags = Some(vec![UNCONFIRMED_TAG.to_owned()]);
            if let Some(username) = &draft.username {
                item.overview.subtitle = Some(username.clone());
            }
            let vault_id = data.personal_vault()?.id.clone();
            let item_id = octapass_core::account::new_id(now_ms(), &mut OsRng);
            let encrypted = encrypt(core, data, &vault_id, &item_id, &item, None)?;
            Ok((vault_id, item_id, encrypted))
        })?;
        self.mutate(|data| {
            data.put_local(&vault_id, &item_id, encrypted, None, &now);
            Ok(())
        })?;
        Ok(item_id)
    }
}

fn owner_of(data: &StoreData) -> Result<String> {
    match &data.account.account_id {
        Some(id) => Ok(id.clone()),
        None => Ok(data.personal_vault()?.id.clone()),
    }
}

#[cfg(test)]
mod tests {
    use octapass_core::kdf::KdfParams;
    use octapass_core::local::{DeviceProtection, LocalVault};

    use super::*;

    const PASSWORD: &str = "vexed-kiwi-trumpet-galaxy-oboe";

    fn store() -> (tempfile::TempDir, Arc<LocalStore>, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.opstore").to_string_lossy().into_owned();
        let vault = LocalVault::create_with_backup_kdf(
            PASSWORD,
            DeviceProtection {
                kdf: KdfParams::DEFAULT,
                hardware_secret: None,
            },
            KdfParams::DEFAULT,
            now_ms(),
            &mut OsRng,
        )
        .unwrap();
        let id = vault.vault_id().to_owned();
        let store = LocalStore::create_local(path.clone(), format!("local:{id}"), &vault).unwrap();
        (dir, store, path)
    }

    fn draft(url: &str, username: &str, password: &str) -> LoginDraft {
        LoginDraft {
            item_id: None,
            title: None,
            url: Some(url.into()),
            username: Some(username.into()),
            password: Some(password.into()),
            totp: None,
        }
    }

    #[test]
    fn saves_while_locked_and_merges_at_the_next_unlock() {
        let (_dir, store, path) = store();
        // Nothing pinned yet: no unlock has happened on this device.
        assert!(!store.inbox_accepts());
        assert!(
            store
                .add_to_inbox("https://a.example".into(), None, "pw".into(), None)
                .is_err()
        );

        let session = store.unlock_local(PASSWORD.into(), None).unwrap();
        let shop = session
            .save_login(store.clone(), draft("https://shop.example", "maya", "old"))
            .unwrap();
        assert_eq!(
            store.clone().merge_inbox(session.clone()).unwrap(),
            InboxMerge::default()
        );
        session.lock();

        // Locked: the Autofill service opens the file and seals into it.
        let service = LocalStore::open(path.clone()).unwrap();
        assert!(service.inbox_accepts());
        let save = |url: &str, user: &str, password: &str, title: Option<&str>| {
            service
                .add_to_inbox(
                    url.into(),
                    Some(user.into()),
                    password.into(),
                    title.map(Into::into),
                )
                .unwrap()
        };
        save(
            "androidapp://com.example.app",
            "samuel-rivers",
            "app-password-17",
            Some("Example App"),
        );
        save("https://shop.example/login", "maya", "new", None);
        save("https://shop.example/login", "maya", "new", None);
        save("https://shop.example/login", "maya", "old", None);
        let sealed = fs::read_to_string(format!("{path}.inbox")).unwrap();
        for secret in ["app-password-17", "samuel-rivers", "shop.example", "com.example.app"] {
            assert!(!sealed.contains(secret), "{secret} is readable");
        }

        // The next unlock (the app's, or an autofill screen's) merges it.
        let session = store.unlock_local(PASSWORD.into(), None).unwrap();
        let merged = store.clone().merge_inbox(session.clone()).unwrap();
        assert_eq!(
            merged,
            InboxMerge {
                added: 1,
                updated: 1,
                dropped: 1,
                failed: 0
            }
        );
        let updated = session.get_item(store.clone(), shop.clone()).unwrap();
        assert_eq!(updated.login.unwrap().password.as_deref(), Some("old"));
        assert!(updated.tags.is_empty(), "a confirmed login stays confirmed");
        let added = session
            .match_logins(store.clone(), "androidapp://com.example.app".into())
            .unwrap();
        assert_eq!(added.len(), 1);
        let added = session
            .get_item(store.clone(), added[0].item.item_id.clone())
            .unwrap();
        assert_eq!(added.title, "Example App");
        assert_eq!(added.tags, vec![UNCONFIRMED_TAG.to_string()]);
        assert_eq!(added.login.unwrap().password.as_deref(), Some("app-password-17"));
        assert!(store.read_inbox().unwrap().entries.is_empty());
        assert_eq!(
            store.clone().merge_inbox(session).unwrap(),
            InboxMerge::default()
        );
    }

    #[test]
    fn the_inbox_is_capped() {
        let (_dir, store, _path) = store();
        let session = store.unlock_local(PASSWORD.into(), None).unwrap();
        store.clone().merge_inbox(session.clone()).unwrap();
        session.lock();
        for n in 0..octapass_core::inbox::CAP {
            store
                .add_to_inbox(format!("https://site{n}.example"), None, "pw".into(), None)
                .unwrap();
        }
        assert!(!store.inbox_accepts());
        assert!(matches!(
            store.add_to_inbox("https://late.example".into(), None, "pw".into(), None),
            Err(OctaPassError::Core { ref code, .. }) if code == "inbox_full"
        ));
    }
}
