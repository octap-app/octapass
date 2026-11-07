//! macOS: Touch ID / Apple Watch **or the Mac login password**.
//!
//! The device secret is a Keychain item protected by a `SecAccessControl` of
//! `[.biometryCurrentSet, .or, .devicePasscode]` (accessible only while the Mac has a password,
//! this device only). Unlocking runs `LAContext.evaluatePolicy(.deviceOwnerAuthentication)` and
//! hands the authenticated context to the Keychain read, so the user sees one prompt. Enrolling
//! a new fingerprint invalidates the biometric path; the password path keeps working.

use zeroize::Zeroizing;

use crate::{
    Capabilities, ChipKey, DeviceSecret, DeviceUnlock, Error, Result, SECRET_LEN, account_tag,
    chip_secret_from, random_secret, secret_from,
};

#[cfg(target_os = "macos")]
pub mod system;

/// Keychain service names. The account attribute is the hashed account tag.
pub const UNLOCK_SERVICE: &str = "app.octap.desktop.device-unlock";
pub const UNPROTECTED_SERVICE: &str = "app.octap.desktop.stay-unlocked";

/// The two kinds of Keychain item this module keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    /// Behind Touch ID or the login password.
    Protected,
    /// Stay unlocked (plan 18): `AfterFirstUnlockThisDeviceOnly`, no user-presence check.
    Unprotected,
}

impl ItemKind {
    pub fn service(self) -> &'static str {
        match self {
            ItemKind::Protected => UNLOCK_SERVICE,
            ItemKind::Unprotected => UNPROTECTED_SERVICE,
        }
    }
}

/// The LocalAuthentication and Keychain calls the logic needs.
pub trait MacApi: Send + Sync {
    /// An authenticated `LAContext`.
    type Auth;

    fn capabilities(&self) -> Result<Capabilities>;
    /// `evaluatePolicy(.deviceOwnerAuthentication)`: Touch ID, Apple Watch or the login password.
    fn authenticate(&self, reason: &str) -> Result<Self::Auth>;
    /// Adds the item, replacing any previous one for `tag`.
    fn store(&self, kind: ItemKind, tag: &str, secret: &[u8]) -> Result<()>;
    /// `auth` is required for [`ItemKind::Protected`] items.
    fn load(
        &self,
        kind: ItemKind,
        tag: &str,
        auth: Option<&Self::Auth>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn delete(&self, kind: ItemKind, tag: &str) -> Result<()>;

    /// Whether a Secure Enclave key can be made and kept here. Needs the chip, and a signed app:
    /// its keys live in the data protection keychain.
    fn enclave_available(&self) -> bool {
        false
    }

    /// Makes a Secure Enclave P-256 key, usable with no prompt, and a throw-away software key
    /// whose private half is forgotten at once. Returns the throw-away public key (X9.63):
    /// the key agreement's other side. `None` when the Enclave can't be used.
    fn enclave_create(&self, _tag: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// ECDH between the Enclave key and `peer`.
    fn enclave_agree(&self, _tag: &str, _peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::NotEnrolled)
    }

    fn enclave_delete(&self, _tag: &str) -> Result<()> {
        Ok(())
    }
}

pub struct MacUnlock<A> {
    api: A,
}

impl<A: MacApi> MacUnlock<A> {
    pub fn new(api: A) -> Self {
        Self { api }
    }
}

impl<A: MacApi> DeviceUnlock for MacUnlock<A> {
    fn capabilities(&self) -> Result<Capabilities> {
        self.api.capabilities()
    }

    fn enroll(&self, account: &str) -> Result<DeviceSecret> {
        if self.api.capabilities()?.method.is_none() {
            return Err(Error::NoDeviceLock);
        }
        let secret = random_secret();
        self.api
            .store(ItemKind::Protected, &account_tag(account), secret.as_ref())?;
        Ok(secret)
    }

    fn unlock(&self, account: &str, reason: &str) -> Result<DeviceSecret> {
        let auth = self.api.authenticate(reason)?;
        let bytes = self
            .api
            .load(ItemKind::Protected, &account_tag(account), Some(&auth))?
            .ok_or(Error::NotEnrolled)?;
        secret_from(&bytes)
    }

    fn verify_user(&self, reason: &str) -> Result<()> {
        self.api.authenticate(reason).map(drop)
    }

    fn remove(&self, account: &str) -> Result<()> {
        self.api.delete(ItemKind::Protected, &account_tag(account))
    }

    fn store_unprotected(&self, account: &str, secret: &[u8; SECRET_LEN]) -> Result<()> {
        self.api
            .store(ItemKind::Unprotected, &account_tag(account), secret)
    }

    fn load_unprotected(&self, account: &str) -> Result<Option<DeviceSecret>> {
        self.api
            .load(ItemKind::Unprotected, &account_tag(account), None)?
            .map(|bytes| secret_from(&bytes))
            .transpose()
    }

    fn remove_unprotected(&self, account: &str) -> Result<()> {
        self.api
            .delete(ItemKind::Unprotected, &account_tag(account))
    }

    fn chip_available(&self) -> bool {
        self.api.enclave_available()
    }

    fn create_chip_key(&self, name: &str) -> Result<Option<ChipKey>> {
        let tag = account_tag(name);
        let Some(context) = self.api.enclave_create(&tag)? else {
            return Ok(None);
        };
        let secret = chip_secret_from(&self.api.enclave_agree(&tag, &context)?);
        Ok(Some(ChipKey { context, secret }))
    }

    fn chip_secret(&self, name: &str, context: &[u8]) -> Result<DeviceSecret> {
        let raw = self.api.enclave_agree(&account_tag(name), context)?;
        Ok(chip_secret_from(&raw))
    }

    fn delete_chip_key(&self, name: &str) -> Result<()> {
        self.api.enclave_delete(&account_tag(name))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use crate::Method;

    /// A Keychain that enforces what the real one does: protected items need an authenticated
    /// context.
    #[derive(Default)]
    struct FakeMac {
        no_lock: bool,
        refuse: Option<Error>,
        items: Mutex<HashMap<(&'static str, String), Vec<u8>>>,
        prompts: Mutex<Vec<String>>,
    }

    struct Authenticated;

    impl MacApi for FakeMac {
        type Auth = Authenticated;

        fn capabilities(&self) -> Result<Capabilities> {
            Ok(Capabilities {
                method: (!self.no_lock).then_some(Method::TouchId),
                device_lock: !self.no_lock,
            })
        }

        fn authenticate(&self, reason: &str) -> Result<Authenticated> {
            self.prompts.lock().unwrap().push(reason.into());
            match &self.refuse {
                Some(error) => Err(error.clone()),
                None if self.no_lock => Err(Error::NoDeviceLock),
                None => Ok(Authenticated),
            }
        }

        fn store(&self, kind: ItemKind, tag: &str, secret: &[u8]) -> Result<()> {
            self.items
                .lock()
                .unwrap()
                .insert((kind.service(), tag.into()), secret.to_vec());
            Ok(())
        }

        fn load(
            &self,
            kind: ItemKind,
            tag: &str,
            auth: Option<&Authenticated>,
        ) -> Result<Option<Zeroizing<Vec<u8>>>> {
            assert!(
                kind == ItemKind::Unprotected || auth.is_some(),
                "protected items are only read with an authenticated context"
            );
            Ok(self
                .items
                .lock()
                .unwrap()
                .get(&(kind.service(), tag.into()))
                .cloned()
                .map(Zeroizing::new))
        }

        fn delete(&self, kind: ItemKind, tag: &str) -> Result<()> {
            self.items
                .lock()
                .unwrap()
                .remove(&(kind.service(), tag.into()));
            Ok(())
        }
    }

    #[test]
    fn enroll_then_unlock_releases_the_same_secret_after_one_prompt() {
        let mac = MacUnlock::new(FakeMac::default());
        let secret = mac.enroll("acct").unwrap();
        assert!(
            mac.api.prompts.lock().unwrap().is_empty(),
            "storing doesn't prompt"
        );

        assert_eq!(*mac.unlock("acct", "unlock Octa Pass").unwrap(), *secret);
        assert_eq!(*mac.api.prompts.lock().unwrap(), ["unlock Octa Pass"]);
        assert_eq!(mac.unlock("other", "r").unwrap_err(), Error::NotEnrolled);
    }

    #[test]
    fn items_are_keyed_by_the_hashed_account() {
        let mac = MacUnlock::new(FakeMac::default());
        mac.enroll("https://server|a@example.com").unwrap();
        let items = mac.api.items.lock().unwrap();
        let (service, tag) = items.keys().next().unwrap();
        assert_eq!(*service, UNLOCK_SERVICE);
        assert_eq!(*tag, account_tag("https://server|a@example.com"));
    }

    #[test]
    fn a_mac_without_a_password_cant_enroll() {
        let mac = MacUnlock::new(FakeMac {
            no_lock: true,
            ..FakeMac::default()
        });
        assert_eq!(mac.enroll("acct").unwrap_err(), Error::NoDeviceLock);
    }

    #[test]
    fn cancelling_the_prompt_releases_nothing() {
        let mac = MacUnlock::new(FakeMac::default());
        mac.enroll("acct").unwrap();
        let refusing = MacUnlock::new(FakeMac {
            refuse: Some(Error::Cancelled),
            items: Mutex::new(mac.api.items.lock().unwrap().clone()),
            ..FakeMac::default()
        });
        assert_eq!(refusing.unlock("acct", "r").unwrap_err(), Error::Cancelled);
        assert_eq!(refusing.verify_user("r").unwrap_err(), Error::Cancelled);
    }

    #[test]
    fn without_an_enclave_a_vault_goes_without_a_chip() {
        let unlock = MacUnlock::new(FakeMac::default());
        assert!(!unlock.chip_available());
        assert!(unlock.create_chip_key("vault").unwrap().is_none());
        assert_eq!(
            unlock.chip_secret("vault", b"peer").err(),
            Some(Error::NotEnrolled)
        );
    }

    #[test]
    fn remove_forgets_the_secret() {
        let mac = MacUnlock::new(FakeMac::default());
        mac.enroll("acct").unwrap();
        mac.remove("acct").unwrap();
        mac.remove("acct").unwrap();
        assert_eq!(mac.unlock("acct", "r").unwrap_err(), Error::NotEnrolled);
    }

    #[test]
    fn unprotected_copies_live_apart_and_need_no_prompt() {
        let mac = MacUnlock::new(FakeMac {
            no_lock: true,
            ..FakeMac::default()
        });
        mac.store_unprotected("acct", &[9; 32]).unwrap();
        assert_eq!(*mac.load_unprotected("acct").unwrap().unwrap(), [9; 32]);
        assert!(mac.api.prompts.lock().unwrap().is_empty());
        assert_eq!(mac.unlock("acct", "r").unwrap_err(), Error::NoDeviceLock);
        mac.remove_unprotected("acct").unwrap();
        assert!(mac.load_unprotected("acct").unwrap().is_none());
    }
}
