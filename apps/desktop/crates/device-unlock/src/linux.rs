//! Linux: polkit asks for the user's password (or a fingerprint where fprintd is set up), and
//! only then is the device secret read from the Secret Service (GNOME Keyring, KWallet).
//!
//! The Secret Service is unlocked with the user's login, so another program running as the same
//! user could read the item directly; the polkit check is what makes unlocking Octa Pass ask for
//! the password. That's the protection plan 03 describes for Linux, weaker than a TPM or Secure
//! Enclave, which is why the master password stays the default there.
//!
//! The polkit action `app.octap.desktop.unlock` is installed by the Linux packages (see
//! `src-tauri/linux/app.octap.desktop.policy`). Without it, polkit refuses and device unlock
//! isn't offered.

use zeroize::Zeroizing;

use crate::{
    Capabilities, DeviceSecret, DeviceUnlock, Error, Method, Result, SECRET_LEN, account_tag,
    random_secret, secret_from,
};

#[cfg(target_os = "linux")]
pub mod system;

pub const POLKIT_ACTION: &str = "app.octap.desktop.unlock";

/// The Secret Service attribute that tells the two kinds of item apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    DeviceUnlock,
    StayUnlocked,
}

impl ItemKind {
    pub fn attribute(self) -> &'static str {
        match self {
            ItemKind::DeviceUnlock => "device-unlock",
            ItemKind::StayUnlocked => "stay-unlocked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    Granted,
    /// The user dismissed the dialog or failed to authenticate.
    Refused,
    /// The action isn't installed or polkit isn't running.
    Unavailable,
}

/// The polkit and Secret Service calls the logic needs.
pub trait LinuxApi: Send + Sync {
    /// Whether a polkit authority with our action is reachable.
    fn polkit_available(&self) -> bool;
    /// `CheckAuthorization` for this process with user interaction allowed.
    fn authorize(&self, action: &str, message: &str) -> Result<Authorization>;
    fn store(&self, kind: ItemKind, tag: &str, secret: &[u8]) -> Result<()>;
    fn load(&self, kind: ItemKind, tag: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn delete(&self, kind: ItemKind, tag: &str) -> Result<()>;
}

pub struct PolkitUnlock<A> {
    api: A,
}

impl<A: LinuxApi> PolkitUnlock<A> {
    pub fn new(api: A) -> Self {
        Self { api }
    }

    fn authorize(&self, message: &str) -> Result<()> {
        match self.api.authorize(POLKIT_ACTION, message)? {
            Authorization::Granted => Ok(()),
            Authorization::Refused => Err(Error::Cancelled),
            Authorization::Unavailable => Err(Error::Unavailable),
        }
    }
}

impl<A: LinuxApi> DeviceUnlock for PolkitUnlock<A> {
    /// Linux gives no reliable way to ask whether the account has a password without root, so
    /// it's assumed to have one: Fill without unlocking is never offered on Linux by itself.
    fn capabilities(&self) -> Result<Capabilities> {
        Ok(Capabilities {
            method: self
                .api
                .polkit_available()
                .then_some(Method::SystemPassword),
            device_lock: true,
        })
    }

    fn enroll(&self, account: &str) -> Result<DeviceSecret> {
        if !self.api.polkit_available() {
            return Err(Error::Unavailable);
        }
        let secret = random_secret();
        self.api.store(
            ItemKind::DeviceUnlock,
            &account_tag(account),
            secret.as_ref(),
        )?;
        Ok(secret)
    }

    fn unlock(&self, account: &str, reason: &str) -> Result<DeviceSecret> {
        self.authorize(reason)?;
        let bytes = self
            .api
            .load(ItemKind::DeviceUnlock, &account_tag(account))?
            .ok_or(Error::NotEnrolled)?;
        secret_from(&bytes)
    }

    fn verify_user(&self, reason: &str) -> Result<()> {
        self.authorize(reason)
    }

    fn remove(&self, account: &str) -> Result<()> {
        self.api
            .delete(ItemKind::DeviceUnlock, &account_tag(account))
    }

    fn store_unprotected(&self, account: &str, secret: &[u8; SECRET_LEN]) -> Result<()> {
        self.api
            .store(ItemKind::StayUnlocked, &account_tag(account), secret)
    }

    fn load_unprotected(&self, account: &str) -> Result<Option<DeviceSecret>> {
        self.api
            .load(ItemKind::StayUnlocked, &account_tag(account))?
            .map(|bytes| secret_from(&bytes))
            .transpose()
    }

    fn remove_unprotected(&self, account: &str) -> Result<()> {
        self.api
            .delete(ItemKind::StayUnlocked, &account_tag(account))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    struct FakeLinux {
        polkit: bool,
        answer: Authorization,
        keyring: Mutex<HashMap<(&'static str, String), Vec<u8>>>,
        asked: Mutex<Vec<(String, String)>>,
    }

    impl Default for FakeLinux {
        fn default() -> Self {
            Self {
                polkit: true,
                answer: Authorization::Granted,
                keyring: Mutex::default(),
                asked: Mutex::default(),
            }
        }
    }

    impl LinuxApi for FakeLinux {
        fn polkit_available(&self) -> bool {
            self.polkit
        }
        fn authorize(&self, action: &str, message: &str) -> Result<Authorization> {
            self.asked
                .lock()
                .unwrap()
                .push((action.into(), message.into()));
            Ok(self.answer)
        }
        fn store(&self, kind: ItemKind, tag: &str, secret: &[u8]) -> Result<()> {
            self.keyring
                .lock()
                .unwrap()
                .insert((kind.attribute(), tag.into()), secret.to_vec());
            Ok(())
        }
        fn load(&self, kind: ItemKind, tag: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self
                .keyring
                .lock()
                .unwrap()
                .get(&(kind.attribute(), tag.into()))
                .cloned()
                .map(Zeroizing::new))
        }
        fn delete(&self, kind: ItemKind, tag: &str) -> Result<()> {
            self.keyring
                .lock()
                .unwrap()
                .remove(&(kind.attribute(), tag.into()));
            Ok(())
        }
    }

    fn with_keyring(
        answer: Authorization,
        from: &PolkitUnlock<FakeLinux>,
    ) -> PolkitUnlock<FakeLinux> {
        PolkitUnlock::new(FakeLinux {
            answer,
            keyring: Mutex::new(from.api.keyring.lock().unwrap().clone()),
            ..FakeLinux::default()
        })
    }

    #[test]
    fn the_secret_is_released_only_after_polkit_says_yes() {
        let linux = PolkitUnlock::new(FakeLinux::default());
        let secret = linux.enroll("acct").unwrap();
        assert!(
            linux.api.asked.lock().unwrap().is_empty(),
            "enrolling doesn't ask"
        );

        assert_eq!(*linux.unlock("acct", "Unlock Octa Pass").unwrap(), *secret);
        assert_eq!(
            *linux.api.asked.lock().unwrap(),
            [(POLKIT_ACTION.to_owned(), "Unlock Octa Pass".to_owned())]
        );

        let refusing = with_keyring(Authorization::Refused, &linux);
        assert_eq!(refusing.unlock("acct", "r").unwrap_err(), Error::Cancelled);
        let missing_action = with_keyring(Authorization::Unavailable, &linux);
        assert_eq!(
            missing_action.unlock("acct", "r").unwrap_err(),
            Error::Unavailable
        );
    }

    #[test]
    fn without_polkit_device_unlock_is_not_offered() {
        let linux = PolkitUnlock::new(FakeLinux {
            polkit: false,
            ..FakeLinux::default()
        });
        assert_eq!(
            linux.capabilities().unwrap(),
            Capabilities {
                method: None,
                device_lock: true
            }
        );
        assert_eq!(linux.enroll("acct").unwrap_err(), Error::Unavailable);
    }

    #[test]
    fn the_two_kinds_of_item_are_kept_apart() {
        let linux = PolkitUnlock::new(FakeLinux::default());
        linux.enroll("acct").unwrap();
        linux.store_unprotected("acct", &[3; 32]).unwrap();
        assert_eq!(*linux.load_unprotected("acct").unwrap().unwrap(), [3; 32]);
        linux.remove("acct").unwrap();
        assert_eq!(linux.unlock("acct", "r").unwrap_err(), Error::NotEnrolled);
        assert!(linux.load_unprotected("acct").unwrap().is_some());
        linux.remove_unprotected("acct").unwrap();
        assert!(linux.load_unprotected("acct").unwrap().is_none());
    }
}
