//! Windows: Windows Hello, so a face, a fingerprint **or the Windows Hello PIN** unlocks.
//!
//! Each account gets a `KeyCredentialManager` key (in the TPM where the machine has one). Unlock
//! asks Windows Hello to sign a fixed per-account challenge, and the device secret is a hash of
//! the signature. Windows Hello keys are RSA with PKCS#1 v1.5 signatures, which are deterministic,
//! so the same key always gives the same secret and nothing secret is stored on disk: the secret
//! exists only after Windows Hello said yes.
//!
//! Fill without unlocking keeps the secret encrypted with DPAPI (user scope), as Chrome does.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    Capabilities, ChipKey, DeviceSecret, DeviceUnlock, Error, Method, Result, SECRET_LEN,
    account_tag, chip_secret_from, random_secret, secret_from,
};

#[cfg(windows)]
pub mod system;

/// The Windows Hello, `UserConsentVerifier` and DPAPI calls the logic needs.
pub trait HelloApi: Send + Sync {
    /// `UserConsentVerifier.CheckAvailabilityAsync() == Available`.
    fn hello_available(&self) -> Result<bool>;
    /// Whether the Windows account has a password (Fill without unlocking is only offered when it
    /// has none).
    fn account_has_password(&self) -> Result<bool>;
    /// `KeyCredentialManager.RequestCreateAsync(name, ReplaceExisting)`. Windows Hello prompts.
    fn create_key(&self, name: &str) -> Result<()>;
    /// `OpenAsync(name)` then `RequestSignAsync(challenge)`. Windows Hello prompts.
    fn sign(&self, name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn delete_key(&self, name: &str) -> Result<()>;
    /// `UserConsentVerifier.RequestVerificationAsync(message)`.
    fn verify(&self, message: &str) -> Result<()>;
    /// Keeps `secret` with `CryptProtectData` (user scope) under `name`.
    fn dpapi_store(&self, name: &str, secret: &[u8]) -> Result<()>;
    fn dpapi_load(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn dpapi_delete(&self, name: &str) -> Result<()>;
    /// A TPM is there, through the Platform Crypto Provider.
    fn tpm_available(&self) -> bool {
        false
    }
    /// `NCryptCreatePersistedKey` in the Platform Crypto Provider: a non-exportable RSA key with
    /// no UI policy. False when there's no TPM to keep it in.
    fn tpm_create_key(&self, _name: &str) -> Result<bool> {
        Ok(false)
    }
    /// `NCryptSignHash`, PKCS#1 v1.5 over SHA-256: deterministic, like Windows Hello's.
    fn tpm_sign(&self, _name: &str, _digest: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::NotEnrolled)
    }
    fn tpm_delete_key(&self, _name: &str) -> Result<()> {
        Ok(())
    }
}

pub struct HelloUnlock<A> {
    api: A,
}

impl<A: HelloApi> HelloUnlock<A> {
    pub fn new(api: A) -> Self {
        Self { api }
    }
}

/// The Windows Hello key name for an account.
pub fn key_name(account: &str) -> String {
    format!("OctaPass-{}", account_tag(account))
}

fn challenge(account: &str) -> [u8; 32] {
    Sha256::digest(
        [
            b"openpass/v1/windows-hello|",
            account_tag(account).as_bytes(),
        ]
        .concat(),
    )
    .into()
}

/// What the TPM signs for a chip key: the vault's own random context.
fn chip_digest(context: &[u8]) -> [u8; 32] {
    Sha256::digest([b"openpass/v1/tpm-chip|", context].concat()).into()
}

fn secret_from_signature(signature: &[u8]) -> Result<DeviceSecret> {
    if signature.is_empty() {
        return Err(Error::Platform(
            "Windows Hello returned an empty signature".into(),
        ));
    }
    let mut hash = Sha256::new();
    hash.update(b"openpass/v1/windows-hello-secret");
    hash.update(signature);
    Ok(Zeroizing::new(hash.finalize().into()))
}

impl<A: HelloApi> DeviceUnlock for HelloUnlock<A> {
    fn capabilities(&self) -> Result<Capabilities> {
        let hello = self.api.hello_available()?;
        Ok(Capabilities {
            method: hello.then_some(Method::WindowsHello),
            device_lock: hello || self.api.account_has_password()?,
        })
    }

    fn enroll(&self, account: &str) -> Result<DeviceSecret> {
        if !self.api.hello_available()? {
            return Err(Error::NoDeviceLock);
        }
        let name = key_name(account);
        self.api.create_key(&name)?;
        secret_from_signature(&self.api.sign(&name, &challenge(account))?)
    }

    /// Windows Hello shows its own text; the reason isn't passed to `RequestSignAsync`.
    fn unlock(&self, account: &str, _reason: &str) -> Result<DeviceSecret> {
        secret_from_signature(&self.api.sign(&key_name(account), &challenge(account))?)
    }

    fn verify_user(&self, reason: &str) -> Result<()> {
        self.api.verify(reason)
    }

    fn remove(&self, account: &str) -> Result<()> {
        self.api.delete_key(&key_name(account))
    }

    fn store_unprotected(&self, account: &str, secret: &[u8; SECRET_LEN]) -> Result<()> {
        self.api.dpapi_store(&account_tag(account), secret)
    }

    fn load_unprotected(&self, account: &str) -> Result<Option<DeviceSecret>> {
        self.api
            .dpapi_load(&account_tag(account))?
            .map(|bytes| secret_from(&bytes))
            .transpose()
    }

    fn remove_unprotected(&self, account: &str) -> Result<()> {
        self.api.dpapi_delete(&account_tag(account))
    }

    fn chip_available(&self) -> bool {
        self.api.tpm_available()
    }

    fn create_chip_key(&self, name: &str) -> Result<Option<ChipKey>> {
        let key = key_name(name);
        if !self.api.tpm_create_key(&key)? {
            return Ok(None);
        }
        let context = random_secret().to_vec();
        let secret = chip_secret_from(&self.api.tpm_sign(&key, &chip_digest(&context))?);
        Ok(Some(ChipKey { context, secret }))
    }

    fn chip_secret(&self, name: &str, context: &[u8]) -> Result<DeviceSecret> {
        let signature = self.api.tpm_sign(&key_name(name), &chip_digest(context))?;
        Ok(chip_secret_from(&signature))
    }

    fn delete_chip_key(&self, name: &str) -> Result<()> {
        self.api.tpm_delete_key(&key_name(name))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    /// Windows Hello as a map of key names to per-key signing secrets; a "signature" is a hash of
    /// that secret and the challenge, deterministic like PKCS#1 v1.5. DPAPI is a XOR with a
    /// per-user byte, enough to see that what's stored isn't the plaintext.
    #[derive(Default)]
    struct FakeHello {
        unavailable: bool,
        has_password: bool,
        refuse: Option<Error>,
        keys: Mutex<HashMap<String, u64>>,
        next_key: Mutex<u64>,
        prompts: Mutex<u32>,
        dpapi: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl FakeHello {
        fn prompt(&self) -> Result<()> {
            *self.prompts.lock().unwrap() += 1;
            self.refuse.clone().map_or(Ok(()), Err)
        }
    }

    impl HelloApi for FakeHello {
        fn hello_available(&self) -> Result<bool> {
            Ok(!self.unavailable)
        }
        fn account_has_password(&self) -> Result<bool> {
            Ok(self.has_password)
        }
        fn create_key(&self, name: &str) -> Result<()> {
            self.prompt()?;
            let mut next = self.next_key.lock().unwrap();
            *next += 1;
            self.keys.lock().unwrap().insert(name.into(), *next);
            Ok(())
        }
        fn sign(&self, name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            let key = *self
                .keys
                .lock()
                .unwrap()
                .get(name)
                .ok_or(Error::NotEnrolled)?;
            self.prompt()?;
            let signature = Sha256::digest([&key.to_le_bytes()[..], challenge].concat());
            Ok(Zeroizing::new(signature.to_vec()))
        }
        fn delete_key(&self, name: &str) -> Result<()> {
            self.keys.lock().unwrap().remove(name);
            Ok(())
        }
        fn verify(&self, _: &str) -> Result<()> {
            self.prompt()
        }
        fn dpapi_store(&self, name: &str, secret: &[u8]) -> Result<()> {
            let blob = secret.iter().map(|b| b ^ 0x5a).collect();
            self.dpapi.lock().unwrap().insert(name.into(), blob);
            Ok(())
        }
        fn dpapi_load(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self
                .dpapi
                .lock()
                .unwrap()
                .get(name)
                .map(|blob| Zeroizing::new(blob.iter().map(|b| b ^ 0x5a).collect())))
        }
        fn dpapi_delete(&self, name: &str) -> Result<()> {
            self.dpapi.lock().unwrap().remove(name);
            Ok(())
        }
    }

    #[test]
    fn the_same_key_always_gives_the_same_secret() {
        let hello = HelloUnlock::new(FakeHello::default());
        let enrolled = hello.enroll("acct").unwrap();
        assert_eq!(*hello.unlock("acct", "r").unwrap(), *enrolled);
        assert_eq!(*hello.unlock("acct", "r").unwrap(), *enrolled);
        assert_eq!(
            *hello.api.prompts.lock().unwrap(),
            4,
            "create, sign, sign, sign"
        );
    }

    #[test]
    fn accounts_get_their_own_keys_and_secrets() {
        let hello = HelloUnlock::new(FakeHello::default());
        let a = hello.enroll("a").unwrap();
        let b = hello.enroll("b").unwrap();
        assert_ne!(*a, *b);
        assert_ne!(key_name("a"), key_name("b"));
        assert!(key_name("a@example.com").starts_with("OctaPass-"));
        assert!(!key_name("a@example.com").contains('@'));
    }

    #[test]
    fn re_enrolling_replaces_the_key_and_the_secret() {
        let hello = HelloUnlock::new(FakeHello::default());
        let first = hello.enroll("acct").unwrap();
        let second = hello.enroll("acct").unwrap();
        assert_ne!(*first, *second);
        assert_eq!(*hello.unlock("acct", "r").unwrap(), *second);
    }

    #[test]
    fn removed_or_missing_keys_are_not_enrolled() {
        let hello = HelloUnlock::new(FakeHello::default());
        assert_eq!(hello.unlock("acct", "r").unwrap_err(), Error::NotEnrolled);
        hello.enroll("acct").unwrap();
        hello.remove("acct").unwrap();
        assert_eq!(hello.unlock("acct", "r").unwrap_err(), Error::NotEnrolled);
    }

    #[test]
    fn without_windows_hello_there_is_no_method_but_maybe_a_lock() {
        let with_password = HelloUnlock::new(FakeHello {
            unavailable: true,
            has_password: true,
            ..FakeHello::default()
        });
        assert_eq!(
            with_password.capabilities().unwrap(),
            Capabilities {
                method: None,
                device_lock: true
            }
        );
        assert_eq!(
            with_password.enroll("acct").unwrap_err(),
            Error::NoDeviceLock
        );

        let no_password = HelloUnlock::new(FakeHello {
            unavailable: true,
            ..FakeHello::default()
        });
        assert!(!no_password.capabilities().unwrap().device_lock);
        assert_eq!(
            HelloUnlock::new(FakeHello::default())
                .capabilities()
                .unwrap()
                .method,
            Some(Method::WindowsHello)
        );
    }

    #[test]
    fn a_cancelled_prompt_releases_nothing() {
        let hello = HelloUnlock::new(FakeHello::default());
        hello.enroll("acct").unwrap();
        let refusing = HelloUnlock::new(FakeHello {
            refuse: Some(Error::Cancelled),
            keys: Mutex::new(hello.api.keys.lock().unwrap().clone()),
            ..FakeHello::default()
        });
        assert_eq!(refusing.unlock("acct", "r").unwrap_err(), Error::Cancelled);
        assert_eq!(refusing.verify_user("r").unwrap_err(), Error::Cancelled);
    }

    #[test]
    fn stay_unlocked_goes_through_dpapi() {
        let hello = HelloUnlock::new(FakeHello::default());
        hello.store_unprotected("acct", &[7; 32]).unwrap();
        let stored = hello.api.dpapi.lock().unwrap()[&account_tag("acct")].clone();
        assert_ne!(stored, [7; 32]);
        assert_eq!(*hello.load_unprotected("acct").unwrap().unwrap(), [7; 32]);
        hello.remove_unprotected("acct").unwrap();
        assert!(hello.load_unprotected("acct").unwrap().is_none());
        assert_eq!(*hello.api.prompts.lock().unwrap(), 0);
    }

    #[test]
    fn empty_signatures_are_rejected() {
        assert!(matches!(
            secret_from_signature(&[]),
            Err(Error::Platform(_))
        ));
    }
}
