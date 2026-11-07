//! An in-memory [`DeviceUnlock`] for tests of code that uses device unlock.

use std::collections::HashMap;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::{
    Capabilities, ChipKey, DeviceSecret, DeviceUnlock, Error, Method, Result, SECRET_LEN,
    chip_secret_from, random_secret,
};

pub struct FakeDeviceUnlock {
    state: Mutex<State>,
}

struct State {
    capabilities: Capabilities,
    /// What the next prompt answers; `None` approves.
    refuse: Option<Error>,
    secrets: HashMap<String, [u8; SECRET_LEN]>,
    unprotected: HashMap<String, [u8; SECRET_LEN]>,
    /// The system key store works (a Linux machine with no keyring running: false).
    keyring: bool,
    prompts: Vec<String>,
    chip: bool,
    chip_keys: HashMap<String, [u8; SECRET_LEN]>,
}

impl Default for FakeDeviceUnlock {
    fn default() -> Self {
        Self::with_capabilities(Capabilities {
            method: Some(Method::TouchId),
            device_lock: true,
        })
    }
}

impl FakeDeviceUnlock {
    pub fn with_capabilities(capabilities: Capabilities) -> Self {
        Self {
            state: Mutex::new(State {
                capabilities,
                refuse: None,
                secrets: HashMap::new(),
                unprotected: HashMap::new(),
                keyring: true,
                prompts: Vec::new(),
                chip: false,
                chip_keys: HashMap::new(),
            }),
        }
    }

    /// A device with no password, passcode or PIN.
    pub fn without_lock() -> Self {
        Self::with_capabilities(Capabilities {
            method: None,
            device_lock: false,
        })
    }

    /// Whether the system key store works, as with no keyring running on Linux.
    pub fn set_keyring(&self, works: bool) {
        self.state.lock().unwrap().keyring = works;
    }

    /// Every prompt from now on answers `error` (`None` approves again).
    pub fn refuse_prompts(&self, error: Option<Error>) {
        self.state.lock().unwrap().refuse = error;
    }

    /// The reasons shown in each prompt so far.
    pub fn prompts(&self) -> Vec<String> {
        self.state.lock().unwrap().prompts.clone()
    }

    pub fn is_enrolled(&self, account: &str) -> bool {
        self.state.lock().unwrap().secrets.contains_key(account)
    }

    pub fn has_unprotected(&self, account: &str) -> bool {
        self.state.lock().unwrap().unprotected.contains_key(account)
    }

    /// Whether this computer has a chip for local vaults. It has none by default, like an
    /// unsigned build.
    pub fn set_chip(&self, chip: bool) {
        self.state.lock().unwrap().chip = chip;
    }

    pub fn has_chip_key(&self, name: &str) -> bool {
        self.state.lock().unwrap().chip_keys.contains_key(name)
    }

    /// What losing the key looks like: a new logic board, a reset chip.
    pub fn lose_chip_key(&self, name: &str) {
        self.state.lock().unwrap().chip_keys.remove(name);
    }

    /// What the OS does when fingerprints change on a `biometryCurrentSet`-only item.
    pub fn invalidate(&self, account: &str) {
        self.state.lock().unwrap().secrets.remove(account);
    }

    fn prompt(&self, reason: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.prompts.push(reason.to_owned());
        match &state.refuse {
            Some(error) => Err(error.clone()),
            None if state.capabilities.method.is_none() => Err(Error::NoDeviceLock),
            None => Ok(()),
        }
    }
}

impl DeviceUnlock for FakeDeviceUnlock {
    fn capabilities(&self) -> Result<Capabilities> {
        Ok(self.state.lock().unwrap().capabilities)
    }

    fn enroll(&self, account: &str) -> Result<DeviceSecret> {
        let mut state = self.state.lock().unwrap();
        if state.capabilities.method.is_none() {
            return Err(Error::NoDeviceLock);
        }
        let secret = random_secret();
        state.secrets.insert(account.to_owned(), *secret);
        Ok(secret)
    }

    fn unlock(&self, account: &str, reason: &str) -> Result<DeviceSecret> {
        self.prompt(reason)?;
        let state = self.state.lock().unwrap();
        state
            .secrets
            .get(account)
            .map(|secret| Zeroizing::new(*secret))
            .ok_or(Error::NotEnrolled)
    }

    fn verify_user(&self, reason: &str) -> Result<()> {
        self.prompt(reason)
    }

    fn remove(&self, account: &str) -> Result<()> {
        self.state.lock().unwrap().secrets.remove(account);
        Ok(())
    }

    fn chip_available(&self) -> bool {
        self.state.lock().unwrap().chip
    }

    fn create_chip_key(&self, name: &str) -> Result<Option<ChipKey>> {
        let mut state = self.state.lock().unwrap();
        if !state.chip {
            return Ok(None);
        }
        let key = random_secret();
        state.chip_keys.insert(name.to_owned(), *key);
        let context = vec![0x04; 65];
        let secret = chip_secret_from(&[key.as_slice(), &context].concat());
        Ok(Some(ChipKey { context, secret }))
    }

    fn chip_secret(&self, name: &str, context: &[u8]) -> Result<DeviceSecret> {
        let state = self.state.lock().unwrap();
        let key = state.chip_keys.get(name).ok_or(Error::NotEnrolled)?;
        Ok(chip_secret_from(&[key.as_slice(), context].concat()))
    }

    fn delete_chip_key(&self, name: &str) -> Result<()> {
        self.state.lock().unwrap().chip_keys.remove(name);
        Ok(())
    }

    fn store_unprotected(&self, account: &str, secret: &[u8; SECRET_LEN]) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if !state.keyring {
            return Err(Error::Unavailable);
        }
        state.unprotected.insert(account.to_owned(), *secret);
        Ok(())
    }

    fn load_unprotected(&self, account: &str) -> Result<Option<DeviceSecret>> {
        let state = self.state.lock().unwrap();
        if !state.keyring {
            return Err(Error::Unavailable);
        }
        Ok(state
            .unprotected
            .get(account)
            .map(|secret| Zeroizing::new(*secret)))
    }

    fn remove_unprotected(&self, account: &str) -> Result<()> {
        self.state.lock().unwrap().unprotected.remove(account);
        Ok(())
    }
}
