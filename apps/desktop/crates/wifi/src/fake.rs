//! An in-memory Wi-Fi for tests.

use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::{Features, Permission, Result, SavedNetwork, Sighting, WifiSystem};

#[derive(Default)]
pub struct State {
    pub permission: Option<Permission>,
    pub current: Option<String>,
    pub nearby: Vec<Sighting>,
    pub saved: Vec<SavedNetwork>,
    /// Passwords the "system" gives, by name.
    pub passwords: Vec<(String, String)>,
    pub rescans: usize,
    pub prompts: usize,
}

#[derive(Default)]
pub struct FakeWifi {
    pub state: Mutex<State>,
}

impl FakeWifi {
    pub fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }
}

impl WifiSystem for FakeWifi {
    fn features(&self) -> Features {
        Features {
            current: true,
            nearby: true,
            saved_networks: true,
            joins: true,
        }
    }

    fn permission(&self) -> Permission {
        self.state().permission.unwrap_or(Permission::Granted)
    }

    fn request_permission(&self) {
        let mut state = self.state();
        if state.permission == Some(Permission::Prompt) {
            state.permission = Some(Permission::Granted);
        }
    }

    fn current(&self) -> Result<Option<String>> {
        Ok(self.state().current.clone())
    }

    fn nearby(&self, rescan: bool) -> Result<Vec<Sighting>> {
        let mut state = self.state();
        state.rescans += usize::from(rescan);
        Ok(crate::strongest_first(state.nearby.clone()))
    }

    fn saved(&self) -> Result<Vec<SavedNetwork>> {
        Ok(self.state().saved.clone())
    }

    fn read_passwords(&self, ssids: &[String]) -> Result<Vec<SavedNetwork>> {
        let mut state = self.state();
        state.prompts += ssids.len();
        Ok(ssids
            .iter()
            .filter_map(|ssid| state.saved.iter().find(|n| &n.ssid == ssid).cloned())
            .map(|mut network| {
                network.password = state
                    .passwords
                    .iter()
                    .find(|(ssid, _)| *ssid == network.ssid)
                    .map(|(_, password)| Zeroizing::new(password.clone()));
                network
            })
            .collect())
    }
}
