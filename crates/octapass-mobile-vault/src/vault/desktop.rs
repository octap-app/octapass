//! The vault's half of the desktop services (`crate::desktop`, plan 19, phase 3): what the
//! browser extension and the CLI may ask of the Mac app, as the Tauri app's
//! `octapass-desktop-vault` answers them (`bridge.rs`, `cli_session.rs` there).

use std::sync::{Arc, Weak};

use octapass_core::encoding::{b64_decode, b64_decode_array, b64_encode};
use octapass_core::keys::SymmetricKey;
use octapass_ffi::Session;
use rand_core::OsRng;
use zeroize::Zeroizing;

use super::Vault;
use crate::desktop::bridge::{BridgeStatus, ChipSecretWrap, SessionKeyWrap};
use crate::desktop::wrap::{CHIP_WRAP_INFO, WRAP_INFO, exchange};
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{SessionStatus, require};

impl Vault {
    /// `unlock-status` from the extension.
    pub fn bridge_status(&self) -> BridgeStatus {
        let session = self.snapshot().session;
        let methods = self.unlock_methods();
        BridgeStatus {
            status: session.status,
            email: session.email,
            server_url: session.server_url,
            device_unlock: methods.device_unlock_enabled,
            label: methods.label,
            stay_unlocked: self.stays_unlocked(),
        }
    }

    /// `unlock` from the extension: the same device unlock as the lock screen. Already unlocked,
    /// nothing asks.
    pub fn bridge_unlock(&self) -> Result<BridgeStatus> {
        self.unlock_with_device_if_locked()?;
        Ok(self.bridge_status())
    }

    /// The open vault's unlock (a new one after every lock), or `None` while locked: the SSH
    /// agent's approval lasts for one.
    pub fn ssh_agent_session(&self) -> Option<u64> {
        self.state().unlocked.as_ref().map(|unlocked| unlocked.id)
    }

    pub(crate) fn unlock_with_device_if_locked(&self) -> Result<()> {
        if self.state().unlocked.is_some() {
            return Ok(());
        }
        self.unlock_with_device()
    }

    /// Stay unlocked (plan 18) is on for the current account: the extension and the CLI get the
    /// account key without a prompt while the app is unlocked, as the app itself opens.
    pub fn stays_unlocked(&self) -> bool {
        self.stay_unlocked_status().enrolled
    }

    /// The device lock's prompt, with no secret behind it.
    pub(crate) fn verify_user(&self, reason: &str) -> Result<()> {
        self.native.verify_user(reason)
    }

    /// The chip secret for a local vault in the extension (plan 05): `context` is what a first
    /// call returned, none makes a new key. `None` when this computer has no chip to offer. The
    /// secret alone opens nothing: it's mixed with the master password (plan 03, *Local mode
    /// keys*), so no prompt.
    pub fn extension_chip(
        &self,
        extension_public_key: &str,
        vault_id: &str,
        context: Option<&str>,
    ) -> Result<Option<ChipSecretWrap>> {
        let extension_public: [u8; 32] = b64_decode_array(extension_public_key).map_err(core)?;
        require(
            !vault_id.is_empty()
                && vault_id.len() <= 64
                && vault_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            ErrorCode::NotFound,
        )?;
        let name = format!("extensionChipKey.{vault_id}");
        let (context, secret) = match context {
            Some(context) => {
                let bytes = b64_decode(context).map_err(core)?;
                let secret = self.native.chip_secret(&name, &bytes)?;
                (b64_encode(&bytes), secret)
            }
            None => match self.native.create_chip_key(&name)? {
                Some(key) => (b64_encode(&key.context), key.secret),
                None => return Ok(None),
            },
        };
        let (app_public, key) = exchange(&extension_public, CHIP_WRAP_INFO)?;
        let sealed_secret = octapass_core::local::keys::seal_chip_secret(
            &SymmetricKey::from_slice(key.as_ref()).map_err(core)?,
            &secret,
            &mut OsRng,
        )
        .map_err(core)?;
        Ok(Some(ChipSecretWrap {
            context,
            ephemeral_public_key: b64_encode(&app_public),
            sealed_secret,
        }))
    }

    /// `get-session-key-wrap`: the account key wrapped for the extension, after the user
    /// confirms with the device lock, unless the app stays unlocked (plan 18). `requester` names
    /// the browser in the prompt. Unlocked only.
    pub fn wrap_session_key(
        &self,
        extension_public_key: &str,
        requester: &str,
    ) -> Result<SessionKeyWrap> {
        require(
            self.snapshot().session.status == SessionStatus::Unlocked,
            ErrorCode::Locked,
        )?;
        if !self.stays_unlocked() {
            self.verify_user(&format!("unlock Octa Pass in {requester}"))?;
        }
        Ok(self.wrap_for_peer(extension_public_key)?.0)
    }

    /// Wraps the account key for `peer_public_key`; the caller has the user's approval. Also
    /// returns the session it wrapped, which names this unlock: locking or signing out ends it.
    pub(crate) fn wrap_for_peer(
        &self,
        peer_public_key: &str,
    ) -> Result<(SessionKeyWrap, Weak<Session>)> {
        let peer_public: [u8; 32] = b64_decode_array(peer_public_key).map_err(core)?;
        let (app_public, key) = exchange(&peer_public, WRAP_INFO)?;
        let unlocked = self.unlocked()?;
        let wrapped = unlocked.session.wrap_for_device_secret(key.as_ref())?;
        Ok((
            SessionKeyWrap {
                email: unlocked.account.email.clone(),
                server_url: unlocked.account.server_url.clone(),
                ephemeral_public_key: b64_encode(&app_public),
                device_salt: b64_encode(&wrapped.device_salt),
                wrapped_ask: Zeroizing::new(wrapped.wrapped_ask),
            },
            Arc::downgrade(&unlocked.session),
        ))
    }

    /// A server session of its own for the CLI (`POST /v1/devices/link`), with this account's
    /// Secret Key: what `link` hands a CLI that isn't signed in (plan 05). Unlocked, signed in
    /// to a server account: a vault on this Mac only has no server to link through.
    pub(crate) fn link_device(
        &self,
        device: octapass_api::DeviceInfo,
    ) -> Result<(Zeroizing<String>, octapass_api::LoginFinishResponse)> {
        let unlocked = self.unlocked()?;
        // `needsSync` for a vault on this Mac only, as for its Secret Key.
        let secret_key = Zeroizing::new(self.secret_key()?);
        let _io = self.io();
        let login = self.with_token(&unlocked, |token| {
            unlocked.server.link_device(token, device.clone())
        })?;
        Ok((secret_key, login))
    }
}

fn core(error: octapass_core::Error) -> VaultError {
    VaultError::from(octapass_ffi::OctaPassError::from(error))
}
