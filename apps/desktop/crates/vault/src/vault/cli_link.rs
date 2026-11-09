//! The CLI linked to the desktop app's account (plan 05, 2026-11-09): a CLI that isn't signed in
//! asks the running app, which makes the CLI a server session of its own
//! (`POST /v1/devices/link`) and hands it over with the Secret Key, so the CLI never needs the
//! master password or `octapass login`. The app's half is [`Vault::link_device`]; the CLI's is
//! [`Vault::sign_in_linked`]. What travels over the socket is in `crate::cli_session`.

use std::sync::Arc;

use octapass_api::{DeviceInfo, LinkDeviceRequest, LoginFinishResponse};
use octapass_core::account::AccountBundle;
use octapass_core::encoding::b64_decode;
use octapass_core::secret_key::SecretKey;
use octapass_core::session::Session;
use zeroize::Zeroizing;

use super::{Vault, convert};
use crate::api::Method;
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{now, require, rfc3339};
use crate::store::{AccountKey, StoredAccount};

/// What the app gives a CLI it links: its account, a new server session and the Secret Key.
pub struct LinkedAccount {
    pub key: AccountKey,
    pub secret_key: Zeroizing<String>,
    pub login: LoginFinishResponse,
}

/// The account key, wrapped by the app for the CLI (`SessionKeyWrap`'s fields).
pub struct LinkWrap<'a> {
    pub wrap_key: &'a [u8; 32],
    pub device_salt: &'a str,
    pub wrapped_ask: &'a str,
}

impl Vault {
    /// The app's half: a server session for `device` made from this one. Unlocked, signed in to a
    /// server account (a vault on this computer only has no server to link through).
    pub(crate) async fn link_device(&self, device: DeviceInfo) -> Result<LinkedAccount> {
        let key = self.account_key()?;
        require(!key.is_local(), ErrorCode::NotAllowed)?;
        let secret_key = Zeroizing::new(self.current_account()?.secret_key);
        let body = serde_json::to_value(LinkDeviceRequest { device })
            .map_err(|error| VaultError::unexpected(error.to_string()))?;
        let _io = self.io.lock().await;
        let login: LoginFinishResponse = self
            .server(&key, Method::POST, "/v1/devices/link", Some(body))
            .await??;
        Ok(LinkedAccount {
            key,
            secret_key,
            login,
        })
    }

    /// The CLI's half: keeps the session the app made, then opens the vault with the key it
    /// wrapped, and syncs. Replaces nothing: the caller checks this CLI isn't signed in.
    pub async fn sign_in_linked(
        self: &Arc<Self>,
        linked: LinkedAccount,
        wrap: LinkWrap<'_>,
    ) -> Result<()> {
        let LinkedAccount {
            key,
            secret_key,
            login,
        } = linked;
        let secret_key = SecretKey::parse(&secret_key)?;
        let bundle: AccountBundle = convert(&login.account)?;
        let session = Session::unlock_with_device_key(
            bundle.clone(),
            wrap.wrap_key,
            &b64_decode(wrap.device_salt)?,
            wrap.wrapped_ask,
        )?;
        let _io = self.io.lock().await;
        self.lock();
        self.remember(
            StoredAccount {
                key: key.clone(),
                secret_key: secret_key.to_text().to_string(),
                bundle,
                refresh_token: Some(login.refresh_token),
                trusted_device_token: login.trusted_device_token,
                // The app vouched for this unlock; its own 14-day check still applies there.
                last_password_unlock_at: rfc3339(now()),
                device_unlock: None,
            },
            login.access_token,
        )?;
        self.install(key, session)?;
        self.report(self.sync_locked().await);
        Ok(())
    }
}
