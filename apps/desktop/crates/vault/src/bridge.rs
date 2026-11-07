//! What the browser extension can ask the desktop app over native messaging.
//!
//! `get-session-key-wrap` hands the extension the account key so one unlock covers both, without
//! the key ever being readable on the way: the extension sends a fresh X25519 public key, the app
//! answers with its own ephemeral public key and the account key wrapped exactly as for device
//! unlock (`octapass_core::device`), using
//!
//! ```text
//! shared    = X25519(app_ephemeral, extension_public)
//! wrap_key  = HKDF-SHA256(ikm = shared, salt = app_ephemeral_public ‖ extension_public,
//!                         info = "octapass/v1/native-messaging")
//! ```
//!
//! as the 32-byte device secret. The extension derives the same key and calls the WASM
//! `Session.unlockWithDeviceKey(wrapKey, deviceSalt, wrappedAsk, account)`. Each request needs the
//! user to confirm with the device lock, unless the app stays unlocked (plan 18).

use std::sync::Arc;

use hkdf::Hkdf;
use octapass_core::encoding::{b64_decode_array, b64_encode};
use octapass_core::keys::SymmetricKey;
use rand_core::OsRng;
use serde::Serialize;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{SessionStatus, require};
use crate::vault::{Vault, blocking};

pub const WRAP_INFO: &[u8] = b"octapass/v1/native-messaging";
/// For the chip secret of the extension's own local vault, so the two keys never coincide.
pub const CHIP_WRAP_INFO: &[u8] = b"octapass/v1/native-messaging-chip";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeStatus {
    pub status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    /// Device unlock is set up, so `unlock` can ask for Touch ID / Windows Hello.
    pub device_unlock: bool,
    pub label: String,
    /// Stay unlocked is on here (plan 18): `get-session-key-wrap` answers without a prompt while
    /// the app is unlocked.
    pub stay_unlocked: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionKeyWrap {
    pub email: String,
    pub server_url: String,
    pub ephemeral_public_key: String,
    pub device_salt: String,
    pub wrapped_ask: String,
}

/// The chip secret for the extension's own local vault, sealed to the extension. `context` goes
/// with the vault in the extension; nothing else is kept there. The secret alone opens nothing:
/// it's mixed with the master password (plan 03, *Local mode keys*), so no device prompt.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChipSecretWrap {
    pub context: String,
    pub ephemeral_public_key: String,
    pub sealed_secret: String,
}

/// Both sides derive the wrapping key the same way.
pub fn wrap_key(
    shared_secret: &[u8; 32],
    app_public: &[u8; 32],
    extension_public: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    derive_wrap_key(shared_secret, app_public, extension_public, WRAP_INFO)
}

fn derive_wrap_key(
    shared_secret: &[u8; 32],
    app_public: &[u8; 32],
    extension_public: &[u8; 32],
    info: &[u8],
) -> Zeroizing<[u8; 32]> {
    let salt = [app_public.as_slice(), extension_public.as_slice()].concat();
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared_secret)
        .expand(info, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    key
}

impl Vault {
    pub async fn bridge_status(&self) -> BridgeStatus {
        let snapshot = self.snapshot().session;
        let methods = self.unlock_methods().await;
        BridgeStatus {
            status: snapshot.status,
            email: snapshot.email,
            server_url: snapshot.server_url,
            device_unlock: methods.device_unlock_enabled,
            label: methods.label,
            stay_unlocked: self.stays_unlocked(),
        }
    }

    /// `unlock` from the extension: the same device unlock as the lock screen.
    pub async fn bridge_unlock(self: &Arc<Self>) -> Result<BridgeStatus> {
        self.unlock_with_device().await?;
        Ok(self.bridge_status().await)
    }

    /// The chip secret for a local vault in the extension (plan 05): `context` is what a first
    /// call returned, none makes a new key. `None` when this computer has no chip to offer.
    pub async fn extension_chip(
        &self,
        extension_public_key: &str,
        vault_id: &str,
        context: Option<&str>,
    ) -> Result<Option<ChipSecretWrap>> {
        let extension_public: [u8; 32] = b64_decode_array(extension_public_key)?;
        require(
            !vault_id.is_empty()
                && vault_id.len() <= 64
                && vault_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            ErrorCode::NotFound,
        )?;
        let Some((context, secret)) = self.extension_chip_secret(vault_id, context).await? else {
            return Ok(None);
        };
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let app_public = PublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(&PublicKey::from(extension_public));
        if !shared.was_contributory() {
            return Err(VaultError::unexpected("invalid extension public key"));
        }
        let key = derive_wrap_key(
            shared.as_bytes(),
            app_public.as_bytes(),
            &extension_public,
            CHIP_WRAP_INFO,
        );
        let sealed_secret = octapass_core::local::keys::seal_chip_secret(
            &SymmetricKey::from_slice(key.as_ref())?,
            &secret,
            &mut OsRng,
        )?;
        Ok(Some(ChipSecretWrap {
            context,
            ephemeral_public_key: b64_encode(app_public.as_bytes()),
            sealed_secret,
        }))
    }

    /// Wraps the account key for the extension after the user confirms with the device lock.
    /// `requester` names the browser in the prompt.
    pub async fn wrap_session_key(
        &self,
        extension_public_key: &str,
        requester: &str,
    ) -> Result<SessionKeyWrap> {
        let session = self.snapshot().session;
        require(session.status == SessionStatus::Unlocked, ErrorCode::Locked)?;

        // Stay unlocked (plan 18): the extension opens through this app without a prompt, as the
        // app itself does.
        if !self.stays_unlocked() {
            let device_unlock = Arc::clone(&self.device_unlock);
            let reason = format!("unlock Octa Pass in {requester}");
            blocking(move || Ok(device_unlock.verify_user(&reason)?)).await?;
        }
        self.wrap_for_peer(extension_public_key)
    }

    /// Wraps the account key for `peer_public_key`. The caller has the user's approval.
    pub(crate) fn wrap_for_peer(&self, peer_public_key: &str) -> Result<SessionKeyWrap> {
        let extension_public: [u8; 32] = b64_decode_array(peer_public_key)?;
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let app_public = PublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(&PublicKey::from(extension_public));
        if !shared.was_contributory() {
            return Err(VaultError::unexpected("invalid extension public key"));
        }
        let key = wrap_key(shared.as_bytes(), app_public.as_bytes(), &extension_public);
        let (email, server_url, wrapped) = self.with_unlocked(|unlocked| {
            Ok((
                unlocked.key.email.clone(),
                unlocked.key.server_url.clone(),
                unlocked
                    .session
                    .enable_device_unlock(key.as_ref(), &mut OsRng)?,
            ))
        })?;
        Ok(SessionKeyWrap {
            email,
            server_url,
            ephemeral_public_key: b64_encode(app_public.as_bytes()),
            device_salt: b64_encode(&wrapped.device_salt),
            wrapped_ask: wrapped.wrapped_ask,
        })
    }
}
