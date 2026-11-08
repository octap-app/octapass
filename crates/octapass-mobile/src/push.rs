//! Push sync on the phones (plan 04, "Push relay"). The app hands over the token the system gave
//! it; a push, which carries only its kind, makes the vault sync. Nothing in a push is read.

use std::sync::Arc;

use octapass_mobile_vault::vault::{PushPlatform as Platform, PushToken};

use crate::error::Result;
use crate::vault::OctaPassVault;

/// Which service delivers this phone's pushes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PushPlatform {
    /// Apple Push Notification service: the device token as lowercase hex.
    Apns,
    /// Firebase Cloud Messaging: the registration token.
    Fcm,
}

#[uniffi::export]
impl OctaPassVault {
    /// Call at every launch with the token the system gave the app, and again when it changes.
    /// It's sent to the signed-in account's server when that server has a push relay, now or
    /// after the next sync (sign-in and unlock included). Returns whether the server has it.
    /// `sandbox` is for development iPhone builds (Apple's sandbox); always false on Android.
    pub async fn set_push_token(
        self: Arc<Self>,
        platform: PushPlatform,
        token: String,
        sandbox: bool,
    ) -> Result<bool> {
        self.run(move |this| {
            let platform = match platform {
                PushPlatform::Apns => Platform::Apns,
                PushPlatform::Fcm => Platform::Fcm,
            };
            Ok(this.vault.set_push_token(Some(PushToken {
                platform,
                token,
                sandbox,
            }))?)
        })
        .await
    }

    /// The app can't be reached any more (notifications turned off, the token revoked): tells
    /// the server to stop sending.
    pub async fn clear_push_token(self: Arc<Self>) -> Result<()> {
        self.run(|this| {
            this.vault.set_push_token(None)?;
            Ok(())
        })
        .await
    }

    /// A push arrived (or a background refresh ran). Unlocked, a full sync as `sync` does.
    /// Locked, the changes come down as ciphertext into the store, so AutoFill and the next unlock
    /// have them; nothing is decrypted. Signed out or a local vault: nothing happens.
    pub async fn sync_on_push(self: Arc<Self>) -> Result<()> {
        self.run(|this| {
            if this.is_unlocked() {
                this.sync_now()
            } else {
                Ok(this.vault.sync_on_push()?)
            }
        })
        .await
    }
}
