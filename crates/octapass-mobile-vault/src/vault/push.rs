//! Push sync (plan 04, "Push relay"): the phone hands its push token to the account's server, and
//! a push makes it sync. A push carries nothing but its kind, so there is nothing in it to read:
//! the sync that follows asks the server, signed in, as every sync does.

use std::sync::Arc;

use octapass_ffi::{HttpMethod, OctaPassError, OctaPassServer};
use serde::Serialize;

use super::Vault;
use crate::accounts::Account;
use crate::error::{ErrorCode, Result};

/// Which service delivers this phone's pushes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PushPlatform {
    /// Apple Push Notification service (iPhone, iPad).
    Apns,
    /// Firebase Cloud Messaging (Android with Google Play services).
    Fcm,
}

/// What the system gave the app to be reached by: an APNs device token in hex, or an FCM
/// registration token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushToken {
    pub platform: PushPlatform,
    pub token: String,
    /// APNs only: a development build, whose pushes go through Apple's sandbox.
    pub sandbox: bool,
}

/// In memory only: the OS gives the token again at every launch.
#[derive(Default)]
pub(crate) struct PushState {
    token: Option<PushToken>,
    /// The account (by tag) and token the server already has, so a sync doesn't send it again.
    registered: Option<(String, PushToken)>,
    /// Accounts (by tag) whose server has no push relay, until the app restarts.
    unavailable: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PushTokenBody<'a> {
    platform: PushPlatform,
    token: &'a str,
    sandbox: bool,
}

impl Vault {
    /// Remembers the token the system gave the app, or forgets it (`None`, notifications turned
    /// off), and tells the current account's server. Returns whether the server has it now. A
    /// server without a push relay, or one that can't be reached, is no error: syncs on opening
    /// and while open go on as before, and the next sync tries again.
    pub fn set_push_token(&self, token: Option<PushToken>) -> Result<bool> {
        let previous = {
            let mut push = self.push_state();
            push.unavailable.clear();
            std::mem::replace(&mut push.token, token.clone())
        };
        let Some(account) = self.remote_account() else {
            return Ok(false);
        };
        let _io = self.io();
        let server = self.server(&account.server_url)?;
        if token.is_none() && previous.is_some() {
            let removed = self.with_account_token(&account, &server, |token| {
                off_is_fine(self.http.call(HttpMethod::Delete, push_url(&server), token))
            });
            self.push_state().registered = None;
            return match removed {
                Ok(_) => Ok(false),
                Err(error) if quiet(&error.code) => Ok(false),
                Err(error) => Err(error),
            };
        }
        Ok(self.register_push(&account, &server))
    }

    /// A push arrived. Unlocked, this is a full sync. Locked, it pulls the changes as ciphertext
    /// into the store, so the AutoFill extension and the next unlock have them; what was saved
    /// here waits for the unlock to go up.
    pub fn sync_on_push(&self) -> Result<()> {
        if self.unlocked().is_ok() {
            return self.sync();
        }
        let Some(account) = self.remote_account() else {
            return Ok(());
        };
        let _io = self.io();
        let server = self.server(&account.server_url)?;
        let store = self.open_store(&account)?;
        let pulled = self.with_account_token(&account, &server, |token| {
            server.sync(token.into(), store.clone())
        });
        if let Err(error) = &pulled
            && error.code == ErrorCode::AccountDeleted
        {
            self.forget(&account)?;
        }
        pulled?;
        self.register_push(&account, &server);
        Ok(())
    }

    /// After a sync: sends the token if this account's server doesn't have it yet. Never fails
    /// the sync. The caller holds `io`.
    pub(crate) fn register_push(&self, account: &Account, server: &Arc<OctaPassServer>) -> bool {
        let token = {
            let push = self.push_state();
            let Some(token) = push.token.clone() else {
                return false;
            };
            if push.unavailable.contains(&account.tag) {
                return false;
            }
            if push.registered.as_ref() == Some(&(account.tag.clone(), token.clone())) {
                return true;
            }
            token
        };
        let body = PushTokenBody {
            platform: token.platform,
            token: &token.token,
            sandbox: token.sandbox,
        };
        let sent = self.with_account_token(account, server, |access| {
            off_is_fine(
                self.http
                    .send_json(HttpMethod::Put, push_url(server), access, &body),
            )
        });
        let mut push = self.push_state();
        match sent {
            Ok(true) => {
                push.registered = Some((account.tag.clone(), token));
                true
            }
            Ok(false) => {
                push.unavailable.push(account.tag.clone());
                false
            }
            // Offline or signed out: the next sync tries again.
            Err(_) => false,
        }
    }

    fn remote_account(&self) -> Option<Account> {
        self.state()
            .accounts
            .current()
            .filter(|account| !account.is_local())
            .cloned()
    }

    fn push_state(&self) -> std::sync::MutexGuard<'_, PushState> {
        self.push
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `with_token` for an account that may be locked: the refresh token is in the Keychain or
    /// Keystore, which needs no unlock. The caller holds `io`.
    fn with_account_token<T>(
        &self,
        account: &Account,
        server: &Arc<OctaPassServer>,
        call: impl Fn(&str) -> std::result::Result<T, OctaPassError>,
    ) -> Result<T> {
        let cached = match &self.state().access_token {
            Some((tag, token)) if *tag == account.tag => Some(token.clone()),
            _ => None,
        };
        let token = match cached {
            Some(token) => token,
            None => self.refresh_account(account, server)?,
        };
        match call(&token) {
            Err(OctaPassError::Unauthorized) => Ok(call(&self.refresh_account(account, server)?)?),
            result => Ok(result?),
        }
    }
}

fn push_url(server: &OctaPassServer) -> String {
    format!(
        "{}/v1/devices/current/push",
        server.base_url().trim_end_matches('/')
    )
}

/// `Ok(false)` for a server without a push relay: `push-off`, or `not-found` from a server too old
/// to know the route.
fn off_is_fine(
    result: std::result::Result<(), OctaPassError>,
) -> std::result::Result<bool, OctaPassError> {
    match result {
        Ok(()) => Ok(true),
        Err(OctaPassError::Server { status: 404, .. }) => Ok(false),
        Err(error) => Err(error),
    }
}

/// What leaves the token where it is without being worth an error on screen.
fn quiet(code: &ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::NotFound | ErrorCode::ServerUnreachable | ErrorCode::SessionExpired
    )
}
