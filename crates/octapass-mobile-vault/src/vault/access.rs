//! What the native apps' API (`crates/octapass-mobile`, plan 17) builds its features on: the
//! unlocked account's store and keys, and authenticated calls to its server.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use octapass_ffi::key_log::KeyCheck;
use octapass_ffi::{LocalStore, OctaPassError, Session};

use super::{Unlocked, Vault};
use crate::error::{Result, VaultError};
use crate::model::{Item, TwoStepMethod};
use crate::outbox::{ChangeKind, Outbox};

/// The unlocked account, for one call. Locking in the meantime zeroes the session's keys, so
/// what it does then fails with `Locked`.
pub struct Access<'a> {
    vault: &'a Vault,
    unlocked: Unlocked,
}

/// A sign-in waiting for its second step (`pendingTwoStep`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwoStepPending {
    Required {
        methods: Vec<TwoStepMethod>,
    },
    /// Too slow: sign in again from the start.
    Expired,
}

/// Files saved on this phone and not uploaded yet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutboxStatus {
    pub files: usize,
    pub bytes: u64,
}

impl Vault {
    /// Fails with `Locked` unless an account is unlocked.
    pub fn access(&self) -> Result<Access<'_>> {
        Ok(Access {
            vault: self,
            unlocked: self.unlocked()?,
        })
    }

    pub fn pending_two_step(&self) -> Option<TwoStepPending> {
        let state = self.state();
        let pending = state.two_step.as_ref()?;
        Some(if pending.expires_at > Instant::now() {
            TwoStepPending::Required {
                methods: TwoStepMethod::offered(&pending.login.methods()),
            }
        } else {
            TwoStepPending::Expired
        })
    }

    /// "Start over": drops a sign-in waiting for its second step.
    pub fn cancel_two_step(&self) {
        self.state().two_step = None;
    }

    /// Every item, the trash included, as stored (no files marked `pending`).
    pub fn all_items(&self) -> Result<Vec<Item>> {
        self.items()
    }

    /// Where a decrypted file named `name` goes on its way to the viewer: a new folder that
    /// `delete_opened` and locking delete.
    pub fn new_opened_path(&self, name: &str) -> Result<PathBuf> {
        let folder = self.opened_dir().join(super::attachments::random_name());
        std::fs::create_dir_all(&folder)
            .map_err(|error| VaultError::unexpected(format!("files: {error}")))?;
        Ok(folder.join(super::attachments::safe_file_name(name)))
    }
}

impl Access<'_> {
    pub fn store(&self) -> &Arc<LocalStore> {
        &self.unlocked.store
    }

    pub fn session(&self) -> &Arc<Session> {
        &self.unlocked.session
    }

    pub fn email(&self) -> &str {
        &self.unlocked.account.email
    }

    /// Checks keys a server offered against the key log (plan 03).
    pub fn check_account(&self, account: octapass_ffi::key_log::Account<'_>) -> Result<KeyCheck> {
        self.authorized(|token| {
            Ok(self
                .unlocked
                .server
                .check_account(token, &self.unlocked.store, account))
        })
    }

    /// Names the account's files and Keychain items.
    pub fn account_tag(&self) -> &str {
        &self.unlocked.account.tag
    }

    /// The server's base URL, ending in `/`.
    pub fn server_url(&self) -> String {
        self.unlocked.server.base_url()
    }

    /// The shared container, where the account's store lives.
    pub fn data_dir(&self) -> &Path {
        &self.vault.config.data_dir
    }

    /// Runs `call` with an access token, refreshed once if it expired. Calls that use the
    /// refresh token take turns, so a rotated one is never presented twice.
    pub fn authorized<T>(
        &self,
        call: impl Fn(&str) -> std::result::Result<T, OctaPassError>,
    ) -> Result<T> {
        let _io = self.vault.io();
        self.vault.with_token(&self.unlocked, call)
    }

    pub fn outbox_status(&self) -> OutboxStatus {
        let outbox = Outbox::new(&self.vault.config.data_dir, &self.unlocked.account);
        let changes = outbox.changes().unwrap_or_default();
        OutboxStatus {
            files: changes
                .iter()
                .filter(|change| change.kind == ChangeKind::Upload && !change.sent)
                .count(),
            bytes: outbox.pending_bytes(&changes),
        }
    }
}
