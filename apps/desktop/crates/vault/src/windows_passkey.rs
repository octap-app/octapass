//! The vault behind the Windows passkey provider (`octapass-windows-passkey`), over the same calls
//! as the macOS AutoFill extension. Windows verifies the calling app or site and writes the client
//! data, so only its hash is signed ([`crate::autofill`] explains the rest).

use std::sync::Arc;
use std::time::{Duration, Instant};

use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_windows_passkey::{
    Account, Assertion, CredentialMetadata, NewPasskey, PasskeyVault, ProviderError, Registration,
};
use tokio::runtime::Handle;

use crate::autofill::PasskeyCreation;
use crate::error::{ErrorCode, VaultError};
use crate::model::SessionStatus;
use crate::vault::Vault;

/// How long a locked vault waits for the user at the lock screen. Long enough for a master
/// password; Windows' own prompt is on screen all the while and can cancel.
const UNLOCK_WAIT: Duration = Duration::from_secs(120);
const UNLOCK_POLL: Duration = Duration::from_millis(200);

/// [`PasskeyVault`] for the desktop vault. Windows calls arrive on threads of their own, outside
/// the runtime, so each call blocks one of those threads on `runtime`.
pub struct PluginVault {
    vault: Arc<Vault>,
    runtime: Handle,
    show_lock_screen: Box<dyn Fn() + Send + Sync>,
    unlock_wait: Duration,
}

impl PluginVault {
    /// `show_lock_screen` brings the vault window up for a master password.
    pub fn new(
        vault: Arc<Vault>,
        runtime: Handle,
        show_lock_screen: Box<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self::with_unlock_wait(vault, runtime, show_lock_screen, UNLOCK_WAIT)
    }

    pub fn with_unlock_wait(
        vault: Arc<Vault>,
        runtime: Handle,
        show_lock_screen: Box<dyn Fn() + Send + Sync>,
        unlock_wait: Duration,
    ) -> Self {
        Self {
            vault,
            runtime,
            show_lock_screen,
            unlock_wait,
        }
    }

    fn status(&self) -> SessionStatus {
        self.vault.snapshot().session.status
    }
}

fn failure(error: VaultError) -> ProviderError {
    match error.code {
        ErrorCode::Locked => ProviderError::Locked,
        ErrorCode::NotFound => ProviderError::NoCredentials,
        _ => match error.message.as_str() {
            "passkey_excluded" => ProviderError::Excluded,
            "passkey_unsupported_algorithm" => ProviderError::Unsupported,
            "passkey_not_found" => ProviderError::NoCredentials,
            "invalid_passkey_request" | "passkey_rp_mismatch" | "passkeyInvalidRequest" => {
                ProviderError::Malformed
            }
            _ => ProviderError::Failed,
        },
    }
}

fn decoded(text: &str) -> Result<Vec<u8>, ProviderError> {
    b64_decode(text).map_err(|_| ProviderError::Failed)
}

fn encoded_ids(ids: &[Vec<u8>]) -> Vec<String> {
    ids.iter().map(|id| b64_encode(id)).collect()
}

impl PasskeyVault for PluginVault {
    fn is_unlocked(&self) -> bool {
        self.status() == SessionStatus::Unlocked
    }

    fn unlock(&self, cancelled: &dyn Fn() -> bool) -> Result<(), ProviderError> {
        if self.status() == SessionStatus::SignedOut {
            return Err(ProviderError::Locked);
        }
        // Device unlock where it's on; everything else is the lock screen's job.
        if self
            .runtime
            .block_on(self.vault.unlock_with_device())
            .is_ok()
        {
            return Ok(());
        }
        (self.show_lock_screen)();
        let deadline = Instant::now() + self.unlock_wait;
        loop {
            if cancelled() {
                return Err(ProviderError::Cancelled);
            }
            if self.is_unlocked() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ProviderError::Locked);
            }
            std::thread::sleep(UNLOCK_POLL);
        }
    }

    fn accounts(
        &self,
        rp_id: &str,
        client_data_hash: &[u8; 32],
        allowed: &[Vec<u8>],
    ) -> Result<Vec<Account>, ProviderError> {
        let found = self
            .vault
            .autofill_passkeys(rp_id, &b64_encode(client_data_hash), &encoded_ids(allowed))
            .map_err(failure)?;
        found
            .into_iter()
            .map(|passkey| {
                Ok(Account {
                    credential_id: decoded(&passkey.credential_id)?,
                    user_id: decoded(&passkey.user_handle)?,
                    user_name: passkey.user_name,
                })
            })
            .collect()
    }

    fn assert(
        &self,
        rp_id: &str,
        client_data_hash: &[u8; 32],
        allowed: &[Vec<u8>],
        account: &Account,
    ) -> Result<Assertion, ProviderError> {
        let signed = self
            .vault
            .autofill_assertion(
                rp_id,
                &b64_encode(client_data_hash),
                &encoded_ids(allowed),
                &b64_encode(&account.credential_id),
            )
            .map_err(failure)?;
        Ok(Assertion {
            credential_id: decoded(&signed.credential_id)?,
            authenticator_data: decoded(&signed.authenticator_data)?,
            signature: decoded(&signed.signature)?,
            user_id: decoded(&signed.user_handle)?,
            user_name: account.user_name.clone(),
        })
    }

    fn register(&self, passkey: NewPasskey) -> Result<Registration, ProviderError> {
        let created = self
            .runtime
            .block_on(self.vault.autofill_register(PasskeyCreation {
                rp_id: passkey.rp_id,
                user_name: passkey.user_name,
                user_handle: b64_encode(&passkey.user_id),
                algorithms: passkey.algorithms,
                excluded: encoded_ids(&passkey.excluded),
                client_data_hash: b64_encode(&passkey.client_data_hash),
            }))
            .map_err(failure)?;
        Ok(Registration {
            credential_id: decoded(&created.credential_id)?,
            attestation_object: decoded(&created.attestation_object)?,
        })
    }
}

/// What Windows should list for the signed-in account. Names and ids, never a key. Fails while
/// the vault is locked: Windows keeps the list it has.
pub fn credential_metadata(vault: &Vault) -> crate::error::Result<Vec<CredentialMetadata>> {
    Ok(vault
        .autofill_identities()?
        .passkeys
        .into_iter()
        .filter_map(|passkey| {
            Some(CredentialMetadata {
                credential_id: b64_decode(&passkey.credential_id).ok()?,
                user_id: b64_decode(&passkey.user_handle).ok()?,
                rp_id: passkey.rp_id,
                user_name: passkey.user_name,
            })
        })
        .collect())
}
