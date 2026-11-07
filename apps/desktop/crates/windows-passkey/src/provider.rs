//! What every operation goes through, in order. Nothing here is specific to Windows' types, so the
//! whole path is tested with fakes.
//!
//! 1. The request type and the **request signature**: Windows signs the SHA-256 of each request
//!    with a key only it holds. Anything else on the machine can call a COM server, so nothing
//!    is read from a request before this passes.
//! 2. The CTAP2 message is decoded.
//! 3. A locked vault asks to be unlocked.
//! 4. For a sign-in, the user picks an account if several match.
//! 5. **User verification**: Windows Hello, every time (plan 03's autofill gate), whatever the
//!    request's `up` and `uv` options say. Hello's own signature over the request hash is checked
//!    against the key Windows reports, so a call that returned without a prompt signs nothing.
//! 6. Only then does the vault sign or create a passkey.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::ctap;
use crate::signature::{PublicKey, request_hash};

/// `WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR` in `pluginauthenticator.idl`, the only type there is.
pub const REQUEST_TYPE_CTAP2_CBOR: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    #[error("the request's signature isn't from Windows")]
    Forged,
    #[error("the request is malformed")]
    Malformed,
    #[error("the request asks for something Octa Pass doesn't do")]
    Unsupported,
    #[error("another operation is running")]
    Busy,
    #[error("cancelled")]
    Cancelled,
    #[error("no matching passkey")]
    NoCredentials,
    #[error("the site already has a passkey from this account")]
    Excluded,
    #[error("the vault is locked")]
    Locked,
    #[error("user verification failed")]
    UserVerification,
    #[error("the operation failed")]
    Failed,
}

impl ProviderError {
    /// What the COM method returns. `NTE_USER_CANCELLED`, `NTE_NOT_FOUND` and `NTE_EXISTS` are
    /// what Windows tells apart (Microsoft's PasskeyManager sample; `webauthn.h` maps
    /// `NTE_NOT_FOUND` to "no credentials").
    pub fn hresult(self) -> i32 {
        (match self {
            Self::Forged => 0x8009_0006_u32,    // NTE_BAD_SIGNATURE
            Self::Malformed => 0x8009_0027,     // NTE_INVALID_PARAMETER
            Self::Unsupported => 0x8009_0029,   // NTE_NOT_SUPPORTED
            Self::Busy => 0x8007_00aa,          // HRESULT_FROM_WIN32(ERROR_BUSY)
            Self::Cancelled => 0x8009_0036,     // NTE_USER_CANCELLED
            Self::NoCredentials => 0x8009_0011, // NTE_NOT_FOUND
            Self::Excluded => 0x8009_000f,      // NTE_EXISTS
            Self::Locked | Self::UserVerification => 0x8007_0005, // E_ACCESSDENIED
            Self::Failed => 0x8000_4005,        // E_FAIL
        }) as i32
    }
}

/// `WEBAUTHN_PLUGIN_OPERATION_REQUEST`.
#[derive(Debug, Clone, Copy)]
pub struct Operation<'a> {
    /// The caller's top-level window (`HWND`), to parent prompts.
    pub window: isize,
    pub transaction: [u8; 16],
    pub signature: &'a [u8],
    pub request_type: u32,
    pub encoded: &'a [u8],
}

/// `WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST`.
#[derive(Debug, Clone, Copy)]
pub struct Cancel<'a> {
    pub transaction: [u8; 16],
    pub signature: &'a [u8],
}

/// `PLUGIN_LOCK_STATUS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockStatus {
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Create,
    SignIn,
}

/// What Windows Hello is asked to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPrompt {
    pub window: isize,
    pub transaction: [u8; 16],
    pub user_name: String,
    pub rp_id: String,
    pub purpose: Purpose,
}

/// A saved passkey the user can pick. No key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub credential_id: Vec<u8>,
    pub user_id: Vec<u8>,
    pub user_name: String,
}

/// A new passkey the vault is asked for, in `ctap`'s terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPasskey {
    pub rp_id: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub algorithms: Vec<i64>,
    pub excluded: Vec<Vec<u8>>,
    pub client_data_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_id: Vec<u8>,
    pub user_name: String,
}

/// A saved passkey as Windows lists it next to its own. Site and user names, no key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialMetadata {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
}

/// What Windows offers: its keys, Windows Hello and a dialog.
pub trait Host: Send + Sync {
    /// `WebAuthNPluginGetOperationSigningPublicKey`: a CNG key blob.
    fn operation_signing_key(&self) -> Result<Vec<u8>, ProviderError>;
    /// `WebAuthNPluginGetUserVerificationPublicKey`: a CNG key blob.
    fn user_verification_key(&self) -> Result<Vec<u8>, ProviderError>;
    /// `WebAuthNPluginPerformUserVerification`: Windows Hello, then its signature over the hash
    /// of the operation's request. `Cancelled` when the user dismissed it.
    fn verify_user(&self, prompt: &UserPrompt) -> Result<Vec<u8>, ProviderError>;
    /// Which of several accounts to use. `Cancelled` when the user dismissed it.
    fn choose_account(
        &self,
        window: isize,
        rp_id: &str,
        accounts: &[Account],
    ) -> Result<usize, ProviderError>;
}

/// What the desktop vault offers. Credential ids and handles are raw bytes here.
pub trait PasskeyVault: Send + Sync {
    fn is_unlocked(&self) -> bool;
    /// The app's usual unlock. Returns once unlocked; `Locked` if it doesn't happen, `Cancelled`
    /// as soon as `cancelled` says so.
    fn unlock(&self, cancelled: &dyn Fn() -> bool) -> Result<(), ProviderError>;
    fn accounts(
        &self,
        rp_id: &str,
        client_data_hash: &[u8; 32],
        allowed: &[Vec<u8>],
    ) -> Result<Vec<Account>, ProviderError>;
    fn assert(
        &self,
        rp_id: &str,
        client_data_hash: &[u8; 32],
        allowed: &[Vec<u8>],
        account: &Account,
    ) -> Result<Assertion, ProviderError>;
    fn register(&self, passkey: NewPasskey) -> Result<Registration, ProviderError>;
}

/// The COM server keeps one provider for the life of the app, with the vault behind this.
impl PasskeyVault for Box<dyn PasskeyVault> {
    fn is_unlocked(&self) -> bool {
        self.as_ref().is_unlocked()
    }
    fn unlock(&self, cancelled: &dyn Fn() -> bool) -> Result<(), ProviderError> {
        self.as_ref().unlock(cancelled)
    }
    fn accounts(
        &self,
        rp_id: &str,
        client_data_hash: &[u8; 32],
        allowed: &[Vec<u8>],
    ) -> Result<Vec<Account>, ProviderError> {
        self.as_ref().accounts(rp_id, client_data_hash, allowed)
    }
    fn assert(
        &self,
        rp_id: &str,
        client_data_hash: &[u8; 32],
        allowed: &[Vec<u8>],
        account: &Account,
    ) -> Result<Assertion, ProviderError> {
        self.as_ref()
            .assert(rp_id, client_data_hash, allowed, account)
    }
    fn register(&self, passkey: NewPasskey) -> Result<Registration, ProviderError> {
        self.as_ref().register(passkey)
    }
}

struct InFlight {
    transaction: [u8; 16],
    hash: [u8; 32],
    cancelled: Arc<AtomicBool>,
}

/// Marks the one operation in progress; dropping it clears the mark, on every path out.
struct Running<'a> {
    slot: &'a Mutex<Option<InFlight>>,
    hash: [u8; 32],
    cancelled: Arc<AtomicBool>,
}

impl Running<'_> {
    fn check(&self) -> Result<(), ProviderError> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(ProviderError::Cancelled)
        } else {
            Ok(())
        }
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        *self.slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

pub struct Provider<H, V> {
    host: H,
    vault: V,
    in_flight: Mutex<Option<InFlight>>,
}

impl<H: Host, V: PasskeyVault> Provider<H, V> {
    pub fn new(host: H, vault: V) -> Self {
        Self {
            host,
            vault,
            in_flight: Mutex::new(None),
        }
    }

    /// The two sides, for tests that change what a fake does mid-way.
    pub fn host_for_tests(&self) -> &H {
        &self.host
    }

    pub fn vault_for_tests(&self) -> &V {
        &self.vault
    }

    pub fn lock_status(&self) -> LockStatus {
        if self.vault.is_unlocked() {
            LockStatus::Unlocked
        } else {
            LockStatus::Locked
        }
    }

    pub fn make_credential(&self, operation: &Operation) -> Result<Registration, ProviderError> {
        let running = self.begin(operation)?;
        let request = ctap::decode_make_credential(operation.encoded)
            .map_err(|_| ProviderError::Malformed)?;
        if request.algorithms.is_empty() {
            return Err(ProviderError::Unsupported);
        }
        self.require_unlocked(&running)?;
        self.verify_user(
            &running,
            operation,
            request.account_name(),
            &request.rp_id,
            Purpose::Create,
        )?;
        running.check()?;
        let user_name = request.account_name().to_owned();
        self.vault.register(NewPasskey {
            rp_id: request.rp_id,
            user_id: request.user_id,
            user_name,
            algorithms: request.algorithms,
            excluded: request.exclude_list,
            client_data_hash: request.client_data_hash,
        })
    }

    pub fn get_assertion(&self, operation: &Operation) -> Result<Assertion, ProviderError> {
        let running = self.begin(operation)?;
        let request =
            ctap::decode_get_assertion(operation.encoded).map_err(|_| ProviderError::Malformed)?;
        self.require_unlocked(&running)?;
        let accounts = self.vault.accounts(
            &request.rp_id,
            &request.client_data_hash,
            &request.allow_list,
        )?;
        let account = match accounts.as_slice() {
            [] => return Err(ProviderError::NoCredentials),
            [only] => only,
            several => {
                let chosen = self
                    .host
                    .choose_account(operation.window, &request.rp_id, several)?;
                several.get(chosen).ok_or(ProviderError::Failed)?
            }
        };
        running.check()?;
        self.verify_user(
            &running,
            operation,
            &account.user_name,
            &request.rp_id,
            Purpose::SignIn,
        )?;
        running.check()?;
        self.vault.assert(
            &request.rp_id,
            &request.client_data_hash,
            &request.allow_list,
            account,
        )
    }

    /// Windows' cancel carries the signature of the request it cancels, so only the transaction
    /// running now, and only Windows, can stop it.
    pub fn cancel(&self, cancel: &Cancel) -> Result<(), ProviderError> {
        let (hash, cancelled) = {
            let slot = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
            match slot.as_ref() {
                Some(running) if running.transaction == cancel.transaction => {
                    (running.hash, Arc::clone(&running.cancelled))
                }
                _ => return Err(ProviderError::NoCredentials),
            }
        };
        self.check_signature(&hash, cancel.signature)?;
        cancelled.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn check_signature(&self, hash: &[u8; 32], signature: &[u8]) -> Result<(), ProviderError> {
        let key = self.host.operation_signing_key()?;
        let key = PublicKey::from_blob(&key).map_err(|_| ProviderError::Forged)?;
        key.verify_hash(hash, signature)
            .map_err(|_| ProviderError::Forged)
    }

    fn begin(&self, operation: &Operation) -> Result<Running<'_>, ProviderError> {
        if operation.request_type != REQUEST_TYPE_CTAP2_CBOR {
            return Err(ProviderError::Unsupported);
        }
        let hash = request_hash(operation.encoded);
        self.check_signature(&hash, operation.signature)?;

        let mut slot = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return Err(ProviderError::Busy);
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        *slot = Some(InFlight {
            transaction: operation.transaction,
            hash,
            cancelled: Arc::clone(&cancelled),
        });
        Ok(Running {
            slot: &self.in_flight,
            hash,
            cancelled,
        })
    }

    fn require_unlocked(&self, running: &Running) -> Result<(), ProviderError> {
        running.check()?;
        if !self.vault.is_unlocked() {
            let cancelled = || running.cancelled.load(Ordering::SeqCst);
            self.vault.unlock(&cancelled)?;
            if !self.vault.is_unlocked() {
                return Err(ProviderError::Locked);
            }
        }
        running.check()
    }

    fn verify_user(
        &self,
        running: &Running,
        operation: &Operation,
        user_name: &str,
        rp_id: &str,
        purpose: Purpose,
    ) -> Result<(), ProviderError> {
        // Fetched first, as Microsoft's sample does: a failure here must not reach the prompt.
        let key = self.host.user_verification_key()?;
        let key = PublicKey::from_blob(&key).map_err(|_| ProviderError::UserVerification)?;
        let signature = self.host.verify_user(&UserPrompt {
            window: operation.window,
            transaction: operation.transaction,
            user_name: user_name.to_owned(),
            rp_id: rp_id.to_owned(),
            purpose,
        })?;
        key.verify_hash(&running.hash, &signature)
            .map_err(|_| ProviderError::UserVerification)
    }
}
