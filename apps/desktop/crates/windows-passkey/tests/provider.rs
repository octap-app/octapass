//! Every path through an operation, with a fake Windows that signs like the real one and a fake
//! vault that records what it was asked for.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use octapass_windows_passkey::provider::{Cancel, REQUEST_TYPE_CTAP2_CBOR};
use octapass_windows_passkey::signature::request_hash;
use octapass_windows_passkey::{
    Account, Assertion, Host, LockStatus, NewPasskey, Operation, PasskeyVault, Provider,
    ProviderError, Purpose, Registration, UserPrompt,
};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};

type Hook = Box<dyn Fn() + Send + Sync>;

struct Keys {
    operation: SigningKey,
    user: SigningKey,
}

impl Keys {
    fn new() -> Self {
        Self {
            operation: SigningKey::from_slice(&[1; 32]).unwrap(),
            user: SigningKey::from_slice(&[2; 32]).unwrap(),
        }
    }
}

fn blob(key: &SigningKey) -> Vec<u8> {
    let point = key.verifying_key().to_encoded_point(false);
    let mut out = 0x3153_4345u32.to_le_bytes().to_vec(); // ECS1
    out.extend_from_slice(&32u32.to_le_bytes());
    out.extend_from_slice(&point.as_bytes()[1..]);
    out
}

fn sign(key: &SigningKey, hash: &[u8; 32]) -> Vec<u8> {
    let signature: Signature = key.sign_prehash(hash).unwrap();
    signature.to_bytes().to_vec()
}

#[derive(Default)]
struct Log {
    prompts: Mutex<Vec<UserPrompt>>,
    chooser: AtomicUsize,
    unlocks: AtomicUsize,
    /// Calls that used a key.
    signed: AtomicUsize,
    registered: Mutex<Vec<NewPasskey>>,
    account_lookups: AtomicUsize,
}

struct FakeHost {
    keys: Arc<Keys>,
    log: Arc<Log>,
    /// What Hello signs; the request's hash, unless a test swaps it.
    signs: Arc<Mutex<[u8; 32]>>,
    verify_result: Arc<Mutex<Option<ProviderError>>>,
    /// `Some`: the wrong key signs Hello's answer.
    wrong_uv_key: AtomicBool,
    on_prompt: Mutex<Option<Hook>>,
    chosen: Mutex<Result<usize, ProviderError>>,
}

impl Host for FakeHost {
    fn operation_signing_key(&self) -> Result<Vec<u8>, ProviderError> {
        Ok(blob(&self.keys.operation))
    }
    fn user_verification_key(&self) -> Result<Vec<u8>, ProviderError> {
        Ok(blob(&self.keys.user))
    }
    fn verify_user(&self, prompt: &UserPrompt) -> Result<Vec<u8>, ProviderError> {
        self.log.prompts.lock().unwrap().push(prompt.clone());
        if let Some(hook) = self.on_prompt.lock().unwrap().as_ref() {
            hook();
        }
        if let Some(error) = *self.verify_result.lock().unwrap() {
            return Err(error);
        }
        let key = if self.wrong_uv_key.load(Ordering::SeqCst) {
            &self.keys.operation
        } else {
            &self.keys.user
        };
        Ok(sign(key, &self.signs.lock().unwrap()))
    }
    fn choose_account(
        &self,
        _window: isize,
        _rp_id: &str,
        _accounts: &[Account],
    ) -> Result<usize, ProviderError> {
        self.log.chooser.fetch_add(1, Ordering::SeqCst);
        *self.chosen.lock().unwrap()
    }
}

struct FakeVault {
    log: Arc<Log>,
    unlocked: AtomicBool,
    unlock_works: AtomicBool,
    accounts: Vec<Account>,
    register_result: Mutex<Result<(), ProviderError>>,
}

impl PasskeyVault for FakeVault {
    fn is_unlocked(&self) -> bool {
        self.unlocked.load(Ordering::SeqCst)
    }
    fn unlock(&self, _cancelled: &dyn Fn() -> bool) -> Result<(), ProviderError> {
        self.log.unlocks.fetch_add(1, Ordering::SeqCst);
        if self.unlock_works.load(Ordering::SeqCst) {
            self.unlocked.store(true, Ordering::SeqCst);
            Ok(())
        } else {
            Err(ProviderError::Locked)
        }
    }
    fn accounts(
        &self,
        _rp_id: &str,
        _hash: &[u8; 32],
        _allowed: &[Vec<u8>],
    ) -> Result<Vec<Account>, ProviderError> {
        self.log.account_lookups.fetch_add(1, Ordering::SeqCst);
        Ok(self.accounts.clone())
    }
    fn assert(
        &self,
        _rp_id: &str,
        _hash: &[u8; 32],
        _allowed: &[Vec<u8>],
        account: &Account,
    ) -> Result<Assertion, ProviderError> {
        self.log.signed.fetch_add(1, Ordering::SeqCst);
        Ok(Assertion {
            credential_id: account.credential_id.clone(),
            authenticator_data: vec![1],
            signature: vec![2],
            user_id: account.user_id.clone(),
            user_name: account.user_name.clone(),
        })
    }
    fn register(&self, passkey: NewPasskey) -> Result<Registration, ProviderError> {
        self.log.signed.fetch_add(1, Ordering::SeqCst);
        self.log.registered.lock().unwrap().push(passkey);
        (*self.register_result.lock().unwrap())?;
        Ok(Registration {
            credential_id: vec![9],
            attestation_object: vec![8],
        })
    }
}

fn account(id: u8, name: &str) -> Account {
    Account {
        credential_id: vec![id],
        user_id: vec![id, id],
        user_name: name.into(),
    }
}

/// `{ 1: "a.example", 2: hash, 5: { "up": false } }`
fn get_assertion_request() -> Vec<u8> {
    let mut bytes = vec![0xa3, 0x01, 0x69];
    bytes.extend_from_slice(b"a.example");
    bytes.extend_from_slice(&[0x02, 0x58, 0x20]);
    bytes.extend_from_slice(&[7; 32]);
    bytes.extend_from_slice(&[0x05, 0xa1, 0x62, b'u', b'p', 0xf4]);
    bytes
}

/// `{ 1: hash, 2: { id }, 3: { id, name }, 4: [ES256], 5: [excluded] }`
fn make_credential_request() -> Vec<u8> {
    let public_key = b"\x64type\x6apublic-key";
    let mut bytes = vec![0xa5, 0x01, 0x58, 0x20];
    bytes.extend_from_slice(&[7; 32]);
    bytes.extend_from_slice(&[0x02, 0xa1, 0x62, b'i', b'd', 0x69]);
    bytes.extend_from_slice(b"a.example");
    bytes.extend_from_slice(&[0x03, 0xa2, 0x62, b'i', b'd', 0x41, 5]);
    bytes.extend_from_slice(b"\x64name\x63ada");
    bytes.extend_from_slice(&[0x04, 0x81, 0xa2, 0x63, b'a', b'l', b'g', 0x26]);
    bytes.extend_from_slice(public_key);
    bytes.extend_from_slice(&[0x05, 0x81, 0xa2, 0x62, b'i', b'd', 0x41, 0xee]);
    bytes.extend_from_slice(public_key);
    bytes
}

const TRANSACTION: [u8; 16] = [3; 16];

struct Rig {
    keys: Arc<Keys>,
    log: Arc<Log>,
    signs: Arc<Mutex<[u8; 32]>>,
    provider: Arc<Provider<FakeHost, FakeVault>>,
    verify_result: Arc<Mutex<Option<ProviderError>>>,
}

fn rig(accounts: Vec<Account>, unlocked: bool, encoded: &[u8]) -> Rig {
    let keys = Arc::new(Keys::new());
    let log = Arc::new(Log::default());
    let signs = Arc::new(Mutex::new(request_hash(encoded)));
    let verify_result = Arc::new(Mutex::new(None));
    let host = FakeHost {
        keys: Arc::clone(&keys),
        log: Arc::clone(&log),
        signs: Arc::clone(&signs),
        verify_result: Arc::clone(&verify_result),
        wrong_uv_key: AtomicBool::new(false),
        on_prompt: Mutex::new(None),
        chosen: Mutex::new(Ok(1)),
    };
    let vault = FakeVault {
        log: Arc::clone(&log),
        unlocked: AtomicBool::new(unlocked),
        unlock_works: AtomicBool::new(true),
        accounts,
        register_result: Mutex::new(Ok(())),
    };
    Rig {
        keys,
        log,
        signs,
        provider: Arc::new(Provider::new(host, vault)),
        verify_result,
    }
}

fn operation<'a>(encoded: &'a [u8], signature: &'a [u8]) -> Operation<'a> {
    Operation {
        window: 42,
        transaction: TRANSACTION,
        signature,
        request_type: REQUEST_TYPE_CTAP2_CBOR,
        encoded,
    }
}

fn signed(rig: &Rig, encoded: &[u8]) -> Vec<u8> {
    sign(&rig.keys.operation, &request_hash(encoded))
}

#[test]
fn signs_in_after_windows_hello() {
    let encoded = get_assertion_request();
    let rig = rig(vec![account(1, "ada")], true, &encoded);
    let signature = signed(&rig, &encoded);

    let assertion = rig
        .provider
        .get_assertion(&operation(&encoded, &signature))
        .unwrap();

    assert_eq!(assertion.credential_id, vec![1]);
    assert_eq!(assertion.user_name, "ada");
    assert_eq!(
        *rig.log.prompts.lock().unwrap(),
        [UserPrompt {
            window: 42,
            transaction: TRANSACTION,
            user_name: "ada".into(),
            rp_id: "a.example".into(),
            purpose: Purpose::SignIn,
        }]
    );
    assert_eq!(
        rig.log.chooser.load(Ordering::SeqCst),
        0,
        "only one account"
    );
}

#[test]
fn up_false_still_asks_for_windows_hello() {
    // The request vector says `up: false`; asking for nothing is never an option.
    let encoded = get_assertion_request();
    let rig = rig(vec![account(1, "ada")], true, &encoded);
    let signature = signed(&rig, &encoded);
    rig.provider
        .get_assertion(&operation(&encoded, &signature))
        .unwrap();
    assert_eq!(rig.log.prompts.lock().unwrap().len(), 1);
}

#[test]
fn creates_a_passkey_after_windows_hello() {
    let encoded = make_credential_request();
    let rig = rig(vec![], true, &encoded);
    let signature = signed(&rig, &encoded);

    let registration = rig
        .provider
        .make_credential(&operation(&encoded, &signature))
        .unwrap();

    assert_eq!(registration.attestation_object, vec![8]);
    let prompts = rig.log.prompts.lock().unwrap();
    assert_eq!(prompts[0].purpose, Purpose::Create);
    assert_eq!(prompts[0].user_name, "ada");
    assert_eq!(
        *rig.log.registered.lock().unwrap(),
        [NewPasskey {
            rp_id: "a.example".into(),
            user_id: vec![5],
            user_name: "ada".into(),
            algorithms: vec![-7],
            excluded: vec![vec![0xee]],
            client_data_hash: [7; 32],
        }]
    );
}

#[test]
fn a_request_without_windows_signature_touches_nothing() {
    let encoded = get_assertion_request();
    let rig = rig(vec![account(1, "ada")], false, &encoded);
    let other = get_assertion_request()[1..].to_vec();
    for signature in [
        vec![],
        vec![0; 64],
        // Another key, and the right key over other bytes.
        sign(&rig.keys.user, &request_hash(&encoded)),
        signed(&rig, &other),
    ] {
        assert_eq!(
            rig.provider
                .get_assertion(&operation(&encoded, &signature))
                .unwrap_err(),
            ProviderError::Forged
        );
        assert_eq!(
            rig.provider
                .make_credential(&operation(&encoded, &signature))
                .unwrap_err(),
            ProviderError::Forged
        );
    }
    assert_eq!(rig.log.unlocks.load(Ordering::SeqCst), 0);
    assert_eq!(rig.log.account_lookups.load(Ordering::SeqCst), 0);
    assert!(rig.log.prompts.lock().unwrap().is_empty());
    assert_eq!(rig.log.signed.load(Ordering::SeqCst), 0);
}

#[test]
fn only_ctap2_cbor_requests_are_accepted() {
    let encoded = get_assertion_request();
    let rig = rig(vec![account(1, "ada")], true, &encoded);
    let signature = signed(&rig, &encoded);
    let mut request = operation(&encoded, &signature);
    request.request_type = 2;
    assert_eq!(
        rig.provider.get_assertion(&request).unwrap_err(),
        ProviderError::Unsupported
    );
}

#[test]
fn a_signed_but_malformed_request_is_refused() {
    let encoded = vec![0xa0];
    let rig = rig(vec![account(1, "ada")], true, &encoded);
    let signature = signed(&rig, &encoded);
    assert_eq!(
        rig.provider
            .get_assertion(&operation(&encoded, &signature))
            .unwrap_err(),
        ProviderError::Malformed
    );
}

#[test]
fn a_failed_or_cancelled_prompt_signs_nothing() {
    for error in [ProviderError::UserVerification, ProviderError::Cancelled] {
        let encoded = get_assertion_request();
        let rig = rig(vec![account(1, "ada")], true, &encoded);
        *rig.verify_result.lock().unwrap() = Some(error);
        let signature = signed(&rig, &encoded);
        assert_eq!(
            rig.provider
                .get_assertion(&operation(&encoded, &signature))
                .unwrap_err(),
            error
        );
        assert_eq!(rig.log.signed.load(Ordering::SeqCst), 0);

        let encoded = make_credential_request();
        *rig.signs.lock().unwrap() = request_hash(&encoded);
        let signature = signed(&rig, &encoded);
        assert_eq!(
            rig.provider
                .make_credential(&operation(&encoded, &signature))
                .unwrap_err(),
            error
        );
        assert_eq!(rig.log.signed.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn hello_must_sign_this_request_with_its_key() {
    let encoded = get_assertion_request();
    let rig = rig(vec![account(1, "ada")], true, &encoded);
    let signature = signed(&rig, &encoded);

    // A prompt that "succeeded" for some other request.
    *rig.signs.lock().unwrap() = [0; 32];
    assert_eq!(
        rig.provider
            .get_assertion(&operation(&encoded, &signature))
            .unwrap_err(),
        ProviderError::UserVerification
    );
    assert_eq!(rig.log.signed.load(Ordering::SeqCst), 0);
}

#[test]
fn hello_signed_by_another_key_signs_nothing() {
    let encoded = get_assertion_request();
    let keys = Arc::new(Keys::new());
    let log = Arc::new(Log::default());
    let provider = Provider::new(
        FakeHost {
            keys: Arc::clone(&keys),
            log: Arc::clone(&log),
            signs: Arc::new(Mutex::new(request_hash(&encoded))),
            verify_result: Arc::new(Mutex::new(None)),
            wrong_uv_key: AtomicBool::new(true),
            on_prompt: Mutex::new(None),
            chosen: Mutex::new(Ok(0)),
        },
        FakeVault {
            log: Arc::clone(&log),
            unlocked: AtomicBool::new(true),
            unlock_works: AtomicBool::new(true),
            accounts: vec![account(1, "ada")],
            register_result: Mutex::new(Ok(())),
        },
    );
    let signature = sign(&keys.operation, &request_hash(&encoded));
    assert_eq!(
        provider
            .get_assertion(&operation(&encoded, &signature))
            .unwrap_err(),
        ProviderError::UserVerification
    );
    assert_eq!(log.signed.load(Ordering::SeqCst), 0);
}

#[test]
fn a_locked_vault_unlocks_first_and_still_asks_for_hello() {
    let encoded = get_assertion_request();
    let rig = rig(vec![account(1, "ada")], false, &encoded);
    let signature = signed(&rig, &encoded);
    assert_eq!(rig.provider.lock_status(), LockStatus::Locked);

    rig.provider
        .get_assertion(&operation(&encoded, &signature))
        .unwrap();

    assert_eq!(rig.log.unlocks.load(Ordering::SeqCst), 1);
    assert_eq!(rig.log.prompts.lock().unwrap().len(), 1);
    assert_eq!(rig.provider.lock_status(), LockStatus::Unlocked);
}

#[test]
fn a_vault_that_stays_locked_refuses() {
    let encoded = get_assertion_request();
    let keys = Arc::new(Keys::new());
    let log = Arc::new(Log::default());
    let provider = Provider::new(
        FakeHost {
            keys: Arc::clone(&keys),
            log: Arc::clone(&log),
            signs: Arc::new(Mutex::new(request_hash(&encoded))),
            verify_result: Arc::new(Mutex::new(None)),
            wrong_uv_key: AtomicBool::new(false),
            on_prompt: Mutex::new(None),
            chosen: Mutex::new(Ok(0)),
        },
        FakeVault {
            log: Arc::clone(&log),
            unlocked: AtomicBool::new(false),
            unlock_works: AtomicBool::new(false),
            accounts: vec![account(1, "ada")],
            register_result: Mutex::new(Ok(())),
        },
    );
    let signature = sign(&keys.operation, &request_hash(&encoded));
    assert_eq!(
        provider
            .get_assertion(&operation(&encoded, &signature))
            .unwrap_err(),
        ProviderError::Locked
    );
    assert!(log.prompts.lock().unwrap().is_empty());
    assert_eq!(log.account_lookups.load(Ordering::SeqCst), 0);
}

#[test]
fn no_passkey_for_the_site_asks_for_nothing() {
    let encoded = get_assertion_request();
    let rig = rig(vec![], true, &encoded);
    let signature = signed(&rig, &encoded);
    assert_eq!(
        rig.provider
            .get_assertion(&operation(&encoded, &signature))
            .unwrap_err(),
        ProviderError::NoCredentials
    );
    assert!(rig.log.prompts.lock().unwrap().is_empty());
}

#[test]
fn several_accounts_are_chosen_from() {
    let encoded = get_assertion_request();
    let rig = rig(vec![account(1, "ada"), account(2, "grace")], true, &encoded);
    let signature = signed(&rig, &encoded);
    let assertion = rig
        .provider
        .get_assertion(&operation(&encoded, &signature))
        .unwrap();
    assert_eq!(assertion.user_name, "grace");
    assert_eq!(rig.log.chooser.load(Ordering::SeqCst), 1);
    assert_eq!(rig.log.prompts.lock().unwrap()[0].user_name, "grace");
}

#[test]
fn a_refused_exclude_list_is_reported() {
    let encoded = make_credential_request();
    let rig = rig(vec![], true, &encoded);
    *rig.provider_vault_register() = Err(ProviderError::Excluded);
    let signature = signed(&rig, &encoded);
    assert_eq!(
        rig.provider
            .make_credential(&operation(&encoded, &signature))
            .unwrap_err(),
        ProviderError::Excluded
    );
}

impl Rig {
    fn provider_vault_register(&self) -> std::sync::MutexGuard<'_, Result<(), ProviderError>> {
        self.provider
            .vault_for_tests()
            .register_result
            .lock()
            .unwrap()
    }
}

#[test]
fn windows_can_cancel_the_running_operation_only() {
    let encoded = get_assertion_request();
    let rig = rig(vec![account(1, "ada")], true, &encoded);
    let signature = signed(&rig, &encoded);

    assert_eq!(
        rig.provider
            .cancel(&Cancel {
                transaction: TRANSACTION,
                signature: &signature,
            })
            .unwrap_err(),
        ProviderError::NoCredentials,
        "nothing is running"
    );

    // While Hello is up: a forged cancel and another transaction's change nothing; Windows' own
    // cancel stops the operation before it signs.
    let provider = Arc::clone(&rig.provider);
    let keys = Arc::clone(&rig.keys);
    let hash = request_hash(&encoded);
    let hook: Hook = Box::new(move || {
        let forged = sign(&keys.user, &hash);
        assert_eq!(
            provider
                .cancel(&Cancel {
                    transaction: TRANSACTION,
                    signature: &forged,
                })
                .unwrap_err(),
            ProviderError::Forged
        );
        let real = sign(&keys.operation, &hash);
        assert_eq!(
            provider
                .cancel(&Cancel {
                    transaction: [9; 16],
                    signature: &real,
                })
                .unwrap_err(),
            ProviderError::NoCredentials
        );
        provider
            .cancel(&Cancel {
                transaction: TRANSACTION,
                signature: &real,
            })
            .unwrap();
    });
    *rig.provider.host_for_tests().on_prompt.lock().unwrap() = Some(hook);

    assert_eq!(
        rig.provider
            .get_assertion(&operation(&encoded, &signature))
            .unwrap_err(),
        ProviderError::Cancelled
    );
    assert_eq!(rig.log.signed.load(Ordering::SeqCst), 0);
}

#[test]
fn one_operation_at_a_time_and_the_next_one_works() {
    let encoded = get_assertion_request();
    let rig = rig(vec![account(1, "ada")], true, &encoded);
    let signature = signed(&rig, &encoded);

    let provider = Arc::clone(&rig.provider);
    let inner_encoded = encoded.clone();
    let inner_signature = signature.clone();
    let hook: Hook = Box::new(move || {
        assert_eq!(
            provider
                .get_assertion(&operation(&inner_encoded, &inner_signature))
                .unwrap_err(),
            ProviderError::Busy
        );
    });
    *rig.provider.host_for_tests().on_prompt.lock().unwrap() = Some(hook);
    rig.provider
        .get_assertion(&operation(&encoded, &signature))
        .unwrap();
    assert_eq!(rig.log.signed.load(Ordering::SeqCst), 1);

    // The mark is gone on failure too.
    *rig.provider.host_for_tests().on_prompt.lock().unwrap() = None;
    *rig.verify_result.lock().unwrap() = Some(ProviderError::Cancelled);
    assert!(
        rig.provider
            .get_assertion(&operation(&encoded, &signature))
            .is_err()
    );
    *rig.verify_result.lock().unwrap() = None;
    rig.provider
        .get_assertion(&operation(&encoded, &signature))
        .unwrap();
}

#[test]
fn errors_are_the_hresults_windows_tells_apart() {
    assert_eq!(ProviderError::Cancelled.hresult() as u32, 0x8009_0036);
    assert_eq!(ProviderError::NoCredentials.hresult() as u32, 0x8009_0011);
    assert_eq!(ProviderError::Excluded.hresult() as u32, 0x8009_000f);
    assert_eq!(ProviderError::Busy.hresult() as u32, 0x8007_00aa);
}
