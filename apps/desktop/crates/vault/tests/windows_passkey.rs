//! The Windows passkey provider against the real vault and server: CTAP2 bytes signed like
//! Windows signs them go in, and what comes out verifies against the passkey's public key. Only
//! Windows itself is a fake here.

use crate::common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use octapass_desktop_vault::Vault;
use octapass_desktop_vault::windows_passkey::{PluginVault, credential_metadata};
use octapass_windows_passkey::ctap::split_attestation_object;
use octapass_windows_passkey::provider::REQUEST_TYPE_CTAP2_CBOR;
use octapass_windows_passkey::signature::request_hash;
use octapass_windows_passkey::{
    Account, Host, Operation, PasskeyVault, Provider, ProviderError, UserPrompt,
};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;

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

struct FakeWindows {
    operation: SigningKey,
    hello: SigningKey,
    /// The request Hello is signing for.
    current: Mutex<[u8; 32]>,
    prompts: AtomicUsize,
}

/// The provider owns its host; the test keeps the other handle to it.
struct WindowsHost(Arc<FakeWindows>);

impl Host for WindowsHost {
    fn operation_signing_key(&self) -> Result<Vec<u8>, ProviderError> {
        Ok(blob(&self.0.operation))
    }
    fn user_verification_key(&self) -> Result<Vec<u8>, ProviderError> {
        Ok(blob(&self.0.hello))
    }
    fn verify_user(&self, _prompt: &UserPrompt) -> Result<Vec<u8>, ProviderError> {
        self.0.prompts.fetch_add(1, Ordering::SeqCst);
        Ok(sign(&self.0.hello, &self.0.current.lock().unwrap()))
    }
    fn choose_account(
        &self,
        _window: isize,
        _rp_id: &str,
        _accounts: &[Account],
    ) -> Result<usize, ProviderError> {
        Ok(0)
    }
}

type TestProvider = Provider<WindowsHost, PluginVault>;

fn provider(vault: &Arc<Vault>) -> (Arc<TestProvider>, Arc<FakeWindows>) {
    let windows = Arc::new(FakeWindows {
        operation: SigningKey::from_slice(&[1; 32]).unwrap(),
        hello: SigningKey::from_slice(&[2; 32]).unwrap(),
        current: Mutex::new([0; 32]),
        prompts: AtomicUsize::new(0),
    });
    let plugin = PluginVault::with_unlock_wait(
        Arc::clone(vault),
        Handle::current(),
        Box::new(|| {}),
        Duration::from_millis(300),
    );
    (
        Arc::new(Provider::new(WindowsHost(Arc::clone(&windows)), plugin)),
        windows,
    )
}

fn text(value: &str) -> ciborium::value::Value {
    ciborium::value::Value::Text(value.into())
}

fn cbor(value: ciborium::value::Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out).unwrap();
    out
}

fn make_credential_request(hash: &[u8; 32]) -> Vec<u8> {
    use ciborium::value::Value::{Array, Bytes, Integer, Map};
    cbor(Map(vec![
        (Integer(1.into()), Bytes(hash.to_vec())),
        (
            Integer(2.into()),
            Map(vec![(text("id"), text("example.com"))]),
        ),
        (
            Integer(3.into()),
            Map(vec![
                (text("id"), Bytes(b"user-handle".to_vec())),
                (text("name"), text("ada")),
            ]),
        ),
        (
            Integer(4.into()),
            Array(vec![Map(vec![
                (text("alg"), Integer((-7).into())),
                (text("type"), text("public-key")),
            ])]),
        ),
    ]))
}

fn get_assertion_request(hash: &[u8; 32]) -> Vec<u8> {
    use ciborium::value::Value::{Bytes, Integer, Map};
    cbor(Map(vec![
        (Integer(1.into()), text("example.com")),
        (Integer(2.into()), Bytes(hash.to_vec())),
    ]))
}

fn operation<'a>(encoded: &'a [u8], signature: &'a [u8]) -> Operation<'a> {
    Operation {
        window: 0,
        transaction: [7; 16],
        signature,
        request_type: REQUEST_TYPE_CTAP2_CBOR,
        encoded,
    }
}

/// The P-256 key in a passkey's authenticator data.
fn public_key(authenticator_data: &[u8]) -> VerifyingKey {
    // rpIdHash(32) flags(1) counter(4) aaguid(16) idLength(2) id, then the COSE key.
    let id_length = u16::from_be_bytes([authenticator_data[53], authenticator_data[54]]) as usize;
    let key: ciborium::value::Value =
        ciborium::de::from_reader(&authenticator_data[55 + id_length..]).unwrap();
    let map = key.as_map().unwrap();
    let coordinate = |label: i64| {
        map.iter()
            .find(|(k, _)| k.as_integer() == Some(label.into()))
            .and_then(|(_, value)| value.as_bytes())
            .unwrap()
            .clone()
    };
    let mut point = vec![4];
    point.extend(coordinate(-2));
    point.extend(coordinate(-3));
    VerifyingKey::from_sec1_bytes(&point).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn windows_creates_a_passkey_and_signs_in_with_it() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault = Arc::clone(&device.vault);
    let (provider, windows) = provider(&vault);

    // Create. Windows wrote the client data; only its hash comes here.
    let client_data = Sha256::digest(b"registration client data").into();
    let encoded = make_credential_request(&client_data);
    *windows.current.lock().unwrap() = request_hash(&encoded);
    let signature = sign(&windows.operation, &request_hash(&encoded));
    let registration = {
        let provider = Arc::clone(&provider);
        let (encoded, signature) = (encoded.clone(), signature.clone());
        tokio::task::spawn_blocking(move || {
            provider.make_credential(&operation(&encoded, &signature))
        })
        .await
        .unwrap()
        .unwrap()
    };
    assert_eq!(windows.prompts.load(Ordering::SeqCst), 1);

    let parts = split_attestation_object(&registration.attestation_object).unwrap();
    assert_eq!(parts.format, "none");
    assert_eq!(
        parts.authenticator_data[..32],
        Sha256::digest(b"example.com")[..]
    );
    assert_eq!(
        parts.authenticator_data[32] & 0x05,
        0x05,
        "user present and verified"
    );
    let key = public_key(&parts.authenticator_data);

    // It's saved, and Windows gets to list it.
    let listed = credential_metadata(&vault).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].rp_id, "example.com");
    assert_eq!(listed[0].user_name, "ada");
    assert_eq!(listed[0].user_id, b"user-handle");
    assert_eq!(listed[0].credential_id, registration.credential_id);

    // Sign in; no allow list, as a discoverable credential.
    let client_data: [u8; 32] = Sha256::digest(b"assertion client data").into();
    let encoded = get_assertion_request(&client_data);
    *windows.current.lock().unwrap() = request_hash(&encoded);
    let signature = sign(&windows.operation, &request_hash(&encoded));
    let assertion = {
        let provider = Arc::clone(&provider);
        let (encoded, signature) = (encoded.clone(), signature.clone());
        tokio::task::spawn_blocking(move || {
            provider.get_assertion(&operation(&encoded, &signature))
        })
        .await
        .unwrap()
        .unwrap()
    };
    assert_eq!(windows.prompts.load(Ordering::SeqCst), 2);
    assert_eq!(assertion.credential_id, registration.credential_id);
    assert_eq!(assertion.user_id, b"user-handle");
    assert_eq!(assertion.user_name, "ada");

    let mut signed = assertion.authenticator_data.clone();
    signed.extend_from_slice(&client_data);
    let der = Signature::from_der(&assertion.signature).unwrap();
    key.verify(&signed, &der)
        .expect("the site can verify the assertion");

    // Excluding it refuses a second one, after Hello.
    let mut with_excluded = ciborium::de::from_reader::<ciborium::value::Value, _>(
        make_credential_request(&client_data).as_slice(),
    )
    .unwrap();
    if let ciborium::value::Value::Map(map) = &mut with_excluded {
        map.push((
            ciborium::value::Value::Integer(5.into()),
            ciborium::value::Value::Array(vec![ciborium::value::Value::Map(vec![
                (
                    text("id"),
                    ciborium::value::Value::Bytes(registration.credential_id.clone()),
                ),
                (text("type"), text("public-key")),
            ])]),
        ));
    }
    let encoded = cbor(with_excluded);
    *windows.current.lock().unwrap() = request_hash(&encoded);
    let signature = sign(&windows.operation, &request_hash(&encoded));
    let provider2 = Arc::clone(&provider);
    let error = tokio::task::spawn_blocking(move || {
        provider2.make_credential(&operation(&encoded, &signature))
    })
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error, ProviderError::Excluded);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_site_without_a_passkey_and_a_forged_request() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault = Arc::clone(&device.vault);
    let (provider, windows) = provider(&vault);

    let encoded = get_assertion_request(&[9; 32]);
    let signature = sign(&windows.operation, &request_hash(&encoded));
    let (forged_encoded, real_signature) = (encoded.clone(), signature.clone());
    let provider2 = Arc::clone(&provider);
    let no_passkey = tokio::task::spawn_blocking(move || {
        provider2.get_assertion(&operation(&forged_encoded, &real_signature))
    })
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(no_passkey, ProviderError::NoCredentials);

    let forged = sign(&windows.hello, &request_hash(&encoded));
    let provider2 = Arc::clone(&provider);
    let error =
        tokio::task::spawn_blocking(move || provider2.get_assertion(&operation(&encoded, &forged)))
            .await
            .unwrap()
            .unwrap_err();
    assert_eq!(error, ProviderError::Forged);
    assert_eq!(windows.prompts.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_locked_vault_waits_for_the_lock_screen() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault = Arc::clone(&device.vault);
    vault.lock();

    let shown = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&shown);
    let plugin = PluginVault::with_unlock_wait(
        Arc::clone(&vault),
        Handle::current(),
        Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }),
        Duration::from_millis(300),
    );
    assert!(!plugin.is_unlocked());
    assert_eq!(
        credential_metadata(&vault).unwrap_err().code,
        octapass_desktop_vault::ErrorCode::Locked
    );
    let result = tokio::task::spawn_blocking(move || {
        let timed_out = plugin.unlock(&|| false);
        let cancelled = plugin.unlock(&|| true);
        (timed_out, cancelled)
    })
    .await
    .unwrap();
    assert_eq!(result.0, Err(ProviderError::Locked), "nobody unlocked it");
    assert_eq!(result.1, Err(ProviderError::Cancelled));
    assert_eq!(shown.load(Ordering::SeqCst), 2);
}
