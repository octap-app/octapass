//! The COM server Windows calls. Each method copies what it was given out of its C structs, runs
//! the portable [`Provider`], and hands back a `CoTaskMemAlloc` buffer. Calls arrive on RPC threads
//! of the multithreaded apartment, so a blocking prompt holds nothing up but the call itself.

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
use std::sync::{Arc, OnceLock};
use std::{ptr, thread};

use windows::Win32::Foundation::{CLASS_E_NOAGGREGATION, E_FAIL, E_INVALIDARG, E_POINTER, S_OK};
use windows::Win32::System::Com::{
    CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, CoInitializeEx, CoInitializeSecurity,
    CoRegisterClassObject, CoTaskMemAlloc, EOAC_NONE, IClassFactory, IClassFactory_Impl,
    REGCLS_MULTIPLEUSE, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::core::{
    BOOL, GUID, HRESULT, IUnknown, IUnknown_Vtbl, Interface, PCWSTR, Ref, implement, interface,
};

use super::api::{CLSID, api};
use super::ffi::*;
use super::host::{WindowsHost, Words};
use crate::ctap::{self, AttestationParts};
use crate::provider::{Cancel, LockStatus, Operation};
use crate::{Assertion, PasskeyVault, Provider, ProviderError, Registration};

type Shared = Provider<WindowsHost, Box<dyn PasskeyVault>>;

static PROVIDER: OnceLock<Arc<Shared>> = OnceLock::new();

/// `pluginauthenticator.idl`. Method order is the vtable's.
#[interface("d26bcf6f-b54c-43ff-9f06-d5bf148625f7")]
unsafe trait IPluginAuthenticator: IUnknown {
    unsafe fn MakeCredential(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT;
    unsafe fn GetAssertion(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT;
    unsafe fn CancelOperation(
        &self,
        request: *const WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST,
    ) -> HRESULT;
    unsafe fn GetLockStatus(&self, status: *mut i32) -> HRESULT;
}

/// # Safety
/// `data` must point at `length` readable bytes, or `length` must be 0.
unsafe fn bytes<'a>(data: *const u8, length: u32) -> &'a [u8] {
    if data.is_null() || length == 0 {
        &[]
    } else {
        // SAFETY: the caller's contract.
        unsafe { slice::from_raw_parts(data, length as usize) }
    }
}

fn guid_bytes(guid: GUID) -> [u8; 16] {
    guid.to_u128().to_be_bytes()
}

/// A panic mustn't cross into COM, which aborts the process.
fn guarded(body: impl FnOnce() -> HRESULT) -> HRESULT {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(E_FAIL)
}

/// Copies an encoded response into memory the caller frees.
fn com_buffer(data: &[u8]) -> Result<*mut u8, ProviderError> {
    // SAFETY: a size; the result is checked.
    let buffer = unsafe { CoTaskMemAlloc(data.len()) }.cast::<u8>();
    if buffer.is_null() {
        return Err(ProviderError::Failed);
    }
    // SAFETY: `buffer` holds `data.len()` bytes and can't overlap `data`.
    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), buffer, data.len()) };
    Ok(buffer)
}

/// Microsoft's encoders define the bytes Windows reads back, including any framing around the
/// CBOR, so they're preferred; the portable encoder only answers if the export is missing.
fn encode_registration(registration: &Registration) -> Result<(u32, *mut u8), ProviderError> {
    let parts = ctap::split_attestation_object(&registration.attestation_object)
        .map_err(|_| ProviderError::Failed)?;
    let api = api().ok_or(ProviderError::Failed)?;
    let Some(encode) = api.encode_make_credential else {
        return portable(&ctap::encode_make_credential(&parts).map_err(|_| ProviderError::Failed)?);
    };
    let format: Vec<u16> = parts.format.encode_utf16().chain(Some(0)).collect();
    let attestation = attestation(&parts, &format);
    let (mut length, mut output) = (0, ptr::null_mut());
    // SAFETY: `attestation` points into `parts` and `format`, alive for the call. The output is
    // the task memory the response hands to the caller (`wil::unique_cotaskmem_ptr` in Microsoft's
    // sample).
    unsafe { encode(&attestation, &mut length, &mut output) }
        .ok()
        .map_err(|_| ProviderError::Failed)?;
    Ok((length, output))
}

fn portable(data: &[u8]) -> Result<(u32, *mut u8), ProviderError> {
    Ok((data.len() as u32, com_buffer(data)?))
}

/// Filled as Microsoft's sample fills it: format and authenticator data, the "none" statement
/// empty.
fn attestation(parts: &AttestationParts, format: &[u16]) -> WEBAUTHN_CREDENTIAL_ATTESTATION {
    WEBAUTHN_CREDENTIAL_ATTESTATION {
        dwVersion: WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION,
        pwszFormatType: PCWSTR(format.as_ptr()),
        cbAuthenticatorData: parts.authenticator_data.len() as u32,
        pbAuthenticatorData: parts.authenticator_data.as_ptr(),
        cbAttestation: 0,
        pbAttestation: ptr::null(),
        dwAttestationDecodeType: 0,
        pvAttestationDecode: ptr::null(),
        cbAttestationObject: 0,
        pbAttestationObject: ptr::null(),
        cbCredentialId: 0,
        pbCredentialId: ptr::null(),
        Extensions: WEBAUTHN_EXTENSIONS::none(),
        dwUsedTransport: 0,
        bEpAtt: 0,
        bLargeBlobSupported: 0,
        bResidentKey: 0,
        bPrfEnabled: 0,
        cbUnsignedExtensionOutputs: 0,
        pbUnsignedExtensionOutputs: ptr::null(),
        pHmacSecret: ptr::null(),
        bThirdPartyPayment: 0,
        dwTransports: 0,
        cbClientDataJSON: 0,
        pbClientDataJSON: ptr::null(),
        cbRegistrationResponseJSON: 0,
        pbRegistrationResponseJSON: ptr::null(),
    }
}

fn encode_assertion(assertion: &Assertion) -> Result<(u32, *mut u8), ProviderError> {
    let api = api().ok_or(ProviderError::Failed)?;
    let Some(encode) = api.encode_get_assertion else {
        return portable(&ctap::encode_get_assertion(
            &assertion.credential_id,
            &assertion.authenticator_data,
            &assertion.signature,
            &assertion.user_id,
            &assertion.user_name,
        ));
    };
    let name: Vec<u16> = assertion.user_name.encode_utf16().chain(Some(0)).collect();
    let credential_type: Vec<u16> = "public-key".encode_utf16().chain(Some(0)).collect();
    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_VERSION,
        cbId: assertion.user_id.len() as u32,
        pbId: assertion.user_id.as_ptr(),
        pwszName: PCWSTR(name.as_ptr()),
        pwszIcon: PCWSTR::null(),
        pwszDisplayName: PCWSTR(name.as_ptr()),
    };
    let response = WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE {
        WebAuthNAssertion: WEBAUTHN_ASSERTION {
            dwVersion: WEBAUTHN_ASSERTION_VERSION,
            cbAuthenticatorData: assertion.authenticator_data.len() as u32,
            pbAuthenticatorData: assertion.authenticator_data.as_ptr(),
            cbSignature: assertion.signature.len() as u32,
            pbSignature: assertion.signature.as_ptr(),
            Credential: WEBAUTHN_CREDENTIAL {
                dwVersion: WEBAUTHN_CREDENTIAL_VERSION,
                cbId: assertion.credential_id.len() as u32,
                pbId: assertion.credential_id.as_ptr(),
                pwszCredentialType: PCWSTR(credential_type.as_ptr()),
            },
            cbUserId: assertion.user_id.len() as u32,
            pbUserId: assertion.user_id.as_ptr(),
            Extensions: WEBAUTHN_EXTENSIONS::none(),
            cbCredLargeBlob: 0,
            pbCredLargeBlob: ptr::null(),
            dwCredLargeBlobStatus: 0,
            pHmacSecret: ptr::null(),
            dwUsedTransport: 0,
            cbUnsignedExtensionOutputs: 0,
            pbUnsignedExtensionOutputs: ptr::null(),
            cbClientDataJSON: 0,
            pbClientDataJSON: ptr::null(),
            cbAuthenticationResponseJSON: 0,
            pbAuthenticationResponseJSON: ptr::null(),
        },
        pUserInformation: &user,
        dwNumberOfCredentials: 1,
        lUserSelected: 0,
        cbLargeBlobKey: 0,
        pbLargeBlobKey: ptr::null(),
        cbUnsignedExtensionOutputs: 0,
        pbUnsignedExtensionOutputs: ptr::null(),
    };
    let (mut length, mut output) = (0, ptr::null_mut());
    // SAFETY: `response` points into `assertion`, `user`, `name` and `credential_type`, alive for
    // the call. The output is task memory, as above.
    unsafe { encode(&response, &mut length, &mut output) }
        .ok()
        .map_err(|_| ProviderError::Failed)?;
    Ok((length, output))
}

/// # Safety
/// `request` and `response` come from COM: the structures of the IDL with their sizes.
unsafe fn answer<T>(
    request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
    response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    run: impl FnOnce(&Shared, &Operation) -> Result<T, ProviderError>,
    encode: impl FnOnce(&T) -> Result<(u32, *mut u8), ProviderError>,
) -> HRESULT {
    if response.is_null() {
        return E_POINTER;
    }
    // SAFETY: checked above, and COM's `[out]` memory is ours to write.
    unsafe {
        response.write(WEBAUTHN_PLUGIN_OPERATION_RESPONSE {
            cbEncodedResponse: 0,
            pbEncodedResponse: ptr::null_mut(),
        });
    }
    // SAFETY: a null pointer gives `None`; otherwise COM's marshaller gave us the request.
    let Some(request) = (unsafe { request.as_ref() }) else {
        return E_INVALIDARG;
    };
    let Some(provider) = PROVIDER.get() else {
        return E_FAIL;
    };
    let operation = Operation {
        window: request.hWnd.0 as isize,
        transaction: guid_bytes(request.transactionId),
        // SAFETY: the IDL's `size_is`.
        signature: unsafe { bytes(request.pbRequestSignature, request.cbRequestSignature) },
        request_type: request.requestType,
        // SAFETY: the IDL's `size_is`.
        encoded: unsafe { bytes(request.pbEncodedRequest, request.cbEncodedRequest) },
    };
    match run(provider, &operation).and_then(|result| encode(&result)) {
        Ok((length, output)) => {
            // SAFETY: checked non-null above.
            unsafe {
                response.write(WEBAUTHN_PLUGIN_OPERATION_RESPONSE {
                    cbEncodedResponse: length,
                    pbEncodedResponse: output,
                });
            }
            S_OK
        }
        Err(error) => HRESULT(error.hresult()),
    }
}

#[implement(IPluginAuthenticator)]
struct Authenticator;

impl IPluginAuthenticator_Impl for Authenticator_Impl {
    unsafe fn MakeCredential(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT {
        guarded(|| {
            // SAFETY: COM's arguments, as `answer` asks.
            unsafe {
                answer(
                    request,
                    response,
                    |provider, operation| provider.make_credential(operation),
                    encode_registration,
                )
            }
        })
    }

    unsafe fn GetAssertion(
        &self,
        request: *const WEBAUTHN_PLUGIN_OPERATION_REQUEST,
        response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE,
    ) -> HRESULT {
        guarded(|| {
            // SAFETY: COM's arguments, as `answer` asks.
            unsafe {
                answer(
                    request,
                    response,
                    |provider, operation| provider.get_assertion(operation),
                    encode_assertion,
                )
            }
        })
    }

    unsafe fn CancelOperation(
        &self,
        request: *const WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST,
    ) -> HRESULT {
        guarded(|| {
            // SAFETY: a null pointer gives `None`; otherwise it's the marshalled request.
            let Some(request) = (unsafe { request.as_ref() }) else {
                return E_INVALIDARG;
            };
            let Some(provider) = PROVIDER.get() else {
                return E_FAIL;
            };
            let cancel = Cancel {
                transaction: guid_bytes(request.transactionId),
                // SAFETY: the IDL's `size_is`.
                signature: unsafe { bytes(request.pbRequestSignature, request.cbRequestSignature) },
            };
            match provider.cancel(&cancel) {
                Ok(()) => S_OK,
                Err(error) => HRESULT(error.hresult()),
            }
        })
    }

    unsafe fn GetLockStatus(&self, status: *mut i32) -> HRESULT {
        guarded(|| {
            if status.is_null() {
                return E_POINTER;
            }
            let Some(provider) = PROVIDER.get() else {
                return E_FAIL;
            };
            let value = match provider.lock_status() {
                LockStatus::Locked => PLUGIN_LOCKED,
                LockStatus::Unlocked => PLUGIN_UNLOCKED,
            };
            // SAFETY: checked non-null; COM's `[out]` memory.
            unsafe { status.write(value) };
            S_OK
        })
    }
}

#[implement(IClassFactory)]
struct Factory;

impl IClassFactory_Impl for Factory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<IUnknown>,
        iid: *const GUID,
        object: *mut *mut c_void,
    ) -> windows::core::Result<()> {
        if !outer.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        if iid.is_null() || object.is_null() {
            return Err(E_POINTER.into());
        }
        let authenticator: IPluginAuthenticator = Authenticator.into();
        // SAFETY: both pointers checked; `query` writes the interface or null to `object`.
        unsafe { authenticator.query(iid, object) }.ok()
    }

    fn LockServer(&self, _lock: BOOL) -> windows::core::Result<()> {
        Ok(())
    }
}

/// Starts the COM server on a thread of its own, which lives as long as the app: it holds the
/// multithreaded apartment open. Does nothing where the API is missing. Registering the class
/// says nothing to Windows' provider list; that's [`super::api::register`], the user's switch.
pub fn serve(vault: Box<dyn PasskeyVault>, words: Box<dyn Words>) {
    if api().is_none() {
        return;
    }
    let provider = Arc::new(Provider::new(WindowsHost::new(words), vault));
    if PROVIDER.set(provider).is_err() {
        return;
    }
    thread::spawn(|| {
        // SAFETY: plain COM start-up with constant arguments on this new thread. Another library
        // may already have set security for the process, which is fine: the failure is ignored,
        // as in Bitwarden's server; the arguments are those of Microsoft's sample.
        let registered = unsafe {
            if CoInitializeEx(None, COINIT_MULTITHREADED).is_err() {
                return;
            }
            let _ = CoInitializeSecurity(
                None,
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            );
            let factory: IClassFactory = Factory.into();
            CoRegisterClassObject(&CLSID, &factory, CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE)
        };
        if let Err(error) = registered {
            eprintln!("passkey provider: {error}");
            return;
        }
        loop {
            thread::park();
        }
    });
}
