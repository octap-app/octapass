//! The C layouts, copied field by field from Microsoft's headers at
//! <https://github.com/microsoft/webauthn> (`webauthnplugin.h`, `pluginauthenticator.idl`,
//! `webauthn.h`). The `windows` crate has no released bindings for them yet. Only the structs Open
//! Pass passes are here; a struct's trailing fields are all present so its size matches its
//! `dwVersion`.

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use std::ptr;

use windows::Win32::Foundation::HWND;
use windows::Win32::Security::Cryptography::{
    BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_RSAPUBLIC_MAGIC,
};
use windows::core::{GUID, HRESULT, PCWSTR};

use crate::signature::{ECDSA_P256_MAGIC, ECDSA_P384_MAGIC, RSA_MAGIC};

const _: () = {
    assert!(ECDSA_P256_MAGIC == BCRYPT_ECDSA_PUBLIC_P256_MAGIC);
    assert!(ECDSA_P384_MAGIC == BCRYPT_ECDSA_PUBLIC_P384_MAGIC);
    assert!(RSA_MAGIC == BCRYPT_RSAPUBLIC_MAGIC.0);
};

// pluginauthenticator.idl

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_OPERATION_REQUEST {
    pub hWnd: HWND,
    pub transactionId: GUID,
    pub cbRequestSignature: u32,
    pub pbRequestSignature: *const u8,
    /// `WEBAUTHN_PLUGIN_REQUEST_TYPE`
    pub requestType: u32,
    pub cbEncodedRequest: u32,
    pub pbEncodedRequest: *const u8,
}

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_OPERATION_RESPONSE {
    pub cbEncodedResponse: u32,
    /// Allocated with `CoTaskMemAlloc`, freed by the caller: Microsoft's sample hands over what
    /// `WebAuthNEncode*Response` returned.
    pub pbEncodedResponse: *mut u8,
}

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST {
    pub transactionId: GUID,
    pub cbRequestSignature: u32,
    pub pbRequestSignature: *const u8,
}

/// `PluginLocked`
pub const PLUGIN_LOCKED: i32 = 0;
/// `PluginUnlocked`
pub const PLUGIN_UNLOCKED: i32 = 1;

// webauthnplugin.h

/// `AuthenticatorState_Enabled`
pub const AUTHENTICATOR_STATE_ENABLED: i32 = 1;

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS {
    pub pwszAuthenticatorName: PCWSTR,
    /// `REFCLSID`: a pointer in the struct's ABI.
    pub rclsid: *const GUID,
    pub pwszPluginRpId: PCWSTR,
    pub pwszLightThemeLogoSvg: PCWSTR,
    pub pwszDarkThemeLogoSvg: PCWSTR,
    pub cbAuthenticatorInfo: u32,
    pub pbAuthenticatorInfo: *const u8,
    pub cSupportedRpIds: u32,
    pub ppwszSupportedRpIds: *const PCWSTR,
}

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE {
    pub cbOpSignPubKey: u32,
    pub pbOpSignPubKey: *mut u8,
}

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS {
    pub cbCredentialId: u32,
    pub pbCredentialId: *const u8,
    pub pwszRpId: PCWSTR,
    pub pwszRpName: PCWSTR,
    pub cbUserId: u32,
    pub pbUserId: *const u8,
    pub pwszUserName: PCWSTR,
    pub pwszUserDisplayName: PCWSTR,
}

#[repr(C)]
pub struct WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST {
    pub hwnd: HWND,
    /// `REFGUID`: a pointer in the struct's ABI.
    pub rguidTransactionId: *const GUID,
    pub pwszUsername: PCWSTR,
    pub pwszDisplayHint: PCWSTR,
}

// webauthn.h

/// `WEBAUTHN_CREDENTIAL_CURRENT_VERSION`
pub const WEBAUTHN_CREDENTIAL_VERSION: u32 = 1;
/// `WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_8`, the layout below.
pub const WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION: u32 = 8;
/// `WEBAUTHN_ASSERTION_VERSION_6`, the layout below.
pub const WEBAUTHN_ASSERTION_VERSION: u32 = 6;
/// `WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION`
pub const WEBAUTHN_USER_ENTITY_INFORMATION_VERSION: u32 = 1;

#[repr(C)]
pub struct WEBAUTHN_EXTENSIONS {
    pub cExtensions: u32,
    pub pExtensions: *const c_void,
}

impl WEBAUTHN_EXTENSIONS {
    pub const fn none() -> Self {
        Self {
            cExtensions: 0,
            pExtensions: ptr::null(),
        }
    }
}

#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: *const u8,
    pub pwszCredentialType: PCWSTR,
}

#[repr(C)]
pub struct WEBAUTHN_USER_ENTITY_INFORMATION {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: *const u8,
    pub pwszName: PCWSTR,
    pub pwszIcon: PCWSTR,
    pub pwszDisplayName: PCWSTR,
}

#[repr(C)]
pub struct WEBAUTHN_CREDENTIAL_ATTESTATION {
    pub dwVersion: u32,
    pub pwszFormatType: PCWSTR,
    pub cbAuthenticatorData: u32,
    pub pbAuthenticatorData: *const u8,
    pub cbAttestation: u32,
    pub pbAttestation: *const u8,
    pub dwAttestationDecodeType: u32,
    pub pvAttestationDecode: *const c_void,
    pub cbAttestationObject: u32,
    pub pbAttestationObject: *const u8,
    pub cbCredentialId: u32,
    pub pbCredentialId: *const u8,
    // VERSION_2
    pub Extensions: WEBAUTHN_EXTENSIONS,
    // VERSION_3
    pub dwUsedTransport: u32,
    // VERSION_4
    pub bEpAtt: i32,
    pub bLargeBlobSupported: i32,
    pub bResidentKey: i32,
    // VERSION_5
    pub bPrfEnabled: i32,
    // VERSION_6
    pub cbUnsignedExtensionOutputs: u32,
    pub pbUnsignedExtensionOutputs: *const u8,
    // VERSION_7
    pub pHmacSecret: *const c_void,
    pub bThirdPartyPayment: i32,
    // VERSION_8
    pub dwTransports: u32,
    pub cbClientDataJSON: u32,
    pub pbClientDataJSON: *const u8,
    pub cbRegistrationResponseJSON: u32,
    pub pbRegistrationResponseJSON: *const u8,
}

#[repr(C)]
pub struct WEBAUTHN_ASSERTION {
    pub dwVersion: u32,
    pub cbAuthenticatorData: u32,
    pub pbAuthenticatorData: *const u8,
    pub cbSignature: u32,
    pub pbSignature: *const u8,
    pub Credential: WEBAUTHN_CREDENTIAL,
    pub cbUserId: u32,
    pub pbUserId: *const u8,
    // VERSION_2
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub cbCredLargeBlob: u32,
    pub pbCredLargeBlob: *const u8,
    pub dwCredLargeBlobStatus: u32,
    // VERSION_3
    pub pHmacSecret: *const c_void,
    // VERSION_4
    pub dwUsedTransport: u32,
    // VERSION_5
    pub cbUnsignedExtensionOutputs: u32,
    pub pbUnsignedExtensionOutputs: *const u8,
    // VERSION_6
    pub cbClientDataJSON: u32,
    pub pbClientDataJSON: *const u8,
    pub cbAuthenticationResponseJSON: u32,
    pub pbAuthenticationResponseJSON: *const u8,
}

/// `webauthnplugin.h`
#[repr(C)]
pub struct WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE {
    pub WebAuthNAssertion: WEBAUTHN_ASSERTION,
    pub pUserInformation: *const WEBAUTHN_USER_ENTITY_INFORMATION,
    pub dwNumberOfCredentials: u32,
    pub lUserSelected: i32,
    pub cbLargeBlobKey: u32,
    pub pbLargeBlobKey: *const u8,
    pub cbUnsignedExtensionOutputs: u32,
    pub pbUnsignedExtensionOutputs: *const u8,
}

// Sizes on x64, measured by compiling Microsoft's headers for x86_64-pc-windows-msvc with clang
// (`sizeof`), so a field dropped or reordered above stops the build.
#[cfg(target_arch = "x86_64")]
const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(size_of::<WEBAUTHN_PLUGIN_OPERATION_REQUEST>() == 56);
    assert!(size_of::<WEBAUTHN_PLUGIN_OPERATION_RESPONSE>() == 16);
    assert!(size_of::<WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST>() == 32);
    assert!(size_of::<WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS>() == 72);
    assert!(size_of::<WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE>() == 16);
    assert!(size_of::<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS>() == 64);
    assert!(size_of::<WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST>() == 32);
    assert!(size_of::<WEBAUTHN_EXTENSIONS>() == 16);
    assert!(size_of::<WEBAUTHN_CREDENTIAL>() == 24);
    assert!(size_of::<WEBAUTHN_USER_ENTITY_INFORMATION>() == 40);
    assert!(size_of::<WEBAUTHN_CREDENTIAL_ATTESTATION>() == 192);
    assert!(offset_of!(WEBAUTHN_CREDENTIAL_ATTESTATION, Extensions) == 96);
    assert!(offset_of!(WEBAUTHN_CREDENTIAL_ATTESTATION, pbRegistrationResponseJSON) == 184);
    assert!(size_of::<WEBAUTHN_ASSERTION>() == 168);
    assert!(offset_of!(WEBAUTHN_ASSERTION, Credential) == 32);
    assert!(offset_of!(WEBAUTHN_ASSERTION, pbAuthenticationResponseJSON) == 160);
    assert!(size_of::<WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE>() == 216);
    assert!(offset_of!(WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE, pUserInformation) == 168);
};

// The entry points, loaded from webauthn.dll by name in `api`.

pub type GetAuthenticatorState = unsafe extern "system" fn(*const GUID, *mut i32) -> HRESULT;
pub type AddAuthenticator = unsafe extern "system" fn(
    *const WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS,
    *mut *mut WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE,
) -> HRESULT;
pub type FreeAddAuthenticatorResponse =
    unsafe extern "system" fn(*mut WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE);
pub type RemoveAuthenticator = unsafe extern "system" fn(*const GUID) -> HRESULT;
pub type ChangeCredentials = unsafe extern "system" fn(
    *const GUID,
    u32,
    *const WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS,
) -> HRESULT;
pub type RemoveAllCredentials = unsafe extern "system" fn(*const GUID) -> HRESULT;
pub type PerformUserVerification = unsafe extern "system" fn(
    *const WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST,
    *mut u32,
    *mut *mut u8,
) -> HRESULT;
pub type FreeBytes = unsafe extern "system" fn(*mut u8);
pub type GetPublicKey = unsafe extern "system" fn(*const GUID, *mut u32, *mut *mut u8) -> HRESULT;
pub type EncodeMakeCredentialResponse = unsafe extern "system" fn(
    *const WEBAUTHN_CREDENTIAL_ATTESTATION,
    *mut u32,
    *mut *mut u8,
) -> HRESULT;
pub type EncodeGetAssertionResponse = unsafe extern "system" fn(
    *const WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE,
    *mut u32,
    *mut *mut u8,
) -> HRESULT;
