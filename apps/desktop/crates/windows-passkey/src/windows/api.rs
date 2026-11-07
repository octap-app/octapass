//! `webauthn.dll`, loaded at run time: a Windows without the plugin API simply has no provider.
//! Everything Windows-specific about turning the provider on and off and about its list of
//! passkeys is here.

use std::mem;
use std::ptr;
use std::sync::OnceLock;

use base64::Engine as _;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HMODULE, NTE_EXISTS, NTE_NOT_FOUND};
use windows::Win32::Storage::Packaging::Appx::GetCurrentPackageFullName;
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{GUID, HRESULT, PCSTR, PCWSTR, s, w};

use super::ffi::*;
use crate::{CredentialMetadata, PROVIDER_CLSID, PROVIDER_NAME};

/// `brand/logo-tile.svg`: the white monogram on the gradient reads on both themes.
const LOGO: &[u8] = include_bytes!("../../../../../../brand/logo-tile.svg");

pub(super) const CLSID: GUID = GUID::from_u128(PROVIDER_CLSID);

pub(super) struct Api {
    get_state: GetAuthenticatorState,
    add: AddAuthenticator,
    free_add: FreeAddAuthenticatorResponse,
    remove: RemoveAuthenticator,
    add_credentials: ChangeCredentials,
    remove_all_credentials: RemoveAllCredentials,
    pub perform_uv: PerformUserVerification,
    pub free_uv: FreeBytes,
    pub uv_key: GetPublicKey,
    pub operation_key: GetPublicKey,
    pub free_key: FreeBytes,
    pub encode_make_credential: Option<EncodeMakeCredentialResponse>,
    pub encode_get_assertion: Option<EncodeGetAssertionResponse>,
}

/// # Safety
/// `T` must be the function pointer type of the export named `name`.
unsafe fn symbol<T: Copy>(library: HMODULE, name: PCSTR) -> Option<T> {
    const { assert!(mem::size_of::<T>() == mem::size_of::<usize>()) };
    // SAFETY: `library` is loaded and never freed; the caller names the type.
    unsafe { GetProcAddress(library, name).map(|found| mem::transmute_copy(&found)) }
}

fn load() -> Option<Api> {
    // SAFETY: a constant name, resolved in System32 only, so no planted DLL can answer. Each
    // `symbol` type is the header's prototype, in `ffi`.
    unsafe {
        let library =
            LoadLibraryExW(w!("webauthn.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32).ok()?;
        Some(Api {
            get_state: symbol(library, s!("WebAuthNPluginGetAuthenticatorState"))?,
            add: symbol(library, s!("WebAuthNPluginAddAuthenticator"))?,
            free_add: symbol(library, s!("WebAuthNPluginFreeAddAuthenticatorResponse"))?,
            remove: symbol(library, s!("WebAuthNPluginRemoveAuthenticator"))?,
            add_credentials: symbol(library, s!("WebAuthNPluginAuthenticatorAddCredentials"))?,
            remove_all_credentials: symbol(
                library,
                s!("WebAuthNPluginAuthenticatorRemoveAllCredentials"),
            )?,
            perform_uv: symbol(library, s!("WebAuthNPluginPerformUserVerification"))?,
            free_uv: symbol(library, s!("WebAuthNPluginFreeUserVerificationResponse"))?,
            uv_key: symbol(library, s!("WebAuthNPluginGetUserVerificationPublicKey"))?,
            operation_key: symbol(library, s!("WebAuthNPluginGetOperationSigningPublicKey"))?,
            free_key: symbol(library, s!("WebAuthNPluginFreePublicKeyResponse"))?,
            encode_make_credential: symbol(library, s!("WebAuthNEncodeMakeCredentialResponse")),
            encode_get_assertion: symbol(library, s!("WebAuthNEncodeGetAssertionResponse")),
        })
    }
}

pub(super) fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(load).as_ref()
}

/// Windows only activates a plugin from an installed package, so the plain installer has none.
fn has_package_identity() -> bool {
    let mut length = 0;
    // SAFETY: a null buffer with length 0 only asks for the length.
    let result = unsafe { GetCurrentPackageFullName(&mut length, None) };
    // A package answers with the size it needs; no package with APPMODEL_ERROR_NO_PACKAGE.
    result == ERROR_INSUFFICIENT_BUFFER
}

/// Where the provider stands on this device. The state lives in Windows, so it can't go stale.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Status {
    /// This Windows has the API and the app runs from its package.
    pub available: bool,
    /// Octa Pass is on Windows' list of providers.
    pub registered: bool,
    /// The user has turned it on in Windows Settings.
    pub enabled: bool,
}

pub fn status() -> Status {
    let Some(api) = api().filter(|_| has_package_identity()) else {
        return Status::default();
    };
    let mut state = 0;
    // SAFETY: `CLSID` and `state` outlive the call.
    let result = unsafe { (api.get_state)(&CLSID, &mut state) };
    Status {
        available: true,
        registered: result.is_ok(),
        enabled: result.is_ok() && state == AUTHENTICATOR_STATE_ENABLED,
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn checked(result: HRESULT) -> windows::core::Result<()> {
    result.ok()
}

/// `info` is the `authenticatorGetInfo` from [`crate::ctap::authenticator_info`]. Already being on
/// the list counts as done.
pub fn register(info: &[u8]) -> windows::core::Result<()> {
    let api = api().ok_or(windows::core::Error::from_hresult(NTE_NOT_FOUND))?;
    let name = wide(PROVIDER_NAME);
    let logo = wide(&base64::engine::general_purpose::STANDARD.encode(LOGO));
    let options = WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS {
        pwszAuthenticatorName: PCWSTR(name.as_ptr()),
        rclsid: &CLSID,
        // Optional: only for nested WebAuthn calls, which Octa Pass doesn't make.
        pwszPluginRpId: PCWSTR::null(),
        pwszLightThemeLogoSvg: PCWSTR(logo.as_ptr()),
        pwszDarkThemeLogoSvg: PCWSTR(logo.as_ptr()),
        cbAuthenticatorInfo: info.len() as u32,
        pbAuthenticatorInfo: info.as_ptr(),
        cSupportedRpIds: 0,
        ppwszSupportedRpIds: ptr::null(),
    };
    let mut response = ptr::null_mut();
    // SAFETY: every pointer in `options` is alive for the call; `response` is freed below with the
    // header's function. The signing key in it isn't kept: each check asks Windows for it.
    let result = unsafe { (api.add)(&options, &mut response) };
    unsafe { (api.free_add)(response) };
    if result == NTE_EXISTS {
        return Ok(());
    }
    checked(result)
}

/// Takes Octa Pass off Windows' list, and with it the names Windows cached.
pub fn unregister() -> windows::core::Result<()> {
    let api = api().ok_or(windows::core::Error::from_hresult(NTE_NOT_FOUND))?;
    // SAFETY: `CLSID` outlives both calls.
    unsafe {
        // Not on the list any more is what was asked for.
        let _ = (api.remove_all_credentials)(&CLSID);
        let result = (api.remove)(&CLSID);
        if result == NTE_NOT_FOUND {
            return Ok(());
        }
        checked(result)
    }
}

/// Replaces what Windows shows in autofill with `credentials`.
pub fn replace_credentials(credentials: &[CredentialMetadata]) -> windows::core::Result<()> {
    let api = api().ok_or(windows::core::Error::from_hresult(NTE_NOT_FOUND))?;
    let names: Vec<(Vec<u16>, Vec<u16>)> = credentials
        .iter()
        .map(|credential| (wide(&credential.rp_id), wide(&credential.user_name)))
        .collect();
    let details: Vec<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS> = credentials
        .iter()
        .zip(&names)
        .map(
            |(credential, (rp_id, user_name))| WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS {
                cbCredentialId: credential.credential_id.len() as u32,
                pbCredentialId: credential.credential_id.as_ptr(),
                pwszRpId: PCWSTR(rp_id.as_ptr()),
                // Required, and the vault keeps no name for the site.
                pwszRpName: PCWSTR(rp_id.as_ptr()),
                cbUserId: credential.user_id.len() as u32,
                pbUserId: credential.user_id.as_ptr(),
                pwszUserName: PCWSTR(user_name.as_ptr()),
                pwszUserDisplayName: PCWSTR(user_name.as_ptr()),
            },
        )
        .collect();
    // SAFETY: `details` points into `credentials` and `names`, alive for the call.
    unsafe {
        let _ = (api.remove_all_credentials)(&CLSID);
        if details.is_empty() {
            return Ok(());
        }
        checked((api.add_credentials)(
            &CLSID,
            details.len() as u32,
            details.as_ptr(),
        ))
    }
}

/// Opens the page of Windows Settings where the user turns the provider on (the URI from
/// Microsoft's sample).
pub fn open_settings() {
    // SAFETY: constant strings; the returned handle is only a status.
    unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            w!("ms-settings:passkeys-advancedoptions"),
            None,
            None,
            SW_SHOWNORMAL,
        );
    }
}
