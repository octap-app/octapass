//! The real Windows Hello (WinRT), DPAPI and LogonUser calls.

use std::path::PathBuf;

use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Security::Credentials::{
    KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCOUNT_RESTRICTION, HANDLE, HLOCAL, LocalFree,
};
use windows::Win32::Security::Cryptography::{
    BCRYPT_PKCS1_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM, CERT_KEY_SPEC,
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE,
    NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
};
use windows::Win32::Security::{LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LogonUserW};
use windows::core::{Array, HSTRING, PCWSTR, w};
use zeroize::Zeroizing;

use super::HelloApi;
use crate::{Error, Result, platform_error};

pub struct SystemApi {
    dpapi_dir: PathBuf,
}

impl SystemApi {
    pub fn new() -> Self {
        let base = std::env::var_os("LOCALAPPDATA").map_or_else(std::env::temp_dir, PathBuf::from);
        Self {
            dpapi_dir: base.join("app.octap.desktop").join("stay-unlocked"),
        }
    }

    fn blob_path(&self, name: &str) -> PathBuf {
        self.dpapi_dir.join(format!("{name}.bin"))
    }
}

impl Default for SystemApi {
    fn default() -> Self {
        Self::new()
    }
}

fn winrt(call: &str) -> impl Fn(windows::core::Error) -> Error + '_ {
    move |error| platform_error(call, error.code())
}

fn status_error(call: &str, status: KeyCredentialStatus) -> Error {
    match status {
        KeyCredentialStatus::UserCanceled => Error::Cancelled,
        KeyCredentialStatus::NotFound => Error::NotEnrolled,
        KeyCredentialStatus::SecurityDeviceLocked => Error::Denied,
        other => platform_error(call, other.0),
    }
}

/// The Platform Crypto Provider: the TPM. Freed when dropped.
struct TpmProvider(NCRYPT_PROV_HANDLE);

impl TpmProvider {
    /// `None` on a machine without a TPM 2.0.
    fn open() -> Option<Self> {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        // SAFETY: the out handle is ours; the name is a constant.
        unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) }.ok()?;
        Some(Self(provider))
    }
}

impl Drop for TpmProvider {
    fn drop(&mut self) {
        // SAFETY: opened above and freed once.
        let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0.0)) };
    }
}

/// A key in the TPM. Freed when dropped.
struct TpmKey(NCRYPT_KEY_HANDLE);

impl Drop for TpmKey {
    fn drop(&mut self) {
        // SAFETY: from `NCryptOpenKey` or `NCryptCreatePersistedKey`, and freed once.
        let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(self.0.0)) };
    }
}

fn ncrypt(call: &str, error: windows::core::Error) -> Error {
    platform_error(call, error.code())
}

impl SystemApi {
    fn open_tpm_key(provider: &TpmProvider, name: &str) -> Result<TpmKey> {
        let mut key = NCRYPT_KEY_HANDLE::default();
        // SAFETY: the provider is open, and the out handle is ours.
        unsafe {
            NCryptOpenKey(
                provider.0,
                &mut key,
                &HSTRING::from(name),
                CERT_KEY_SPEC(0),
                NCRYPT_SILENT_FLAG,
            )
        }
        .map_err(|_| Error::NotEnrolled)?;
        Ok(TpmKey(key))
    }
}

impl HelloApi for SystemApi {
    fn tpm_available(&self) -> bool {
        TpmProvider::open().is_some()
    }

    fn tpm_create_key(&self, name: &str) -> Result<bool> {
        let Some(provider) = TpmProvider::open() else {
            return Ok(false);
        };
        let mut key = NCRYPT_KEY_HANDLE::default();
        // SAFETY: the provider is open, and the out handle is ours. No export policy is set, so
        // the key can't leave the TPM.
        let created = unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut key,
                BCRYPT_RSA_ALGORITHM,
                &HSTRING::from(name),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        };
        if created.is_err() {
            return Ok(false);
        }
        let key = TpmKey(key);
        let bits = 2048u32.to_le_bytes();
        // SAFETY: the key is open, and not finalized yet.
        unsafe {
            NCryptSetProperty(
                NCRYPT_HANDLE(key.0.0),
                NCRYPT_LENGTH_PROPERTY,
                &bits,
                NCRYPT_FLAGS(0),
            )
        }
        .map_err(|error| ncrypt("NCryptSetProperty", error))?;
        // SAFETY: as above.
        unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) }
            .map_err(|error| ncrypt("NCryptFinalizeKey", error))?;
        Ok(true)
    }

    fn tpm_sign(&self, name: &str, digest: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        let provider = TpmProvider::open().ok_or(Error::NotEnrolled)?;
        let key = Self::open_tpm_key(&provider, name)?;
        let padding = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
        };
        let flags = NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG;
        let padding_info = Some(std::ptr::from_ref(&padding).cast());
        let mut size = 0u32;
        // SAFETY: the key is open, and every pointer outlives the call.
        unsafe { NCryptSignHash(key.0, padding_info, digest, None, &mut size, flags) }
            .map_err(|error| ncrypt("NCryptSignHash", error))?;
        let mut signature = Zeroizing::new(vec![0u8; size as usize]);
        // SAFETY: as above, with room for `size` bytes.
        unsafe {
            NCryptSignHash(
                key.0,
                padding_info,
                digest,
                Some(signature.as_mut_slice()),
                &mut size,
                flags,
            )
        }
        .map_err(|error| ncrypt("NCryptSignHash", error))?;
        signature.truncate(size as usize);
        Ok(signature)
    }

    fn tpm_delete_key(&self, name: &str) -> Result<()> {
        let Some(provider) = TpmProvider::open() else {
            return Ok(());
        };
        let Ok(key) = Self::open_tpm_key(&provider, name) else {
            return Ok(());
        };
        // NCryptDeleteKey frees the handle itself.
        let key = std::mem::ManuallyDrop::new(key);
        // SAFETY: the key is open, and not used again.
        unsafe { NCryptDeleteKey(key.0, 0) }.map_err(|error| ncrypt("NCryptDeleteKey", error))
    }

    fn hello_available(&self) -> Result<bool> {
        let availability = UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|operation| operation.join())
            .map_err(winrt("CheckAvailabilityAsync"))?;
        Ok(availability == UserConsentVerifierAvailability::Available)
    }

    /// A blank password can't be used to log on remotely, so `LogonUser` with an empty password
    /// answers `ERROR_ACCOUNT_RESTRICTION` (or succeeds) only when the account has none.
    fn account_has_password(&self) -> Result<bool> {
        let user = std::env::var("USERNAME").map_err(|_| Error::Unavailable)?;
        let mut token = HANDLE::default();
        let result = unsafe {
            LogonUserW(
                &HSTRING::from(user),
                w!("."),
                w!(""),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        };
        match result {
            Ok(()) => {
                let _ = unsafe { CloseHandle(token) };
                Ok(false)
            }
            Err(error) if error.code() == ERROR_ACCOUNT_RESTRICTION.to_hresult() => Ok(false),
            // Wrong password, or anything we can't interpret: assume there is a lock.
            Err(_) => Ok(true),
        }
    }

    fn create_key(&self, name: &str) -> Result<()> {
        let result = KeyCredentialManager::RequestCreateAsync(
            &HSTRING::from(name),
            KeyCredentialCreationOption::ReplaceExisting,
        )
        .and_then(|operation| operation.join())
        .map_err(winrt("RequestCreateAsync"))?;
        match result.Status().map_err(winrt("Status"))? {
            KeyCredentialStatus::Success => Ok(()),
            status => Err(status_error("RequestCreateAsync", status)),
        }
    }

    fn sign(&self, name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let opened = KeyCredentialManager::OpenAsync(&HSTRING::from(name))
            .and_then(|operation| operation.join())
            .map_err(winrt("OpenAsync"))?;
        match opened.Status().map_err(winrt("Status"))? {
            KeyCredentialStatus::Success => {}
            status => return Err(status_error("OpenAsync", status)),
        }
        let credential = opened.Credential().map_err(winrt("Credential"))?;
        let data = CryptographicBuffer::CreateFromByteArray(challenge)
            .map_err(winrt("CreateFromByteArray"))?;
        let signed = credential
            .RequestSignAsync(&data)
            .and_then(|operation| operation.join())
            .map_err(winrt("RequestSignAsync"))?;
        match signed.Status().map_err(winrt("Status"))? {
            KeyCredentialStatus::Success => {}
            status => return Err(status_error("RequestSignAsync", status)),
        }
        let buffer = signed.Result().map_err(winrt("Result"))?;
        let mut signature = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&buffer, &mut signature)
            .map_err(winrt("CopyToByteArray"))?;
        Ok(Zeroizing::new(signature.to_vec()))
    }

    fn delete_key(&self, name: &str) -> Result<()> {
        match KeyCredentialManager::DeleteAsync(&HSTRING::from(name))
            .and_then(|operation| operation.join())
        {
            Ok(()) => Ok(()),
            // Deleting a key that was never created is fine.
            Err(error) if error.code().0 as u32 == 0x8009_0011 => Ok(()),
            Err(error) => Err(platform_error("DeleteAsync", error.code())),
        }
    }

    fn verify(&self, message: &str) -> Result<()> {
        let result = UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(message))
            .and_then(|operation| operation.join())
            .map_err(winrt("RequestVerificationAsync"))?;
        match result {
            UserConsentVerificationResult::Verified => Ok(()),
            UserConsentVerificationResult::Canceled => Err(Error::Cancelled),
            UserConsentVerificationResult::DeviceNotPresent
            | UserConsentVerificationResult::NotConfiguredForUser => Err(Error::NoDeviceLock),
            other => Err(platform_error("RequestVerificationAsync", other.0)),
        }
    }

    fn dpapi_store(&self, name: &str, secret: &[u8]) -> Result<()> {
        let blob = crypt(secret, true)?;
        std::fs::create_dir_all(&self.dpapi_dir)
            .and_then(|()| std::fs::write(self.blob_path(name), &blob))
            .map_err(|error| Error::Platform(error.to_string()))
    }

    fn dpapi_load(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match std::fs::read(self.blob_path(name)) {
            Ok(blob) => crypt(&blob, false).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(Error::Platform(error.to_string())),
        }
    }

    fn dpapi_delete(&self, name: &str) -> Result<()> {
        match std::fs::remove_file(self.blob_path(name)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(Error::Platform(error.to_string()))
            }
            _ => Ok(()),
        }
    }
}

/// `CryptProtectData` / `CryptUnprotectData` in user scope, never showing UI.
fn crypt(input: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>> {
    let blob_in = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(input.len()).map_err(|_| Error::Platform("blob too large".into()))?,
        pbData: input.as_ptr().cast_mut(),
    };
    let mut blob_out = CRYPT_INTEGER_BLOB::default();
    let result = unsafe {
        if protect {
            CryptProtectData(
                &blob_in,
                PCWSTR::null(),
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut blob_out,
            )
        } else {
            CryptUnprotectData(
                &blob_in,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut blob_out,
            )
        }
    };
    result.map_err(|error| platform_error("CryptProtectData", error.code()))?;
    // SAFETY: DPAPI returned a LocalAlloc'd buffer of cbData bytes. It's copied, wiped (it may
    // hold the plaintext secret) and freed.
    let output = unsafe {
        let len = blob_out.cbData as usize;
        let copy = Zeroizing::new(std::slice::from_raw_parts(blob_out.pbData, len).to_vec());
        std::ptr::write_bytes(blob_out.pbData, 0, len);
        let _ = LocalFree(Some(HLOCAL(blob_out.pbData.cast())));
        copy
    };
    Ok(output)
}
