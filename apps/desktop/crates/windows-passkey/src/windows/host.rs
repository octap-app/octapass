//! [`Host`] on Windows: its signing keys, Windows Hello, and the account chooser.

use std::mem;
use std::ptr;
use std::slice;

use windows::Win32::Foundation::{HWND, NTE_USER_CANCELLED};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::UI::Controls::{
    TASKDIALOG_BUTTON, TASKDIALOGCONFIG, TDCBF_CANCEL_BUTTON, TDF_ALLOW_DIALOG_CANCELLATION,
    TDF_POSITION_RELATIVE_TO_WINDOW, TDF_RTL_LAYOUT, TDF_USE_COMMAND_LINKS_NO_ICON,
};
use windows::core::{BOOL, GUID, HRESULT, PCWSTR, s, w};

use super::api::{CLSID, api};
use super::ffi::*;
use crate::{Account, Host, ProviderError, Purpose, UserPrompt};

/// The words Windows shows for Octa Pass, in the app's language.
pub trait Words: Send + Sync {
    /// The line under the user name in Windows Hello.
    fn hint(&self, purpose: Purpose, site: &str) -> String;
    /// The chooser's heading.
    fn choose_account(&self, site: &str) -> String;
    fn right_to_left(&self) -> bool;
}

pub struct WindowsHost {
    words: Box<dyn Words>,
}

impl WindowsHost {
    pub fn new(words: Box<dyn Words>) -> Self {
        Self { words }
    }

    fn key(&self, get: GetPublicKey) -> Result<Vec<u8>, ProviderError> {
        let api = api().ok_or(ProviderError::Failed)?;
        let (mut length, mut data) = (0, ptr::null_mut());
        // SAFETY: `get` is one of the two key functions; outputs are written by the call.
        unsafe { get(&CLSID, &mut length, &mut data) }
            .ok()
            .map_err(|_| ProviderError::Forged)?;
        if data.is_null() {
            return Err(ProviderError::Forged);
        }
        // SAFETY: the call gave `length` bytes at `data`, freed right after with its function.
        unsafe {
            let key = slice::from_raw_parts(data, length as usize).to_vec();
            (api.free_key)(data);
            Ok(key)
        }
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn guid(bytes: [u8; 16]) -> GUID {
    GUID::from_u128(u128::from_be_bytes(bytes))
}

impl Host for WindowsHost {
    fn operation_signing_key(&self) -> Result<Vec<u8>, ProviderError> {
        self.key(api().ok_or(ProviderError::Failed)?.operation_key)
    }

    fn user_verification_key(&self) -> Result<Vec<u8>, ProviderError> {
        self.key(api().ok_or(ProviderError::Failed)?.uv_key)
    }

    fn verify_user(&self, prompt: &UserPrompt) -> Result<Vec<u8>, ProviderError> {
        let api = api().ok_or(ProviderError::Failed)?;
        let transaction = guid(prompt.transaction);
        let user_name = wide(&prompt.user_name);
        let hint = wide(&self.words.hint(prompt.purpose, &prompt.rp_id));
        let request = WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST {
            hwnd: HWND(prompt.window as *mut _),
            rguidTransactionId: &transaction,
            pwszUsername: PCWSTR(user_name.as_ptr()),
            pwszDisplayHint: PCWSTR(hint.as_ptr()),
        };
        let (mut length, mut data) = (0, ptr::null_mut());
        // SAFETY: `request` points into locals alive for the call.
        let result = unsafe { (api.perform_uv)(&request, &mut length, &mut data) };
        if result == NTE_USER_CANCELLED {
            return Err(ProviderError::Cancelled);
        }
        result.ok().map_err(|_| ProviderError::UserVerification)?;
        if data.is_null() {
            return Err(ProviderError::UserVerification);
        }
        // SAFETY: the call gave `length` bytes at `data`, freed right after with its function.
        unsafe {
            let signature = slice::from_raw_parts(data, length as usize).to_vec();
            (api.free_uv)(data);
            Ok(signature)
        }
    }

    fn choose_account(
        &self,
        window: isize,
        rp_id: &str,
        accounts: &[Account],
    ) -> Result<usize, ProviderError> {
        // comctl32 version 6 has it, through the app's manifest. Looked up here because an import
        // would fail at load in any program without that manifest, tests included.
        type TaskDialogIndirect = unsafe extern "system" fn(
            *const TASKDIALOGCONFIG,
            *mut i32,
            *mut i32,
            *mut BOOL,
        ) -> HRESULT;
        // SAFETY: a constant system library and export, of the prototype above.
        let show: TaskDialogIndirect = unsafe {
            let library = LoadLibraryW(w!("comctl32.dll")).map_err(|_| ProviderError::Failed)?;
            let found =
                GetProcAddress(library, s!("TaskDialogIndirect")).ok_or(ProviderError::Failed)?;
            mem::transmute(found)
        };

        const FIRST_ID: i32 = 100;
        let heading = wide(&self.words.choose_account(rp_id));
        let names: Vec<Vec<u16>> = accounts
            .iter()
            .map(|account| wide(&account.user_name))
            .collect();
        let buttons: Vec<TASKDIALOG_BUTTON> = names
            .iter()
            .enumerate()
            .map(|(index, name)| TASKDIALOG_BUTTON {
                nButtonID: FIRST_ID + index as i32,
                pszButtonText: PCWSTR(name.as_ptr()),
            })
            .collect();
        let title = wide(crate::PROVIDER_NAME);
        let mut flags = TDF_ALLOW_DIALOG_CANCELLATION
            | TDF_USE_COMMAND_LINKS_NO_ICON
            | TDF_POSITION_RELATIVE_TO_WINDOW;
        if self.words.right_to_left() {
            flags |= TDF_RTL_LAYOUT;
        }
        let config = TASKDIALOGCONFIG {
            cbSize: mem::size_of::<TASKDIALOGCONFIG>() as u32,
            hwndParent: HWND(window as *mut _),
            dwFlags: flags,
            dwCommonButtons: TDCBF_CANCEL_BUTTON,
            pszWindowTitle: PCWSTR(title.as_ptr()),
            pszMainInstruction: PCWSTR(heading.as_ptr()),
            cButtons: buttons.len() as u32,
            pButtons: buttons.as_ptr(),
            ..Default::default()
        };
        let mut pressed = 0;
        // SAFETY: `config` points into locals alive for the call; unused outputs are null.
        unsafe { show(&config, &mut pressed, ptr::null_mut(), ptr::null_mut()) }
            .ok()
            .map_err(|_| ProviderError::Failed)?;
        pressed
            .checked_sub(FIRST_ID)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < accounts.len())
            .ok_or(ProviderError::Cancelled)
    }
}
