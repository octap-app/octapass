//! The Octa Pass passkey provider for Windows 11, built on Microsoft's plugin authenticator API
//! (<https://github.com/microsoft/webauthn>, `webauthnplugin.h`, `pluginauthenticator.idl`).
//!
//! Windows calls a COM server the app registers. Everything that decides anything is portable and
//! tested on every platform:
//!
//! - [`ctap`] reads CTAP2 `authenticatorMakeCredential` and `authenticatorGetAssertion` requests
//!   and writes their responses and `authenticatorGetInfo`.
//! - [`signature`] checks the signatures Windows puts on requests and on user verification.
//! - [`provider`] is the order of checks every operation goes through, over two traits: [`Host`],
//!   what Windows offers, and [`PasskeyVault`], what the desktop vault offers.
//!
//! `windows` (only built on Windows) is the thin layer under them: the COM objects, `webauthn.dll`
//! loaded at run time so older Windows just reports the provider as unavailable, and the account
//! chooser. Passkey keys and signatures stay in `octapass_core::passkey`, through the vault; this
//! crate holds no key and never signs.

pub mod ctap;
pub mod provider;
pub mod signature;
#[cfg(windows)]
pub mod windows;

pub use provider::{
    Account, Assertion, CredentialMetadata, Host, LockStatus, NewPasskey, Operation, PasskeyVault,
    Provider, ProviderError, Purpose, Registration, UserPrompt,
};

/// The CLSID Windows activates, also in `apps/desktop/windows/AppxManifest.xml`. Generated for
/// Octa Pass on 2026-11-02; changing it is a new provider to Windows.
pub const PROVIDER_CLSID: u128 = 0x4ba386cd_7fd2_4238_bf45_b3b3e1cf144d;
/// The same CLSID as the manifest writes it.
pub const PROVIDER_CLSID_TEXT: &str = "4ba386cd-7fd2-4238-bf45-b3b3e1cf144d";
/// The name in Windows' Settings and passkey dialogs.
pub const PROVIDER_NAME: &str = "Octa Pass";
/// The argument Windows starts the app with (`Arguments` of the manifest's `ExeServer`).
pub const ACTIVATION_ARGUMENT: &str = "-PluginActivated";
