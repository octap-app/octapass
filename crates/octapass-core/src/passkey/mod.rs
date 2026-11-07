//! A software WebAuthn authenticator, so passkeys are ordinary encrypted items.
//!
//! - [`create`] makes an ES256 (P-256) or EdDSA (Ed25519) key pair for a relying party, with
//!   attestation `none`, and returns the `RegistrationResponseJSON` plus the [`PasskeyRecord`] to
//!   store in a login's `details.passkeys`.
//! - [`get`] signs `authenticatorData ‖ SHA-256(clientDataJSON)` and returns the
//!   `AuthenticationResponseJSON`. The signature counter stays 0, as for every synced passkey.
//! - [`ClientData`] says who wrote `clientDataJSON`. For a page ([`ClientData::Web`]) both check
//!   the [`Caller`] first: `https` origins only (or `http://localhost`), an `rpId` that is the
//!   origin's host or a registrable-domain suffix of it, and no cross-origin frame unless the
//!   host says the user allowed it. Then the core writes the client data. iOS and Android verify
//!   the calling app or browser themselves and pass only the hash of the client data they wrote
//!   ([`ClientData::Hash`]): that hash is signed, with the same `rpId`, `allowCredentials`,
//!   `excludeCredentials`, flags and counter rules.
//! - [`Session::create_passkey`](crate::session::Session::create_passkey),
//!   [`find_passkeys`](crate::session::Session::find_passkeys) and
//!   [`get_assertion`](crate::session::Session::get_assertion) do the same on encrypted items, so
//!   the passkey flows never hand the private key to the caller.
//! - [`PasskeyRecord::to_cxf`] and [`PasskeyRecord::from_cxf`] convert to and from the FIDO
//!   Credential Exchange Format's `passkey` credential.
//!
//! The host (browser extension, app) calls these only after the user chose Octa Pass for the
//! request in an unlocked vault, so the UP and UV flags are always set. BE and BS are set too:
//! passkeys sync like every other item. See `README.md` for the byte layouts.

mod authenticator;
mod cbor;
mod cxf;
mod json;
mod key;
mod origin;
mod record;
mod vault;

pub use authenticator::{AAGUID, CREDENTIAL_ID_LEN, NewPasskey, create, get};
pub use cxf::CxfPasskey;
pub use json::{
    AssertionResponse, AttestationResponse, AuthenticationResponse, CreationOptions,
    CredentialDescriptor, CredentialParameters, CredentialProperties, ExtensionInputs,
    ExtensionOutputs, PrfInputs, PrfOutputs, PrfValues, RegistrationResponse, RelyingPartyEntity,
    RequestOptions, UserEntity,
};
pub use key::Algorithm;
pub use origin::{Caller, ClientData};
pub use record::PasskeyRecord;
pub use vault::{Candidate, PasskeyMatch, Target};
