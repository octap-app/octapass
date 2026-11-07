//! OpenPGP keys for signing Git commits (plan 16): read a private key, and make detached
//! signatures the way `gpg -bsa` does, on the device only.
//!
//! The vault keeps the key as the armored block it came in, with its passphrase next to it when it
//! has one: rewriting a key without its protection isn't something rPGP offers, and the vault
//! encrypts both.
//!
//! RSA OpenPGP keys are read but can't sign: rPGP signs them with the `rsa` crate, and
//! RUSTSEC-2023-0071 is still open (plan 16). [`GpgKey::can_sign`] says so before anyone tries.

use std::io::Cursor;

use pgp::composed::{ArmorOptions, Deserializable, DetachedSignature, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{SecretKey, SecretSubkey};
use pgp::types::{KeyDetails, Password};
use rand_core::OsRng;
use serde::Serialize;

use crate::error::{Error, Result};

/// What can be shown without the private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpgKey {
    /// The primary key's fingerprint, upper-case hex without spaces.
    pub fingerprint: String,
    /// The last 16 hex digits of the fingerprint for v4 keys, as `gpg --keyid-format=long` shows.
    pub key_id: String,
    /// The first User ID, usually `Name <email>`.
    pub user_id: String,
    /// The public key block, for GitHub's or GitLab's settings.
    pub public_key: String,
    /// False for keys that can't sign here: RSA keys (see the module's documentation) and keys
    /// with no signing key at all.
    pub can_sign: bool,
    /// The fingerprints of the key and its subkeys, so `user.signingkey` can name either.
    pub fingerprints: Vec<String>,
}

enum Signer<'a> {
    Primary(&'a SecretKey),
    Subkey(&'a SecretSubkey),
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn parse(armored: &str) -> Result<SignedSecretKey> {
    let (key, _) =
        SignedSecretKey::from_string(armored.trim()).map_err(|_| Error::InvalidGpgKey)?;
    Ok(key)
}

/// The key that signs: the newest subkey that may, otherwise the primary key.
fn signer(key: &SignedSecretKey) -> Option<Signer<'_>> {
    let subkey = key
        .secret_subkeys
        .iter()
        .filter(|subkey| {
            subkey
                .signatures
                .iter()
                .any(|signature| signature.key_flags().sign())
        })
        .max_by_key(|subkey| subkey.key.created_at());
    if let Some(subkey) = subkey {
        return Some(Signer::Subkey(&subkey.key));
    }
    let may_sign = key
        .details
        .users
        .iter()
        .flat_map(|user| &user.signatures)
        .any(|signature| signature.key_flags().sign());
    may_sign.then_some(Signer::Primary(&key.primary_key))
}

fn is_rsa(algorithm: PublicKeyAlgorithm) -> bool {
    matches!(
        algorithm,
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSASign | PublicKeyAlgorithm::RSAEncrypt
    )
}

fn can_sign(key: &SignedSecretKey) -> bool {
    match signer(key) {
        Some(Signer::Primary(primary)) => !is_rsa(primary.algorithm()),
        Some(Signer::Subkey(subkey)) => !is_rsa(subkey.algorithm()),
        None => false,
    }
}

/// Reads an armored private key. A wrong passphrase is [`Error::WrongPassphrase`]; a missing one
/// on a protected key is [`Error::WrongPassphrase`] too, since OpenPGP can't tell them apart.
pub fn read_private_key(armored: &str, passphrase: Option<&str>) -> Result<GpgKey> {
    let key = parse(armored)?;
    let public = key.to_public_key();
    let user_id = key
        .details
        .users
        .first()
        .map(|user| String::from_utf8_lossy(user.id.id()).into_owned())
        .unwrap_or_default();
    let mut fingerprints = vec![hex(key.primary_key.fingerprint().as_bytes())];
    fingerprints.extend(
        key.secret_subkeys
            .iter()
            .map(|subkey| hex(subkey.key.fingerprint().as_bytes())),
    );
    let info = GpgKey {
        fingerprint: fingerprints[0].clone(),
        key_id: hex(key.primary_key.legacy_key_id().as_ref()),
        user_id,
        public_key: public
            .to_armored_string(ArmorOptions::default())
            .map_err(|_| Error::InvalidGpgKey)?,
        can_sign: can_sign(&key),
        fingerprints,
    };
    if info.can_sign {
        // Trying it is the only way to learn whether the passphrase is right.
        sign_with(&key, passphrase, b"openpass")?;
    }
    Ok(info)
}

fn sign_with(key: &SignedSecretKey, passphrase: Option<&str>, data: &[u8]) -> Result<String> {
    if !can_sign(key) {
        return Err(Error::UnsupportedSshKey);
    }
    let password = Password::from(passphrase.unwrap_or_default());
    let signature = match signer(key).ok_or(Error::InvalidGpgKey)? {
        Signer::Primary(primary) => DetachedSignature::sign_binary_data(
            OsRng,
            primary,
            &password,
            HashAlgorithm::Sha512,
            Cursor::new(data),
        ),
        Signer::Subkey(subkey) => DetachedSignature::sign_binary_data(
            OsRng,
            subkey,
            &password,
            HashAlgorithm::Sha512,
            Cursor::new(data),
        ),
    }
    .map_err(|_| Error::WrongPassphrase)?;
    signature
        .to_armored_string(ArmorOptions::default())
        .map_err(|_| Error::InvalidGpgKey)
}

/// A detached, armored signature over `data`, as `gpg --detach-sign --armor` writes it.
pub fn sign_detached(armored: &str, passphrase: Option<&str>, data: &[u8]) -> Result<String> {
    sign_with(&parse(armored)?, passphrase, data)
}

/// The fingerprint of the key that signs, as `SIG_CREATED` reports it, and its algorithm's OpenPGP
/// number.
pub fn signing_key(armored: &str) -> Result<(String, u8)> {
    let key = parse(armored)?;
    let (fingerprint, algorithm) = match signer(&key).ok_or(Error::InvalidGpgKey)? {
        Signer::Primary(primary) => (primary.fingerprint(), primary.algorithm()),
        Signer::Subkey(subkey) => (subkey.fingerprint(), subkey.algorithm()),
    };
    Ok((hex(fingerprint.as_bytes()), algorithm.into()))
}
