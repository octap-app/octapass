//! The ciphertext envelope: `version (0x01) ‖ key_id (16) ‖ nonce (24) ‖ ciphertext ‖ tag (16)`,
//! sealed with XChaCha20-Poly1305 and bound to a context through the associated data.

use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::encoding::{b64_decode, b64_encode};
use crate::error::{Error, Result};
use crate::keys::{KEY_ID_LEN, SymmetricKey};

pub const VERSION: u8 = 0x01;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = 1 + KEY_ID_LEN + NONCE_LEN;

/// What a ciphertext is for. It becomes the associated data `"openpass/v1|" + context`, so a
/// ciphertext only opens in the place it was sealed for: the server can't move a vault key into
/// another vault, or one item's details into another item.
#[derive(Clone, PartialEq, Eq)]
pub enum Context<'a> {
    Ask,
    PrivateKeys,
    /// The ML-KEM-768 seed, sealed by the ASK.
    PqPrivateKey,
    Recovery,
    DeviceUnlock,
    VaultKey {
        vault_id: &'a str,
    },
    ItemKey {
        vault_id: &'a str,
        item_id: &'a str,
    },
    ItemOverview {
        vault_id: &'a str,
        item_id: &'a str,
    },
    ItemDetails {
        vault_id: &'a str,
        item_id: &'a str,
    },
    /// An attachment's file key, sealed by the item key.
    AttachmentKey {
        vault_id: &'a str,
        item_id: &'a str,
        attachment_id: &'a str,
    },
    /// Every chunk of an attachment's file (see [`crate::attachment`]).
    Attachment {
        vault_id: &'a str,
        item_id: &'a str,
        attachment_id: &'a str,
    },
    /// ASK sealed by a local vault's Local Unlock Key.
    LocalAsk,
    /// A local vault's contents, sealed by its ASK.
    LocalVault,
    /// A backup file's key, sealed by the backup recovery code.
    BackupRecovery,
    /// A service account's name, sealed by its creator's ASK.
    ServiceAccountName {
        vault_id: &'a str,
        service_account_id: &'a str,
    },
    /// One security log entry only the account can read, sealed by its ASK.
    AuditDetail {
        account_id: &'a str,
    },
    /// A device chip's secret on its way from the desktop app to the browser extension.
    ChipSecret,
    /// One revision of a Safe object's record: its name, place and file key (see [`crate::safe`]).
    SafeRecord {
        safe_id: &'a str,
        blob_id: &'a str,
    },
    /// Every chunk of one revision of a file in a Safe (see [`crate::safe`]).
    SafeContent {
        safe_id: &'a str,
        object_id: &'a str,
        blob_id: &'a str,
    },
    /// A Safe's sync notes, kept on this device only.
    SafeState {
        safe_id: &'a str,
    },
    /// A chunk of a file being written to a Safe, under a key that lives only as long as the write.
    SafeStaging {
        index: u64,
    },
    /// One entry in a vault's save inbox, under its own entry key (see [`crate::inbox`]).
    InboxEntry {
        owner: &'a str,
        entry_id: &'a str,
    },
}

impl fmt::Display for Context<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Context::Ask => f.write_str("ask"),
            Context::PrivateKeys => f.write_str("privkeys"),
            Context::PqPrivateKey => f.write_str("pqprivkey"),
            Context::Recovery => f.write_str("recovery"),
            Context::DeviceUnlock => f.write_str("device-unlock"),
            Context::VaultKey { vault_id } => write!(f, "vaultkey:{vault_id}"),
            Context::ItemKey { vault_id, item_id } => write!(f, "itemkey:{vault_id}:{item_id}"),
            Context::ItemOverview { vault_id, item_id } => {
                write!(f, "item:{vault_id}:{item_id}:overview")
            }
            Context::ItemDetails { vault_id, item_id } => {
                write!(f, "item:{vault_id}:{item_id}:details")
            }
            Context::AttachmentKey {
                vault_id,
                item_id,
                attachment_id,
            } => write!(f, "attachmentkey:{vault_id}:{item_id}:{attachment_id}"),
            Context::Attachment {
                vault_id,
                item_id,
                attachment_id,
            } => write!(f, "attachment:{vault_id}:{item_id}:{attachment_id}"),
            Context::LocalAsk => f.write_str("local-ask"),
            Context::LocalVault => f.write_str("local-vault"),
            Context::BackupRecovery => f.write_str("backup-recovery"),
            Context::ServiceAccountName {
                vault_id,
                service_account_id,
            } => write!(f, "service-account-name:{vault_id}:{service_account_id}"),
            Context::AuditDetail { account_id } => write!(f, "audit-detail:{account_id}"),
            Context::ChipSecret => f.write_str("chip-secret"),
            Context::SafeRecord { safe_id, blob_id } => {
                write!(f, "saferecord:{safe_id}:{blob_id}")
            }
            Context::SafeContent {
                safe_id,
                object_id,
                blob_id,
            } => write!(f, "safecontent:{safe_id}:{object_id}:{blob_id}"),
            Context::SafeState { safe_id } => write!(f, "safestate:{safe_id}"),
            Context::SafeStaging { index } => write!(f, "safestaging:{index}"),
            Context::InboxEntry { owner, entry_id } => write!(f, "inbox-entry:{owner}:{entry_id}"),
        }
    }
}

impl Context<'_> {
    pub fn associated_data(&self) -> Vec<u8> {
        format!("openpass/v1|{self}").into_bytes()
    }
}

/// Seals `plaintext` under `key` with a fresh random nonce.
pub fn seal(
    key: &SymmetricKey,
    context: &Context<'_>,
    plaintext: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let aad = context.associated_data();
    let ciphertext = XChaCha20Poly1305::new(key.as_bytes().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::EncryptionFailed)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.push(VERSION);
    out.extend_from_slice(&key.key_id());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens an envelope sealed by [`seal`]. The plaintext is zeroed when dropped.
pub fn open(
    key: &SymmetricKey,
    context: &Context<'_>,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if envelope.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::MalformedCiphertext);
    }
    if envelope[0] != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if envelope[1..1 + KEY_ID_LEN] != key.key_id() {
        return Err(Error::WrongKey);
    }
    let nonce = XNonce::from_slice(&envelope[1 + KEY_ID_LEN..HEADER_LEN]);
    let aad = context.associated_data();
    XChaCha20Poly1305::new(key.as_bytes().into())
        .decrypt(
            nonce,
            Payload {
                msg: &envelope[HEADER_LEN..],
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::DecryptionFailed)
}

/// [`seal`] and encode as base64url, the form used on the wire and in JSON.
pub fn seal_b64(
    key: &SymmetricKey,
    context: &Context<'_>,
    plaintext: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<String> {
    seal(key, context, plaintext, rng).map(|bytes| b64_encode(&bytes))
}

/// Decode base64url and [`open`].
pub fn open_b64(
    key: &SymmetricKey,
    context: &Context<'_>,
    envelope: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    open(key, context, &b64_decode(envelope)?)
}

/// Seals another key under `key`.
pub fn wrap_key(
    key: &SymmetricKey,
    context: &Context<'_>,
    inner: &SymmetricKey,
    rng: &mut impl CryptoRngCore,
) -> Result<String> {
    seal_b64(key, context, inner.as_bytes(), rng)
}

/// Opens a key sealed by [`wrap_key`].
pub fn unwrap_key(
    key: &SymmetricKey,
    context: &Context<'_>,
    wrapped: &str,
) -> Result<SymmetricKey> {
    SymmetricKey::from_slice(&open_b64(key, context, wrapped)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(1)
    }

    const VAULT: Context<'static> = Context::VaultKey { vault_id: "v1" };

    #[test]
    fn context_strings_match_the_contract() {
        let (v, i) = ("V", "I");
        assert_eq!(Context::Ask.to_string(), "ask");
        assert_eq!(Context::PrivateKeys.to_string(), "privkeys");
        assert_eq!(Context::Recovery.to_string(), "recovery");
        assert_eq!(Context::DeviceUnlock.to_string(), "device-unlock");
        assert_eq!(Context::VaultKey { vault_id: v }.to_string(), "vaultkey:V");
        assert_eq!(
            Context::ItemKey {
                vault_id: v,
                item_id: i
            }
            .to_string(),
            "itemkey:V:I"
        );
        assert_eq!(
            Context::ItemOverview {
                vault_id: v,
                item_id: i
            }
            .to_string(),
            "item:V:I:overview"
        );
        assert_eq!(
            Context::ItemDetails {
                vault_id: v,
                item_id: i
            }
            .to_string(),
            "item:V:I:details"
        );
        let a = "A";
        assert_eq!(
            Context::AttachmentKey {
                vault_id: v,
                item_id: i,
                attachment_id: a
            }
            .to_string(),
            "attachmentkey:V:I:A"
        );
        assert_eq!(
            Context::Attachment {
                vault_id: v,
                item_id: i,
                attachment_id: a
            }
            .to_string(),
            "attachment:V:I:A"
        );
        assert_eq!(Context::LocalAsk.to_string(), "local-ask");
        assert_eq!(Context::LocalVault.to_string(), "local-vault");
        assert_eq!(Context::BackupRecovery.to_string(), "backup-recovery");
        assert_eq!(Context::ChipSecret.to_string(), "chip-secret");
        assert_eq!(Context::Ask.associated_data(), b"openpass/v1|ask");
    }

    #[test]
    fn layout() {
        let key = SymmetricKey::from_bytes([9; 32]);
        let sealed = seal(&key, &VAULT, b"abc", &mut rng()).unwrap();
        assert_eq!(sealed.len(), 1 + 16 + 24 + 3 + 16);
        assert_eq!(sealed[0], VERSION);
        assert_eq!(sealed[1..17], key.key_id());
    }

    #[test]
    fn rejects_wrong_key_context_and_tampering() {
        let key = SymmetricKey::from_bytes([9; 32]);
        let other = SymmetricKey::from_bytes([8; 32]);
        let sealed = seal(&key, &VAULT, b"secret", &mut rng()).unwrap();

        assert_eq!(open(&other, &VAULT, &sealed).unwrap_err(), Error::WrongKey);
        let moved = Context::VaultKey { vault_id: "v2" };
        assert_eq!(
            open(&key, &moved, &sealed).unwrap_err(),
            Error::DecryptionFailed
        );

        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            open(&key, &VAULT, &tampered).unwrap_err(),
            Error::DecryptionFailed
        );

        let mut versioned = sealed.clone();
        versioned[0] = 2;
        assert_eq!(
            open(&key, &VAULT, &versioned).unwrap_err(),
            Error::UnsupportedVersion
        );

        assert_eq!(
            open(&key, &VAULT, &sealed[..40]).unwrap_err(),
            Error::MalformedCiphertext
        );
    }

    #[test]
    fn nonces_are_fresh() {
        let key = SymmetricKey::from_bytes([9; 32]);
        let mut rng = rng();
        assert_ne!(
            seal(&key, &VAULT, b"x", &mut rng).unwrap(),
            seal(&key, &VAULT, b"x", &mut rng).unwrap()
        );
    }

    proptest! {
        #[test]
        fn round_trip(key in any::<[u8; 32]>(), seed in any::<u64>(), msg in proptest::collection::vec(any::<u8>(), 0..512)) {
            let key = SymmetricKey::from_bytes(key);
            let context = Context::ItemDetails { vault_id: "v", item_id: "i" };
            let sealed = seal_b64(&key, &context, &msg, &mut ChaCha20Rng::seed_from_u64(seed)).unwrap();
            let opened = open_b64(&key, &context, &sealed).unwrap();
            prop_assert_eq!(opened.as_slice(), msg.as_slice());
        }

        #[test]
        fn key_wrap_round_trip(outer in any::<[u8; 32]>(), inner in any::<[u8; 32]>()) {
            let outer = SymmetricKey::from_bytes(outer);
            let inner = SymmetricKey::from_bytes(inner);
            let wrapped = wrap_key(&outer, &Context::Ask, &inner, &mut rng()).unwrap();
            prop_assert_eq!(unwrap_key(&outer, &Context::Ask, &wrapped).unwrap(), inner);
        }
    }
}
