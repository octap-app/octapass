//! SSH keys on the phones (plan 16): the item's fields and the key operations, on the core's
//! `tools::ssh`. The labels and file names are the web vault's (`packages/vault-client/src/sshKeys.ts`).
//!
//! Showing, copying or saving a private key is the app's to gate: `confirmUser` first (plan 16 §6).

use octapass_core::tools::ssh as core_ssh;
use rand_core::OsRng;

use crate::error::Result;
use crate::items::CustomField;

/// An SSH key item. Generating or reading a key is the only way its first four fields change.
/// Newer clients' fields survive a save.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct SshKeyDetails {
    /// OpenSSH format, without a passphrase: the vault encrypts it.
    pub private_key: Option<String>,
    /// Without its comment: `ssh-ed25519 AAAA…`.
    pub public_key: Option<String>,
    /// The SSH algorithm's name, like `ssh-ed25519`.
    pub key_type: Option<String>,
    /// `SHA256:…`, as `ssh-keygen -l` shows it.
    pub fingerprint: Option<String>,
    pub comment: Option<String>,
    /// Protects copies written out of the vault; the stored key has none.
    pub passphrase: Option<String>,
    pub notes: Option<String>,
    pub custom_fields: Vec<CustomField>,
}

/// The keys the editor can make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SshKeyKind {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa3072,
    Rsa4096,
}

impl From<SshKeyKind> for core_ssh::SshKeyKind {
    fn from(kind: SshKeyKind) -> Self {
        match kind {
            SshKeyKind::Ed25519 => Self::Ed25519,
            SshKeyKind::EcdsaP256 => Self::EcdsaP256,
            SshKeyKind::EcdsaP384 => Self::EcdsaP384,
            SshKeyKind::Rsa3072 => Self::Rsa3072,
            SshKeyKind::Rsa4096 => Self::Rsa4096,
        }
    }
}

/// A kind the editor offers. `name` is its catalog key: `sshKey.kinds.<name>`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SshKeyKindChoice {
    pub kind: SshKeyKind,
    pub name: String,
}

#[uniffi::export]
pub fn ssh_key_kinds() -> Vec<SshKeyKindChoice> {
    [
        (SshKeyKind::Ed25519, "ed25519"),
        (SshKeyKind::EcdsaP256, "ecdsaP256"),
        (SshKeyKind::EcdsaP384, "ecdsaP384"),
        (SshKeyKind::Rsa3072, "rsa3072"),
        (SshKeyKind::Rsa4096, "rsa4096"),
    ]
    .into_iter()
    .map(|(kind, name)| SshKeyKindChoice {
        kind,
        name: name.into(),
    })
    .collect()
}

/// A key ready for the vault: pass it to `withSshKey`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SshKeyMaterial {
    pub private_key: String,
    pub public_key: String,
    pub key_type: String,
    pub fingerprint: String,
    pub comment: String,
    /// False for keys stored but not usable yet: DSA, and FIDO (`sk-`) keys.
    pub usable: bool,
}

impl From<core_ssh::SshKey> for SshKeyMaterial {
    fn from(key: core_ssh::SshKey) -> Self {
        Self {
            private_key: key.private_key.to_string(),
            public_key: key.info.public_key,
            key_type: key.info.key_type,
            fingerprint: key.info.fingerprint,
            comment: key.info.comment,
            usable: key.info.usable,
        }
    }
}

pub(crate) fn generate(kind: SshKeyKind, comment: &str) -> Result<SshKeyMaterial> {
    Ok(core_ssh::generate(kind.into(), comment.trim(), &mut OsRng)?.into())
}

pub(crate) fn read(text: &str, passphrase: Option<&str>) -> Result<SshKeyMaterial> {
    Ok(core_ssh::read_private_key(text, passphrase)?.into())
}

/// The file `export` writes: an OpenSSH private key, encrypted when there's a passphrase.
pub(crate) fn write(private_key: &str, comment: &str, passphrase: Option<&str>) -> Result<String> {
    let text = core_ssh::write_private_key(
        private_key,
        comment.trim(),
        passphrase.filter(|p| !p.is_empty()),
        &mut OsRng,
    )?;
    Ok(text.to_string())
}

/// `details` with `key`'s fields; a comment typed before generating or reading wins over the
/// file's. A passphrase is kept only when the user asked to. Notes and the rest stay.
#[uniffi::export]
pub fn with_ssh_key(
    details: SshKeyDetails,
    key: SshKeyMaterial,
    passphrase: Option<String>,
) -> SshKeyDetails {
    let comment = details
        .comment
        .clone()
        .filter(|c| !c.is_empty())
        .or(Some(key.comment).filter(|c| !c.is_empty()));
    SshKeyDetails {
        private_key: Some(key.private_key),
        public_key: Some(key.public_key),
        key_type: Some(key.key_type),
        fingerprint: Some(key.fingerprint),
        comment,
        passphrase: passphrase.filter(|p| !p.is_empty()).or(details.passphrase),
        ..details
    }
}

/// The `authorized_keys` line: the public key, a space and the comment. Empty without a key.
#[uniffi::export]
pub fn authorized_keys_line(details: SshKeyDetails) -> String {
    let key = details.public_key.as_deref().unwrap_or_default().trim();
    match details.comment.as_deref().map(str::trim) {
        Some(comment) if !comment.is_empty() && !key.is_empty() => format!("{key} {comment}"),
        _ => key.to_owned(),
    }
}

fn type_label(name: &str) -> &str {
    match name {
        "ssh-ed25519" => "Ed25519",
        "ecdsa-sha2-nistp256" => "ECDSA P-256",
        "ecdsa-sha2-nistp384" => "ECDSA P-384",
        "ecdsa-sha2-nistp521" => "ECDSA P-521",
        "ssh-rsa" => "RSA",
        "ssh-dss" => "DSA",
        "sk-ssh-ed25519@openssh.com" => "Ed25519 (security key)",
        "sk-ecdsa-sha2-nistp256@openssh.com" => "ECDSA P-256 (security key)",
        other => other,
    }
}

/// "Ed25519", "ECDSA P-256", "RSA 4096": the type people know, with the size where it varies.
#[uniffi::export]
pub fn ssh_key_type_label(details: SshKeyDetails) -> Option<String> {
    let public = details.public_key.as_deref().unwrap_or_default();
    let name = details
        .key_type
        .clone()
        .filter(|t| !t.is_empty())
        .or_else(|| public.split_whitespace().next().map(str::to_owned))?;
    let label = type_label(&name);
    let bits = matches!(name.as_str(), "ssh-rsa" | "ssh-dss")
        .then(|| core_ssh::read_public_key(public).ok())
        .flatten()
        .map(|info| info.bits);
    Some(match bits {
        Some(bits) => format!("{label} {bits}"),
        None => label.to_owned(),
    })
}

/// DSA and FIDO (`sk-`) keys are stored but can't be used yet.
#[uniffi::export]
pub fn is_usable_ssh_key(details: SshKeyDetails) -> bool {
    let name = details.key_type.as_deref().unwrap_or_default();
    name == "ssh-ed25519" || name == "ssh-rsa" || name.starts_with("ecdsa-sha2-")
}

/// A file name for the private key: the title in lower case, `id_<type>` when there's none. The
/// public key's is this and `.pub`.
#[uniffi::export]
pub fn ssh_key_file_name(title: String, details: SshKeyDetails) -> String {
    let mut base = String::new();
    let mut gap = false;
    for c in title.trim().to_lowercase().chars() {
        if c.is_alphanumeric() || matches!(c, '.' | '_' | '-') {
            base.push(c);
            gap = false;
        } else if !gap {
            base.push('_');
            gap = true;
        }
    }
    let base = base
        .trim_start_matches(['.', '_'])
        .trim_end_matches('_')
        .to_owned();
    if !base.is_empty() {
        return base;
    }
    let name = details.key_type.as_deref().unwrap_or_default();
    if name.contains("ed25519") {
        "id_ed25519"
    } else if name.contains("ecdsa") {
        "id_ecdsa"
    } else if name == "ssh-dss" {
        "id_dsa"
    } else {
        "id_rsa"
    }
    .into()
}

pub(crate) fn details_from_core(key: octapass_core::item::SshKeyDetails) -> SshKeyDetails {
    SshKeyDetails {
        private_key: key.private_key,
        public_key: key.public_key,
        key_type: key.key_type,
        fingerprint: key.fingerprint,
        comment: key.comment,
        passphrase: key.passphrase,
        notes: key.notes,
        custom_fields: key
            .custom_fields
            .unwrap_or_default()
            .into_iter()
            .map(|f| CustomField {
                label: f.label,
                value: f.value,
                hidden: f.hidden,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    const ED25519: &str = include_str!("../../octapass-core/tests/ssh-fixtures/ed25519");
    const ED25519_PASS: &str = include_str!("../../octapass-core/tests/ssh-fixtures/ed25519-pass");
    const RSA_PUB: &str = include_str!("../../octapass-core/tests/ssh-fixtures/rsa-4096-pass.pub");

    #[test]
    fn a_generated_key_reads_back_and_fills_the_item() {
        let made = generate(SshKeyKind::Ed25519, " me@phone ").unwrap();
        assert_eq!(made.key_type, "ssh-ed25519");
        assert_eq!(made.comment, "me@phone");
        assert!(made.fingerprint.starts_with("SHA256:"));
        let read_back = read(&made.private_key, None).unwrap();
        assert_eq!(read_back.fingerprint, made.fingerprint);

        let details = with_ssh_key(
            SshKeyDetails {
                comment: Some("typed first".into()),
                notes: Some("keep".into()),
                ..SshKeyDetails::default()
            },
            made.clone(),
            None,
        );
        assert_eq!(details.comment.as_deref(), Some("typed first"));
        assert_eq!(details.notes.as_deref(), Some("keep"));
        assert_eq!(details.fingerprint.as_ref(), Some(&made.fingerprint));
        assert_eq!(
            authorized_keys_line(details),
            format!("{} typed first", made.public_key)
        );
    }

    #[test]
    fn a_protected_key_asks_for_its_passphrase() {
        assert_eq!(
            read(ED25519_PASS, None).unwrap_err().code(),
            ErrorCode::SshPassphraseRequired
        );
        assert_eq!(
            read(ED25519_PASS, Some("wrong")).unwrap_err().code(),
            ErrorCode::WrongPassphrase
        );
        assert_eq!(
            read("not a key", None).unwrap_err().code(),
            ErrorCode::InvalidSshKey
        );
        assert_eq!(
            read(RSA_PUB, None).unwrap_err().code(),
            ErrorCode::SshPublicKeyOnly
        );
    }

    #[test]
    fn a_written_copy_takes_a_passphrase() {
        let key = read(ED25519, None).unwrap();
        let plain = write(&key.private_key, "c", None).unwrap();
        assert_eq!(read(&plain, None).unwrap().fingerprint, key.fingerprint);
        let locked = write(&key.private_key, "c", Some("hunter2")).unwrap();
        assert_eq!(
            read(&locked, None).unwrap_err().code(),
            ErrorCode::SshPassphraseRequired
        );
        assert_eq!(
            read(&locked, Some("hunter2")).unwrap().fingerprint,
            key.fingerprint
        );
    }

    #[test]
    fn labels_and_file_names_follow_the_web_vault() {
        let label = |key_type: &str, public: &str| {
            ssh_key_type_label(SshKeyDetails {
                key_type: Some(key_type.into()),
                public_key: Some(public.into()),
                ..SshKeyDetails::default()
            })
        };
        assert_eq!(label("ssh-ed25519", "").as_deref(), Some("Ed25519"));
        assert_eq!(
            label("ecdsa-sha2-nistp256", "").as_deref(),
            Some("ECDSA P-256")
        );
        assert_eq!(label("ssh-rsa", RSA_PUB).as_deref(), Some("RSA 4096"));
        assert_eq!(ssh_key_type_label(SshKeyDetails::default()), None);

        let file = |title: &str, key_type: &str| {
            ssh_key_file_name(
                title.into(),
                SshKeyDetails {
                    key_type: Some(key_type.into()),
                    ..SshKeyDetails::default()
                },
            )
        };
        assert_eq!(file(" Deploy Key (prod) ", "ssh-rsa"), "deploy_key_prod");
        assert_eq!(file("  ", "ssh-ed25519"), "id_ed25519");
        assert_eq!(file("...", "ecdsa-sha2-nistp256"), "id_ecdsa");
        assert_eq!(file("", "ssh-dss"), "id_dsa");
        assert_eq!(file("", ""), "id_rsa");

        assert!(is_usable_ssh_key(SshKeyDetails {
            key_type: Some("ecdsa-sha2-nistp384".into()),
            ..SshKeyDetails::default()
        }));
        assert!(!is_usable_ssh_key(SshKeyDetails {
            key_type: Some("ssh-dss".into()),
            ..SshKeyDetails::default()
        }));
    }
}
