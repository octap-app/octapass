//! Long-term server secrets, generated on first start and kept in the data
//! directory with owner-only permissions.
//!
//! Losing the OPAQUE server setup locks every account out, so back up the data
//! directory, not just the database.

use std::fs::{self, DirBuilder, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use opaque_ke::ServerSetup;
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::crypto::{Suite, random_bytes};

pub(crate) const OPAQUE_SETUP_FILE: &str = "opaque-server-setup.bin";
pub(crate) const SERVER_SECRET_FILE: &str = "server-secret.bin";

pub struct ServerSecrets {
    pub opaque_setup: ServerSetup<Suite>,
    /// Keys the fake prelogin salts and the verification code hashes.
    pub hmac_key: Zeroizing<[u8; 32]>,
}

impl ServerSecrets {
    pub fn load_or_create(data_dir: &Path) -> io::Result<Self> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(data_dir)?;

        let setup_bytes = load_or_create_file(&data_dir.join(OPAQUE_SETUP_FILE), || {
            ServerSetup::<Suite>::new(&mut OsRng).serialize().to_vec()
        })?;
        let opaque_setup = ServerSetup::<Suite>::deserialize(&setup_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{OPAQUE_SETUP_FILE} is corrupt"),
            )
        })?;

        let secret_bytes = load_or_create_file(&data_dir.join(SERVER_SECRET_FILE), || {
            random_bytes::<32>().to_vec()
        })?;
        let hmac_key: [u8; 32] = secret_bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{SERVER_SECRET_FILE} is corrupt"),
            )
        })?;

        Ok(Self {
            opaque_setup,
            hmac_key: Zeroizing::new(hmac_key),
        })
    }
}

fn load_or_create_file(
    path: &Path,
    generate: impl FnOnce() -> Vec<u8>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            let bytes = Zeroizing::new(generate());
            file.write_all(&bytes)?;
            file.sync_all()?;
            tracing::info!(path = %path.display(), "generated server secret");
            Ok(bytes)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            // Tighten permissions in case the file was restored from a backup.
            fs::set_permissions(path, Permissions::from_mode(0o600))?;
            Ok(Zeroizing::new(fs::read(path)?))
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_once_with_owner_only_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let first = ServerSecrets::load_or_create(dir.path()).unwrap();
        let second = ServerSecrets::load_or_create(dir.path()).unwrap();

        assert_eq!(
            first.opaque_setup.serialize(),
            second.opaque_setup.serialize()
        );
        assert_eq!(*first.hmac_key, *second.hmac_key);
        for file in [OPAQUE_SETUP_FILE, SERVER_SECRET_FILE] {
            let mode = fs::metadata(dir.path().join(file))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{file}");
        }
    }

    #[test]
    fn rejects_a_corrupt_secret() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(SERVER_SECRET_FILE), b"short").unwrap();
        assert!(ServerSecrets::load_or_create(dir.path()).is_err());
    }
}
