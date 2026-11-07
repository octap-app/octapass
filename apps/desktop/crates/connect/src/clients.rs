//! The clients a person approved. Only the SHA-256 of each session token is kept, in a file
//! readable only by the user.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// How long an approval lasts.
pub const TOKEN_LIFETIME_SECONDS: u64 = 30 * 86_400;
pub const MAX_NAME_CHARS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Client {
    pub id: String,
    /// What the client calls itself. Only a claim.
    pub name: String,
    /// The program that was approved, where the OS tells us. Its later requests must come from
    /// the same program.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// Unix seconds.
    pub approved_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    /// base64url SHA-256 of the token.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    token_hash: String,
}

fn hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// Constant-time, though the hash already hides how much of a token matched.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

pub struct Clients {
    path: PathBuf,
    clients: Vec<Client>,
}

impl Clients {
    pub fn path(folder: &Path) -> PathBuf {
        folder.join("clients.json")
    }

    /// Loads the file. A damaged one counts as empty: every client asks again, which is safe.
    pub fn open(folder: &Path) -> Self {
        let path = Self::path(folder);
        let clients = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self { path, clients }
    }

    fn save(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.clients).expect("clients serialize");
        let temp = self.path.with_extension("tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temp, &self.path)
    }

    /// Records an approval and returns the client with its session token, the only copy.
    pub fn approve(
        &mut self,
        name: &str,
        program: Option<String>,
        now: u64,
    ) -> io::Result<(Client, Zeroizing<String>)> {
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        let token = Zeroizing::new(format!("opc1_{}", URL_SAFE_NO_PAD.encode(token)));
        let mut id = [0u8; 8];
        OsRng.fill_bytes(&mut id);
        let client = Client {
            id: URL_SAFE_NO_PAD.encode(id),
            name: name.to_owned(),
            program,
            approved_at: now,
            expires_at: now + TOKEN_LIFETIME_SECONDS,
            last_used_at: None,
            token_hash: hash(&token),
        };
        self.clients.retain(|client| client.expires_at > now);
        self.clients.push(client.clone());
        self.save()?;
        Ok((client, token))
    }

    /// The client this token belongs to, when it's still good and, when both are known, comes
    /// from the program that was approved. Reads the file first, so a revocation from another
    /// process counts at once.
    pub fn authenticate(&mut self, token: &str, program: Option<&str>, now: u64) -> Option<Client> {
        *self = Self::open(self.path.parent()?);
        let wanted = hash(token.trim());
        let client = self
            .clients
            .iter_mut()
            .find(|client| same(&client.token_hash, &wanted))?;
        if client.expires_at <= now {
            return None;
        }
        if let (Some(approved), Some(program)) = (&client.program, program)
            && approved != program
        {
            return None;
        }
        client.last_used_at = Some(now);
        let found = client.clone();
        // Best effort: it's a convenience for `octapass connect clients`.
        let _ = self.save();
        Some(found)
    }

    pub fn list(&self) -> Vec<Client> {
        self.clients
            .iter()
            .cloned()
            .map(|mut client| {
                client.token_hash.clear();
                client
            })
            .collect()
    }

    /// `false` when no client has that id.
    pub fn revoke(&mut self, id: &str) -> io::Result<bool> {
        let before = self.clients.len();
        self.clients.retain(|client| client.id != id);
        if self.clients.len() == before {
            return Ok(false);
        }
        self.save()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn a_token_works_until_it_expires_or_is_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let mut clients = Clients::open(dir.path());
        let (client, token) = clients.approve("VS Code", None, NOW).unwrap();
        assert_eq!(
            clients.authenticate(&token, None, NOW + 1).unwrap().id,
            client.id
        );
        assert!(clients.authenticate("opc1_wrong", None, NOW).is_none());
        let late = NOW + TOKEN_LIFETIME_SECONDS;
        assert!(clients.authenticate(&token, None, late).is_none());

        let mut other = Clients::open(dir.path());
        assert!(other.revoke(&client.id).unwrap());
        assert!(!other.revoke(&client.id).unwrap());
        assert!(
            clients.authenticate(&token, None, NOW + 2).is_none(),
            "another process's revocation counts"
        );
    }

    #[test]
    fn only_a_hash_is_stored_and_listing_leaves_it_out() {
        let dir = tempfile::tempdir().unwrap();
        let mut clients = Clients::open(dir.path());
        let (_, token) = clients.approve("x", None, NOW).unwrap();
        let text = fs::read_to_string(Clients::path(dir.path())).unwrap();
        assert!(!text.contains(token.as_str()));
        assert!(text.contains("tokenHash"));
        let listed = serde_json::to_string(&clients.list()).unwrap();
        assert!(!listed.contains("tokenHash"));
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut clients = Clients::open(dir.path());
        clients.approve("x", None, NOW).unwrap();
        let mode = fs::metadata(Clients::path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_token_is_bound_to_the_approved_program() {
        let dir = tempfile::tempdir().unwrap();
        let mut clients = Clients::open(dir.path());
        let (_, token) = clients
            .approve("IDE", Some("/usr/bin/ide".into()), NOW)
            .unwrap();
        assert!(
            clients
                .authenticate(&token, Some("/usr/bin/ide"), NOW)
                .is_some()
        );
        assert!(
            clients
                .authenticate(&token, Some("/tmp/evil"), NOW)
                .is_none()
        );
        // Over loopback the OS can't say who's calling.
        assert!(clients.authenticate(&token, None, NOW).is_some());
    }

    #[test]
    fn a_damaged_file_means_everyone_asks_again() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(Clients::path(dir.path()), "not json").unwrap();
        assert!(Clients::open(dir.path()).list().is_empty());
    }
}
