//! The record of what Connect handed out. Each entry is sealed under the account key and appended
//! here before the secret leaves, then sent to the security log. A secret is never handed out
//! without its entry on disk, so going offline loses nothing.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The most entries one upload carries (the server's limit).
pub const BATCH: usize = 100;

/// What an entry holds, before it's sealed. The server never sees this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    /// Unix seconds, on this device.
    pub at: u64,
    pub client_id: String,
    pub client_name: String,
    pub reference: String,
}

/// The sealed entries of one account that haven't reached the server yet.
pub struct Queue {
    path: PathBuf,
}

impl Queue {
    /// `account` is any stable name for the account: it's hashed into the file's name.
    pub fn open(folder: &Path, account: &str) -> Self {
        let digest = Sha256::digest(account.as_bytes());
        let name: String = digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Self {
            path: folder.join(format!("log-{name}.queue")),
        }
    }

    /// Appends and flushes to disk. Failing here must stop the secret being handed out.
    pub fn push(&self, sealed: &str) -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&self.path)?;
        writeln!(file, "{sealed}")?;
        file.sync_all()
    }

    /// The oldest entries, at most `BATCH`.
    pub fn peek(&self) -> io::Result<Vec<String>> {
        match File::open(&self.path) {
            Ok(file) => BufReader::new(file)
                .lines()
                .take(BATCH)
                .collect::<io::Result<Vec<_>>>(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    /// Drops the oldest `count` entries, once the server has them.
    pub fn remove(&self, count: usize) -> io::Result<()> {
        let text = fs::read_to_string(&self.path)?;
        let rest: Vec<&str> = text.lines().skip(count).collect();
        if rest.is_empty() {
            return fs::remove_file(&self.path);
        }
        let temp = self.path.with_extension("tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&temp)?;
        file.write_all((rest.join("\n") + "\n").as_bytes())?;
        file.sync_all()?;
        fs::rename(temp, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_wait_in_order_until_the_server_has_them() {
        let dir = tempfile::tempdir().unwrap();
        let queue = Queue::open(dir.path(), "https://a|ada@example.com");
        assert!(queue.peek().unwrap().is_empty());
        for n in 0..3 {
            queue.push(&format!("sealed{n}")).unwrap();
        }
        assert_eq!(queue.peek().unwrap(), ["sealed0", "sealed1", "sealed2"]);
        queue.remove(2).unwrap();
        assert_eq!(queue.peek().unwrap(), ["sealed2"]);
        queue.remove(1).unwrap();
        assert!(queue.peek().unwrap().is_empty());
    }

    #[test]
    fn uploads_are_batched() {
        let dir = tempfile::tempdir().unwrap();
        let queue = Queue::open(dir.path(), "a");
        for n in 0..BATCH + 5 {
            queue.push(&n.to_string()).unwrap();
        }
        assert_eq!(queue.peek().unwrap().len(), BATCH);
    }

    #[test]
    fn accounts_keep_separate_queues_named_by_hash() {
        let dir = tempfile::tempdir().unwrap();
        Queue::open(dir.path(), "ada@example.com")
            .push("a")
            .unwrap();
        assert!(
            Queue::open(dir.path(), "bob@example.com")
                .peek()
                .unwrap()
                .is_empty()
        );
        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!names[0].contains("ada"));
    }
}
