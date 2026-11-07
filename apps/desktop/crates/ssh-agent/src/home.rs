//! `~/.ssh` in the desktop app: reading the keys that are there, writing a key from the vault back,
//! and pointing SSH at the agent. Everything happens on the user's request, a file at a time.
//! Private keys are written readable only by the user, and nothing is replaced unless asked.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use octapass_core::Error as CoreError;
use octapass_core::tools::ssh::{self, SshKey};
use serde::Serialize;
use zeroize::Zeroizing;

/// Key files are a few kilobytes; a scan skips anything much bigger.
const MAX_KEY_FILE: u64 = 64 * 1024;
const BEGIN: &str = "# >>> Octa Pass SSH agent >>>";
const END: &str = "# <<< Octa Pass SSH agent <<<";

/// A private key file found in `~/.ssh`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FoundKey {
    pub path: PathBuf,
    pub name: String,
    /// Asks for a passphrase. A protected key's details come from its `.pub`, if there is one.
    pub protected: bool,
    pub key_type: Option<String>,
    pub fingerprint: Option<String>,
    pub comment: Option<String>,
}

/// `~/.ssh`.
pub fn ssh_dir() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(".ssh"))
}

fn is_candidate(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    !name.ends_with(".pub")
        && !name.starts_with("known_hosts")
        && !name.starts_with('.')
        && !matches!(
            name,
            "config" | "authorized_keys" | "authorized_keys2" | "environment"
        )
}

/// The private keys in `dir`, by name. What doesn't read as a key is skipped quietly.
pub fn scan(dir: &Path) -> Vec<FoundKey> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<FoundKey> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .metadata()
                .is_ok_and(|meta| meta.is_file() && meta.len() <= MAX_KEY_FILE)
        })
        .map(|entry| entry.path())
        .filter(|path| is_candidate(path))
        .filter_map(found_key)
        .collect();
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

fn found_key(path: PathBuf) -> Option<FoundKey> {
    let text = Zeroizing::new(fs::read_to_string(&path).ok()?);
    let name = path.file_name()?.to_str()?.to_owned();
    match ssh::read_private_key(&text, None) {
        Ok(key) => Some(FoundKey {
            protected: false,
            key_type: Some(key.info.key_type),
            fingerprint: Some(key.info.fingerprint),
            comment: Some(key.info.comment).filter(|comment| !comment.is_empty()),
            path,
            name,
        }),
        Err(CoreError::SshPassphraseRequired) => {
            let public = fs::read_to_string(public_path(&path))
                .ok()
                .and_then(|line| ssh::read_public_key(&line).ok());
            Some(FoundKey {
                protected: true,
                key_type: public.as_ref().map(|info| info.key_type.clone()),
                fingerprint: public.as_ref().map(|info| info.fingerprint.clone()),
                comment: public
                    .map(|info| info.comment)
                    .filter(|comment| !comment.is_empty()),
                path,
                name,
            })
        }
        Err(_) => None,
    }
}

fn public_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// Reads a key file. The comment comes from the `.pub` next to it when the file has none and it's
/// the same key.
pub fn read(path: &Path, passphrase: Option<&str>) -> Result<SshKey, CoreError> {
    let text = fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|_| CoreError::InvalidSshKey)?;
    let mut key = ssh::read_private_key(&text, passphrase)?;
    if key.info.comment.is_empty()
        && let Ok(line) = fs::read_to_string(public_path(path))
        && let Ok(info) = ssh::read_public_key(&line)
        && info.public_key == key.info.public_key
    {
        key.info.comment = info.comment;
    }
    Ok(key)
}

/// A file name, not a path: the app writes only directly in `~/.ssh`.
pub fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | '+'))
        && !name.ends_with(".pub")
        && is_candidate(Path::new(name))
}

#[cfg(unix)]
fn create_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

fn create_file(path: &Path, mode: u32, replace: bool) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if replace {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    #[cfg(not(unix))]
    let _ = mode;
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    Ok(file)
}

/// Writes a key to `dir/name` (readable only by the user) and its `.pub` next to it. With
/// `replace` false, either file existing is [`io::ErrorKind::AlreadyExists`], and nothing changes.
pub fn write(
    dir: &Path,
    name: &str,
    private_key: &str,
    public_line: &str,
    replace: bool,
) -> io::Result<PathBuf> {
    if !valid_file_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a file name for ~/.ssh",
        ));
    }
    create_dir(dir)?;
    let path = dir.join(name);
    let public = public_path(&path);
    if !replace && public.exists() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    let mut file = create_file(&path, 0o600, replace)?;
    file.write_all(private_key.as_bytes())?;
    file.sync_all()?;
    let mut file = create_file(&public, 0o644, replace)?;
    file.write_all(public_line.trim_end().as_bytes())?;
    file.write_all(b"\n")?;
    Ok(path)
}

fn block(socket: &Path) -> String {
    format!(
        "{BEGIN}\nHost *\n  IdentityAgent \"{}\"\n{END}\n",
        socket.display()
    )
}

/// `text` without our block, if it has one.
fn without_block(text: &str) -> Option<String> {
    let start = text.find(BEGIN)?;
    let end = start + text[start..].find(END)? + END.len();
    let rest = text[end..].strip_prefix('\n').unwrap_or(&text[end..]);
    Some(format!("{}{rest}", &text[..start]))
}

/// Whether `~/.ssh/config` has the agent's block.
pub fn config_connected(dir: &Path) -> bool {
    fs::read_to_string(dir.join("config")).is_ok_and(|text| without_block(&text).is_some())
}

/// Adds the agent to `~/.ssh/config`, at the end: SSH takes the first value it finds, so a host
/// with its own `IdentityAgent` keeps it. The file's other lines aren't touched, and it's written
/// in place, so a config that's a link to dotfiles stays one.
pub fn connect_config(dir: &Path, socket: &Path) -> io::Result<()> {
    let path = dir.join("config");
    create_dir(dir)?;
    let text = match fs::read_to_string(&path) {
        Ok(text) => without_block(&text).unwrap_or(text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    let separator = if text.is_empty() || text.ends_with("\n\n") {
        ""
    } else if text.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    let updated = format!("{text}{separator}{}", block(socket));
    if path.exists() {
        fs::write(&path, updated)
    } else {
        create_file(&path, 0o600, false)?.write_all(updated.as_bytes())
    }
}

/// Takes the agent's block out of `~/.ssh/config`.
pub fn disconnect_config(dir: &Path) -> io::Result<()> {
    let path = dir.join("config");
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    match without_block(&text) {
        Some(rest) => {
            fs::write(&path, rest.trim_end_matches('\n').to_owned() + "\n").and_then(|()| {
                if rest.trim().is_empty() {
                    fs::write(&path, "")
                } else {
                    Ok(())
                }
            })
        }
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use octapass_core::tools::ssh::{SshKeyKind, generate, write_private_key};
    use rand_core::OsRng;

    use super::*;

    fn key_text(passphrase: Option<&str>) -> (String, ssh::SshKey) {
        let key = generate(SshKeyKind::Ed25519, "me@laptop", &mut OsRng).unwrap();
        let text =
            write_private_key(&key.private_key, "me@laptop", passphrase, &mut OsRng).unwrap();
        (text.to_string(), key)
    }

    #[test]
    fn a_scan_finds_keys_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let (plain, key) = key_text(None);
        let (protected, other) = key_text(Some("secret"));
        fs::write(dir.path().join("id_ed25519"), plain).unwrap();
        fs::write(dir.path().join("work"), protected).unwrap();
        fs::write(
            dir.path().join("work.pub"),
            format!("{} me@work\n", other.info.public_key),
        )
        .unwrap();
        for (name, text) in [
            ("config", "Host *\n"),
            ("known_hosts", "github.com ssh-ed25519 AAAA\n"),
            ("notes.txt", "not a key"),
            ("authorized_keys", "ssh-ed25519 AAAA x\n"),
        ] {
            fs::write(dir.path().join(name), text).unwrap();
        }
        fs::write(dir.path().join("huge"), vec![b'x'; 70_000]).unwrap();
        let found = scan(dir.path());
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].name, "id_ed25519");
        assert!(!found[0].protected);
        assert_eq!(
            found[0].fingerprint.as_deref(),
            Some(key.info.fingerprint.as_str())
        );
        assert_eq!(found[1].name, "work");
        assert!(found[1].protected);
        assert_eq!(
            found[1].fingerprint.as_deref(),
            Some(other.info.fingerprint.as_str())
        );
        assert_eq!(found[1].comment.as_deref(), Some("me@work"));
        assert!(scan(&dir.path().join("missing")).is_empty());
    }

    #[test]
    fn keys_read_with_their_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let (protected, key) = key_text(Some("secret"));
        let path = dir.path().join("work");
        fs::write(&path, protected).unwrap();
        assert_eq!(
            read(&path, None).unwrap_err(),
            CoreError::SshPassphraseRequired
        );
        assert_eq!(
            read(&path, Some("nope")).unwrap_err(),
            CoreError::WrongPassphrase
        );
        assert_eq!(
            read(&path, Some("secret")).unwrap().info.fingerprint,
            key.info.fingerprint
        );
    }

    #[test]
    fn writing_is_private_and_never_replaces_unasked() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        let (text, key) = key_text(None);
        let line = format!("{} me", key.info.public_key);
        let path = write(&ssh, "id_vault", &text, &line, false).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
        assert_eq!(
            fs::read_to_string(ssh.join("id_vault.pub")).unwrap(),
            format!("{line}\n")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(&ssh.join("id_vault.pub")), 0o644);
            assert_eq!(mode(&ssh), 0o700);
        }
        let error = write(&ssh, "id_vault", "new", &line, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
        write(&ssh, "id_vault", "new", &line, true).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn file_names_stay_in_the_folder() {
        for name in ["id_ed25519", "github.com", "work-2024", "a@b+c_d"] {
            assert!(valid_file_name(name), "{name}");
        }
        for name in [
            "",
            "../id",
            "a/b",
            "a\\b",
            ".hidden",
            "config",
            "known_hosts",
            "x.pub",
            "with space",
        ] {
            assert!(!valid_file_name(name), "{name}");
        }
    }

    #[test]
    fn the_config_block_is_added_once_and_removed_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let socket = Path::new("/home/ada/.octapass/agent.sock");
        let config = dir.path().join("config");
        let original = "Host work\n  User ada\n";
        fs::write(&config, original).unwrap();
        assert!(!config_connected(dir.path()));
        connect_config(dir.path(), socket).unwrap();
        connect_config(dir.path(), socket).unwrap();
        let text = fs::read_to_string(&config).unwrap();
        assert!(config_connected(dir.path()));
        assert_eq!(text.matches(BEGIN).count(), 1);
        assert!(text.starts_with(original), "{text}");
        assert!(text.contains("IdentityAgent \"/home/ada/.octapass/agent.sock\""));
        disconnect_config(dir.path()).unwrap();
        assert_eq!(fs::read_to_string(&config).unwrap(), original);
        disconnect_config(dir.path()).unwrap();
    }

    #[test]
    fn a_new_config_is_private() {
        let dir = tempfile::tempdir().unwrap();
        connect_config(dir.path(), Path::new("/tmp/a.sock")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("config"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        disconnect_config(dir.path()).unwrap();
        assert_eq!(fs::read_to_string(dir.path().join("config")).unwrap(), "");
    }
}
