//! The local channel between the host and the running desktop app: a Unix socket in the app's
//! data folder (readable only by the user), or a named pipe on Windows. One connection carries
//! one request line and one reply line.
//!
//! On macOS the app is the native Mac app (plan 19), which is sandboxed: its sockets are in its
//! App Group container, `~/Library/Group Containers/<team>.app.octap`, the one folder both it
//! and the programs that connect (this host, the CLI, SSH clients) can reach.

use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::protocol::{Forwarded, Reply};

/// Tauri's app identifier, which names the app's data folder.
pub const APP_IDENTIFIER: &str = "app.octap.desktop";
/// Overrides the data folder for development and tests; the app and the host both read it.
pub const DATA_DIR_ENV: &str = "OCTAPASS_DESKTOP_DATA_DIR";
/// The user may take a while to answer a Touch ID or Windows Hello prompt.
const REPLY_TIMEOUT: Duration = Duration::from_secs(300);

/// The bridge's socket in the app's data folder.
pub const SOCKET_NAME: &str = "native-host.sock";
/// The native Mac app's App Group, after its team's prefix: `<team>.app.octap`.
pub const APP_GROUP: &str = "app.octap";

/// The desktop app's data folder: on macOS the native app's App Group container, elsewhere the
/// Tauri app's data folder. [`DATA_DIR_ENV`] overrides it.
pub fn data_dir() -> Option<PathBuf> {
    match std::env::var_os(DATA_DIR_ENV) {
        Some(dir) if !dir.is_empty() => Some(PathBuf::from(dir)),
        _ => default_data_dir(),
    }
}

/// The host is signed by the app's own team, so that names the container.
#[cfg(target_os = "macos")]
fn default_data_dir() -> Option<PathBuf> {
    app_group_container(SOCKET_NAME, crate::system::own_team())
}

#[cfg(not(target_os = "macos"))]
fn default_data_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|dir| dir.join(APP_IDENTIFIER))
}

/// This user's home folder from their account record. A sandboxed app's `HOME` is its own
/// container, so `dirs::home_dir` would name that instead.
#[cfg(target_os = "macos")]
pub fn user_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: plain data, filled in by `getpwuid_r`.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    // SAFETY: the buffer and the entry outlive the call, and their sizes are what we say.
    let status = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        )
    };
    if status != 0 || found.is_null() || entry.pw_dir.is_null() {
        return dirs::home_dir();
    }
    // SAFETY: `pw_dir` points into `buffer`, NUL-terminated.
    let dir = unsafe { CStr::from_ptr(entry.pw_dir) };
    Some(PathBuf::from(OsStr::from_bytes(dir.to_bytes())))
}

#[cfg(not(target_os = "macos"))]
pub fn user_home() -> Option<PathBuf> {
    dirs::home_dir()
}

/// The native Mac app's App Group container, `~/Library/Group Containers/<team>.app.octap`,
/// where it keeps its sockets. `team` is the app's team when known (this host is signed by it).
/// Without it (the CLI, a build that isn't signed), the container with `socket` in it; the most
/// recently started app's when there are several.
#[cfg(target_os = "macos")]
pub fn app_group_container(socket: &str, team: Option<String>) -> Option<PathBuf> {
    let containers = user_home()?.join("Library").join("Group Containers");
    match team {
        Some(team) => Some(containers.join(format!("{team}.{APP_GROUP}"))),
        None => find_container(&containers, socket),
    }
}

/// The `<team>.app.octap` folder in `containers` that has `socket`, the newest one first.
#[cfg(any(target_os = "macos", all(test, unix)))]
fn find_container(containers: &Path, socket: &str) -> Option<PathBuf> {
    let suffix = format!(".{APP_GROUP}");
    std::fs::read_dir(containers)
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            name.to_str()
                .and_then(|name| name.strip_suffix(&suffix))
                .is_some_and(|team| {
                    team.len() == 10
                        && team
                            .bytes()
                            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
                })
        })
        .filter_map(|entry| {
            let modified = std::fs::symlink_metadata(entry.path().join(socket))
                .and_then(|metadata| metadata.modified())
                .ok()?;
            Some((modified, entry.path()))
        })
        .max_by_key(|(modified, _)| *modified)
        .map(|(_, path)| path)
}

/// Where the app listens: in the data folder, or, when that path is too long for a socket
/// address (about 100 bytes), in the user's temporary folder under a name derived from it. Not
/// on macOS: the sandboxed app's temporary folder is its own, so the socket is always in its
/// container (whose path is short enough for any but the longest user names).
#[cfg(unix)]
pub fn endpoint(data_dir: &Path) -> PathBuf {
    const MAX_SOCKET_PATH: usize = 100;
    let path = data_dir.join(SOCKET_NAME);
    if cfg!(target_os = "macos") || path.as_os_str().len() <= MAX_SOCKET_PATH {
        return path;
    }
    std::env::temp_dir().join(format!("octapass-{:016x}.sock", path_hash(data_dir)))
}

/// A stable hash: the app and the host must agree on it across processes.
fn path_hash(path: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

/// Where the app listens: a pipe named after the data folder, so each user (and each test
/// folder) gets its own.
#[cfg(windows)]
pub fn endpoint(data_dir: &Path) -> PathBuf {
    PathBuf::from(format!(
        r"\\.\pipe\octapass-desktop-{:016x}",
        path_hash(data_dir)
    ))
}

/// Sends one request to the app and waits for its reply.
pub fn request(endpoint: &Path, forwarded: &Forwarded) -> io::Result<Reply> {
    let stream = connect(endpoint)?;
    let mut line = serde_json::to_vec(forwarded).expect("requests serialize");
    line.push(b'\n');
    (&stream).write_all(&line)?;
    let mut reply = String::new();
    BufReader::new(&stream).read_line(&mut reply)?;
    serde_json::from_str(&reply).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(unix)]
fn connect(endpoint: &Path) -> io::Result<std::os::unix::net::UnixStream> {
    let stream = std::os::unix::net::UnixStream::connect(endpoint)?;
    stream.set_read_timeout(Some(REPLY_TIMEOUT))?;
    Ok(stream)
}

#[cfg(windows)]
fn connect(endpoint: &Path) -> io::Result<std::fs::File> {
    // Named pipes have no read timeout; the app answers every request, with an error if needed.
    let _ = REPLY_TIMEOUT;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(endpoint)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::net::UnixListener;

    use serde_json::json;

    use super::*;
    use crate::protocol::{Message, Request};

    #[test]
    fn a_request_gets_the_apps_reply() {
        let dir = tempfile::tempdir().unwrap();
        let endpoint = endpoint(dir.path());
        let listener = UnixListener::bind(&endpoint).unwrap();
        let app = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let forwarded: Forwarded = serde_json::from_str(&line).unwrap();
            let reply = Reply::ok(forwarded.message.id, json!({ "origin": forwarded.origin }));
            (&stream)
                .write_all(format!("{}\n", serde_json::to_string(&reply).unwrap()).as_bytes())
                .unwrap();
        });
        let reply = request(
            &endpoint,
            &Forwarded {
                origin: "chrome-extension://x/".into(),
                message: Message {
                    id: json!(7),
                    request: Request::UnlockStatus,
                },
            },
        )
        .unwrap();
        app.join().unwrap();
        assert_eq!(
            reply,
            Reply::ok(json!(7), json!({ "origin": "chrome-extension://x/" }))
        );
    }

    #[test]
    fn no_app_is_a_connection_error() {
        let dir = tempfile::tempdir().unwrap();
        let message = Message {
            id: json!(1),
            request: Request::Unlock,
        };
        let forwarded = Forwarded {
            origin: String::new(),
            message,
        };
        assert!(request(&endpoint(dir.path()), &forwarded).is_err());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn long_data_folders_get_a_short_socket_path() {
        assert!(data_dir().is_some());
        assert_eq!(
            endpoint(Path::new("/tmp/x")),
            Path::new("/tmp/x/native-host.sock")
        );
        let long = Path::new("/tmp").join("x".repeat(120));
        let socket = endpoint(&long);
        assert!(socket.as_os_str().len() < 104 && socket.starts_with(std::env::temp_dir()));
        assert_eq!(socket, endpoint(&long), "stable");
        assert_ne!(socket, endpoint(&Path::new("/tmp").join("y".repeat(120))));
    }

    /// The Mac app is sandboxed: its socket stays in its container, however long the path.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_mac_apps_socket_is_in_its_container() {
        let container = Path::new("/Users/someone/Library/Group Containers/ABCDE12345.app.octap");
        assert_eq!(endpoint(container), container.join("native-host.sock"));
        let long = Path::new("/Users").join("x".repeat(120));
        assert_eq!(endpoint(&long), long.join("native-host.sock"));
        assert!(user_home().is_some_and(|home| home.is_absolute()));
        assert_eq!(
            app_group_container("native-host.sock", Some("ABCDE12345".into())),
            Some(
                user_home()
                    .unwrap()
                    .join("Library/Group Containers/ABCDE12345.app.octap")
            )
        );
    }

    #[test]
    fn the_container_with_the_socket_is_found() {
        let containers = tempfile::tempdir().unwrap();
        let make = |name: &str, socket: bool| {
            let dir = containers.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            if socket {
                std::fs::write(dir.join("cli.sock"), b"").unwrap();
            }
            dir
        };
        assert_eq!(find_container(containers.path(), "cli.sock"), None);
        make("ABCDE12345.app.octap", false);
        make("group.app.octap", true);
        make("abcde67890.app.octap", true);
        make("ABCDE1234.app.octap", true);
        make("ABCDE12345.app.octap.other", true);
        assert_eq!(find_container(containers.path(), "cli.sock"), None);
        let older = make("ZZZZZ00000.app.octap", true);
        assert_eq!(
            find_container(containers.path(), "cli.sock"),
            Some(older.clone())
        );
        std::thread::sleep(Duration::from_millis(20));
        let newer = make("AAAAA11111.app.octap", true);
        assert_eq!(find_container(containers.path(), "cli.sock"), Some(newer));
        assert_eq!(find_container(&older.join("none"), "cli.sock"), None);
    }
}
