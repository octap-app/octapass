//! The local socket each desktop service listens on: one connection carries one request line
//! and one reply line, as in the Tauri app. The socket file is readable only by the user; who
//! may ask is each service's own check on the process at the other end.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// Requests are a few hundred bytes; a longer line is refused.
pub const MAX_LINE: u64 = 64 * 1024;
/// The client writes its request as soon as it connects; one that doesn't is dropped rather
/// than holding a thread.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Binds `endpoint`, replacing a socket left by a previous run (or a crash), readable and
/// writable by this user only.
pub fn bind(endpoint: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::remove_file(endpoint) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    if let Some(dir) = endpoint.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let listener = UnixListener::bind(endpoint)?;
    std::fs::set_permissions(endpoint, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// A service answering on its socket, each connection on a thread of its own (an answer can
/// wait for a person at the Touch ID prompt). Stopping it removes the socket.
pub struct Service {
    endpoint: PathBuf,
    /// Closing it wakes the accept loop, which then ends.
    stop: Option<OwnedFd>,
    thread: Option<JoinHandle<()>>,
}

impl Service {
    /// Binds `endpoint` and answers each connection with `answer`.
    pub(crate) fn start(
        endpoint: PathBuf,
        answer: impl Fn(UnixStream) + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let listener = bind(&endpoint)?;
        let (stopped, stop) = pipe()?;
        let answer = Arc::new(answer);
        let thread = std::thread::Builder::new()
            .name("octapass-service".into())
            .spawn(move || {
                while let Some(stream) = next(&listener, &stopped) {
                    let Ok(stream) = stream else { continue };
                    let answer = Arc::clone(&answer);
                    let _ = std::thread::Builder::new()
                        .name("octapass-connection".into())
                        .spawn(move || answer(stream));
                }
            })?;
        Ok(Self {
            endpoint,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Stops accepting connections; ones being answered finish.
    pub fn stop(mut self) {
        self.shut_down();
    }

    fn shut_down(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
            let _ = std::fs::remove_file(&self.endpoint);
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.shut_down();
    }
}

/// Waits for the next connection. `None` once `stopped` closes (or the wait fails).
fn next(listener: &UnixListener, stopped: &OwnedFd) -> Option<io::Result<UnixStream>> {
    loop {
        let mut fds = [
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stopped.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: two valid `pollfd`s, as many as we say.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
        if fds[1].revents != 0 {
            return None;
        }
        if fds[0].revents != 0 {
            return Some(listener.accept().map(|(stream, _)| stream));
        }
    }
}

/// A pipe's read and write ends.
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: `pipe` writes two descriptors into the array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both are new descriptors that nothing else owns.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Reads one request line. `None` when the client went away or sent too much or nothing.
pub(crate) fn read_request(stream: &UnixStream) -> Option<String> {
    stream.set_read_timeout(Some(REQUEST_TIMEOUT)).ok()?;
    let mut line = String::new();
    BufReader::new(stream)
        .take(MAX_LINE)
        .read_line(&mut line)
        .ok()?;
    Some(line)
}

/// Writes one reply line.
pub(crate) fn write_reply(mut stream: &UnixStream, reply: &impl serde::Serialize) {
    let mut bytes = serde_json::to_vec(reply).expect("replies serialize");
    bytes.push(b'\n');
    let _ = stream.write_all(&bytes);
}

/// Where a service listens: `name` in the data folder, or, when that path is too long for a
/// socket address (about 100 bytes), `<prefix>-<hash of the folder>.sock` in the temporary
/// folder. The host and the CLI work the path out the same way.
///
/// On macOS always `name` in the folder: the Mac app is sandboxed, so its temporary folder is its
/// own, and its App Group container (the data folder it passes) is the one place the host and
/// the CLI reach too. A path too long for a socket fails when the service starts.
pub(crate) fn endpoint(data_dir: &Path, name: &str, prefix: &str) -> PathBuf {
    const MAX_SOCKET_PATH: usize = 100;
    let path = data_dir.join(name);
    if cfg!(target_os = "macos") || path.as_os_str().len() <= MAX_SOCKET_PATH {
        return path;
    }
    std::env::temp_dir().join(format!("{prefix}-{:016x}.sock", path_hash(data_dir)))
}

/// Stable across processes: the app and its clients must agree on it.
fn path_hash(path: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_answers_until_it_stops() {
        let dir = tempfile::tempdir().unwrap();
        let endpoint = dir.path().join("x.sock");
        // A socket left over from a crash doesn't stop the next start.
        std::fs::write(&endpoint, b"").unwrap();
        let service = Service::start(endpoint.clone(), |stream| {
            let line = read_request(&stream).unwrap();
            write_reply(&stream, &line.trim());
        })
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&endpoint).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let mut stream = UnixStream::connect(&endpoint).unwrap();
        stream.write_all(b"hello\n").unwrap();
        let mut reply = String::new();
        BufReader::new(&stream).read_line(&mut reply).unwrap();
        assert_eq!(reply, "\"hello\"\n");

        service.stop();
        assert!(!endpoint.exists());
        assert!(UnixStream::connect(&endpoint).is_err());
    }

    #[test]
    fn a_service_stops_even_when_its_socket_file_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let endpoint = dir.path().join("x.sock");
        let service = Service::start(endpoint.clone(), |_| {}).unwrap();
        std::fs::remove_file(&endpoint).unwrap();
        service.stop();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_mac_apps_sockets_are_in_its_container() {
        let long = Path::new("/tmp").join("x".repeat(120));
        assert_eq!(
            endpoint(&long, "cli.sock", "octapass-cli"),
            long.join("cli.sock")
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn long_data_folders_get_a_short_socket_path() {
        assert_eq!(
            endpoint(Path::new("/tmp/x"), "cli.sock", "octapass-cli"),
            Path::new("/tmp/x/cli.sock")
        );
        let long = Path::new("/tmp").join("x".repeat(120));
        let socket = endpoint(&long, "cli.sock", "octapass-cli");
        assert!(socket.as_os_str().len() < 104 && socket.starts_with(std::env::temp_dir()));
        assert_eq!(
            socket,
            endpoint(&long, "cli.sock", "octapass-cli"),
            "stable"
        );
    }
}
