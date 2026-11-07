//! Linux: `/proc` for processes, `SO_PEERCRED` for the socket peer. There are no code
//! signatures; release builds check that the browser is a root-owned system install instead.

use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::trust::{Process, System};

pub struct OsSystem;

impl System for OsSystem {
    fn executable(&self, pid: u32) -> io::Result<PathBuf> {
        // A deleted or replaced executable reads as "<path> (deleted)", which doesn't resolve.
        std::fs::canonicalize(std::fs::read_link(format!("/proc/{pid}/exe"))?)
    }

    fn parent(&self, pid: u32) -> io::Result<Option<u32>> {
        let child = stat(pid)?;
        if child.parent == 0 {
            return Ok(None);
        }
        Ok(stat(child.parent)
            .ok()
            .filter(|parent| parent.started <= child.started)
            .map(|_| child.parent))
    }

    fn signed_by(&self, _: &Process, _: &Path, _: &str) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Linux has no code signatures",
        ))
    }

    fn root_owned(&self, path: &Path) -> io::Result<bool> {
        super::root_owned(path)
    }

    fn is_system_shell(&self, _: &Path) -> bool {
        false
    }
}

/// The process on the other end of a Unix socket.
pub fn peer(socket: &impl AsRawFd) -> io::Result<Process> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `SO_PEERCRED` writes a `ucred` into the buffer.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let pid = u32::try_from(credentials.pid)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "the peer has no PID"))?;
    Ok(Process::pid(pid))
}

struct Stat {
    parent: u32,
    /// Clock ticks after boot.
    started: u64,
}

/// `/proc/<pid>/stat`: the command name is in parentheses and may hold spaces, so count fields
/// after the last `)`. The parent is field 4, the start time field 22.
fn stat(pid: u32) -> io::Result<Stat> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_stat(&text).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad /proc stat"))
}

fn parse_stat(text: &str) -> Option<Stat> {
    let (_, rest) = text.rsplit_once(')')?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    Some(Stat {
        parent: fields.get(1)?.parse().ok()?,
        started: fields.get(19)?.parse().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::process::Command;

    use super::*;

    #[test]
    fn stat_lines_parse_even_with_odd_names() {
        let line =
            "1234 (a) b (c)) S 42 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 10";
        let stat = parse_stat(line).unwrap();
        assert_eq!((stat.parent, stat.started), (42, 98765));
        assert!(parse_stat("garbage").is_none());
    }

    #[test]
    fn processes_have_an_executable_and_a_parent() {
        let me = std::process::id();
        let mut child = Command::new("sleep").arg("5").spawn().unwrap();
        assert_eq!(OsSystem.parent(child.id()).unwrap(), Some(me));
        assert!(OsSystem.executable(child.id()).unwrap().is_absolute());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn a_socket_peer_has_our_pid() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        assert_eq!(peer(&ours).unwrap().pid, std::process::id());
    }
}
