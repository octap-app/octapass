//! The agent's listener: a Unix socket only this user can reach, or Windows' agent pipe.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::wire::{self, Request};
use crate::{Backend, Peer};

/// Where `IdentityAgent` and `SSH_AUTH_SOCK` point: `~/.octapass/agent.sock`, short and without a
/// space, so it fits a socket address and an SSH config line.
#[cfg(unix)]
pub fn endpoint() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(".octapass").join("agent.sock"))
}

/// The pipe Windows' own `ssh.exe` looks for. Only one agent can have it: the OpenSSH
/// Authentication Agent service has to be stopped.
#[cfg(windows)]
pub fn endpoint() -> Option<PathBuf> {
    Some(PathBuf::from(r"\\.\pipe\openssh-ssh-agent"))
}

/// Answers one connection's requests until it closes.
pub async fn handle<B: Backend>(
    backend: &B,
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    peer: Peer,
) -> io::Result<()> {
    loop {
        let mut length = [0u8; 4];
        match stream.read_exact(&mut length).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let length = u32::from_be_bytes(length) as usize;
        if length > wire::MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "agent message too long",
            ));
        }
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await?;
        let reply = match wire::parse(&body) {
            Some(Request::Identities) => wire::identities(&backend.identities(&peer).await),
            Some(Request::Sign { key, data, flags }) => {
                match backend.sign(&peer, key, data, flags).await {
                    Some(signature) => wire::signature(&signature),
                    None => wire::failure(),
                }
            }
            Some(Request::Unsupported) | None => wire::failure(),
        };
        stream.write_all(&reply).await?;
    }
}

/// Makes the socket's folder, readable only by this user.
#[cfg(unix)]
fn prepare(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        // Only when they're wrong: the Mac app's folder is its App Group container, already
        // 0700, whose permissions the sandbox doesn't let it change ("operation not permitted").
        if std::fs::metadata(dir)?.permissions().mode() & 0o777 != 0o700 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    // A socket left by a previous run (or a crash) would make bind fail.
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Serves until the listener fails. `identify` asks the OS who connected.
#[cfg(unix)]
pub async fn serve<B: Backend>(
    backend: Arc<B>,
    path: PathBuf,
    identify: impl Fn(&tokio::net::UnixStream) -> Peer,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    prepare(&path)?;
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (stream, _) = listener.accept().await?;
        let peer = identify(&stream);
        let backend = Arc::clone(&backend);
        tokio::spawn(async move {
            let _ = handle(&*backend, stream, peer).await;
        });
    }
}

/// Serves until the listener fails. Fails at once when another agent has the pipe.
#[cfg(windows)]
pub async fn serve<B: Backend>(
    backend: Arc<B>,
    path: PathBuf,
    identify: impl Fn(&tokio::net::windows::named_pipe::NamedPipeServer) -> Peer,
) -> io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let name = path.as_os_str();
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(name)?;
    loop {
        server.connect().await?;
        let connected = server;
        server = ServerOptions::new()
            .reject_remote_clients(true)
            .create(name)?;
        let peer = identify(&connected);
        let backend = Arc::clone(&backend);
        tokio::spawn(async move {
            let _ = handle(&*backend, connected, peer).await;
        });
    }
}

/// Removes the socket when the agent is turned off.
#[cfg(unix)]
pub fn remove(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
pub fn remove(_path: &Path) {}
