//! The Octa Pass SSH agent (plans 05 and 16). `ssh`, Git and IDEs talk to it over the standard
//! agent protocol on a local socket (or `openssh-ssh-agent` pipe); the desktop app answers from
//! the vault and asks before every signature. This crate is the part with no UI and no vault: the
//! protocol ([`wire`]), the server ([`server`]) and what the app does in `~/.ssh` ([`home`]).
//!
//! The agent only lists keys and signs. Adding, removing and locking keys through the protocol
//! are refused: the vault owns them.

pub mod home;
pub mod server;
pub mod wire;

use std::future::Future;
use std::path::PathBuf;

/// A key the agent offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub blob: Vec<u8>,
    pub comment: String,
}

/// Who is asking, as the operating system reports it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Peer {
    pub pid: u32,
    /// The program, when it can be told.
    pub executable: Option<PathBuf>,
    /// The program that started it (`git` for `ssh`).
    pub parent: Option<PathBuf>,
}

/// What answers the agent's requests: the vault and the user, in the app.
pub trait Backend: Send + Sync + 'static {
    fn identities(&self, peer: &Peer) -> impl Future<Output = Vec<Identity>> + Send;
    /// A signature in SSH's wire form, after the user approved; `None` refuses.
    fn sign(
        &self,
        peer: &Peer,
        blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    ) -> impl Future<Output = Option<Vec<u8>>> + Send;
}
