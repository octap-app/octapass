//! Calls that block (Argon2id, the network, Face ID or the fingerprint prompt, file encryption)
//! are `async` in Swift and Kotlin: each runs on a thread of its own, so the caller's thread, the
//! main one included, is never held up.

use futures_channel::oneshot;

use crate::error::{Result, VaultError};

/// Runs `work` on a new thread and waits for it without blocking the caller's executor.
pub(crate) async fn background<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let (sender, receiver) = oneshot::channel();
    std::thread::Builder::new()
        .name("octapass-vault".into())
        .spawn(move || {
            let _ = sender.send(work());
        })
        .map_err(|error| VaultError::unexpected(format!("no thread: {error}")))?;
    // A panic drops the sender.
    receiver
        .await
        .map_err(|_| VaultError::unexpected("the vault call failed"))?
}
