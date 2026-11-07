//! The STREAM construction over XChaCha20-Poly1305 that attachments and encrypted exports share:
//! a file is cut into chunks, each sealed with a nonce made of a random prefix, the chunk's index
//! and a flag for the last chunk, so chunks can't be dropped, reordered or cut off unnoticed.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::envelope::{NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::keys::SymmetricKey;

/// The random part of each nonce; the other 5 bytes are the chunk index and the last-chunk flag.
pub(crate) const PREFIX_LEN: usize = NONCE_LEN - 5;

fn chunk_nonce(prefix: &[u8; PREFIX_LEN], counter: u32, last: bool) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..PREFIX_LEN].copy_from_slice(prefix);
    nonce[PREFIX_LEN..NONCE_LEN - 1].copy_from_slice(&counter.to_be_bytes());
    nonce[NONCE_LEN - 1] = u8::from(last);
    nonce
}

/// The state both directions share: the key, the associated data and the next chunk's position.
pub(crate) struct Stream {
    pub key: SymmetricKey,
    pub aad: Vec<u8>,
    pub prefix: [u8; PREFIX_LEN],
    /// The next chunk's index, or `None` once 2³² chunks were used (256 TiB, never in practice).
    pub counter: Option<u32>,
}

impl Stream {
    fn next_nonce(&mut self, last: bool) -> Result<[u8; NONCE_LEN]> {
        let counter = self.counter.ok_or(Error::MalformedCiphertext)?;
        self.counter = counter.checked_add(1);
        Ok(chunk_nonce(&self.prefix, counter, last))
    }

    pub fn seal(&mut self, plaintext: &[u8], last: bool, out: &mut Vec<u8>) -> Result<()> {
        let nonce = self.next_nonce(last)?;
        let sealed = XChaCha20Poly1305::new(self.key.as_bytes().into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| Error::EncryptionFailed)?;
        out.extend_from_slice(&sealed);
        Ok(())
    }

    pub fn open(&mut self, sealed: &[u8], last: bool, out: &mut Vec<u8>) -> Result<()> {
        if sealed.len() < TAG_LEN {
            return Err(Error::MalformedCiphertext);
        }
        let nonce = self.next_nonce(last)?;
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new(self.key.as_bytes().into())
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: sealed,
                        aad: &self.aad,
                    },
                )
                .map_err(|_| Error::DecryptionFailed)?,
        );
        out.extend_from_slice(&plaintext);
        Ok(())
    }
}
