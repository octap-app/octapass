//! Encrypted attachments: files kept with an item.
//!
//! Each file gets its own random 32-byte file key, wrapped by the item key (context
//! `attachmentkey:<vaultId>:<itemId>:<attachmentId>`). The wrapped key, the file's name, media
//! type and size go in the item's encrypted details; the server stores only the encrypted file.
//! Because the file key hangs off the item key, rotating a vault key (which re-wraps item keys)
//! leaves attachments readable without touching them.
//!
//! The file is encrypted in chunks with XChaCha20-Poly1305, following the STREAM construction, so
//! neither side needs the whole file in memory:
//!
//! ```text
//! file    = header ‖ chunk_0 ‖ … ‖ chunk_n
//! header  = version (0x01) ‖ key_id (16) ‖ nonce_prefix (19 random bytes)
//! chunk_i = XChaCha20-Poly1305(file key, nonce = nonce_prefix ‖ i (u32, big-endian) ‖ last,
//!                              aad = "octapass/v1|attachment:<vaultId>:<itemId>:<attachmentId>")
//! ```
//!
//! Every chunk holds [`CHUNK_LEN`] bytes of plaintext except the last, which holds 0 to
//! `CHUNK_LEN` bytes and is the only one sealed with `last = 0x01`. So dropping, reordering or
//! truncating chunks, or moving a file to another item, fails to decrypt.

use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::account::parse_id;
use crate::envelope::{Context, TAG_LEN, VERSION, unwrap_key, wrap_key};
use crate::error::{Error, Result};
use crate::keys::{KEY_ID_LEN, SymmetricKey};
use crate::session::Session;
use crate::stream::{PREFIX_LEN, Stream};

/// Plaintext bytes per chunk.
pub const CHUNK_LEN: usize = 64 * 1024;
pub const HEADER_LEN: usize = 1 + KEY_ID_LEN + PREFIX_LEN;
pub(crate) const SEALED_CHUNK_LEN: usize = CHUNK_LEN + TAG_LEN;

/// The size of a file of `plaintext_len` bytes once encrypted: what the server stores and counts.
pub fn encrypted_len(plaintext_len: u64) -> u64 {
    let chunks = plaintext_len.div_ceil(CHUNK_LEN as u64).max(1);
    HEADER_LEN as u64 + plaintext_len + chunks * TAG_LEN as u64
}

/// Where a file belongs, with every id already normalised.
struct Ids {
    vault_id: String,
    item_id: String,
    attachment_id: String,
}

impl Ids {
    fn parse(vault_id: &str, item_id: &str, attachment_id: &str) -> Result<Self> {
        Ok(Self {
            vault_id: parse_id(vault_id)?,
            item_id: parse_id(item_id)?,
            attachment_id: parse_id(attachment_id)?,
        })
    }

    fn key_context(&self) -> Context<'_> {
        Context::AttachmentKey {
            vault_id: &self.vault_id,
            item_id: &self.item_id,
            attachment_id: &self.attachment_id,
        }
    }

    fn file_aad(&self) -> Vec<u8> {
        Context::Attachment {
            vault_id: &self.vault_id,
            item_id: &self.item_id,
            attachment_id: &self.attachment_id,
        }
        .associated_data()
    }
}

/// Encrypts one file, a piece at a time. Feed it with [`Encryptor::push`] and end with
/// [`Encryptor::finish`]; the outputs, concatenated, are the encrypted file.
pub struct Encryptor {
    stream: Stream,
    /// Written before the first chunk.
    header: Option<Vec<u8>>,
    /// Plaintext not sealed yet: a chunk is sealed only once more data follows it, because the last
    /// chunk is sealed differently.
    pending: Zeroizing<Vec<u8>>,
}

impl Encryptor {
    pub fn new(
        file_key: &SymmetricKey,
        vault_id: &str,
        item_id: &str,
        attachment_id: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let ids = Ids::parse(vault_id, item_id, attachment_id)?;
        let mut prefix = [0u8; PREFIX_LEN];
        rng.fill_bytes(&mut prefix);
        Ok(Self::with_prefix(file_key, ids.file_aad(), prefix))
    }

    pub(crate) fn with_prefix(
        file_key: &SymmetricKey,
        aad: Vec<u8>,
        prefix: [u8; PREFIX_LEN],
    ) -> Self {
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.push(VERSION);
        header.extend_from_slice(&file_key.key_id());
        header.extend_from_slice(&prefix);
        Self {
            stream: Stream {
                key: file_key.clone(),
                aad,
                prefix,
                counter: Some(0),
            },
            header: Some(header),
            pending: Zeroizing::new(Vec::with_capacity(CHUNK_LEN)),
        }
    }

    /// Adds plaintext. Returns the ciphertext ready so far, which may be empty.
    pub fn push(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = self.header.take().unwrap_or_default();
        self.pending.extend_from_slice(plaintext);
        let mut start = 0;
        while self.pending.len() - start > CHUNK_LEN {
            let chunk = &self.pending[start..start + CHUNK_LEN];
            self.stream.seal(chunk, false, &mut out)?;
            start += CHUNK_LEN;
        }
        self.pending.drain(..start);
        Ok(out)
    }

    /// Seals the last chunk. Returns the rest of the ciphertext.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        let mut out = self.header.take().unwrap_or_default();
        let last = std::mem::take(&mut *self.pending);
        self.stream.seal(&last, true, &mut out)?;
        Ok(out)
    }
}

/// Decrypts one file, a piece at a time, checking each chunk before returning its plaintext.
/// A file that was cut short fails in [`Decryptor::finish`], so callers must not treat the
/// plaintext as complete before `finish` succeeds.
pub struct Decryptor {
    stream: Stream,
    key_id: [u8; KEY_ID_LEN],
    /// Ciphertext not opened yet, starting with the header until that has arrived.
    pending: Vec<u8>,
    header_read: bool,
}

impl Decryptor {
    pub fn new(
        file_key: &SymmetricKey,
        vault_id: &str,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<Self> {
        let ids = Ids::parse(vault_id, item_id, attachment_id)?;
        Ok(Self {
            stream: Stream {
                key: file_key.clone(),
                aad: ids.file_aad(),
                prefix: [0; PREFIX_LEN],
                counter: Some(0),
            },
            key_id: file_key.key_id(),
            pending: Vec::with_capacity(HEADER_LEN + SEALED_CHUNK_LEN),
            header_read: false,
        })
    }

    /// A decryptor for a file bound to `aad`, as Safe content is.
    pub(crate) fn with_aad(file_key: &SymmetricKey, aad: Vec<u8>) -> Self {
        Self {
            stream: Stream {
                key: file_key.clone(),
                aad,
                prefix: [0; PREFIX_LEN],
                counter: Some(0),
            },
            key_id: file_key.key_id(),
            pending: Vec::with_capacity(HEADER_LEN + SEALED_CHUNK_LEN),
            header_read: false,
        }
    }

    fn read_header(&mut self) -> Result<()> {
        if self.header_read || self.pending.len() < HEADER_LEN {
            return Ok(());
        }
        if self.pending[0] != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.pending[1..1 + KEY_ID_LEN] != self.key_id {
            return Err(Error::WrongKey);
        }
        self.stream
            .prefix
            .copy_from_slice(&self.pending[1 + KEY_ID_LEN..HEADER_LEN]);
        self.pending.drain(..HEADER_LEN);
        self.header_read = true;
        Ok(())
    }

    /// Adds ciphertext. Returns the plaintext of every chunk that is complete and verified.
    pub fn push(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.pending.extend_from_slice(ciphertext);
        self.read_header()?;
        let mut out = Zeroizing::new(Vec::new());
        if !self.header_read {
            return Ok(out);
        }
        let mut start = 0;
        // A full chunk with more data after it can't be the last one.
        while self.pending.len() - start > SEALED_CHUNK_LEN {
            let chunk = &self.pending[start..start + SEALED_CHUNK_LEN];
            self.stream.open(chunk, false, &mut out)?;
            start += SEALED_CHUNK_LEN;
        }
        self.pending.drain(..start);
        Ok(out)
    }

    /// Opens the last chunk. Fails if the file was truncated or had chunks added.
    pub fn finish(mut self) -> Result<Zeroizing<Vec<u8>>> {
        self.read_header()?;
        if !self.header_read {
            return Err(Error::MalformedCiphertext);
        }
        let mut out = Zeroizing::new(Vec::new());
        let last = std::mem::take(&mut self.pending);
        self.stream.open(&last, true, &mut out)?;
        Ok(out)
    }
}

impl Session {
    /// Starts a new attachment for an item: a fresh file key, wrapped by the item key (pass the
    /// item's `encryptedItemKey`), and an encryptor for the file. Store the wrapped key in the
    /// item's details next to the file's name, type and size.
    pub fn new_attachment(
        &self,
        vault_id: &str,
        item_id: &str,
        encrypted_item_key: &str,
        attachment_id: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(String, Encryptor)> {
        let ids = Ids::parse(vault_id, item_id, attachment_id)?;
        let item_key = self.attachment_item_key(&ids, encrypted_item_key)?;
        let file_key = SymmetricKey::generate(rng);
        let wrapped = wrap_key(&item_key, &ids.key_context(), &file_key, rng)?;
        let encryptor = Encryptor::new(&file_key, vault_id, item_id, attachment_id, rng)?;
        Ok((wrapped, encryptor))
    }

    /// A decryptor for an attachment, from its wrapped key in the item's details.
    pub fn open_attachment(
        &self,
        vault_id: &str,
        item_id: &str,
        encrypted_item_key: &str,
        attachment_id: &str,
        wrapped_key: &str,
    ) -> Result<Decryptor> {
        let ids = Ids::parse(vault_id, item_id, attachment_id)?;
        let item_key = self.attachment_item_key(&ids, encrypted_item_key)?;
        let file_key = unwrap_key(&item_key, &ids.key_context(), wrapped_key)?;
        Decryptor::new(&file_key, vault_id, item_id, attachment_id)
    }

    fn attachment_item_key(&self, ids: &Ids, encrypted_item_key: &str) -> Result<SymmetricKey> {
        let context = Context::ItemKey {
            vault_id: &ids.vault_id,
            item_id: &ids.item_id,
        };
        unwrap_key(self.vault_key(&ids.vault_id)?, &context, encrypted_item_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const VAULT: &str = "0192f0c8-1c2d-7a00-8000-0000000000aa";
    const ITEM: &str = "0192f0c8-1c2d-7a00-8000-0000000000bb";
    const FILE: &str = "0192f0c8-1c2d-7a00-8000-0000000000cc";

    fn key() -> SymmetricKey {
        SymmetricKey::from_bytes([7; 32])
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Encrypts `plaintext`, pushing it in pieces of `piece` bytes.
    fn encrypt(plaintext: &[u8], piece: usize) -> Vec<u8> {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut encryptor = Encryptor::new(&key(), VAULT, ITEM, FILE, &mut rng).unwrap();
        let mut out = Vec::new();
        for part in plaintext.chunks(piece.max(1)) {
            out.extend(encryptor.push(part).unwrap());
        }
        out.extend(encryptor.finish().unwrap());
        out
    }

    fn decrypt_with(
        key: &SymmetricKey,
        item: &str,
        ciphertext: &[u8],
        piece: usize,
    ) -> Result<Vec<u8>> {
        let mut decryptor = Decryptor::new(key, VAULT, item, FILE)?;
        let mut out = Vec::new();
        for part in ciphertext.chunks(piece.max(1)) {
            out.extend_from_slice(&decryptor.push(part)?);
        }
        out.extend_from_slice(&decryptor.finish()?);
        Ok(out)
    }

    fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt_with(&key(), ITEM, ciphertext, 10_000)
    }

    #[test]
    fn sizes_around_chunk_boundaries_round_trip() {
        for len in [
            0,
            1,
            CHUNK_LEN - 1,
            CHUNK_LEN,
            CHUNK_LEN + 1,
            3 * CHUNK_LEN,
            3 * CHUNK_LEN + 5,
        ] {
            let plaintext = data(len);
            let ciphertext = encrypt(&plaintext, 4096);
            assert_eq!(ciphertext.len() as u64, encrypted_len(len as u64), "{len}");
            assert_eq!(decrypt(&ciphertext).unwrap(), plaintext, "{len}");
        }
        assert_eq!(encrypted_len(0), 36 + 16);
        assert_eq!(encrypted_len(CHUNK_LEN as u64), 36 + CHUNK_LEN as u64 + 16);
        assert_eq!(
            encrypted_len(CHUNK_LEN as u64 + 1),
            36 + CHUNK_LEN as u64 + 1 + 32
        );
    }

    #[test]
    fn layout() {
        let ciphertext = encrypt(b"abc", 3);
        assert_eq!(ciphertext[0], VERSION);
        assert_eq!(ciphertext[1..17], key().key_id());
        assert_eq!(ciphertext.len(), HEADER_LEN + 3 + TAG_LEN);
    }

    #[test]
    fn refuses_tampering_truncation_and_reordering() {
        let plaintext = data(3 * CHUNK_LEN + 10);
        let ciphertext = encrypt(&plaintext, CHUNK_LEN);
        let chunk = |i: usize| {
            let start = HEADER_LEN + i * SEALED_CHUNK_LEN;
            &ciphertext[start..(start + SEALED_CHUNK_LEN).min(ciphertext.len())]
        };

        let mut flipped = ciphertext.clone();
        flipped[HEADER_LEN + 5] ^= 1;
        assert_eq!(decrypt(&flipped).unwrap_err(), Error::DecryptionFailed);

        // Cut after a whole chunk: the new last chunk wasn't sealed as the last.
        let cut = &ciphertext[..HEADER_LEN + 2 * SEALED_CHUNK_LEN];
        assert_eq!(decrypt(cut).unwrap_err(), Error::DecryptionFailed);
        // Cut inside a chunk.
        assert_eq!(
            decrypt(&ciphertext[..ciphertext.len() - 1]).unwrap_err(),
            Error::DecryptionFailed
        );

        let mut swapped = ciphertext[..HEADER_LEN].to_vec();
        for i in [1, 0, 2, 3] {
            swapped.extend_from_slice(chunk(i));
        }
        assert_eq!(decrypt(&swapped).unwrap_err(), Error::DecryptionFailed);

        let mut extended = ciphertext.clone();
        extended.extend_from_slice(chunk(0));
        assert!(decrypt(&extended).is_err());

        assert_eq!(
            decrypt(&ciphertext[..20]).unwrap_err(),
            Error::MalformedCiphertext
        );
        assert_eq!(decrypt(&[]).unwrap_err(), Error::MalformedCiphertext);
        let mut versioned = ciphertext.clone();
        versioned[0] = 2;
        assert_eq!(decrypt(&versioned).unwrap_err(), Error::UnsupportedVersion);
    }

    #[test]
    fn is_bound_to_its_key_and_place() {
        let ciphertext = encrypt(b"contract.pdf", 64);
        let other_key = SymmetricKey::from_bytes([8; 32]);
        assert_eq!(
            decrypt_with(&other_key, ITEM, &ciphertext, 64).unwrap_err(),
            Error::WrongKey
        );
        let other_item = "0192f0c8-1c2d-7a00-8000-0000000000dd";
        assert_eq!(
            decrypt_with(&key(), other_item, &ciphertext, 64).unwrap_err(),
            Error::DecryptionFailed
        );
        assert!(matches!(
            Decryptor::new(&key(), VAULT, ITEM, "not-a-uuid"),
            Err(Error::InvalidId)
        ));
    }

    #[test]
    fn the_same_file_encrypts_differently_each_time() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let mut once = || {
            let encryptor = Encryptor::new(&key(), VAULT, ITEM, FILE, &mut rng).unwrap();
            encryptor.finish().unwrap()
        };
        assert_ne!(once(), once());
    }

    #[test]
    fn the_file_key_is_wrapped_by_the_item_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut session = crate::sharing::test_support::account(&mut rng);
        let vault = session.create_shared_vault(0, &mut rng).unwrap();
        let item: crate::item::Item = crate::item::Item::from_json(
            r#"{"overview":{"title":"Lease","type":"document"},"details":{}}"#,
        )
        .unwrap();
        let encrypted = session
            .encrypt_item(&vault.id, ITEM, &item, None, &mut rng)
            .unwrap();
        let other = session
            .encrypt_item(&vault.id, ITEM, &item, None, &mut rng)
            .unwrap();
        let item_key = &encrypted.encrypted_item_key;

        let (wrapped, mut encryptor) = session
            .new_attachment(&vault.id, ITEM, item_key, FILE, &mut rng)
            .unwrap();
        let mut file = encryptor.push(b"signed").unwrap();
        file.extend(encryptor.finish().unwrap());

        let mut decryptor = session
            .open_attachment(&vault.id, ITEM, item_key, FILE, &wrapped)
            .unwrap();
        let mut plaintext = decryptor.push(&file).unwrap().to_vec();
        plaintext.extend_from_slice(&decryptor.finish().unwrap());
        assert_eq!(plaintext, b"signed");

        // Another item key, or the wrapped key moved to another attachment, doesn't open it.
        let open = |item_key: &str, attachment_id: &str| {
            session
                .open_attachment(&vault.id, ITEM, item_key, attachment_id, &wrapped)
                .err()
        };
        assert_eq!(open(&other.encrypted_item_key, FILE), Some(Error::WrongKey));
        assert_eq!(
            open(item_key, "0192f0c8-1c2d-7a00-8000-0000000000dd"),
            Some(Error::DecryptionFailed)
        );
        assert_eq!(
            session
                .new_attachment(VAULT, ITEM, item_key, FILE, &mut rng)
                .err(),
            Some(Error::VaultNotOpen)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]
        #[test]
        fn any_split_round_trips(len in 0usize..(3 * CHUNK_LEN), push in 1usize..100_000, pull in 1usize..100_000) {
            let plaintext = data(len);
            let ciphertext = encrypt(&plaintext, push);
            prop_assert_eq!(ciphertext.len() as u64, encrypted_len(len as u64));
            prop_assert_eq!(decrypt_with(&key(), ITEM, &ciphertext, pull).unwrap(), plaintext);
        }
    }
}
