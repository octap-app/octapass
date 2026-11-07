//! The Octa Pass encrypted export (`.octapass`): every item and every attachment, encrypted with a
//! password chosen for the export, so it can be restored into any account or local vault.
//!
//! ```text
//! file    = header ‖ chunk_0 ‖ … ‖ chunk_n
//! header  = magic "OPEX" ‖ version (0x01) ‖ Argon2id memory KiB, iterations, parallelism
//!           (u32 each, big-endian) ‖ salt (16) ‖ nonce_prefix (19)
//! key     = HKDF-SHA256(ikm = Argon2id v1.3(NFKD(password), salt), salt = "", info = "openpass/v1/export")
//! chunk_i = XChaCha20-Poly1305(key, nonce = nonce_prefix ‖ i (u32, big-endian) ‖ last, aad = header)
//! ```
//!
//! Chunks hold [`CHUNK_LEN`] bytes of plaintext except the last (the STREAM construction shared
//! with attachments, see [`crate::stream`]), so the file is written and read a piece at a time, and
//! nothing can be cut off, reordered or changed unnoticed. The whole header is authenticated.
//!
//! The plaintext is a ZIP (see [`super::zip`]): `export.json` first (the Octa Pass JSON export,
//! see [`super::document`]), then one `files/<attachment id>` per attachment.

use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use super::zip::{ZipReader, ZipWriter};
use crate::envelope::TAG_LEN;
use crate::error::{Error, Result};
use crate::kdf::{self, KdfAlgorithm, KdfParams};
use crate::keys::{SymmetricKey, hkdf_key};
use crate::stream::{PREFIX_LEN, Stream};

pub const MAGIC: &[u8; 4] = b"OPEX";
pub const VERSION: u8 = 0x01;
const SALT_LEN: usize = 16;
pub const HEADER_LEN: usize = 4 + 1 + 12 + SALT_LEN + PREFIX_LEN;
/// Plaintext bytes per chunk.
pub const CHUNK_LEN: usize = 64 * 1024;
const SEALED_CHUNK_LEN: usize = CHUNK_LEN + TAG_LEN;

/// The export's own JSON, first in the ZIP.
pub const ITEMS_ENTRY: &str = "export.json";
const FILES_PREFIX: &str = "files/";

/// Anyone holding the file can guess passwords offline, so exports use more memory than sign-in.
pub const EXPORT_KDF: KdfParams = KdfParams {
    algorithm: KdfAlgorithm::Argon2id,
    memory_kib: 262_144,
    iterations: 3,
    parallelism: 1,
};

/// Whether `bytes` start like an encrypted export (to tell it from the plaintext JSON).
pub fn is_archive(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

fn export_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<SymmetricKey> {
    let password_key = kdf::argon2id(password, salt, params)?;
    Ok(hkdf_key(
        password_key.as_bytes(),
        b"",
        b"openpass/v1/export",
    ))
}

/// Writes an encrypted export. Add the items first ([`ArchiveWriter::add_items`]), then each
/// attachment ([`ArchiveWriter::add_file`]), then [`ArchiveWriter::finish`]. The outputs,
/// concatenated, are the file; only one attachment at a time needs to be in memory.
pub struct ArchiveWriter {
    stream: Stream,
    /// Written before the first chunk.
    header: Option<Vec<u8>>,
    /// Plaintext not sealed yet: a chunk is sealed only once more data follows it.
    pending: Zeroizing<Vec<u8>>,
    zip: ZipWriter,
    items_added: bool,
}

impl ArchiveWriter {
    /// Derives the key from `password` (runs Argon2id with `params`).
    pub fn new(password: &str, params: KdfParams, rng: &mut impl CryptoRngCore) -> Result<Self> {
        if password.is_empty() {
            return Err(Error::InvalidExport);
        }
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mut prefix = [0u8; PREFIX_LEN];
        rng.fill_bytes(&mut prefix);
        let key = export_key(password, &salt, &params)?;
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        for value in [params.memory_kib, params.iterations, params.parallelism] {
            header.extend_from_slice(&value.to_be_bytes());
        }
        header.extend_from_slice(&salt);
        header.extend_from_slice(&prefix);
        Ok(Self {
            stream: Stream {
                key,
                aad: header.clone(),
                prefix,
                counter: Some(0),
            },
            header: Some(header),
            pending: Zeroizing::new(Vec::with_capacity(CHUNK_LEN)),
            zip: ZipWriter::default(),
            items_added: false,
        })
    }

    /// The export's JSON (see [`super::document::ExportDocument`]). Must come first, once.
    pub fn add_items(&mut self, json: &[u8]) -> Result<Vec<u8>> {
        if self.items_added {
            return Err(Error::InvalidExport);
        }
        self.items_added = true;
        let entry = self.zip.add(ITEMS_ENTRY, json, true);
        self.write(&entry)
    }

    /// One attachment's plaintext, under its attachment id from the items' JSON.
    pub fn add_file(&mut self, attachment_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let valid_id = !attachment_id.is_empty()
            && attachment_id.len() <= 64
            && attachment_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !self.items_added || !valid_id {
            return Err(Error::InvalidExport);
        }
        let entry = self
            .zip
            .add(&format!("{FILES_PREFIX}{attachment_id}"), data, false);
        self.write(&entry)
    }

    /// Ends the ZIP and seals the last chunk. Returns the rest of the file.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        if !self.items_added {
            return Err(Error::InvalidExport);
        }
        let directory = std::mem::take(&mut self.zip).finish();
        let mut out = self.write(&directory)?;
        let last = std::mem::take(&mut *self.pending);
        self.stream.seal(&last, true, &mut out)?;
        Ok(out)
    }

    fn write(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
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
}

/// What an export holds, in order: the items' JSON once, then the attachments.
pub enum ArchiveEntry {
    Items(Zeroizing<Vec<u8>>),
    File {
        attachment_id: String,
        data: Zeroizing<Vec<u8>>,
    },
}

impl core::fmt::Debug for ArchiveEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ArchiveEntry::Items(json) => write!(f, "Items({} bytes)", json.len()),
            ArchiveEntry::File {
                attachment_id,
                data,
            } => write!(f, "File({attachment_id}, {} bytes)", data.len()),
        }
    }
}

/// Reads an encrypted export a piece at a time, returning the items and each attachment as soon
/// as they're complete and verified. A file that was cut short fails in [`ArchiveReader::finish`],
/// so treat the import as complete only once that succeeds.
pub struct ArchiveReader {
    password: Zeroizing<String>,
    stream: Option<Stream>,
    /// Ciphertext not opened yet, starting with the header until that has arrived.
    pending: Vec<u8>,
    zip: ZipReader,
    chunks_opened: u64,
    items_seen: bool,
}

impl ArchiveReader {
    /// The key is derived (Argon2id) once the header has arrived.
    pub fn new(password: &str) -> Self {
        Self {
            password: Zeroizing::new(password.to_owned()),
            stream: None,
            pending: Vec::with_capacity(HEADER_LEN + SEALED_CHUNK_LEN),
            zip: ZipReader::default(),
            chunks_opened: 0,
            items_seen: false,
        }
    }

    fn read_header(&mut self) -> Result<()> {
        if self.stream.is_some() || self.pending.len() < HEADER_LEN.min(MAGIC.len() + 1) {
            return Ok(());
        }
        if !is_archive(&self.pending) {
            return Err(Error::InvalidImportFile);
        }
        if self.pending[4] != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.pending.len() < HEADER_LEN {
            return Ok(());
        }
        let header = self.pending[..HEADER_LEN].to_vec();
        let u32_at = |at: usize| u32::from_be_bytes(header[at..at + 4].try_into().expect("4"));
        let params = KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: u32_at(5),
            iterations: u32_at(9),
            parallelism: u32_at(13),
        };
        // Checked before running Argon2id, so a crafted file can't freeze the device.
        let key = export_key(&self.password, &header[17..17 + SALT_LEN], &params)?;
        let prefix = header[17 + SALT_LEN..].try_into().expect("prefix");
        self.stream = Some(Stream {
            key,
            aad: header,
            prefix,
            counter: Some(0),
        });
        self.pending.drain(..HEADER_LEN);
        Ok(())
    }

    fn open(&mut self, sealed_len: usize, last: bool) -> Result<Zeroizing<Vec<u8>>> {
        let stream = self.stream.as_mut().expect("header read");
        let mut out = Zeroizing::new(Vec::with_capacity(CHUNK_LEN));
        stream
            .open(&self.pending[..sealed_len], last, &mut out)
            .map_err(|_| {
                // The first chunk always exists: failing there means another key.
                if self.chunks_opened == 0 {
                    Error::WrongImportPassword
                } else {
                    Error::DecryptionFailed
                }
            })?;
        self.chunks_opened += 1;
        self.pending.drain(..sealed_len);
        Ok(out)
    }

    /// Adds ciphertext. Returns the entries that are complete.
    pub fn push(&mut self, ciphertext: &[u8]) -> Result<Vec<ArchiveEntry>> {
        self.pending.extend_from_slice(ciphertext);
        self.read_header()?;
        let mut entries = Vec::new();
        if self.stream.is_none() {
            return Ok(entries);
        }
        // A full chunk with more data after it can't be the last one.
        while self.pending.len() > SEALED_CHUNK_LEN {
            let plaintext = self.open(SEALED_CHUNK_LEN, false)?;
            self.unzip(&plaintext, &mut entries)?;
        }
        Ok(entries)
    }

    /// Opens the last chunk. Fails if the file was cut short or had anything added.
    pub fn finish(mut self) -> Result<Vec<ArchiveEntry>> {
        self.read_header()?;
        if self.stream.is_none() {
            return Err(Error::InvalidImportFile);
        }
        let plaintext = self.open(self.pending.len(), true)?;
        let mut entries = Vec::new();
        self.unzip(&plaintext, &mut entries)?;
        std::mem::take(&mut self.zip).finish()?;
        Ok(entries)
    }

    fn unzip(&mut self, plaintext: &[u8], entries: &mut Vec<ArchiveEntry>) -> Result<()> {
        for file in self.zip.push(plaintext)? {
            let entry = match file.name.strip_prefix(FILES_PREFIX) {
                _ if !self.items_seen && file.name == ITEMS_ENTRY => {
                    self.items_seen = true;
                    ArchiveEntry::Items(file.data)
                }
                Some(id) if self.items_seen => ArchiveEntry::File {
                    attachment_id: id.to_owned(),
                    data: file.data,
                },
                // Newer exports may hold more; anything before the items isn't an Octa Pass export.
                _ if self.items_seen => continue,
                _ => return Err(Error::InvalidImportFile),
            };
            entries.push(entry);
        }
        Ok(())
    }
}

/// Attachment files by attachment id.
pub type ArchiveFiles = Vec<(String, Zeroizing<Vec<u8>>)>;

/// Reads a whole export held in memory: the items' JSON and the attachments by id.
pub fn read_archive(file: &[u8], password: &str) -> Result<(Zeroizing<Vec<u8>>, ArchiveFiles)> {
    let mut reader = ArchiveReader::new(password);
    let mut entries = reader.push(file)?;
    entries.extend(reader.finish()?);
    let mut items = None;
    let mut files = Vec::new();
    for entry in entries {
        match entry {
            ArchiveEntry::Items(json) => items = Some(json),
            ArchiveEntry::File {
                attachment_id,
                data,
            } => files.push((attachment_id, data)),
        }
    }
    Ok((items.ok_or(Error::InvalidImportFile)?, files))
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    const ID: &str = "0192f0c8-1c2d-7a00-8000-0000000000cc";

    fn export(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let mut writer = ArchiveWriter::new("export pw", KdfParams::DEFAULT, &mut rng).unwrap();
        let mut out = writer
            .add_items(br#"{"format":"octapass-export"}"#)
            .unwrap();
        for (id, data) in files {
            out.extend(writer.add_file(id, data).unwrap());
        }
        out.extend(writer.finish().unwrap());
        out
    }

    #[test]
    fn layout() {
        let file = export(&[]);
        assert_eq!(&file[..5], b"OPEX\x01");
        assert_eq!(&file[5..9], &65_536u32.to_be_bytes());
        assert_eq!(&file[9..13], &3u32.to_be_bytes());
        assert_eq!(&file[13..17], &1u32.to_be_bytes());
        assert_eq!(HEADER_LEN, 52);
        assert!(is_archive(&file));
        assert!(!is_archive(b"{\"format\""));
    }

    #[test]
    fn streams_in_any_piece_size() {
        let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let file = export(&[(ID, &big), ("other-id", b"")]);
        for step in [1000, 70_000, file.len()] {
            let mut reader = ArchiveReader::new("export pw");
            let mut entries = Vec::new();
            for piece in file.chunks(step) {
                entries.extend(reader.push(piece).unwrap());
            }
            entries.extend(reader.finish().unwrap());
            assert_eq!(entries.len(), 3, "{step}");
            let ArchiveEntry::Items(json) = &entries[0] else {
                panic!()
            };
            assert_eq!(json.as_slice(), br#"{"format":"octapass-export"}"#);
            let ArchiveEntry::File {
                attachment_id,
                data,
            } = &entries[1]
            else {
                panic!()
            };
            assert_eq!(attachment_id, ID);
            assert_eq!(data.as_slice(), big.as_slice());
        }
        let (items, files) = read_archive(&file, "export pw").unwrap();
        assert!(items.starts_with(b"{"));
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn wrong_password_damage_and_truncation() {
        let file = export(&[(ID, &[1u8; 200_000])]);
        assert_eq!(
            read_archive(&file, "nope").unwrap_err(),
            Error::WrongImportPassword
        );
        // Header fields are authenticated.
        let mut salt = file.clone();
        salt[20] ^= 1;
        assert_eq!(
            read_archive(&salt, "export pw").unwrap_err(),
            Error::WrongImportPassword
        );
        let mut later = file.clone();
        later[HEADER_LEN + SEALED_CHUNK_LEN + 5] ^= 1;
        assert_eq!(
            read_archive(&later, "export pw").unwrap_err(),
            Error::DecryptionFailed
        );
        // Cut at a chunk boundary: the last chunk is missing its flag.
        let cut = &file[..HEADER_LEN + 2 * SEALED_CHUNK_LEN];
        assert!(read_archive(cut, "export pw").is_err());
        let mut longer = file.clone();
        longer.extend_from_slice(&[0; 40]);
        assert!(read_archive(&longer, "export pw").is_err());
    }

    #[test]
    fn hostile_headers() {
        let file = export(&[]);
        let mut weak = file.clone();
        weak[5..9].copy_from_slice(&1024u32.to_be_bytes());
        assert_eq!(
            read_archive(&weak, "export pw").unwrap_err(),
            Error::UnsupportedKdf
        );
        let mut huge = file.clone();
        huge[9..13].copy_from_slice(&1_000_000u32.to_be_bytes());
        assert_eq!(
            read_archive(&huge, "export pw").unwrap_err(),
            Error::UnsupportedKdf
        );
        let mut future = file.clone();
        future[4] = 2;
        assert_eq!(
            read_archive(&future, "export pw").unwrap_err(),
            Error::UnsupportedVersion
        );
        assert_eq!(
            read_archive(b"PK\x03\x04", "x").unwrap_err(),
            Error::InvalidImportFile
        );
        assert_eq!(
            read_archive(b"OPEX", "x").unwrap_err(),
            Error::InvalidImportFile
        );
    }

    #[test]
    fn writer_rules() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        assert!(ArchiveWriter::new("", KdfParams::DEFAULT, &mut rng).is_err());
        let mut writer = ArchiveWriter::new("pw", KdfParams::DEFAULT, &mut rng).unwrap();
        assert!(writer.add_file(ID, b"x").is_err(), "items come first");
        writer.add_items(b"{}").unwrap();
        assert!(writer.add_items(b"{}").is_err());
        assert!(writer.add_file("../escape", b"x").is_err());
    }
}
