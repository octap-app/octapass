//! A file being written. Its changed chunks wait in an unnamed temporary file, each sealed under a
//! key that exists only in this process, so plaintext never reaches the disk and whatever a crash
//! leaves behind is unreadable.

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use octapass_core::keys::SymmetricKey;
use octapass_core::safe::{CONTENT_CHUNK_LEN, STAGING_SLOT_LEN, open_staging, seal_staging};
use rand_core::OsRng;
use zeroize::Zeroizing;

use super::Result;

pub(crate) struct Staged {
    file: File,
    key: SymmetricKey,
    /// Chunks held here; every other chunk is still as it is in the content blob.
    held: HashSet<u64>,
    /// Chunks of the content blob still in the file. A cut lowers this for good, so growing the
    /// file again gives zeros, never the bytes that were cut.
    base_chunks: u64,
    len: u64,
    dirty: bool,
}

impl Staged {
    pub fn new(folder: &Path, len: u64) -> Result<Self> {
        Ok(Self {
            file: tempfile::tempfile_in(folder)?,
            key: SymmetricKey::generate(&mut OsRng),
            held: HashSet::new(),
            base_chunks: len.div_ceil(CONTENT_CHUNK_LEN as u64),
            len,
            dirty: false,
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }

    pub fn holds(&self, index: u64) -> bool {
        self.held.contains(&index)
    }

    /// Whether this chunk's bytes are still the content blob's.
    pub fn from_base(&self, index: u64) -> bool {
        index < self.base_chunks
    }

    pub fn grow_to(&mut self, len: u64) {
        self.len = self.len.max(len);
    }

    /// Cuts or extends the file. Chunks past the end are forgotten.
    pub fn set_len(&mut self, len: u64) -> Result<()> {
        let chunk = CONTENT_CHUNK_LEN as u64;
        let cut = len.div_ceil(chunk);
        self.held.retain(|index| *index < cut);
        self.base_chunks = self.base_chunks.min(cut);
        if len % chunk != 0 && len < self.len && self.held.contains(&(len / chunk)) {
            let index = len / chunk;
            let mut plain = self.read_chunk(index)?;
            plain.truncate((len % chunk) as usize);
            self.write_chunk(index, &plain)?;
        }
        self.len = len;
        self.dirty = true;
        Ok(())
    }

    fn slot(index: u64) -> u64 {
        index * STAGING_SLOT_LEN as u64
    }

    /// Stores a chunk of at most [`CONTENT_CHUNK_LEN`] bytes.
    pub fn write_chunk(&mut self, index: u64, plain: &[u8]) -> Result<()> {
        let sealed = seal_staging(&self.key, index, plain, &mut OsRng)?;
        self.file.seek(SeekFrom::Start(Self::slot(index)))?;
        self.file.write_all(&sealed)?;
        self.held.insert(index);
        self.dirty = true;
        Ok(())
    }

    pub fn read_chunk(&mut self, index: u64) -> Result<Zeroizing<Vec<u8>>> {
        self.file.seek(SeekFrom::Start(Self::slot(index)))?;
        let mut sealed = vec![0u8; STAGING_SLOT_LEN];
        self.file.read_exact(&mut sealed)?;
        Ok(open_staging(&self.key, index, &sealed)?)
    }
}
