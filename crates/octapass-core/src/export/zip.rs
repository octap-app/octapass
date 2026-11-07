//! The ZIP inside an encrypted export, written and read as a stream so neither side needs the whole
//! archive in memory.
//!
//! The writer knows each file's size and CRC before writing its local header (files are added
//! whole), so no data descriptors are needed and the reader can walk the local headers in order.
//! Every entry carries ZIP64 sizes, so archives and files over 4 GiB need no other code path. Any
//! unzip tool opens the result.

use std::io::{Read, Write};

use flate2::Compression;
use flate2::Crc;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const LOCAL: u32 = 0x0403_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const ZIP64_END: u32 = 0x0606_4b50;
const ZIP64_LOCATOR: u32 = 0x0706_4b50;
const END: u32 = 0x0605_4b50;
const STORED: u16 = 0;
const DEFLATED: u16 = 8;
/// ZIP64 needs version 4.5.
const VERSION: u16 = 45;
/// Names are UTF-8.
const UTF8: u16 = 1 << 11;
/// 1980-01-01 00:00 in MS-DOS format: entries carry no real timestamps.
const DOS_DATE: u16 = (1 << 5) | 1;
const LOCAL_HEADER_LEN: usize = 30;
const ZIP64_EXTRA_LEN: usize = 20;
/// Longer names aren't from an Octa Pass export.
const MAX_NAME_LEN: usize = 1024;

fn u16le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u32le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u64le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

struct Entry {
    name: String,
    method: u16,
    crc: u32,
    compressed: u64,
    size: u64,
    offset: u64,
}

/// Writes a ZIP one whole file at a time; the outputs, concatenated, are the archive.
#[derive(Default)]
pub(crate) struct ZipWriter {
    entries: Vec<Entry>,
    offset: u64,
}

impl ZipWriter {
    /// The local header and data of one file. `deflate` compresses it (worth it for JSON, not for
    /// attachments, which are mostly compressed already).
    pub fn add(&mut self, name: &str, data: &[u8], deflate: bool) -> Zeroizing<Vec<u8>> {
        let mut crc = Crc::new();
        crc.update(data);
        let compressed = deflate.then(|| {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data).expect("writing to memory");
            Zeroizing::new(encoder.finish().expect("writing to memory"))
        });
        let body = compressed.as_deref().map_or(data, Vec::as_slice);
        let entry = Entry {
            name: name.to_owned(),
            method: if deflate { DEFLATED } else { STORED },
            crc: crc.sum(),
            compressed: body.len() as u64,
            size: data.len() as u64,
            offset: self.offset,
        };
        let mut out = Zeroizing::new(Vec::with_capacity(
            LOCAL_HEADER_LEN + name.len() + 20 + body.len(),
        ));
        u32le(&mut out, LOCAL);
        u16le(&mut out, VERSION);
        u16le(&mut out, UTF8);
        u16le(&mut out, entry.method);
        u16le(&mut out, 0);
        u16le(&mut out, DOS_DATE);
        u32le(&mut out, entry.crc);
        u32le(&mut out, u32::MAX);
        u32le(&mut out, u32::MAX);
        u16le(&mut out, name.len() as u16);
        u16le(&mut out, ZIP64_EXTRA_LEN as u16);
        out.extend_from_slice(name.as_bytes());
        u16le(&mut out, 0x0001);
        u16le(&mut out, 16);
        u64le(&mut out, entry.size);
        u64le(&mut out, entry.compressed);
        out.extend_from_slice(body);
        self.offset += out.len() as u64;
        self.entries.push(entry);
        out
    }

    /// The central directory and its end records.
    pub fn finish(self) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in &self.entries {
            u32le(&mut out, CENTRAL);
            u16le(&mut out, VERSION);
            u16le(&mut out, VERSION);
            u16le(&mut out, UTF8);
            u16le(&mut out, entry.method);
            u16le(&mut out, 0);
            u16le(&mut out, DOS_DATE);
            u32le(&mut out, entry.crc);
            u32le(&mut out, u32::MAX);
            u32le(&mut out, u32::MAX);
            u16le(&mut out, entry.name.len() as u16);
            u16le(&mut out, 28);
            u16le(&mut out, 0);
            u16le(&mut out, 0);
            u16le(&mut out, 0);
            u32le(&mut out, 0);
            u32le(&mut out, u32::MAX);
            out.extend_from_slice(entry.name.as_bytes());
            u16le(&mut out, 0x0001);
            u16le(&mut out, 24);
            u64le(&mut out, entry.size);
            u64le(&mut out, entry.compressed);
            u64le(&mut out, entry.offset);
        }
        let count = self.entries.len() as u64;
        let directory_len = out.len() as u64;
        let zip64_end = self.offset + directory_len;
        u32le(&mut out, ZIP64_END);
        u64le(&mut out, 44);
        u16le(&mut out, VERSION);
        u16le(&mut out, VERSION);
        u32le(&mut out, 0);
        u32le(&mut out, 0);
        u64le(&mut out, count);
        u64le(&mut out, count);
        u64le(&mut out, directory_len);
        u64le(&mut out, self.offset);
        u32le(&mut out, ZIP64_LOCATOR);
        u32le(&mut out, 0);
        u64le(&mut out, zip64_end);
        u32le(&mut out, 1);
        u32le(&mut out, END);
        u16le(&mut out, 0);
        u16le(&mut out, 0);
        u16le(&mut out, u16::MAX);
        u16le(&mut out, u16::MAX);
        u32le(&mut out, u32::MAX);
        u32le(&mut out, u32::MAX);
        u16le(&mut out, 0);
        out
    }
}

/// One file read from the archive, checked against its CRC.
pub(crate) struct ZipFile {
    pub name: String,
    pub data: Zeroizing<Vec<u8>>,
}

/// Reads the files of a ZIP from the local headers as its bytes arrive. Only the subset
/// [`ZipWriter`] writes is accepted: stored or deflated files with their sizes in the header.
#[derive(Default)]
pub(crate) struct ZipReader {
    pending: Zeroizing<Vec<u8>>,
    /// The central directory was reached: everything after it is ignored.
    done: bool,
}

impl ZipReader {
    /// Adds bytes. Returns the files that are complete.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<ZipFile>> {
        if self.done {
            return Ok(Vec::new());
        }
        self.pending.extend_from_slice(bytes);
        let mut files = Vec::new();
        let mut start = 0;
        loop {
            match Self::next(&self.pending[start..])? {
                Next::Incomplete => break,
                Next::File(file, used) => {
                    files.push(file);
                    start += used;
                }
                Next::End => {
                    self.done = true;
                    start = self.pending.len();
                    break;
                }
            }
        }
        self.pending.drain(..start);
        Ok(files)
    }

    /// Fails unless the archive ended cleanly, at its central directory.
    pub fn finish(self) -> Result<()> {
        self.done.then_some(()).ok_or(Error::InvalidImportFile)
    }
}

/// What starts at the front of the unread bytes.
enum Next {
    /// More bytes are needed.
    Incomplete,
    /// A file, and how many bytes it took.
    File(ZipFile, usize),
    /// The central directory: the files are over.
    End,
}

impl ZipReader {
    fn next(bytes: &[u8]) -> Result<Next> {
        if bytes.len() < 4 {
            return Ok(Next::Incomplete);
        }
        let u16_at = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        match u32_at(0) {
            CENTRAL | END | ZIP64_END => return Ok(Next::End),
            LOCAL => {}
            _ => return Err(Error::InvalidImportFile),
        }
        if bytes.len() < LOCAL_HEADER_LEN {
            return Ok(Next::Incomplete);
        }
        let (flags, method, crc) = (u16_at(6), u16_at(8), u32_at(14));
        let (name_len, extra_len) = (u16_at(26) as usize, u16_at(28) as usize);
        let encrypted_or_streamed = flags & 0b1001 != 0;
        if encrypted_or_streamed || ![STORED, DEFLATED].contains(&method) || name_len > MAX_NAME_LEN
        {
            return Err(Error::InvalidImportFile);
        }
        let header_len = LOCAL_HEADER_LEN + name_len + extra_len;
        if bytes.len() < header_len {
            return Ok(Next::Incomplete);
        }
        let (mut compressed, mut size) = (u64::from(u32_at(18)), u64::from(u32_at(22)));
        let mut extra = &bytes[LOCAL_HEADER_LEN + name_len..header_len];
        while extra.len() >= 4 {
            let id = u16::from_le_bytes([extra[0], extra[1]]);
            let len = usize::from(u16::from_le_bytes([extra[2], extra[3]]));
            let body = extra.get(4..4 + len).ok_or(Error::InvalidImportFile)?;
            if id == 0x0001 && len >= 16 {
                size = u64::from_le_bytes(body[..8].try_into().expect("8 bytes"));
                compressed = u64::from_le_bytes(body[8..16].try_into().expect("8 bytes"));
            }
            extra = &extra[4 + len..];
        }
        let total = usize::try_from(compressed)
            .ok()
            .and_then(|len| len.checked_add(header_len))
            .ok_or(Error::InvalidImportFile)?;
        if bytes.len() < total {
            return Ok(Next::Incomplete);
        }
        let name = std::str::from_utf8(&bytes[LOCAL_HEADER_LEN..LOCAL_HEADER_LEN + name_len])
            .map_err(|_| Error::InvalidImportFile)?
            .to_owned();
        let body = &bytes[header_len..total];
        let data = if method == DEFLATED {
            // Never inflate past the declared size: a crafted entry can't balloon in memory.
            let limit = usize::try_from(size).map_err(|_| Error::InvalidImportFile)?;
            let mut data = Zeroizing::new(Vec::with_capacity(limit.min(1 << 20)));
            DeflateDecoder::new(body)
                .take(size + 1)
                .read_to_end(&mut data)
                .map_err(|_| Error::InvalidImportFile)?;
            data
        } else {
            Zeroizing::new(body.to_vec())
        };
        let mut check = Crc::new();
        check.update(&data);
        if data.len() as u64 != size || check.sum() != crc {
            return Err(Error::InvalidImportFile);
        }
        Ok(Next::File(ZipFile { name, data }, total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(files: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut writer = ZipWriter::default();
        let mut out = Vec::new();
        for (name, data, deflate) in files {
            out.extend_from_slice(&writer.add(name, data, *deflate));
        }
        out.extend_from_slice(&writer.finish());
        out
    }

    #[test]
    fn reads_back_byte_by_byte_or_at_once() {
        let big = vec![7u8; 200_000];
        let bytes = archive(&[
            ("export.json", b"{\"a\": 1}", true),
            ("files/one", &big, false),
            ("files/empty", b"", false),
        ]);
        for step in [1, 4096, bytes.len()] {
            let mut reader = ZipReader::default();
            let mut files = Vec::new();
            for piece in bytes.chunks(step) {
                files.extend(reader.push(piece).unwrap());
            }
            reader.finish().unwrap();
            let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
            assert_eq!(names, ["export.json", "files/one", "files/empty"], "{step}");
            assert_eq!(files[0].data.as_slice(), b"{\"a\": 1}");
            assert_eq!(files[1].data.as_slice(), big.as_slice());
            assert!(files[2].data.is_empty());
        }
    }

    #[test]
    fn standard_tools_can_open_it() {
        // The `zip` crate (used for 1Password files) reads the central directory and ZIP64 records.
        let bytes = archive(&[("export.json", b"{}", true), ("files/x", b"hello", false)]);
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(zip.len(), 2);
        let mut text = String::new();
        zip.by_name("files/x")
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "hello");
    }

    #[test]
    fn rejects_damage_and_truncation() {
        let bytes = archive(&[("files/x", b"hello", false)]);
        let mut corrupt = bytes.clone();
        corrupt[LOCAL_HEADER_LEN + 7 + ZIP64_EXTRA_LEN] ^= 1;
        assert!(ZipReader::default().push(&corrupt).is_err());
        assert!(ZipReader::default().push(b"not a zip").is_err());
        let mut reader = ZipReader::default();
        reader.push(&bytes[..LOCAL_HEADER_LEN + 10]).unwrap();
        assert!(reader.finish().is_err());
    }

    #[test]
    fn a_deflate_bomb_stops_at_the_declared_size() {
        let mut bytes = archive(&[("export.json", &[b'a'; 100_000], true)]);
        // Claim 10 bytes: inflating stops just past them and the size check fails.
        let size_at = LOCAL_HEADER_LEN + "export.json".len() + 4;
        bytes[size_at..size_at + 8].copy_from_slice(&10u64.to_le_bytes());
        assert!(ZipReader::default().push(&bytes).is_err());
    }
}
