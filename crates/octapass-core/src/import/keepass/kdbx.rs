//! Opening KeePass databases (KDBX 3.1 and 4.x) down to the XML inside, with a password, a key
//! file or both.
//!
//! ```text
//! composite   = SHA-256(SHA-256(password) ‖ key file key)          (either part may be missing)
//! transformed = SHA-256(AES-256-ECB^rounds(composite))  |  Argon2d/Argon2id(composite, salt, …)
//! master key  = SHA-256(master seed ‖ transformed)
//! KDBX 3.1  payload = AES-256-CBC | Twofish-CBC | ChaCha20 (start bytes ‖ SHA-256 hashed blocks)
//! KDBX 4    header SHA-256, then HMAC-SHA-256 with SHA-512(master seed ‖ transformed ‖ 0x01)
//!           payload = HMAC'd blocks of ciphertext; plaintext = inner header ‖ XML
//! ```
//!
//! Either payload may be gzipped. Protected strings in the XML are XORed with a Salsa20 or
//! ChaCha20 key stream ([`InnerStream`]). KDF settings are checked against caps before anything
//! runs, so a crafted file can't freeze the device.

use std::io::Read;

use aes::Aes256;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use quick_xml::Reader;
use quick_xml::events::Event;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;
use crate::import::ImportError;

/// The first four bytes of every KeePass database.
pub(super) const SIGNATURE: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];
const KDBX: [u8; 4] = [0x67, 0xfb, 0x4b, 0xb5];
const KDB: [u8; 4] = [0x65, 0xfb, 0x4b, 0xb5];

const AES256: [u8; 16] = uuid(0x31c1f2e6_bf71_4350_be58_05216afc5aff);
const TWOFISH: [u8; 16] = uuid(0xad68f29f_576f_4bb9_a36a_d47af965346c);
const CHACHA20: [u8; 16] = uuid(0xd6038a2b_8b6f_4cb5_a524_339a31dbb59a);
const AES_KDF: [u8; 16] = uuid(0xc9d9f39a_628a_4460_bf74_0d08c18a4fea);
/// KeePassXC's id for AES-KDF in KDBX 3.1 settings, also accepted in KDBX 4.
const AES_KDF_KDBX3: [u8; 16] = uuid(0x7c02bb82_79a7_4ac0_927d_114a00648238);
const ARGON2D: [u8; 16] = uuid(0xef636ddf_8c29_444b_91f7_a9a403e30a0c);
const ARGON2ID: [u8; 16] = uuid(0x9e298b19_56db_4773_b23d_fc3ec6f0a1e6);

const fn uuid(value: u128) -> [u8; 16] {
    value.to_be_bytes()
}

/// Caps on the key derivation, high enough for databases tuned to one second on a fast computer.
/// At the caps it takes seconds natively, but a couple of minutes in a browser's WebAssembly (one
/// thread, no AES instructions: about 6 µs per AES-KDF round and 12 ms per GiB of Argon2).
const MAX_AES_ROUNDS: u64 = 20_000_000;
const MAX_ARGON2_MEMORY_KIB: u64 = 1 << 20;
/// Memory × passes: 1 GiB × 16 (the Bitwarden importer's limit), or 64 MiB × 256.
const MAX_ARGON2_WORK_KIB: u64 = 16 << 20;
const MAX_ARGON2_LANES: u64 = 256;

/// The XML may be at most this many times the database's size (and never over 512 MiB), so a
/// small file can't inflate to fill the memory.
const MAX_INFLATE_RATIO: usize = 100;
const MIN_INFLATE_LIMIT: usize = 16 << 20;
const MAX_INFLATE_LIMIT: usize = 512 << 20;

const SALSA20_IV: [u8; 8] = [0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a];

/// A decrypted database: its XML and the stream that unmasks its protected values.
pub(super) struct Opened {
    pub xml: Zeroizing<Vec<u8>>,
    pub stream: InnerStream,
}

pub(super) fn open(
    bytes: &[u8],
    password: Option<&str>,
    key_file: Option<&[u8]>,
) -> Result<Opened, ImportError> {
    let signature = bytes.get(4..8).ok_or_else(damaged)?;
    if signature == KDB {
        return Err(unsupported(
            "This is a KeePass 1 database (.kdb). Open it in KeePass 2 or KeePassXC, save it as .kdbx and import that.",
        ));
    }
    if signature != KDBX {
        return Err(damaged());
    }
    let major = u16::from_le_bytes(*read::<2>(bytes, 10)?);
    let kdbx4 = match major {
        2 | 3 => false,
        4 => true,
        _ => {
            return Err(unsupported(
                "This KeePass database is from a newer version than Octa Pass can read.",
            ));
        }
    };
    let header = Header::parse(bytes, kdbx4)?;
    header.kdf.check()?;
    let composite = composite_key(password, key_file)?;
    let transformed = header.kdf.transform(&composite)?;
    if kdbx4 {
        open4(bytes, &header, &transformed)
    } else {
        open3(bytes, &header, &transformed)
    }
}

fn open3(bytes: &[u8], header: &Header, transformed: &[u8; 32]) -> Result<Opened, ImportError> {
    let master = master_key(header.master_seed, transformed);
    let mut plain = decrypt(header.cipher, &master, header.iv, &bytes[header.end..])?;
    // Without a MAC, the start bytes are what tells a wrong key from a damaged file.
    if header.start_bytes.len() != 32 || plain.get(..32) != Some(header.start_bytes) {
        return Err(wrong_key());
    }
    unpad(header.cipher, &mut plain)?;
    let blocks = hashed_blocks(&plain[32..])?;
    let xml = inflate(blocks, header.gzip, inflate_limit(bytes.len()))?;
    let stream = InnerStream::new(header.stream_id, header.stream_key)?;
    Ok(Opened { xml, stream })
}

fn open4(bytes: &[u8], header: &Header, transformed: &[u8; 32]) -> Result<Opened, ImportError> {
    let header_bytes = &bytes[..header.end];
    let hash = bytes.get(header.end..header.end + 32).ok_or_else(damaged)?;
    let mac = bytes
        .get(header.end + 32..header.end + 64)
        .ok_or_else(damaged)?;
    if Sha256::digest(header_bytes).as_slice() != hash {
        return Err(damaged());
    }
    let mut hmac_key = Zeroizing::new([0u8; 64]);
    hmac_key.copy_from_slice(
        &Sha512::new()
            .chain_update(header.master_seed)
            .chain_update(transformed)
            .chain_update([1])
            .finalize(),
    );
    let mut header_mac = block_mac(u64::MAX, &hmac_key);
    header_mac.update(header_bytes);
    header_mac.verify_slice(mac).map_err(|_| wrong_key())?;

    let ciphertext = hmac_blocks(&bytes[header.end + 64..], &hmac_key)?;
    let master = master_key(header.master_seed, transformed);
    let mut plain = decrypt(header.cipher, &master, header.iv, &ciphertext)?;
    unpad(header.cipher, &mut plain)?;
    let mut payload = inflate(plain, header.gzip, inflate_limit(bytes.len()))?;

    // The inner header: the protected-value stream, then attachments (not imported).
    let (mut pos, mut stream_id, mut stream_key) = (0, None, None);
    loop {
        let id = read::<1>(&payload, pos)?[0];
        let size = u32::from_le_bytes(*read::<4>(&payload, pos + 1)?) as usize;
        let start = pos + 5;
        let end = start.checked_add(size).ok_or_else(damaged)?;
        let data = payload.get(start..end).ok_or_else(damaged)?;
        pos = end;
        match id {
            0 => break,
            1 => stream_id = Some(u32::from_le_bytes(*read::<4>(data, 0)?)),
            2 => stream_key = Some(Zeroizing::new(data.to_vec())),
            _ => {}
        }
    }
    let stream = InnerStream::new(
        stream_id.ok_or_else(damaged)?,
        stream_key.as_deref().map_or(&[], Vec::as_slice),
    )?;
    payload.drain(..pos);
    Ok(Opened {
        xml: payload,
        stream,
    })
}

#[derive(Clone, Copy)]
enum Cipher {
    Aes256,
    Twofish,
    ChaCha20,
}

struct Header<'a> {
    /// Where the header ends (after its end field).
    end: usize,
    cipher: Cipher,
    gzip: bool,
    master_seed: &'a [u8],
    iv: &'a [u8],
    kdf: Kdf,
    // KDBX 3.1 only; KDBX 4 moved the stream into the encrypted inner header.
    stream_id: u32,
    stream_key: &'a [u8],
    start_bytes: &'a [u8],
}

impl<'a> Header<'a> {
    /// Fields are `id: u8, size: u16 (KDBX 3) or u32 (KDBX 4), data`, ending with id 0.
    fn parse(bytes: &'a [u8], kdbx4: bool) -> Result<Self, ImportError> {
        let mut pos = 12;
        let (mut cipher, mut gzip, mut master_seed, mut iv, mut kdf) =
            (None, false, None, None, None);
        let (mut aes_seed, mut aes_rounds) = (None, None);
        let (mut stream_id, mut stream_key, mut start_bytes): (u32, &[u8], &[u8]) = (0, &[], &[]);
        loop {
            let id = read::<1>(bytes, pos)?[0];
            let (size, start) = if kdbx4 {
                (
                    u32::from_le_bytes(*read::<4>(bytes, pos + 1)?) as usize,
                    pos + 5,
                )
            } else {
                (
                    u16::from_le_bytes(*read::<2>(bytes, pos + 1)?) as usize,
                    pos + 3,
                )
            };
            let end = start.checked_add(size).ok_or_else(damaged)?;
            let data = bytes.get(start..end).ok_or_else(damaged)?;
            pos = end;
            match id {
                0 => break,
                2 => {
                    cipher = Some(match data {
                        _ if data == AES256 => Cipher::Aes256,
                        _ if data == TWOFISH => Cipher::Twofish,
                        _ if data == CHACHA20 => Cipher::ChaCha20,
                        _ => {
                            return Err(unsupported(
                                "This KeePass database uses an encryption algorithm Octa Pass doesn't support. Switch it to AES-256 or ChaCha20 in the database settings and try again.",
                            ));
                        }
                    })
                }
                3 => {
                    gzip = match u32::from_le_bytes(*read::<4>(data, 0)?) {
                        0 => false,
                        1 => true,
                        _ => return Err(damaged()),
                    }
                }
                4 => master_seed = Some(data),
                5 => aes_seed = Some(data),
                6 => aes_rounds = Some(u64::from_le_bytes(*read::<8>(data, 0)?)),
                7 => iv = Some(data),
                8 => stream_key = data,
                9 => start_bytes = data,
                10 => stream_id = u32::from_le_bytes(*read::<4>(data, 0)?),
                11 if kdbx4 => kdf = Some(Kdf::from_dictionary(data)?),
                _ => {}
            }
        }
        if !kdbx4 {
            kdf = Some(Kdf::aes(
                aes_seed.ok_or_else(damaged)?,
                aes_rounds.ok_or_else(damaged)?,
            )?);
        }
        Ok(Self {
            end: pos,
            cipher: cipher.ok_or_else(damaged)?,
            gzip,
            master_seed: master_seed.ok_or_else(damaged)?,
            iv: iv.ok_or_else(damaged)?,
            kdf: kdf.ok_or_else(damaged)?,
            stream_id,
            stream_key,
            start_bytes,
        })
    }
}

enum Kdf {
    Aes {
        seed: [u8; 32],
        rounds: u64,
    },
    Argon2 {
        algorithm: argon2::Algorithm,
        version: argon2::Version,
        salt: Vec<u8>,
        memory_kib: u64,
        iterations: u64,
        lanes: u64,
        secret: Vec<u8>,
        data: Vec<u8>,
    },
}

impl Kdf {
    fn aes(seed: &[u8], rounds: u64) -> Result<Self, ImportError> {
        Ok(Self::Aes {
            seed: seed.try_into().map_err(|_| damaged())?,
            rounds,
        })
    }

    /// KDBX 4 keeps the KDF settings in a "variant dictionary": `version: u16`, then entries of
    /// `type: u8, name size: u32, name, value size: u32, value`, ending with type 0.
    fn from_dictionary(dictionary: &[u8]) -> Result<Self, ImportError> {
        let version = u16::from_le_bytes(*read::<2>(dictionary, 0)?);
        if version & 0xff00 > 0x0100 {
            return Err(unknown_kdf());
        }
        let mut entries: Vec<(&[u8], &[u8])> = Vec::new();
        let mut pos = 2;
        while read::<1>(dictionary, pos)?[0] != 0 {
            let field = |pos: usize| -> Result<(&[u8], usize), ImportError> {
                let size = u32::from_le_bytes(*read::<4>(dictionary, pos)?) as usize;
                let end = (pos + 4).checked_add(size).ok_or_else(damaged)?;
                Ok((dictionary.get(pos + 4..end).ok_or_else(damaged)?, end))
            };
            let (name, next) = field(pos + 1)?;
            let (value, next) = field(next)?;
            entries.push((name, value));
            pos = next;
        }
        let get = |name: &str| {
            entries
                .iter()
                .find(|(n, _)| *n == name.as_bytes())
                .map(|(_, v)| *v)
        };
        let number = |name: &str| -> Option<u64> {
            match get(name)? {
                v if v.len() == 4 => Some(u32::from_le_bytes(v.try_into().ok()?).into()),
                v if v.len() == 8 => Some(u64::from_le_bytes(v.try_into().ok()?)),
                _ => None,
            }
        };
        let id = get("$UUID").ok_or_else(damaged)?;
        if id == AES_KDF || id == AES_KDF_KDBX3 {
            return Self::aes(
                get("S").ok_or_else(damaged)?,
                number("R").ok_or_else(damaged)?,
            );
        }
        let algorithm = match id {
            _ if id == ARGON2D => argon2::Algorithm::Argon2d,
            _ if id == ARGON2ID => argon2::Algorithm::Argon2id,
            _ => return Err(unknown_kdf()),
        };
        let version = match number("V").unwrap_or(0x13) {
            0x10 => argon2::Version::V0x10,
            0x13 => argon2::Version::V0x13,
            _ => return Err(unknown_kdf()),
        };
        Ok(Self::Argon2 {
            algorithm,
            version,
            salt: get("S").ok_or_else(damaged)?.to_vec(),
            // KeePass stores the memory in bytes.
            memory_kib: number("M").ok_or_else(damaged)? / 1024,
            iterations: number("I").ok_or_else(damaged)?,
            lanes: number("P").ok_or_else(damaged)?,
            secret: get("K").unwrap_or_default().to_vec(),
            data: get("A").unwrap_or_default().to_vec(),
        })
    }

    fn check(&self) -> Result<(), ImportError> {
        let ok = match *self {
            Self::Aes { rounds, .. } => rounds <= MAX_AES_ROUNDS,
            Self::Argon2 {
                memory_kib,
                iterations,
                lanes,
                ..
            } => {
                (1..=MAX_ARGON2_MEMORY_KIB).contains(&memory_kib)
                    && (1..=MAX_ARGON2_LANES).contains(&lanes)
                    && iterations >= 1
                    && memory_kib.saturating_mul(iterations) <= MAX_ARGON2_WORK_KIB
            }
        };
        ok.then_some(()).ok_or_else(unsupported_kdf)
    }

    fn transform(&self, composite: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, ImportError> {
        let mut out = Zeroizing::new([0u8; 32]);
        match self {
            Self::Aes { seed, rounds } => {
                let cipher = Aes256::new(seed.into());
                let mut blocks = [
                    aes::Block::clone_from_slice(&composite[..16]),
                    aes::Block::clone_from_slice(&composite[16..]),
                ];
                // The two halves are independent, so each round encrypts them as one batch.
                for _ in 0..*rounds {
                    cipher.encrypt_blocks(&mut blocks);
                }
                let digest = Sha256::new()
                    .chain_update(blocks[0])
                    .chain_update(blocks[1])
                    .finalize();
                out.copy_from_slice(&digest);
                for block in &mut blocks {
                    block.as_mut_slice().zeroize();
                }
            }
            Self::Argon2 {
                algorithm,
                version,
                salt,
                memory_kib,
                iterations,
                lanes,
                secret,
                data,
            } => {
                // `check` has bounded every number to fit in a u32.
                let mut params = argon2::ParamsBuilder::new();
                params
                    .m_cost(*memory_kib as u32)
                    .t_cost(*iterations as u32)
                    .p_cost(*lanes as u32)
                    .output_len(32);
                if !data.is_empty() {
                    params.data(argon2::AssociatedData::new(data).map_err(|_| unsupported_kdf())?);
                }
                let params = params.build().map_err(|_| unsupported_kdf())?;
                let argon2 = if secret.is_empty() {
                    argon2::Argon2::new(*algorithm, *version, params)
                } else {
                    argon2::Argon2::new_with_secret(secret, *algorithm, *version, params)
                        .map_err(|_| unsupported_kdf())?
                };
                argon2
                    .hash_password_into(composite, salt, out.as_mut())
                    .map_err(|_| unsupported_kdf())?;
            }
        }
        Ok(out)
    }
}

/// SHA-256 over the password's hash and the key file's key. An empty password next to a key
/// file counts as no password, which is how KeePassXC opens key-file-only databases.
fn composite_key(
    password: Option<&str>,
    key_file: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>, ImportError> {
    let password = password.filter(|p| !p.is_empty());
    if password.is_none() && key_file.is_none() {
        return Err(ImportError::new(
            Error::ImportPasswordRequired,
            "This KeePass database is locked with a password or a key file.",
        ));
    }
    let mut hasher = Sha256::new();
    if let Some(password) = password {
        hasher.update(Sha256::digest(password.as_bytes()));
    }
    if let Some(file) = key_file {
        hasher.update(key_file_key(file)?.as_slice());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&hasher.finalize());
    Ok(key)
}

/// A key file's key: the data of an XML key file (version 1.0 base64, 2.0 hex), 32 raw bytes,
/// 64 hex digits, or else the SHA-256 of the whole file.
pub(super) fn key_file_key(file: &[u8]) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    if let Some(key) = xml_key_file(file)? {
        return Ok(key);
    }
    if file.len() == 32 {
        return Ok(Zeroizing::new(file.to_vec()));
    }
    if file.len() == 64
        && let Some(key) = hex_decode(file)
    {
        return Ok(Zeroizing::new(key));
    }
    Ok(Zeroizing::new(Sha256::digest(file).to_vec()))
}

/// `None` when the file isn't an XML key file (`<KeyFile><Meta><Version>` …
/// `<Key><Data Hash="…">`), so it is read as a plain one.
fn xml_key_file(file: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, ImportError> {
    let Ok(text) = std::str::from_utf8(file.strip_prefix(b"\xef\xbb\xbf").unwrap_or(file)) else {
        return Ok(None);
    };
    let mut reader = Reader::from_str(text);
    reader.config_mut().expand_empty_elements = true;
    let (mut path, mut text) = (Vec::<String>::new(), Zeroizing::new(String::new()));
    let (mut version, mut data, mut hash) = (None, None, None);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref().as_bytes()).into_owned();
                if path.is_empty() && name != "KeyFile" {
                    return Ok(None);
                }
                if name == "Data" {
                    hash = e
                        .try_get_attribute("Hash")
                        .ok()
                        .flatten()
                        .map(|a| a.value.into_owned());
                }
                path.push(name);
                text.clear();
            }
            Ok(Event::Text(t)) => text.push_str(&t.xml10_content()),
            Ok(Event::End(_)) => {
                match path.iter().map(String::as_str).collect::<Vec<_>>()[..] {
                    ["KeyFile", "Meta", "Version"] => version = Some(text.trim().to_string()),
                    ["KeyFile", "Key", "Data"] => data = Some(Zeroizing::new(text.to_string())),
                    _ => {}
                }
                path.pop();
                text.clear();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Ok(None),
        }
    }
    let (Some(version), Some(data)) = (version, data) else {
        return Ok(None);
    };
    let bad = || ImportError::new(Error::InvalidImportFile, "The key file is damaged.");
    let key = if version.starts_with("1.") {
        STANDARD.decode(data.trim()).map_err(|_| bad())?
    } else if version.starts_with("2.") {
        let digits: Vec<u8> = data.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        let key = hex_decode(&digits).ok_or_else(bad)?;
        if let Some(hash) = hash
            && hex_decode(hash.as_bytes()).as_deref() != Some(&Sha256::digest(&key)[..4])
        {
            return Err(bad());
        }
        key
    } else {
        return Err(bad());
    };
    Ok(Some(Zeroizing::new(key)))
}

pub(super) fn hex_decode(digits: &[u8]) -> Option<Vec<u8>> {
    let value = |d: u8| char::from(d).to_digit(16);
    let (pairs, rest) = digits.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[high, low]| Some((value(high)? * 16 + value(low)?) as u8))
        .collect()
}

fn master_key(master_seed: &[u8], transformed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(
        &Sha256::new()
            .chain_update(master_seed)
            .chain_update(transformed)
            .finalize(),
    );
    key
}

/// Decrypts the payload. Block ciphers keep their padding; [`unpad`] removes it.
fn decrypt(
    cipher: Cipher,
    key: &[u8; 32],
    iv: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let mut buffer = Zeroizing::new(data.to_vec());
    match cipher {
        Cipher::Aes256 => {
            cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|_| damaged())?
                .decrypt_padded_mut::<NoPadding>(&mut buffer)
                .map_err(|_| damaged())?;
        }
        Cipher::Twofish => {
            cbc::Decryptor::<twofish::Twofish>::new_from_slices(key, iv)
                .map_err(|_| damaged())?
                .decrypt_padded_mut::<NoPadding>(&mut buffer)
                .map_err(|_| damaged())?;
        }
        Cipher::ChaCha20 => chacha20::ChaCha20::new_from_slices(key, iv)
            .map_err(|_| damaged())?
            .apply_keystream(&mut buffer),
    }
    Ok(buffer)
}

/// Removes PKCS#7 padding after a block cipher.
fn unpad(cipher: Cipher, buffer: &mut Zeroizing<Vec<u8>>) -> Result<(), ImportError> {
    if matches!(cipher, Cipher::ChaCha20) {
        return Ok(());
    }
    let pad = usize::from(*buffer.last().ok_or_else(damaged)?);
    let len = buffer.len();
    if !(1..=16).contains(&pad)
        || pad > len
        || buffer[len - pad..].iter().any(|&b| usize::from(b) != pad)
    {
        return Err(damaged());
    }
    buffer.truncate(len - pad);
    Ok(())
}

/// KDBX 3.1 blocks: `index: u32, SHA-256: [u8; 32], size: u32, data`, ending with an empty block.
fn hashed_blocks(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    let mut pos = 0;
    loop {
        let hash = read::<32>(data, pos + 4)?;
        let size = u32::from_le_bytes(*read::<4>(data, pos + 36)?) as usize;
        let end = (pos + 40).checked_add(size).ok_or_else(damaged)?;
        let block = data.get(pos + 40..end).ok_or_else(damaged)?;
        if size == 0 {
            return Ok(out);
        }
        if Sha256::digest(block).as_slice() != hash {
            return Err(damaged());
        }
        out.extend_from_slice(block);
        pos = end;
    }
}

/// KDBX 4 blocks: `HMAC: [u8; 32], size: u32, data`, each MAC keyed by its block index and
/// covering `index: u64 ‖ size ‖ data`; an empty block ends the stream.
fn hmac_blocks(data: &[u8], hmac_key: &[u8; 64]) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    let (mut pos, mut index) = (0, 0u64);
    loop {
        let tag = read::<32>(data, pos)?;
        let size_bytes = read::<4>(data, pos + 32)?;
        let size = u32::from_le_bytes(*size_bytes) as usize;
        let end = (pos + 36).checked_add(size).ok_or_else(damaged)?;
        let block = data.get(pos + 36..end).ok_or_else(damaged)?;
        let mut mac = block_mac(index, hmac_key);
        mac.update(&index.to_le_bytes());
        mac.update(size_bytes);
        mac.update(block);
        mac.verify_slice(tag).map_err(|_| damaged())?;
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(block);
        (pos, index) = (end, index + 1);
    }
}

fn block_mac(index: u64, hmac_key: &[u8; 64]) -> Hmac<Sha256> {
    let key = Zeroizing::new(
        Sha512::new()
            .chain_update(index.to_le_bytes())
            .chain_update(hmac_key)
            .finalize(),
    );
    <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC takes any key length")
}

fn inflate_limit(file_size: usize) -> usize {
    file_size
        .saturating_mul(MAX_INFLATE_RATIO)
        .clamp(MIN_INFLATE_LIMIT, MAX_INFLATE_LIMIT)
}

fn inflate(
    data: Zeroizing<Vec<u8>>,
    gzip: bool,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    if !gzip {
        return Ok(data);
    }
    let mut out = Zeroizing::new(Vec::new());
    flate2::read::GzDecoder::new(data.as_slice())
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| damaged())?;
    if out.len() > limit {
        return Err(ImportError::new(
            Error::InvalidImportFile,
            "This KeePass database is too large to import.",
        ));
    }
    Ok(out)
}

/// The key stream that masks protected values in the XML, in document order.
pub(super) enum InnerStream {
    /// KeePass's XML export: values are in the clear.
    None,
    Salsa20(Box<salsa20::Salsa20>),
    ChaCha20(Box<chacha20::ChaCha20>),
}

impl InnerStream {
    fn new(id: u32, key: &[u8]) -> Result<Self, ImportError> {
        match id {
            0 => Ok(Self::None),
            2 => {
                let key = Zeroizing::new(Sha256::digest(key));
                Ok(Self::Salsa20(Box::new(salsa20::Salsa20::new(
                    &key,
                    &SALSA20_IV.into(),
                ))))
            }
            3 => {
                let hash = Zeroizing::new(Sha512::digest(key));
                Ok(Self::ChaCha20(Box::new(
                    chacha20::ChaCha20::new_from_slices(&hash[..32], &hash[32..44])
                        .map_err(|_| damaged())?,
                )))
            }
            // 1 is the ArcFour variant of KeePass 2.0 betas.
            _ => Err(unsupported(
                "This KeePass database is from an old version Octa Pass can't read. Save it again in KeePass 2 or KeePassXC and try again.",
            )),
        }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        match self {
            Self::None => {}
            Self::Salsa20(cipher) => cipher.apply_keystream(data),
            Self::ChaCha20(cipher) => cipher.apply_keystream(data),
        }
    }
}

fn read<const N: usize>(bytes: &[u8], pos: usize) -> Result<&[u8; N], ImportError> {
    bytes
        .get(pos..pos.checked_add(N).ok_or_else(damaged)?)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(damaged)
}

fn damaged() -> ImportError {
    ImportError::new(
        Error::InvalidImportFile,
        "This KeePass database is damaged.",
    )
}

fn wrong_key() -> ImportError {
    ImportError::new(
        Error::WrongImportPassword,
        "Wrong password or key file for this KeePass database.",
    )
}

fn unsupported(detail: &'static str) -> ImportError {
    ImportError::new(Error::UnsupportedImport, detail)
}

fn unknown_kdf() -> ImportError {
    unsupported(
        "This KeePass database uses a key derivation function Octa Pass doesn't support. Switch it to Argon2 or AES-KDF in the database settings and try again.",
    )
}

fn unsupported_kdf() -> ImportError {
    unsupported(
        "This KeePass database uses key derivation settings that would take too long to open here. Lower them in the database settings (encryption, transform rounds or Argon2 memory and iterations) and try again.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_files() {
        let raw = [7u8; 32];
        assert_eq!(key_file_key(&raw).unwrap().as_slice(), raw);
        let hex = b"0707070707070707070707070707070707070707070707070707070707070707";
        assert_eq!(key_file_key(hex).unwrap().as_slice(), raw);
        let v1 = format!(
            "<?xml version=\"1.0\"?>\n<KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>{}</Data></Key></KeyFile>",
            STANDARD.encode(raw)
        );
        assert_eq!(key_file_key(v1.as_bytes()).unwrap().as_slice(), raw);
        let checksum: String = Sha256::digest(raw)[..4]
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        let v2 = format!(
            "<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"{checksum}\">\n 07070707 07070707 07070707 07070707\n 07070707 07070707 07070707 07070707\n</Data></Key></KeyFile>"
        );
        assert_eq!(key_file_key(v2.as_bytes()).unwrap().as_slice(), raw);
        let tampered = v2.replace(&checksum, "00000000");
        assert_eq!(
            key_file_key(tampered.as_bytes()).unwrap_err().code,
            Error::InvalidImportFile
        );
        // Anything else, XML included, is hashed.
        for other in [&b"<other/>"[..], b"short", &[0xff; 64]] {
            assert_eq!(
                key_file_key(other).unwrap().as_slice(),
                Sha256::digest(other).as_slice()
            );
        }
    }

    fn dictionary(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = vec![0x00, 0x01];
        for (name, value) in entries {
            out.push(0x42);
            out.extend((name.len() as u32).to_le_bytes());
            out.extend(name.as_bytes());
            out.extend((value.len() as u32).to_le_bytes());
            out.extend(*value);
        }
        out.push(0);
        out
    }

    fn argon2(memory: u64, iterations: u64, lanes: u32) -> Result<Kdf, ImportError> {
        Kdf::from_dictionary(&dictionary(&[
            ("$UUID", &ARGON2ID),
            ("S", &[1; 32]),
            ("M", &memory.to_le_bytes()),
            ("I", &iterations.to_le_bytes()),
            ("P", &lanes.to_le_bytes()),
        ]))
    }

    #[test]
    fn kdf_caps() {
        let ok = |kdf: Result<Kdf, ImportError>| kdf.and_then(|k| k.check()).is_ok();
        // KeePassXC's default memory is 64 MiB; at most 1 GiB × 16 passes.
        assert!(ok(argon2(64 << 20, 10, 8)));
        assert!(ok(argon2(1 << 30, 16, 4)));
        assert!(!ok(argon2(1 << 30, 17, 4)));
        assert!(!ok(argon2(2 << 30, 1, 4)));
        assert!(!ok(argon2(64 << 20, 0, 1)));
        assert!(!ok(argon2(64 << 20, 1, 0)));
        assert!(!ok(argon2(64 << 20, u64::MAX, 1)), "no overflow");
        assert!(Kdf::aes(&[0; 32], MAX_AES_ROUNDS).unwrap().check().is_ok());
        assert!(
            Kdf::aes(&[0; 32], MAX_AES_ROUNDS + 1)
                .unwrap()
                .check()
                .is_err()
        );
        let unknown = Kdf::from_dictionary(&dictionary(&[("$UUID", &[9; 16])]));
        assert_eq!(unknown.err().unwrap().code, Error::UnsupportedImport);
        // Truncated and oversized entries.
        let mut broken = dictionary(&[("$UUID", &ARGON2ID)]);
        broken.truncate(10);
        assert!(Kdf::from_dictionary(&broken).is_err());
        assert!(Kdf::from_dictionary(&[0x00, 0x01, 0x42, 0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn argon2_uses_the_settings_as_given() {
        let key = argon2(1 << 20, 2, 1).unwrap().transform(&[3; 32]).unwrap();
        let mut expected = [0u8; 32];
        argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(1024, 2, 1, Some(32)).unwrap(),
        )
        .hash_password_into(&[3; 32], &[1; 32], &mut expected)
        .unwrap();
        assert_eq!(*key, expected);
    }

    #[test]
    fn padding() {
        let mut buffer = Zeroizing::new(b"abc\x03\x03\x03".to_vec());
        unpad(Cipher::Aes256, &mut buffer).unwrap();
        assert_eq!(buffer.as_slice(), b"abc");
        for bad in [&b"abc\x00"[..], b"abc\x02\x03", b"", b"\x11"] {
            let mut buffer = Zeroizing::new(bad.to_vec());
            assert!(unpad(Cipher::Twofish, &mut buffer).is_err());
        }
        let mut stream = Zeroizing::new(b"abc\x00".to_vec());
        unpad(Cipher::ChaCha20, &mut stream).unwrap();
        assert_eq!(stream.len(), 4);
    }

    #[test]
    fn inflating_is_bounded() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&[0u8; 1001]).unwrap();
        let bomb = Zeroizing::new(encoder.finish().unwrap());
        assert_eq!(inflate(bomb.clone(), true, 1001).unwrap().len(), 1001);
        assert_eq!(
            inflate(bomb, true, 1000).unwrap_err().code,
            Error::InvalidImportFile
        );
        assert_eq!(inflate_limit(1000), MIN_INFLATE_LIMIT);
        assert_eq!(inflate_limit(1 << 20), 100 << 20);
        assert_eq!(inflate_limit(usize::MAX), MAX_INFLATE_LIMIT);
    }
}
