//! Octa Pass Safe: the format of the encrypted drive (plan 16). Everything here is pure; the engine
//! that keeps blobs on disk and mounts them is `octapass-files`.
//!
//! A Safe is a flat set of **blobs**, named by random UUIDs, so its folder shows only how many
//! blobs there are and how big. Nothing on disk or on a server names a file, a folder or which
//! blobs belong together.
//!
//! ```text
//! safe key (32 random bytes, in a vault item)
//!  ├─ HKDF(salt = safe id, info = "openpass/v1/safe/records") ─► record key
//!  └─ HKDF(salt = safe id, info = "openpass/v1/safe/state")   ─► state key
//!
//! record blob = envelope(record key, padded(JSON record),
//!                        aad = "openpass/v1|saferecord:<safeId>:<blobId>")
//! record      = { object, rev, prev, parent, name, kind, size, modified, content, fileKey }
//! padded      = length (u32, big-endian) ‖ JSON ‖ zeros to a multiple of 512 bytes
//!
//! content blob = header ‖ chunk_0 ‖ … ‖ chunk_n, exactly as attachments
//! header       = version (0x01) ‖ key_id (16) ‖ nonce_prefix (19 random bytes)
//! chunk_i      = XChaCha20-Poly1305(file key, nonce = nonce_prefix ‖ i ‖ last,
//!                  aad = "openpass/v1|safecontent:<safeId>:<objectId>:<blobId>")
//! ```
//!
//! - **Every file and folder is one object**, whose current state is its newest record. A change
//!   writes a new record blob with `rev + 1` and deletes the old one. A rename touches one small
//!   blob, which is why a Safe syncs efficiently.
//! - **Every content revision has its own random file key and nonce prefix.** Blobs are never
//!   rewritten, so no nonce is ever reused however often a file changes.
//! - **Names** live only in the records, which are padded so that a name's length doesn't show.
//! - **A record names its content blob**, and the content's associated data names the object, so a
//!   server can't pair a record with another file's content, or an old one.
//! - **Rollback.** Records are authenticated but a server can still withhold the newest one. The
//!   engine keeps the highest `rev` it has seen per object on each device and reports a drop; a
//!   device that never saw the newer record can't tell.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::account::parse_id;
use crate::attachment::{CHUNK_LEN, Decryptor, Encryptor, HEADER_LEN, SEALED_CHUNK_LEN};
use crate::encoding::{b64_decode, b64_encode};
use crate::envelope::{Context, HEADER_LEN as ENVELOPE_HEADER_LEN, TAG_LEN, VERSION, open, seal};
use crate::error::{Error, Result};
use crate::keys::{KEY_ID_LEN, SymmetricKey, hkdf_key};
use crate::stream::{PREFIX_LEN, Stream};

/// The parent of everything at the top of a Safe.
pub const ROOT: &str = "00000000-0000-0000-0000-000000000000";
/// The longest name, in bytes of UTF-8: what file systems allow.
pub const MAX_NAME_LEN: usize = 255;
/// Records are padded to a multiple of this.
pub const RECORD_PADDING: usize = 512;
const ENVELOPE_LEN: usize = ENVELOPE_HEADER_LEN + TAG_LEN;
/// Plaintext bytes per chunk of a content blob.
pub const CONTENT_CHUNK_LEN: usize = CHUNK_LEN;

/// The first byte of a blob id says what it is, so a device can fetch records without fetching
/// content. Anyone can see which is which; the sizes already show that much.
const RECORD_BLOB_TAG: u8 = 0x4d;
const CONTENT_BLOB_TAG: u8 = 0x43;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKind {
    Record,
    Content,
}

/// A new random id for a blob of this kind.
pub fn new_blob_id(kind: BlobKind, rng: &mut impl CryptoRngCore) -> String {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes[0] = match kind {
        BlobKind::Record => RECORD_BLOB_TAG,
        BlobKind::Content => CONTENT_BLOB_TAG,
    };
    uuid::Uuid::from_bytes(bytes).hyphenated().to_string()
}

/// What kind of blob an id names, or `None` if it isn't one of ours.
pub fn blob_kind(blob_id: &str) -> Option<BlobKind> {
    let uuid = uuid::Uuid::try_parse(blob_id).ok()?;
    match uuid.as_bytes()[0] {
        RECORD_BLOB_TAG => Some(BlobKind::Record),
        CONTENT_BLOB_TAG => Some(BlobKind::Content),
        _ => None,
    }
}

/// A new random id for a Safe or an object in it.
pub fn new_object_id(rng: &mut impl CryptoRngCore) -> String {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .hyphenated()
        .to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ObjectKind {
    File,
    Folder,
    /// Deleted. Kept so the deletion reaches the other devices.
    Deleted,
}

/// One revision of a file or folder.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct ObjectRecord {
    /// The object this is a revision of.
    pub object: String,
    /// Goes up by one with every revision.
    pub rev: u64,
    /// The record blob this revision replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// The containing folder's object, or [`ROOT`].
    pub parent: String,
    pub name: String,
    #[zeroize(skip)]
    pub kind: ObjectKind,
    /// Plaintext bytes.
    pub size: u64,
    /// Milliseconds since 1970.
    pub modified: u64,
    /// The content blob, for a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// The content's file key, base64url, for a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_key: Option<String>,
}

impl core::fmt::Debug for ObjectRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjectRecord")
            .field("object", &self.object)
            .field("rev", &self.rev)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl ObjectRecord {
    /// The record's file key.
    pub fn file_key(&self) -> Result<SymmetricKey> {
        let encoded = self.file_key.as_deref().ok_or(Error::MalformedCiphertext)?;
        SymmetricKey::from_slice(&Zeroizing::new(b64_decode(encoded)?))
    }
}

/// Encodes a file key for [`ObjectRecord::file_key`].
pub fn encode_file_key(key: &SymmetricKey) -> String {
    b64_encode(key.as_bytes())
}

/// Whether a name is one a Safe can hold: not empty, not `.` or `..`, no separator or NUL, and no
/// longer than file systems allow.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0'])
}

/// The keys one Safe works with while unlocked.
pub struct SafeKeys {
    safe_id: String,
    record_key: SymmetricKey,
    state_key: SymmetricKey,
}

impl SafeKeys {
    pub fn derive(safe_key: &SymmetricKey, safe_id: &str) -> Result<Self> {
        let safe_id = parse_id(safe_id)?;
        Ok(Self {
            record_key: hkdf_key(
                safe_key.as_bytes(),
                safe_id.as_bytes(),
                b"openpass/v1/safe/records",
            ),
            state_key: hkdf_key(
                safe_key.as_bytes(),
                safe_id.as_bytes(),
                b"openpass/v1/safe/state",
            ),
            safe_id,
        })
    }

    pub fn safe_id(&self) -> &str {
        &self.safe_id
    }

    /// Seals a record as the blob named `blob_id`.
    pub fn seal_record(
        &self,
        blob_id: &str,
        record: &ObjectRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let blob_id = parse_id(blob_id)?;
        let json = Zeroizing::new(serde_json::to_vec(record).map_err(|_| Error::EncryptionFailed)?);
        let used = 4 + json.len();
        let mut padded = Zeroizing::new(Vec::with_capacity(used.next_multiple_of(RECORD_PADDING)));
        padded.extend_from_slice(&(json.len() as u32).to_be_bytes());
        padded.extend_from_slice(&json);
        padded.resize(used.next_multiple_of(RECORD_PADDING), 0);
        seal(
            &self.record_key,
            &Context::SafeRecord {
                safe_id: &self.safe_id,
                blob_id: &blob_id,
            },
            &padded,
            rng,
        )
    }

    /// Opens a record blob. Fails if it was changed, or renamed to another blob's id.
    pub fn open_record(&self, blob_id: &str, sealed: &[u8]) -> Result<ObjectRecord> {
        let blob_id = parse_id(blob_id)?;
        let padded = open(
            &self.record_key,
            &Context::SafeRecord {
                safe_id: &self.safe_id,
                blob_id: &blob_id,
            },
            sealed,
        )?;
        let len = padded
            .first_chunk::<4>()
            .map(|bytes| u32::from_be_bytes(*bytes) as usize)
            .ok_or(Error::MalformedCiphertext)?;
        let json = padded
            .get(4..4usize.saturating_add(len))
            .ok_or(Error::MalformedCiphertext)?;
        let record: ObjectRecord =
            serde_json::from_slice(json).map_err(|_| Error::MalformedCiphertext)?;
        if parse_id(&record.object)? != record.object
            || parse_id(&record.parent)? != record.parent
            || (record.kind != ObjectKind::Deleted && !valid_name(&record.name))
        {
            return Err(Error::MalformedCiphertext);
        }
        Ok(record)
    }

    /// Seals this device's notes about the Safe (never leaves the device).
    pub fn seal_state(&self, state: &[u8], rng: &mut impl CryptoRngCore) -> Result<Vec<u8>> {
        seal(
            &self.state_key,
            &Context::SafeState {
                safe_id: &self.safe_id,
            },
            state,
            rng,
        )
    }

    pub fn open_state(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        open(
            &self.state_key,
            &Context::SafeState {
                safe_id: &self.safe_id,
            },
            sealed,
        )
    }

    fn content_aad(&self, object_id: &str, blob_id: &str) -> Result<Vec<u8>> {
        Ok(Context::SafeContent {
            safe_id: &self.safe_id,
            object_id: &parse_id(object_id)?,
            blob_id: &parse_id(blob_id)?,
        }
        .associated_data())
    }

    /// Starts a content blob under a fresh file key. Put `encode_file_key` of the returned key in
    /// the record.
    pub fn new_content(
        &self,
        object_id: &str,
        blob_id: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(SymmetricKey, Encryptor)> {
        let file_key = SymmetricKey::generate(rng);
        let mut prefix = [0u8; PREFIX_LEN];
        rng.fill_bytes(&mut prefix);
        let aad = self.content_aad(object_id, blob_id)?;
        let encryptor = Encryptor::with_prefix(&file_key, aad, prefix);
        Ok((file_key, encryptor))
    }

    /// Reads a content blob from its first bytes. `blob_len` is the whole blob's size.
    pub fn open_content(
        &self,
        record: &ObjectRecord,
        header: &[u8],
        blob_len: u64,
    ) -> Result<ContentReader> {
        let blob_id = record
            .content
            .as_deref()
            .ok_or(Error::MalformedCiphertext)?;
        let key = record.file_key()?;
        if header.len() != HEADER_LEN {
            return Err(Error::MalformedCiphertext);
        }
        if header[0] != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if header[1..1 + KEY_ID_LEN] != key.key_id() {
            return Err(Error::WrongKey);
        }
        let plain = plain_len(blob_len)?;
        if plain != record.size {
            return Err(Error::MalformedCiphertext);
        }
        let mut prefix = [0u8; PREFIX_LEN];
        prefix.copy_from_slice(&header[1 + KEY_ID_LEN..]);
        Ok(ContentReader {
            stream: Stream {
                aad: self.content_aad(&record.object, blob_id)?,
                key,
                prefix,
                counter: Some(0),
            },
            plain_len: plain,
        })
    }
}

/// How many chunks hold `plaintext_len` bytes; an empty file still has one (empty) chunk.
pub fn chunk_count(plaintext_len: u64) -> u64 {
    plaintext_len.div_ceil(CHUNK_LEN as u64).max(1)
}

/// The size of a content blob holding `plaintext_len` bytes.
pub fn content_len(plaintext_len: u64) -> u64 {
    crate::attachment::encrypted_len(plaintext_len)
}

/// The plaintext size of a content blob of `blob_len` bytes.
pub fn plain_len(blob_len: u64) -> Result<u64> {
    let body = blob_len
        .checked_sub(HEADER_LEN as u64)
        .ok_or(Error::MalformedCiphertext)?;
    let sealed = SEALED_CHUNK_LEN as u64;
    let full = body / sealed;
    let rest = body % sealed;
    let tail = match rest {
        0 if full > 0 => return Ok(full * CHUNK_LEN as u64),
        0 => return Err(Error::MalformedCiphertext),
        rest if rest < TAG_LEN as u64 => return Err(Error::MalformedCiphertext),
        // A tail chunk with no data is only legal in an empty file.
        rest if rest == TAG_LEN as u64 && full > 0 => return Err(Error::MalformedCiphertext),
        rest => rest - TAG_LEN as u64,
    };
    Ok(full * CHUNK_LEN as u64 + tail)
}

/// The range of a chunk within a content blob, and whether it's the last.
pub fn chunk_span(plaintext_len: u64, index: u64) -> Option<(u64, usize, bool)> {
    let count = chunk_count(plaintext_len);
    if index >= count {
        return None;
    }
    let last = index + 1 == count;
    let len = if last {
        (plaintext_len - index * CHUNK_LEN as u64) as usize + TAG_LEN
    } else {
        SEALED_CHUNK_LEN
    };
    Some((
        HEADER_LEN as u64 + index * SEALED_CHUNK_LEN as u64,
        len,
        last,
    ))
}

/// Opens any chunk of a content blob, in any order, so a mounted Safe can seek.
pub struct ContentReader {
    stream: Stream,
    plain_len: u64,
}

impl ContentReader {
    pub fn plain_len(&self) -> u64 {
        self.plain_len
    }

    /// Opens chunk `index`, given exactly the bytes [`chunk_span`] named.
    pub fn open_chunk(&mut self, index: u64, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let (_, len, last) = chunk_span(self.plain_len, index).ok_or(Error::MalformedCiphertext)?;
        if sealed.len() != len {
            return Err(Error::MalformedCiphertext);
        }
        self.stream.counter = Some(u32::try_from(index).map_err(|_| Error::MalformedCiphertext)?);
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        self.stream.open(sealed, last, &mut out)?;
        Ok(out)
    }
}

/// Opens a whole content blob in one go: the check other tools and tests use.
pub fn open_content_blob(
    keys: &SafeKeys,
    record: &ObjectRecord,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let blob_id = record
        .content
        .as_deref()
        .ok_or(Error::MalformedCiphertext)?;
    let aad = keys.content_aad(&record.object, blob_id)?;
    let mut decryptor = Decryptor::with_aad(&record.file_key()?, aad);
    let mut out = decryptor.push(blob)?;
    out.extend_from_slice(&decryptor.finish()?);
    Ok(out)
}

/// The header of a blob, as [`SafeKeys::open_content`] wants it.
pub const CONTENT_HEADER_LEN: usize = HEADER_LEN;

/// The bytes one staged chunk takes. Chunks are padded so that any can be rewritten in place; each
/// write draws a fresh nonce, so rewriting one reuses nothing.
pub const STAGING_SLOT_LEN: usize = 4 + CHUNK_LEN + ENVELOPE_LEN;

/// Seals a chunk of a file being written, under a key that lives only as long as the write.
pub fn seal_staging(
    key: &SymmetricKey,
    index: u64,
    plain: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    if plain.len() > CHUNK_LEN {
        return Err(Error::EncryptionFailed);
    }
    let mut padded = Zeroizing::new(vec![0u8; 4 + CHUNK_LEN]);
    padded[..4].copy_from_slice(&(plain.len() as u32).to_be_bytes());
    padded[4..4 + plain.len()].copy_from_slice(plain);
    seal(key, &Context::SafeStaging { index }, &padded, rng)
}

/// Opens a chunk sealed by [`seal_staging`].
pub fn open_staging(key: &SymmetricKey, index: u64, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let padded = open(key, &Context::SafeStaging { index }, sealed)?;
    let len = padded
        .first_chunk::<4>()
        .map(|bytes| u32::from_be_bytes(*bytes) as usize)
        .ok_or(Error::MalformedCiphertext)?;
    let plain = padded
        .get(4..4usize.saturating_add(len))
        .ok_or(Error::MalformedCiphertext)?;
    Ok(Zeroizing::new(plain.to_vec()))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    const SAFE: &str = "11111111-1111-4111-8111-111111111111";
    const OBJECT: &str = "22222222-2222-4222-8222-222222222222";

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([9; 32])
    }

    fn keys() -> SafeKeys {
        SafeKeys::derive(&SymmetricKey::from_bytes([5; 32]), SAFE).unwrap()
    }

    fn record(name: &str) -> ObjectRecord {
        ObjectRecord {
            object: OBJECT.into(),
            rev: 1,
            prev: None,
            parent: ROOT.into(),
            name: name.into(),
            kind: ObjectKind::File,
            size: 0,
            modified: 1_700_000_000_000,
            content: None,
            file_key: None,
        }
    }

    fn content(keys: &SafeKeys, plaintext: &[u8]) -> (ObjectRecord, Vec<u8>) {
        let mut rng = rng();
        let blob_id = new_blob_id(BlobKind::Content, &mut rng);
        let (file_key, mut encryptor) = keys.new_content(OBJECT, &blob_id, &mut rng).unwrap();
        let mut blob = encryptor.push(plaintext).unwrap();
        blob.extend_from_slice(&encryptor.finish().unwrap());
        let mut record = record("file");
        record.size = plaintext.len() as u64;
        record.content = Some(blob_id);
        record.file_key = Some(encode_file_key(&file_key));
        (record, blob)
    }

    fn read_all(keys: &SafeKeys, record: &ObjectRecord, blob: &[u8]) -> Result<Vec<u8>> {
        let mut reader = keys.open_content(record, &blob[..HEADER_LEN], blob.len() as u64)?;
        let mut out = Vec::new();
        for index in 0..chunk_count(record.size) {
            let (start, len, _) = chunk_span(record.size, index).unwrap();
            let start = start as usize;
            out.extend_from_slice(&reader.open_chunk(index, &blob[start..start + len])?);
        }
        Ok(out)
    }

    #[test]
    fn records_round_trip_and_hide_the_name_length() {
        let keys = keys();
        let mut rng = rng();
        let id = new_blob_id(BlobKind::Record, &mut rng);
        let short = keys.seal_record(&id, &record("a"), &mut rng).unwrap();
        let long = keys
            .seal_record(&id, &record(&"b".repeat(200)), &mut rng)
            .unwrap();
        assert_eq!(short.len(), long.len());
        assert_eq!((short.len() - ENVELOPE_LEN) % RECORD_PADDING, 0);
        assert_eq!(keys.open_record(&id, &short).unwrap().name, "a");
    }

    #[test]
    fn a_record_can_not_change_blob_or_safe() {
        let keys = keys();
        let mut rng = rng();
        let id = new_blob_id(BlobKind::Record, &mut rng);
        let other = new_blob_id(BlobKind::Record, &mut rng);
        let sealed = keys.seal_record(&id, &record("a"), &mut rng).unwrap();
        assert!(keys.open_record(&other, &sealed).is_err());
        let another = SafeKeys::derive(
            &SymmetricKey::from_bytes([5; 32]),
            "33333333-3333-4333-8333-333333333333",
        )
        .unwrap();
        assert!(another.open_record(&id, &sealed).is_err());
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(keys.open_record(&id, &flipped).is_err());
    }

    #[test]
    fn records_with_impossible_names_are_refused() {
        let keys = keys();
        let mut rng = rng();
        let id = new_blob_id(BlobKind::Record, &mut rng);
        for name in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
            let sealed = keys.seal_record(&id, &record(name), &mut rng).unwrap();
            assert!(keys.open_record(&id, &sealed).is_err(), "{name:?}");
        }
    }

    #[test]
    fn content_opens_in_any_order() {
        let keys = keys();
        let plaintext: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
        let (record, blob) = content(&keys, &plaintext);
        assert_eq!(content_len(plaintext.len() as u64), blob.len() as u64);
        assert_eq!(read_all(&keys, &record, &blob).unwrap(), plaintext);
        assert_eq!(
            *open_content_blob(&keys, &record, &blob).unwrap(),
            plaintext
        );

        let mut reader = keys
            .open_content(&record, &blob[..HEADER_LEN], blob.len() as u64)
            .unwrap();
        let (start, len, last) = chunk_span(record.size, 4).unwrap();
        assert!(last);
        let tail = reader
            .open_chunk(4, &blob[start as usize..start as usize + len])
            .unwrap();
        assert_eq!(&*tail, &plaintext[4 * CHUNK_LEN..]);
    }

    #[test]
    fn empty_and_exact_files_work() {
        let keys = keys();
        for size in [0, 1, CHUNK_LEN - 1, CHUNK_LEN, CHUNK_LEN + 1, 2 * CHUNK_LEN] {
            let plaintext = vec![3u8; size];
            let (record, blob) = content(&keys, &plaintext);
            assert_eq!(plain_len(blob.len() as u64).unwrap(), size as u64, "{size}");
            assert_eq!(
                read_all(&keys, &record, &blob).unwrap(),
                plaintext,
                "{size}"
            );
        }
    }

    #[test]
    fn cut_or_swapped_content_fails() {
        let keys = keys();
        let plaintext = vec![1u8; 3 * CHUNK_LEN];
        let (record, blob) = content(&keys, &plaintext);

        // Cut at a chunk boundary: chunk 1 was not sealed as the last.
        let cut = &blob[..HEADER_LEN + 2 * SEALED_CHUNK_LEN];
        let mut shorter = record.clone();
        shorter.size = 2 * CHUNK_LEN as u64;
        assert!(read_all(&keys, &shorter, cut).is_err());
        // The record's size and the blob's must agree.
        assert!(read_all(&keys, &record, cut).is_err());

        // Two chunks swapped.
        let mut swapped = blob.clone();
        swapped.copy_within(
            HEADER_LEN..HEADER_LEN + SEALED_CHUNK_LEN,
            HEADER_LEN + SEALED_CHUNK_LEN,
        );
        assert!(read_all(&keys, &record, &swapped).is_err());

        // Another object's content, under this record.
        let mut moved = record.clone();
        moved.object = "44444444-4444-4444-8444-444444444444".into();
        assert!(read_all(&keys, &moved, &blob).is_err());
    }

    #[test]
    fn staged_chunks_round_trip_at_any_length_and_stay_in_their_slot() {
        let key = SymmetricKey::from_bytes([8; 32]);
        let mut rng = rng();
        for len in [0, 1, CHUNK_LEN] {
            let plain = vec![6u8; len];
            let sealed = seal_staging(&key, 7, &plain, &mut rng).unwrap();
            assert_eq!(sealed.len(), STAGING_SLOT_LEN);
            assert_eq!(*open_staging(&key, 7, &sealed).unwrap(), plain);
            assert!(open_staging(&key, 8, &sealed).is_err());
        }
        assert!(seal_staging(&key, 0, &vec![0; CHUNK_LEN + 1], &mut rng).is_err());
    }

    #[test]
    fn blob_ids_tell_their_kind() {
        let mut rng = rng();
        assert_eq!(
            blob_kind(&new_blob_id(BlobKind::Record, &mut rng)),
            Some(BlobKind::Record)
        );
        assert_eq!(
            blob_kind(&new_blob_id(BlobKind::Content, &mut rng)),
            Some(BlobKind::Content)
        );
        assert_eq!(blob_kind(OBJECT), None);
        assert_eq!(blob_kind("nope"), None);
    }

    proptest! {
        #[test]
        fn plain_len_inverts_content_len(len in 0u64..(1 << 40)) {
            prop_assert_eq!(plain_len(content_len(len)).unwrap(), len);
        }

        #[test]
        fn plain_len_refuses_impossible_sizes(extra in 1u64..16, chunks in 1u64..1000) {
            let len = HEADER_LEN as u64 + chunks * SEALED_CHUNK_LEN as u64 + extra;
            prop_assert!(plain_len(len).is_err());
        }
    }
}
