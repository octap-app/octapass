//! C2SP signed notes, checkpoints and checkpoint cosignatures, so the key log can be witnessed by
//! any witness that speaks the C2SP protocols (plan 03, "Witnesses").
//!
//! - signed-note: `text ‖ "\n" ‖ ("— " name " " base64(keyId u32 BE ‖ signature) "\n")+`
//! - tlog-checkpoint: the text is `origin\nsize\nbase64(root)\n` and optional extension lines.
//! - tlog-cosignature: `cosignature/v1\ntime <seconds>\n` ‖ checkpoint text, signed with
//!   Ed25519; the signature is `timestamp u64 BE ‖ signature`.
//!
//! Base64 here is standard with padding (RFC 4648 section 4), as the specs say, and only the
//! canonical encoding is accepted. The rest of Octa Pass uses base64url.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::transparency::merkle::{HASH_LEN, Hash};

/// signed-note's Ed25519 type: how a log signs its own checkpoints.
pub const ED25519: u8 = 0x01;
/// tlog-cosignature's timestamped Ed25519 checkpoint cosignature: how witnesses sign.
pub const COSIGNATURE_V1: u8 = 0x04;

/// A note bigger than this isn't read. Every signature we know of fits many times over.
pub const MAX_NOTE_LEN: usize = 64 * 1024;
/// signed-note: verifiers must accept at least 16 signatures.
pub const MAX_SIGNATURES: usize = 64;
const MAX_NAME_LEN: usize = 255;
const DASH: &str = "\u{2014} ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteError {
    /// Not a well-formed note, checkpoint or key.
    Malformed,
    /// A signature from a known key that doesn't verify.
    BadSignature,
}

pub type NoteResult<T> = core::result::Result<T, NoteError>;

pub fn b64_std_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decodes standard base64, refusing anything but the canonical encoding.
pub fn b64_std_decode(text: &str) -> NoteResult<Vec<u8>> {
    let bytes = STANDARD.decode(text).map_err(|_| NoteError::Malformed)?;
    if STANDARD.encode(&bytes) != text {
        return Err(NoteError::Malformed);
    }
    Ok(bytes)
}

pub fn decode_hash(text: &str) -> NoteResult<Hash> {
    b64_std_decode(text)?
        .try_into()
        .map_err(|_| NoteError::Malformed)
}

/// A key name, origin or cosigner name: non-empty, at most 255 bytes, no spaces, no `+`, no
/// control characters.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name
            .chars()
            .any(|c| c.is_whitespace() || c == '+' || c.is_control())
}

/// An ASCII decimal with no extra leading zeros.
pub fn decimal(text: &str) -> NoteResult<u64> {
    let canonical = text == "0" || (!text.starts_with('0') && !text.is_empty());
    if !canonical || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(NoteError::Malformed);
    }
    text.parse().map_err(|_| NoteError::Malformed)
}

pub fn key_id(name: &str, kind: u8, public_key: &[u8]) -> u32 {
    let hash = Sha256::new()
        .chain_update(name.as_bytes())
        .chain_update([b'\n', kind])
        .chain_update(public_key)
        .finalize();
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

/// A public key that verifies note signatures: a log's (type 0x01) or a witness's (type 0x04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verifier {
    pub name: String,
    pub kind: u8,
    pub key: VerifyingKey,
    pub id: u32,
}

impl Verifier {
    pub fn new(name: &str, kind: u8, key: VerifyingKey) -> NoteResult<Self> {
        if !valid_name(name) || !matches!(kind, ED25519 | COSIGNATURE_V1) {
            return Err(NoteError::Malformed);
        }
        Ok(Self {
            name: name.to_owned(),
            kind,
            key,
            id: key_id(name, kind, key.as_bytes()),
        })
    }

    /// `name+hex(keyId)+base64(type ‖ key)`, the signed-note verifier key format.
    pub fn from_vkey(vkey: &str) -> NoteResult<Self> {
        // Names and ids have no `+`; standard base64 can.
        let mut parts = vkey.splitn(3, '+');
        let (Some(name), Some(id), Some(key)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(NoteError::Malformed);
        };
        let id_ok = id.len() == 8 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        let id = u32::from_str_radix(id, 16).map_err(|_| NoteError::Malformed)?;
        let key = b64_std_decode(key)?;
        let (Some(&kind), true) = (key.first(), id_ok) else {
            return Err(NoteError::Malformed);
        };
        let public: [u8; 32] = key[1..].try_into().map_err(|_| NoteError::Malformed)?;
        let public = VerifyingKey::from_bytes(&public).map_err(|_| NoteError::Malformed)?;
        let verifier = Self::new(name, kind, public)?;
        if verifier.id != id {
            return Err(NoteError::Malformed);
        }
        Ok(verifier)
    }

    pub fn vkey(&self) -> String {
        let mut key = vec![self.kind];
        key.extend_from_slice(self.key.as_bytes());
        format!("{}+{:08x}+{}", self.name, self.id, b64_std_encode(&key))
    }

    fn matches(&self, sig: &NoteSignature) -> bool {
        sig.name == self.name && sig.id == self.id
    }

    /// Verifies one signature over a note's text. A cosignature also gives its timestamp
    /// (Unix seconds).
    pub fn verify(&self, text: &str, sig: &NoteSignature) -> NoteResult<Option<u64>> {
        if !self.matches(sig) {
            return Err(NoteError::BadSignature);
        }
        let bad = |_| NoteError::BadSignature;
        match self.kind {
            ED25519 => {
                let signature: [u8; 64] = sig.payload.as_slice().try_into().map_err(bad)?;
                self.key
                    .verify_strict(text.as_bytes(), &Signature::from_bytes(&signature))
                    .map_err(|_| NoteError::BadSignature)?;
                Ok(None)
            }
            _ => {
                let (time, signature) = sig
                    .payload
                    .split_at_checked(8)
                    .ok_or(NoteError::BadSignature)?;
                let time = u64::from_be_bytes(time.try_into().map_err(bad)?);
                let signature: [u8; 64] = signature.try_into().map_err(bad)?;
                self.key
                    .verify_strict(
                        cosigned_message(time, text).as_bytes(),
                        &Signature::from_bytes(&signature),
                    )
                    .map_err(|_| NoteError::BadSignature)?;
                Ok(Some(time))
            }
        }
    }
}

fn cosigned_message(time: u64, text: &str) -> String {
    format!("cosignature/v1\ntime {time}\n{text}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteSignature {
    pub name: String,
    pub id: u32,
    pub payload: Vec<u8>,
}

impl NoteSignature {
    fn line(&self) -> String {
        let mut bytes = self.id.to_be_bytes().to_vec();
        bytes.extend_from_slice(&self.payload);
        format!("{DASH}{} {}\n", self.name, b64_std_encode(&bytes))
    }

    fn parse_line(line: &str) -> NoteResult<Self> {
        let rest = line.strip_prefix(DASH).ok_or(NoteError::Malformed)?;
        let (name, sig) = rest.split_once(' ').ok_or(NoteError::Malformed)?;
        let bytes = b64_std_decode(sig)?;
        if !valid_name(name) || bytes.len() < 5 {
            return Err(NoteError::Malformed);
        }
        Ok(Self {
            name: name.to_owned(),
            id: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            payload: bytes[4..].to_vec(),
        })
    }

    /// Signature lines, as a witness answers `add-checkpoint`.
    pub fn parse_lines(lines: &str) -> NoteResult<Vec<Self>> {
        if lines.len() > MAX_NOTE_LEN || !lines.ends_with('\n') {
            return Err(NoteError::Malformed);
        }
        let sigs: Vec<Self> = lines
            .strip_suffix('\n')
            .unwrap_or_default()
            .split('\n')
            .map(Self::parse_line)
            .collect::<NoteResult<_>>()?;
        if sigs.len() > MAX_SIGNATURES {
            return Err(NoteError::Malformed);
        }
        Ok(sigs)
    }

    pub fn to_lines(sigs: &[Self]) -> String {
        sigs.iter().map(Self::line).collect()
    }
}

/// A signed note: the text (with its final newline) and its signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub text: String,
    pub signatures: Vec<NoteSignature>,
}

impl Note {
    pub fn parse(note: &str) -> NoteResult<Self> {
        if note.len() > MAX_NOTE_LEN || note.chars().any(|c| c.is_control() && c != '\n') {
            return Err(NoteError::Malformed);
        }
        // The text ends at the last blank line; signatures follow it.
        let split = note.rfind("\n\n").ok_or(NoteError::Malformed)?;
        let (text, sigs) = (&note[..=split], &note[split + 2..]);
        let signatures = NoteSignature::parse_lines(sigs)?;
        if signatures.is_empty() {
            return Err(NoteError::Malformed);
        }
        let mut seen = std::collections::BTreeSet::new();
        if !signatures
            .iter()
            .all(|sig| seen.insert((&sig.name, sig.id)))
        {
            return Err(NoteError::Malformed);
        }
        Ok(Self {
            text: text.to_owned(),
            signatures,
        })
    }

    pub fn encode(&self) -> String {
        format!(
            "{}\n{}",
            self.text,
            NoteSignature::to_lines(&self.signatures)
        )
    }

    /// Adds signatures not already on the note (same name and key id).
    pub fn add(&mut self, sigs: impl IntoIterator<Item = NoteSignature>) {
        for sig in sigs {
            if !self
                .signatures
                .iter()
                .any(|known| known.name == sig.name && known.id == sig.id)
            {
                self.signatures.push(sig);
            }
        }
    }

    /// Checks every signature from a known key: any that fails rejects the note, as signed-note
    /// says. Signatures from unknown keys are ignored. Returns, for each verifier, the timestamp
    /// of its verified signature (`Some(None)` for a log signature, which has none).
    pub fn verify(&self, verifiers: &[Verifier]) -> NoteResult<Vec<Option<Option<u64>>>> {
        let mut found = vec![None; verifiers.len()];
        for sig in &self.signatures {
            if let Some(index) = verifiers.iter().position(|v| v.matches(sig)) {
                found[index] = Some(verifiers[index].verify(&self.text, sig)?);
            }
        }
        Ok(found)
    }
}

/// A tlog-checkpoint's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: Hash,
    pub extensions: Vec<String>,
}

impl Checkpoint {
    pub fn new(origin: &str, size: u64, root: Hash) -> Self {
        Self {
            origin: origin.to_owned(),
            size,
            root,
            extensions: Vec::new(),
        }
    }

    pub fn text(&self) -> String {
        let mut text = format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            b64_std_encode(&self.root)
        );
        for line in &self.extensions {
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    pub fn parse(text: &str) -> NoteResult<Self> {
        let lines: Vec<&str> = text
            .strip_suffix('\n')
            .ok_or(NoteError::Malformed)?
            .split('\n')
            .collect();
        let [origin, size, root, extensions @ ..] = lines.as_slice() else {
            return Err(NoteError::Malformed);
        };
        if !valid_name(origin) || extensions.iter().any(|line| line.is_empty()) {
            return Err(NoteError::Malformed);
        }
        let root = decode_hash(root)?;
        debug_assert_eq!(root.len(), HASH_LEN);
        Ok(Self {
            origin: (*origin).to_owned(),
            size: decimal(size)?,
            root,
            extensions: extensions.iter().map(|line| (*line).to_owned()).collect(),
        })
    }
}

/// A log's signature on its checkpoint (type 0x01, key name = origin).
pub fn sign_checkpoint(key: &SigningKey, checkpoint: &Checkpoint) -> NoteSignature {
    let verifier = log_verifier(&checkpoint.origin, key.verifying_key());
    NoteSignature {
        name: verifier.name,
        id: verifier.id,
        payload: key.sign(checkpoint.text().as_bytes()).to_bytes().to_vec(),
    }
}

pub fn log_verifier(origin: &str, key: VerifyingKey) -> Verifier {
    let name = origin.to_owned();
    let id = key_id(&name, ED25519, key.as_bytes());
    Verifier {
        name,
        kind: ED25519,
        key,
        id,
    }
}

/// A witness's timestamped cosignature on a checkpoint text (type 0x04).
pub fn cosign(key: &SigningKey, name: &str, text: &str, time: u64) -> NoteResult<NoteSignature> {
    let verifier = Verifier::new(name, COSIGNATURE_V1, key.verifying_key())?;
    let mut payload = time.to_be_bytes().to_vec();
    payload.extend_from_slice(&key.sign(cosigned_message(time, text).as_bytes()).to_bytes());
    Ok(NoteSignature {
        name: verifier.name,
        id: verifier.id,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_spec_example_vkey_parses_and_its_key_id_is_recomputed() {
        // signed-note.md's example verifier key.
        let vkey = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
        let verifier = Verifier::from_vkey(vkey).unwrap();
        assert_eq!(verifier.kind, ED25519);
        assert_eq!(verifier.id, 0x530d903a);
        assert_eq!(verifier.vkey(), vkey);
        let wrong_id = vkey.replace("530d903a", "530d903b");
        assert_eq!(Verifier::from_vkey(&wrong_id), Err(NoteError::Malformed));
    }

    #[test]
    fn vkeys_whose_base64_has_a_plus_round_trip() {
        let key = SigningKey::from_bytes(&[10; 32]).verifying_key();
        let vkey = Verifier::new("witness.example/10", COSIGNATURE_V1, key)
            .unwrap()
            .vkey();
        assert!(vkey.split('+').count() > 3);
        assert_eq!(Verifier::from_vkey(&vkey).unwrap().vkey(), vkey);
    }

    #[test]
    fn notes_signed_by_the_go_reference_implementations_verify() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/c2sp-note.json")).unwrap();
        let field = |name: &str| vector[name].as_str().unwrap().to_owned();
        let log = Verifier::from_vkey(&field("logVkey")).unwrap();
        let witness = Verifier::from_vkey(&field("witnessVkey")).unwrap();
        // Same keys as the vector's seeds, so key ids and vkeys match too.
        assert_eq!(
            log.vkey(),
            log_verifier(&log.name, SigningKey::from_bytes(&[1; 32]).verifying_key()).vkey()
        );
        let ours = Verifier::new(
            &witness.name,
            COSIGNATURE_V1,
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
        )
        .unwrap();
        assert_eq!(ours.vkey(), field("witnessVkey"));

        let note = Note::parse(&field("note")).unwrap();
        assert_eq!(note.encode(), field("note"));
        let found = note.verify(&[log, witness]).unwrap();
        assert_eq!(found[0], Some(None));
        assert!(matches!(found[1], Some(Some(time)) if time > 1_700_000_000));
        assert_eq!(Checkpoint::parse(&note.text).unwrap().size, 5);
    }

    /// Prints a note signed here, for the Go reference implementations to verify
    /// (`cargo test -p octapass-core print_a_note_for_go -- --ignored --nocapture`).
    #[test]
    #[ignore]
    fn print_a_note_for_go() {
        let log = SigningKey::from_bytes(&[1; 32]);
        let witness = SigningKey::from_bytes(&[2; 32]);
        let checkpoint = Checkpoint::new("openpass-key-log/test", 6, [3; 32]);
        let mut note = Note {
            text: checkpoint.text(),
            signatures: vec![sign_checkpoint(&log, &checkpoint)],
        };
        note.add([cosign(&witness, "witness.example/w1", &note.text, 1_761_177_600).unwrap()]);
        let vector = serde_json::json!({
            "logVkey": log_verifier(&checkpoint.origin, log.verifying_key()).vkey(),
            "witnessVkey": Verifier::new("witness.example/w1", COSIGNATURE_V1, witness.verifying_key()).unwrap().vkey(),
            "note": note.encode(),
        });
        println!("{vector}");
    }

    #[test]
    fn spec_checkpoint_text_round_trips() {
        let text =
            "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";
        let checkpoint = Checkpoint::parse(text).unwrap();
        assert_eq!(checkpoint.origin, "example.com/behind-the-sofa");
        assert_eq!(checkpoint.size, 20852163);
        assert_eq!(checkpoint.text(), text);
    }

    #[test]
    fn checkpoints_refuse_non_canonical_fields() {
        for text in [
            "o\n01\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n",
            "o\n1\nCsUYapGGPo4dkMgIAUqom_Xajj7h2fB2MPA3j2jxq2I=\n",
            "o\n1\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I\n",
            "o o\n1\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n",
            "o\n1\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=",
            "o\n1\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n\n",
            "o\n-1\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n",
        ] {
            assert_eq!(
                Checkpoint::parse(text),
                Err(NoteError::Malformed),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_signed_and_cosigned_checkpoint_round_trips_and_verifies() {
        let log = SigningKey::from_bytes(&[1; 32]);
        let witness = SigningKey::from_bytes(&[2; 32]);
        let checkpoint = Checkpoint::new("example.com/log", 5, [7; 32]);
        let mut note = Note {
            text: checkpoint.text(),
            signatures: vec![sign_checkpoint(&log, &checkpoint)],
        };
        note.add([cosign(&witness, "example.com/w", &note.text, 1_700_000_000).unwrap()]);
        let parsed = Note::parse(&note.encode()).unwrap();
        assert_eq!(parsed, note);

        let verifiers = [
            log_verifier("example.com/log", log.verifying_key()),
            Verifier::new("example.com/w", COSIGNATURE_V1, witness.verifying_key()).unwrap(),
            Verifier::new("example.com/other", COSIGNATURE_V1, witness.verifying_key()).unwrap(),
        ];
        assert_eq!(
            parsed.verify(&verifiers).unwrap(),
            vec![Some(None), Some(Some(1_700_000_000)), None]
        );
    }

    #[test]
    fn a_known_key_with_a_bad_signature_rejects_the_note() {
        let log = SigningKey::from_bytes(&[1; 32]);
        let checkpoint = Checkpoint::new("example.com/log", 5, [7; 32]);
        let mut sig = sign_checkpoint(&log, &checkpoint);
        sig.payload[0] ^= 1;
        let note = Note {
            text: checkpoint.text(),
            signatures: vec![sig],
        };
        let verifiers = [log_verifier("example.com/log", log.verifying_key())];
        assert_eq!(note.verify(&verifiers), Err(NoteError::BadSignature));
    }

    #[test]
    fn a_cosignature_commits_to_its_timestamp() {
        let witness = SigningKey::from_bytes(&[2; 32]);
        let text = Checkpoint::new("example.com/log", 5, [7; 32]).text();
        let mut sig = cosign(&witness, "example.com/w", &text, 100).unwrap();
        sig.payload[7] ^= 1;
        let verifier =
            Verifier::new("example.com/w", COSIGNATURE_V1, witness.verifying_key()).unwrap();
        assert_eq!(verifier.verify(&text, &sig), Err(NoteError::BadSignature));
    }

    #[test]
    fn notes_refuse_duplicates_control_characters_and_missing_signatures() {
        let log = SigningKey::from_bytes(&[1; 32]);
        let checkpoint = Checkpoint::new("example.com/log", 5, [7; 32]);
        let sig = sign_checkpoint(&log, &checkpoint);
        let doubled = Note {
            text: checkpoint.text(),
            signatures: vec![sig.clone(), sig],
        }
        .encode();
        assert_eq!(Note::parse(&doubled), Err(NoteError::Malformed));
        assert_eq!(Note::parse(&checkpoint.text()), Err(NoteError::Malformed));
        let control = format!("{}\n{}", checkpoint.text().replace("log", "l\tg"), "x");
        assert_eq!(Note::parse(&control), Err(NoteError::Malformed));
    }
}
