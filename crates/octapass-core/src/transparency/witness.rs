//! Witnesses for the key log (plan 03, "Witnesses"): independent parties that cosign the log's
//! checkpoints, each only after checking the new one extends the last one it cosigned. A server
//! that showed two people two different logs would need the witnesses to cosign both, which an
//! honest witness never does. No I/O here.
//!
//! - The witness's side of C2SP tlog-witness: [`AddCheckpoint`] and [`check_add`].
//! - The client's side: [`WitnessPolicy`], [`Witnessed`] and [`verify_witnessed`].

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::encoding::b64_decode_array;
use crate::transparency::head::LogIdentity;
use crate::transparency::merkle::{Hash, empty_root, verify_consistency};
use crate::transparency::note::{
    self, COSIGNATURE_V1, Checkpoint, Note, NoteError, Verifier, b64_std_encode,
};

/// tlog-witness: a client must not send more proof lines than this.
pub const MAX_PROOF_LINES: usize = 63;
/// A cosignature older than this doesn't count: a server could otherwise keep a forked client on
/// an old witnessed checkpoint. The same window as for heads.
pub const MAX_COSIGNATURE_AGE_S: u64 = 7 * 24 * 60 * 60;
/// Allowed clock skew for a cosignature from the future.
pub const MAX_FUTURE_S: u64 = 10 * 60;
/// A policy names at most this many witnesses.
pub const MAX_WITNESSES: usize = 16;

/// The origin of an Octa Pass key log's checkpoints. Derived from the log id, so a server can't
/// run one log under two names and have each witness cosign two forks as two logs.
pub fn origin(log: &LogIdentity) -> crate::error::Result<String> {
    Ok(format!("octapass-key-log/{}", log.log_id_b64()?))
}

/// The verifier for the log's own signature on its checkpoints: the head-signing key, under the
/// origin. Checkpoints can't be confused with heads: a note has no NUL byte, and every head
/// message has one.
pub fn log_verifier(log: &LogIdentity) -> crate::error::Result<Verifier> {
    let key: [u8; 32] = b64_decode_array(&log.sign_key)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| crate::error::Error::KeyLogMismatch)?;
    Ok(note::log_verifier(&origin(log)?, key))
}

// --- The witness's side ---------------------------------------------------------------------

/// A `POST /add-checkpoint` body: `old <size>\n`, up to 63 proof lines, a blank line, then the
/// checkpoint note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddCheckpoint {
    pub old_size: u64,
    pub proof: Vec<Hash>,
    pub note: Note,
    pub checkpoint: Checkpoint,
}

impl AddCheckpoint {
    pub fn parse(body: &str) -> NoteResult<Self> {
        let (head, note) = body.split_once("\n\n").ok_or(NoteError::Malformed)?;
        let mut lines = head.split('\n');
        let old = lines
            .next()
            .and_then(|line| line.strip_prefix("old "))
            .ok_or(NoteError::Malformed)?;
        let old_size = note::decimal(old)?;
        let proof: Vec<Hash> = lines.map(note::decode_hash).collect::<NoteResult<_>>()?;
        if proof.len() > MAX_PROOF_LINES {
            return Err(NoteError::Malformed);
        }
        let note = Note::parse(note)?;
        let checkpoint = Checkpoint::parse(&note.text)?;
        Ok(Self {
            old_size,
            proof,
            note,
            checkpoint,
        })
    }

    pub fn encode(old_size: u64, proof: &[Hash], note: &Note) -> String {
        let mut body = format!("old {old_size}\n");
        for hash in proof {
            body.push_str(&b64_std_encode(hash));
            body.push('\n');
        }
        body.push('\n');
        body.push_str(&note.encode());
        body
    }
}

type NoteResult<T> = core::result::Result<T, NoteError>;

/// Why a witness refuses a checkpoint, with the HTTP status tlog-witness gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// 400: malformed, or `old` is larger than the checkpoint.
    BadRequest,
    /// 403: no valid signature from the log's key, or a bad one.
    Forbidden,
    /// 404: a log this witness doesn't know.
    UnknownOrigin,
    /// 409: `old` isn't the size this witness last cosigned; the body is that size.
    Conflict(u64),
    /// 422: the proof doesn't show the checkpoint extends the last one cosigned.
    Inconsistent,
}

impl Refusal {
    pub fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Forbidden => 403,
            Self::UnknownOrigin => 404,
            Self::Conflict(_) => 409,
            Self::Inconsistent => 422,
        }
    }
}

/// What a witness keeps per log: the newest checkpoint it cosigned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessedState {
    pub size: u64,
    /// Standard base64 root, as in the checkpoint.
    pub root: String,
    /// The cosigned checkpoint note, for the monitoring endpoint.
    pub checkpoint: String,
}

/// The witness's checks for `add-checkpoint`, in tlog-witness's terms. `log` is the verifier the
/// witness was configured with for the checkpoint's origin (`None`: unknown). On success the
/// caller must persist the new size and root before answering, atomically with this check.
pub fn check_add(
    request: &AddCheckpoint,
    log: Option<&Verifier>,
    stored: Option<&WitnessedState>,
) -> core::result::Result<(), Refusal> {
    let log = log.ok_or(Refusal::UnknownOrigin)?;
    if log.name != request.checkpoint.origin {
        return Err(Refusal::UnknownOrigin);
    }
    match request.note.verify(std::slice::from_ref(log)) {
        Ok(found) if found[0].is_some() => {}
        _ => return Err(Refusal::Forbidden),
    }
    let new = &request.checkpoint;
    if request.old_size > new.size {
        return Err(Refusal::BadRequest);
    }
    let stored_size = stored.map_or(0, |state| state.size);
    if request.old_size != stored_size {
        return Err(Refusal::Conflict(stored_size));
    }
    if new.size == 0 && new.root != empty_root() {
        return Err(Refusal::Inconsistent);
    }
    match stored {
        None => {
            if !request.proof.is_empty() {
                return Err(Refusal::Inconsistent);
            }
        }
        Some(state) => {
            let old_root = note::decode_hash(&state.root).map_err(|_| Refusal::Inconsistent)?;
            if !verify_consistency(state.size, new.size, &old_root, &new.root, &request.proof) {
                return Err(Refusal::Inconsistent);
            }
        }
    }
    Ok(())
}

// --- The client's side ----------------------------------------------------------------------

/// Which witnesses a client requires, and how many of them. The server says which witnesses it
/// uses; a device pins that the first time, alongside the log's keys, and from then on only
/// accepts a policy at least as strong (every pinned witness, and a quorum no lower).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessPolicy {
    /// C2SP verifier keys (`name+id+base64`), type 0x04.
    pub witnesses: Vec<String>,
    pub quorum: u32,
}

impl WitnessPolicy {
    pub fn verifiers(&self) -> crate::error::Result<Vec<Verifier>> {
        let invalid = crate::error::Error::KeyLogMismatch;
        if self.witnesses.is_empty()
            || self.witnesses.len() > MAX_WITNESSES
            || self.quorum == 0
            || self.quorum as usize > self.witnesses.len()
        {
            return Err(invalid);
        }
        let verifiers: Vec<Verifier> = self
            .witnesses
            .iter()
            .map(|vkey| Verifier::from_vkey(vkey))
            .collect::<NoteResult<_>>()
            .map_err(|_| crate::error::Error::KeyLogMismatch)?;
        let mut keys = std::collections::BTreeSet::new();
        let distinct = verifiers.iter().all(|v| keys.insert(*v.key.as_bytes()));
        if !distinct || verifiers.iter().any(|v| v.kind != COSIGNATURE_V1) {
            return Err(crate::error::Error::KeyLogMismatch);
        }
        Ok(verifiers)
    }

    /// Whether `self` keeps every witness `pinned` has and asks for at least as many.
    pub fn at_least(&self, pinned: &WitnessPolicy) -> bool {
        self.quorum >= pinned.quorum
            && pinned
                .witnesses
                .iter()
                .all(|vkey| self.witnesses.contains(vkey))
    }

    /// The quorum that makes any two sets of cosigners overlap: a majority.
    pub fn majority(count: usize) -> u32 {
        (count / 2 + 1) as u32
    }
}

/// The newest checkpoint the witnesses cosigned, and the proof that the head extends it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Witnessed {
    /// The checkpoint as a signed note: the log's signature and the witnesses'.
    pub checkpoint: String,
    /// RFC 9162 consistency proof from the checkpoint's size to the head's, base64url hashes.
    #[serde(default)]
    pub consistency: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessFailure {
    /// Missing, malformed, not signed by the log, or too few fresh cosignatures. Could be an
    /// outage: a reason not to seal, not proof of anything.
    Unwitnessed,
    /// A validly signed, witnessed checkpoint the head doesn't extend.
    Inconsistent,
}

/// Checks a witnessed checkpoint against a policy and a head the caller already verified (its
/// size and root). `now_s` is Unix seconds.
pub fn verify_witnessed(
    log: &LogIdentity,
    policy: &WitnessPolicy,
    witnessed: &Witnessed,
    head_size: u64,
    head_root: &Hash,
    now_s: u64,
) -> core::result::Result<(), WitnessFailure> {
    let unwitnessed = WitnessFailure::Unwitnessed;
    let witnesses = policy.verifiers().map_err(|_| unwitnessed)?;
    let note = Note::parse(&witnessed.checkpoint).map_err(|_| unwitnessed)?;
    let checkpoint = Checkpoint::parse(&note.text).map_err(|_| unwitnessed)?;
    let log_key = log_verifier(log).map_err(|_| unwitnessed)?;
    if checkpoint.origin != log_key.name || !checkpoint.extensions.is_empty() {
        return Err(WitnessFailure::Unwitnessed);
    }
    let mut verifiers = witnesses;
    verifiers.push(log_key);
    let found = note.verify(&verifiers).map_err(|_| unwitnessed)?;
    let (cosigned, logged) = found.split_at(found.len() - 1);
    if logged[0].is_none() {
        return Err(WitnessFailure::Unwitnessed);
    }
    let fresh = cosigned
        .iter()
        .filter(|found| {
            matches!(found, Some(Some(time))
                if *time <= now_s + MAX_FUTURE_S && now_s.saturating_sub(*time) <= MAX_COSIGNATURE_AGE_S)
        })
        .count();
    if fresh < policy.quorum as usize {
        return Err(WitnessFailure::Unwitnessed);
    }
    let proof: Vec<Hash> = witnessed
        .consistency
        .iter()
        .map(|hash| b64_decode_array(hash))
        .collect::<crate::error::Result<_>>()
        .map_err(|_| WitnessFailure::Inconsistent)?;
    if !verify_consistency(
        checkpoint.size,
        head_size,
        &checkpoint.root,
        head_root,
        &proof,
    ) {
        return Err(WitnessFailure::Inconsistent);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::encoding::b64_encode;
    use crate::transparency::merkle::{Frontier, leaf_hash};
    use crate::transparency::note::{NoteSignature, cosign, sign_checkpoint};

    const NOW: u64 = 1_761_177_600;

    fn log() -> (SigningKey, LogIdentity) {
        let key = SigningKey::from_bytes(&[1; 32]);
        let identity = LogIdentity {
            sign_key: b64_encode(key.verifying_key().as_bytes()),
            oprf_key: b64_encode(&[2; 32]),
        };
        (key, identity)
    }

    fn root(size: u8) -> Hash {
        let mut frontier = Frontier::default();
        for i in 0..size {
            frontier.push(leaf_hash(&[i; 64]));
        }
        frontier.root()
    }

    fn signed(key: &SigningKey, identity: &LogIdentity, size: u8) -> Note {
        let checkpoint = Checkpoint::new(&origin(identity).unwrap(), size.into(), root(size));
        Note {
            text: checkpoint.text(),
            signatures: vec![sign_checkpoint(key, &checkpoint)],
        }
    }

    fn witness(seed: u8) -> (SigningKey, String) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let name = format!("witness.example/{seed}");
        let vkey = Verifier::new(&name, COSIGNATURE_V1, key.verifying_key())
            .unwrap()
            .vkey();
        (key, vkey)
    }

    fn cosigned(note: &Note, seeds: &[u8], time: u64) -> Note {
        let mut note = note.clone();
        for seed in seeds {
            let key = SigningKey::from_bytes(&[*seed; 32]);
            note.add([cosign(&key, &format!("witness.example/{seed}"), &note.text, time).unwrap()]);
        }
        note
    }

    fn proof(old: u8, new: u8) -> Vec<Hash> {
        // A tiny in-memory log: the server's range helpers over a full leaf list.
        use crate::transparency::merkle::{consistency_ranges, fold_nodes, range_nodes};
        consistency_ranges(old.into(), new.into())
            .into_iter()
            .map(|range| {
                let nodes: Vec<Hash> = range_nodes(range)
                    .into_iter()
                    .map(|node| {
                        let start = node.index << node.level;
                        let mut sub = Frontier::default();
                        for i in start..start + (1 << node.level) {
                            sub.push(leaf_hash(&[i as u8; 64]));
                        }
                        sub.root()
                    })
                    .collect();
                fold_nodes(&nodes).unwrap()
            })
            .collect()
    }

    fn policy(seeds: &[u8], quorum: u32) -> WitnessPolicy {
        WitnessPolicy {
            witnesses: seeds.iter().map(|seed| witness(*seed).1).collect(),
            quorum,
        }
    }

    #[test]
    fn add_checkpoint_bodies_round_trip() {
        let (key, identity) = log();
        let note = signed(&key, &identity, 5);
        let proof = proof(3, 5);
        let body = AddCheckpoint::encode(3, &proof, &note);
        assert!(body.starts_with("old 3\n"));
        let parsed = AddCheckpoint::parse(&body).unwrap();
        assert_eq!(
            (parsed.old_size, &parsed.proof, &parsed.note),
            (3, &proof, &note)
        );
        assert_eq!(parsed.checkpoint.size, 5);
        assert_eq!(
            AddCheckpoint::parse("old 03\n\nx"),
            Err(NoteError::Malformed)
        );
    }

    #[test]
    fn a_witness_follows_tlog_witness() {
        let (key, identity) = log();
        let verifier = log_verifier(&identity).unwrap();
        let request = |old: u64, proof: Vec<Hash>, size: u8| AddCheckpoint {
            old_size: old,
            proof,
            note: signed(&key, &identity, size),
            checkpoint: Checkpoint::parse(&signed(&key, &identity, size).text).unwrap(),
        };
        let state = |size: u8| WitnessedState {
            size: size.into(),
            root: b64_std_encode(&root(size)),
            checkpoint: String::new(),
        };

        assert_eq!(
            check_add(&request(0, vec![], 3), Some(&verifier), None),
            Ok(())
        );
        assert_eq!(
            check_add(&request(0, vec![], 3), None, None),
            Err(Refusal::UnknownOrigin)
        );
        assert_eq!(
            check_add(
                &request(3, proof(3, 5), 5),
                Some(&verifier),
                Some(&state(3))
            ),
            Ok(())
        );
        // The same size again is fine: the witness re-cosigns with a fresh timestamp.
        assert_eq!(
            check_add(&request(3, vec![], 3), Some(&verifier), Some(&state(3))),
            Ok(())
        );
        assert_eq!(
            check_add(
                &request(2, proof(2, 5), 5),
                Some(&verifier),
                Some(&state(3))
            ),
            Err(Refusal::Conflict(3))
        );
        assert_eq!(
            check_add(&request(6, vec![], 5), Some(&verifier), Some(&state(3))),
            Err(Refusal::BadRequest)
        );
        assert_eq!(
            check_add(
                &request(3, proof(2, 5), 5),
                Some(&verifier),
                Some(&state(3))
            ),
            Err(Refusal::Inconsistent)
        );
        assert_eq!(
            check_add(&request(0, proof(3, 5), 5), Some(&verifier), None),
            Err(Refusal::Inconsistent)
        );

        // A fork: same size, other root.
        let mut fork = request(3, vec![], 3);
        let other = Checkpoint::new(&verifier.name, 3, [9; 32]);
        fork.note = Note {
            text: other.text(),
            signatures: vec![sign_checkpoint(&key, &other)],
        };
        fork.checkpoint = other;
        assert_eq!(
            check_add(&fork, Some(&verifier), Some(&state(3))),
            Err(Refusal::Inconsistent)
        );

        // Signed by someone else.
        let stranger = SigningKey::from_bytes(&[8; 32]);
        let mut forged = request(0, vec![], 3);
        forged.note.signatures = vec![sign_checkpoint(&stranger, &forged.checkpoint)];
        assert_eq!(
            check_add(&forged, Some(&verifier), None),
            Err(Refusal::Forbidden)
        );
    }

    #[test]
    fn clients_need_a_quorum_of_fresh_cosignatures() {
        let (key, identity) = log();
        let note = signed(&key, &identity, 5);
        let head_root = root(7);
        let witnessed = |note: &Note| Witnessed {
            checkpoint: note.encode(),
            consistency: proof(5, 7).iter().map(|hash| b64_encode(hash)).collect(),
        };
        let check = |note: &Note, policy: &WitnessPolicy| {
            verify_witnessed(&identity, policy, &witnessed(note), 7, &head_root, NOW)
        };

        assert_eq!(
            check(&cosigned(&note, &[10, 11], NOW), &policy(&[10, 11, 12], 2)),
            Ok(())
        );
        assert_eq!(
            check(&cosigned(&note, &[10], NOW), &policy(&[10, 11, 12], 2)),
            Err(WitnessFailure::Unwitnessed)
        );
        // Witnesses the policy doesn't name don't count.
        assert_eq!(
            check(&cosigned(&note, &[10, 13], NOW), &policy(&[10, 11, 12], 2)),
            Err(WitnessFailure::Unwitnessed)
        );
        let stale = NOW - MAX_COSIGNATURE_AGE_S - 1;
        assert_eq!(
            check(&cosigned(&note, &[10, 11], stale), &policy(&[10, 11], 2)),
            Err(WitnessFailure::Unwitnessed)
        );
        let future = NOW + MAX_FUTURE_S + 1;
        assert_eq!(
            check(&cosigned(&note, &[10, 11], future), &policy(&[10, 11], 2)),
            Err(WitnessFailure::Unwitnessed)
        );
    }

    #[test]
    fn a_head_that_does_not_extend_the_witnessed_checkpoint_is_a_fork() {
        let (key, identity) = log();
        let note = cosigned(&signed(&key, &identity, 5), &[10], NOW);
        let witnessed = Witnessed {
            checkpoint: note.encode(),
            consistency: proof(5, 7).iter().map(|hash| b64_encode(hash)).collect(),
        };
        let p = policy(&[10], 1);
        assert_eq!(
            verify_witnessed(&identity, &p, &witnessed, 7, &[0; 32], NOW),
            Err(WitnessFailure::Inconsistent)
        );
        // A witnessed checkpoint ahead of the head can't be extended by it either.
        assert_eq!(
            verify_witnessed(&identity, &p, &witnessed, 4, &root(4), NOW),
            Err(WitnessFailure::Inconsistent)
        );
    }

    #[test]
    fn the_log_must_sign_under_its_own_origin() {
        let (key, identity) = log();
        let checkpoint = Checkpoint::new("example.com/another-name", 5, root(5));
        let note = cosigned(
            &Note {
                text: checkpoint.text(),
                signatures: vec![sign_checkpoint(&key, &checkpoint)],
            },
            &[10],
            NOW,
        );
        let witnessed = Witnessed {
            checkpoint: note.encode(),
            consistency: vec![],
        };
        assert_eq!(
            verify_witnessed(&identity, &policy(&[10], 1), &witnessed, 5, &root(5), NOW),
            Err(WitnessFailure::Unwitnessed)
        );
    }

    #[test]
    fn a_bad_signature_from_a_named_witness_rejects_the_checkpoint() {
        let (key, identity) = log();
        let mut note = cosigned(&signed(&key, &identity, 5), &[10, 11], NOW);
        let last: &mut NoteSignature = note.signatures.last_mut().unwrap();
        last.payload[20] ^= 1;
        let witnessed = Witnessed {
            checkpoint: note.encode(),
            consistency: vec![],
        };
        assert_eq!(
            verify_witnessed(
                &identity,
                &policy(&[10, 11], 1),
                &witnessed,
                5,
                &root(5),
                NOW
            ),
            Err(WitnessFailure::Unwitnessed)
        );
    }

    #[test]
    fn policies_must_be_sound() {
        assert!(policy(&[10, 11], 2).verifiers().is_ok());
        assert!(policy(&[10, 11], 3).verifiers().is_err());
        assert!(policy(&[10, 11], 0).verifiers().is_err());
        assert!(policy(&[], 0).verifiers().is_err());
        assert!(policy(&[10, 10], 1).verifiers().is_err());
        let (_, log_key) = log();
        let wrong_type = WitnessPolicy {
            witnesses: vec![log_verifier(&log_key).unwrap().vkey()],
            quorum: 1,
        };
        assert!(wrong_type.verifiers().is_err());

        assert!(policy(&[10, 11, 12], 2).at_least(&policy(&[10, 11], 2)));
        assert!(!policy(&[10, 12], 2).at_least(&policy(&[10, 11], 2)));
        assert!(!policy(&[10, 11, 12], 1).at_least(&policy(&[10, 11], 2)));
        assert_eq!(
            (
                WitnessPolicy::majority(1),
                WitnessPolicy::majority(2),
                WitnessPolicy::majority(3)
            ),
            (1, 2, 2)
        );
    }
}
