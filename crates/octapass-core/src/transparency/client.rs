//! What a client pins and checks. No I/O: a caller fetches, hands the answers here, and stores
//! [`LogState`] on the device afterwards, whether or not a check passed, since a failed check
//! records an alert.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::encoding::{b64_decode_array, b64_encode};
use crate::error::{Error, Result};
use crate::transparency::head::{LogIdentity, SignedHead};
use crate::transparency::merkle::{
    Frontier, Hash, leaf_hash, verify_consistency, verify_inclusion,
};
use crate::transparency::record::{KeyRecord, LEAF_LEN, OfferedKeys};

/// A head older than this isn't accepted: a server could otherwise freeze a client's view.
pub const MAX_HEAD_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// A head and what proves it extends the one the client pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeadUpdate {
    pub log: LogIdentity,
    pub head: SignedHead,
    /// Consistency proof from the size the client asked about, base64url hashes.
    #[serde(default)]
    pub consistency: Vec<String>,
}

/// A label's latest record, proven included in `update.head`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub leaf_index: u64,
    pub record: KeyRecord,
    pub inclusion: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelProof {
    #[serde(flatten)]
    pub update: HeadUpdate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<LogEntry>,
}

/// One page of the log, for monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogPage {
    pub start: u64,
    /// The perfect subtrees covering everything before `start`, base64url.
    pub frontier: Vec<String>,
    /// base64url concatenation of 64-byte leaves.
    pub leaves: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AlertKind {
    /// The log's keys aren't the ones this device pinned.
    LogChanged,
    /// A head doesn't extend the pinned one, or the leaves don't add up to it.
    LogInconsistent,
    /// A record for this account's email that this account didn't make.
    ForeignRecord,
    /// This account's own record has gone from the log.
    OwnRecordMissing,
}

/// Something the user should be told about. It stays until they dismiss it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogAlert {
    pub kind: AlertKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_index: Option<u64>,
    pub at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyStatus {
    /// The record is in the log and matches the keys offered.
    Verified,
    /// Nothing to check against. Not a pass: see plan 03.
    NotLogged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactPin {
    pub leaf_index: u64,
    pub record_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Monitor {
    pub label: String,
    pub own_leaf: u64,
    pub own_record_hash: String,
    pub next_leaf: u64,
    /// The compact form of everything before `next_leaf`. Empty until the first page.
    pub frontier: Vec<String>,
}

/// What a device keeps, per account.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LogState {
    pub log: Option<LogIdentity>,
    pub head: Option<SignedHead>,
    /// Normalised email → label: labels never change, and each new one costs a request.
    pub labels: BTreeMap<String, String>,
    pub contacts: BTreeMap<String, ContactPin>,
    pub monitor: Option<Monitor>,
    pub alert: Option<LogAlert>,
    /// Unix milliseconds of the last finished monitoring run.
    pub checked_at: u64,
}

fn hash_list(list: &[String]) -> Result<Vec<Hash>> {
    list.iter()
        .map(|hash| b64_decode_array(hash).map_err(|_| Error::KeyLogMismatch))
        .collect()
}

impl LogState {
    fn alert(&mut self, kind: AlertKind, leaf_index: Option<u64>, now_ms: u64) -> Error {
        self.alert.get_or_insert(LogAlert {
            kind,
            leaf_index,
            at: now_ms,
        });
        Error::KeyLogMismatch
    }

    /// The size to ask for a consistency proof from.
    pub fn pinned_size(&self) -> u64 {
        self.head.as_ref().map_or(0, |head| head.tree_size)
    }

    /// Forgets every pin, after the user has heard the alert and accepted a new log. Monitoring
    /// and contacts start over.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Takes a head: pins the log the first time, and otherwise requires the same log, a valid
    /// signature, a recent timestamp and proof that it extends the pinned head.
    pub fn accept_head(&mut self, update: &HeadUpdate, now_ms: u64) -> Result<()> {
        match &self.log {
            Some(pinned) if *pinned != update.log => {
                return Err(self.alert(AlertKind::LogChanged, None, now_ms));
            }
            _ => {}
        }
        update.head.verify(&update.log)?;
        if now_ms.saturating_sub(update.head.timestamp) > MAX_HEAD_AGE_MS {
            return Err(Error::KeyLogMismatch);
        }
        if let Some(pinned) = &self.head {
            let proof = hash_list(&update.consistency)?;
            let extends = update.head.timestamp >= pinned.timestamp
                && verify_consistency(
                    pinned.tree_size,
                    update.head.tree_size,
                    &pinned.root()?,
                    &update.head.root()?,
                    &proof,
                );
            if !extends {
                return Err(self.alert(AlertKind::LogInconsistent, None, now_ms));
            }
        }
        self.log = Some(update.log.clone());
        self.head = Some(update.head.clone());
        Ok(())
    }

    fn check_inclusion(&self, entry: &LogEntry) -> Result<()> {
        let head = self.head.as_ref().ok_or(Error::KeyLogMismatch)?;
        let included = verify_inclusion(
            entry.leaf_index,
            head.tree_size,
            &entry.record.leaf_hash()?,
            &hash_list(&entry.inclusion)?,
            &head.root()?,
        );
        included.then_some(()).ok_or(Error::KeyLogMismatch)
    }

    fn log_id(&self) -> Result<String> {
        self.log
            .as_ref()
            .ok_or(Error::KeyLogMismatch)?
            .log_id_b64()
            .map_err(|_| Error::KeyLogMismatch)
    }

    /// Checks the keys a server offered for someone against the log, before sealing to them.
    /// `record` is what came with the keys, `label` the label of the email they're for, `proof`
    /// the log's answer for that label. An error means don't seal.
    pub fn verify_account(
        &mut self,
        offered: &OfferedKeys<'_>,
        record: Option<&KeyRecord>,
        label: &str,
        proof: &LabelProof,
        now_ms: u64,
    ) -> Result<KeyStatus> {
        self.accept_head(&proof.update, now_ms)?;
        let pin = self.contacts.get(offered.account_id);
        let Some(entry) = &proof.entry else {
            // A device that has seen a record doesn't accept that it's gone: that's how a server
            // would hide an ML-KEM key. Nor can a record exist outside the log.
            if pin.is_some() || record.is_some() {
                return Err(Error::KeyLogMismatch);
            }
            return Ok(KeyStatus::NotLogged);
        };
        if record != Some(&entry.record) {
            return Err(Error::KeyLogMismatch);
        }
        entry.record.verify_for(offered)?;
        if entry.record.label != label || entry.record.log_id != self.log_id()? {
            return Err(Error::KeyLogMismatch);
        }
        self.check_inclusion(entry)?;
        if pin.is_some_and(|pin| entry.leaf_index < pin.leaf_index) {
            return Err(Error::KeyLogMismatch);
        }
        self.contacts.insert(
            offered.account_id.to_owned(),
            ContactPin {
                leaf_index: entry.leaf_index,
                record_hash: b64_encode(&entry.record.record_hash()),
            },
        );
        Ok(KeyStatus::Verified)
    }

    /// Checks this account's own record, and starts monitoring from its leaf the first time. The
    /// proof is for the account's own label, so a newer record under it shows here at once.
    pub fn check_own(&mut self, record: &KeyRecord, proof: &LabelProof, now_ms: u64) -> Result<()> {
        self.accept_head(&proof.update, now_ms)?;
        if record.log_id != self.log_id()? {
            return Err(self.alert(AlertKind::LogChanged, None, now_ms));
        }
        let Some(entry) = &proof.entry else {
            return Err(self.alert(AlertKind::OwnRecordMissing, None, now_ms));
        };
        if entry.record != *record {
            return Err(self.alert(AlertKind::ForeignRecord, Some(entry.leaf_index), now_ms));
        }
        if self.check_inclusion(entry).is_err() {
            return Err(self.alert(AlertKind::LogInconsistent, None, now_ms));
        }
        if self.monitor.is_none() {
            self.monitor = Some(Monitor {
                label: record.label.clone(),
                own_leaf: entry.leaf_index,
                own_record_hash: b64_encode(&record.record_hash()),
                next_leaf: entry.leaf_index,
                frontier: Vec::new(),
            });
        }
        Ok(())
    }

    /// The leaves still to read, `start..end`, up to the pinned head.
    pub fn scan_range(&self) -> Option<(u64, u64)> {
        let start = self.monitor.as_ref()?.next_leaf;
        let end = self.head.as_ref()?.tree_size;
        (start < end).then_some((start, end))
    }

    /// Reads a page of leaves. Any leaf under this account's label that isn't its own record is
    /// an alert. On reaching the pinned head the leaves must add up to its root, so nothing was
    /// left out or changed along the way. Returns whether the scan reached the head.
    pub fn apply_page(&mut self, page: &LogPage, now_ms: u64) -> Result<bool> {
        let mut monitor = self.monitor.clone().ok_or(Error::KeyLogMismatch)?;
        let head = self.head.clone().ok_or(Error::KeyLogMismatch)?;
        if page.start != monitor.next_leaf {
            return Err(Error::KeyLogMismatch);
        }
        let leaves =
            crate::encoding::b64_decode(&page.leaves).map_err(|_| Error::KeyLogMismatch)?;
        if leaves.is_empty() || !leaves.len().is_multiple_of(LEAF_LEN) {
            return Err(Error::KeyLogMismatch);
        }
        // The first page's frontier comes from the server. It needs no trust: a wrong one can't
        // add up to the signed root.
        let nodes = if monitor.frontier.is_empty() {
            &page.frontier
        } else {
            &monitor.frontier
        };
        let mut frontier = Frontier::from_nodes(monitor.next_leaf, hash_list(nodes)?)
            .ok_or(Error::KeyLogMismatch)?;
        let label: Hash = b64_decode_array(&monitor.label).map_err(|_| Error::KeyLogMismatch)?;
        let own: Hash =
            b64_decode_array(&monitor.own_record_hash).map_err(|_| Error::KeyLogMismatch)?;
        let mut foreign = None;
        for leaf in leaves.as_chunks::<LEAF_LEN>().0 {
            if leaf[..32] == label && leaf[32..] != own {
                foreign = foreign.or(Some(frontier.size()));
            }
            frontier.push(leaf_hash(leaf));
        }
        if frontier.size() > head.tree_size {
            return Err(Error::KeyLogMismatch);
        }
        monitor.next_leaf = frontier.size();
        monitor.frontier = frontier
            .nodes()
            .iter()
            .map(|hash| b64_encode(hash))
            .collect();
        self.monitor = Some(monitor);
        if let Some(index) = foreign {
            return Err(self.alert(AlertKind::ForeignRecord, Some(index), now_ms));
        }
        let done = frontier.size() == head.tree_size;
        if done {
            if frontier.root() != head.root()? {
                return Err(self.alert(AlertKind::LogInconsistent, None, now_ms));
            }
            self.checked_at = now_ms;
        }
        Ok(done)
    }
}

#[cfg(test)]
mod tests {
    use core::ops::Range;

    use ed25519_dalek::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::transparency::merkle::{
        Frontier, consistency_ranges, inclusion_ranges, range_nodes,
    };
    use crate::transparency::record::test_support::{self, ACCOUNT};

    const NOW: u64 = 1_761_177_600_000;

    /// A log server in miniature.
    struct Log {
        key: SigningKey,
        identity: LogIdentity,
        leaves: Vec<[u8; LEAF_LEN]>,
        records: BTreeMap<u64, KeyRecord>,
        now: u64,
    }

    impl Log {
        fn new(seed: u8) -> Self {
            let key = SigningKey::from_bytes(&[seed; 32]);
            Self {
                identity: LogIdentity {
                    sign_key: b64_encode(key.verifying_key().as_bytes()),
                    oprf_key: b64_encode(&[seed.wrapping_add(1); 32]),
                },
                key,
                leaves: Vec::new(),
                records: BTreeMap::new(),
                now: NOW,
            }
        }

        fn log_id(&self) -> String {
            self.identity.log_id_b64().unwrap()
        }

        fn filler(&mut self, count: u8) {
            for i in 0..count {
                self.leaves.push([i.wrapping_add(100); LEAF_LEN]);
            }
        }

        fn publish(&mut self, record: KeyRecord) -> u64 {
            let index = self.leaves.len() as u64;
            self.leaves.push(record.leaf().unwrap());
            self.records.insert(index, record);
            index
        }

        fn hash(&self, range: Range<u64>) -> Hash {
            let mut frontier = Frontier::default();
            if range.start == 0 {
                for leaf in &self.leaves[..range.end as usize] {
                    frontier.push(leaf_hash(leaf));
                }
                return frontier.root();
            }
            // Any other range in a proof is a single subtree of the tree's own shape.
            let nodes: Vec<Hash> = range_nodes(range)
                .into_iter()
                .map(|node| {
                    let start = node.index << node.level;
                    let mut sub = Frontier::default();
                    for leaf in &self.leaves[start as usize..(start + (1 << node.level)) as usize] {
                        sub.push(leaf_hash(leaf));
                    }
                    sub.root()
                })
                .collect();
            crate::transparency::merkle::fold_nodes(&nodes).unwrap()
        }

        fn proof(&self, ranges: Vec<Range<u64>>) -> Vec<String> {
            ranges
                .into_iter()
                .map(|range| b64_encode(&self.hash(range)))
                .collect()
        }

        fn head(&self) -> SignedHead {
            let size = self.leaves.len() as u64;
            SignedHead::sign(
                &self.key,
                &self.identity.log_id().unwrap(),
                size,
                &self.hash(0..size),
                self.now,
            )
        }

        fn update(&self, since: u64) -> HeadUpdate {
            HeadUpdate {
                log: self.identity.clone(),
                head: self.head(),
                consistency: self.proof(consistency_ranges(since, self.leaves.len() as u64)),
            }
        }

        fn answer(&self, state: &LogState, leaf: Option<u64>) -> LabelProof {
            LabelProof {
                update: self.update(state.pinned_size()),
                entry: leaf.map(|index| LogEntry {
                    leaf_index: index,
                    record: self.records[&index].clone(),
                    inclusion: self.proof(inclusion_ranges(index, self.leaves.len() as u64)),
                }),
            }
        }

        fn page(&self, start: u64, end: u64) -> LogPage {
            let frontier = range_nodes(0..start)
                .into_iter()
                .map(|node| {
                    b64_encode(
                        &self.hash((node.index << node.level)..((node.index + 1) << node.level)),
                    )
                })
                .collect();
            LogPage {
                start,
                frontier,
                leaves: b64_encode(&self.leaves[start as usize..end as usize].concat()),
            }
        }
    }

    fn signing() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }

    fn record_for(log: &Log, rng: &mut ChaCha20Rng) -> KeyRecord {
        let mut record = test_support::record(&signing(), rng);
        record.log_id = log.log_id();
        record.signed(&signing())
    }

    fn offered(record: &KeyRecord) -> OfferedKeys<'_> {
        OfferedKeys {
            account_id: ACCOUNT,
            public_enc_key: &record.public_enc_key,
            public_sign_key: &record.public_sign_key,
        }
    }

    fn setup() -> (Log, KeyRecord, u64, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut log = Log::new(1);
        log.filler(5);
        let record = record_for(&log, &mut rng);
        let index = log.publish(record.clone());
        log.filler(3);
        (log, record, index, rng)
    }

    #[test]
    fn a_logged_key_verifies() {
        let (log, record, index, _) = setup();
        let mut state = LogState::default();
        let status = state
            .verify_account(
                &offered(&record),
                Some(&record),
                &record.label,
                &log.answer(&state, Some(index)),
                NOW,
            )
            .unwrap();
        assert_eq!(status, KeyStatus::Verified);
        assert_eq!(state.pinned_size(), 9);
        assert_eq!(state.contacts[ACCOUNT].leaf_index, index);
        assert_eq!(state.alert, None);
    }

    #[test]
    fn an_account_with_nothing_logged_is_not_a_pass_or_a_failure() {
        let (log, record, _, _) = setup();
        let mut state = LogState::default();
        let status = state
            .verify_account(
                &offered(&record),
                None,
                &record.label,
                &log.answer(&state, None),
                NOW,
            )
            .unwrap();
        assert_eq!(status, KeyStatus::NotLogged);
    }

    #[test]
    fn a_swapped_key_is_refused() {
        let (log, record, index, _) = setup();
        let answer = |state: &LogState| log.answer(state, Some(index));
        let swapped = OfferedKeys {
            public_enc_key: "swapped",
            ..offered(&record)
        };
        let mut state = LogState::default();
        assert_eq!(
            state
                .verify_account(&swapped, Some(&record), &record.label, &answer(&state), NOW)
                .err(),
            Some(Error::KeyLogMismatch)
        );
    }

    #[test]
    fn a_record_filed_under_someone_elses_label_is_refused() {
        let (log, record, index, _) = setup();
        let mut state = LogState::default();
        let other_label = b64_encode(&[7; 32]);
        assert_eq!(
            state
                .verify_account(
                    &offered(&record),
                    Some(&record),
                    &other_label,
                    &log.answer(&state, Some(index)),
                    NOW
                )
                .err(),
            Some(Error::KeyLogMismatch)
        );
    }

    #[test]
    fn a_record_for_another_log_is_refused() {
        let (mut log, _, _, mut rng) = setup();
        let mut other = record_for(&log, &mut rng);
        other.log_id = b64_encode(&[8; 32]);
        let other = other.signed(&signing());
        let index = log.publish(other.clone());
        let mut state = LogState::default();
        assert_eq!(
            state
                .verify_account(
                    &offered(&other),
                    Some(&other),
                    &other.label,
                    &log.answer(&state, Some(index)),
                    NOW
                )
                .err(),
            Some(Error::KeyLogMismatch)
        );
    }

    #[test]
    fn a_record_outside_the_tree_is_refused() {
        let (log, record, index, mut rng) = setup();
        let mut state = LogState::default();
        let mut answer = log.answer(&state, Some(index));
        let unlogged = record_for(&log, &mut rng);
        answer.entry.as_mut().unwrap().record = unlogged.clone();
        assert_eq!(
            state
                .verify_account(
                    &offered(&unlogged),
                    Some(&unlogged),
                    &unlogged.label,
                    &answer,
                    NOW
                )
                .err(),
            Some(Error::KeyLogMismatch)
        );
        drop(record);
    }

    #[test]
    fn a_record_can_t_exist_outside_the_log_or_vanish_from_it() {
        let (log, record, index, _) = setup();
        let mut state = LogState::default();
        assert_eq!(
            state
                .verify_account(
                    &offered(&record),
                    Some(&record),
                    &record.label,
                    &log.answer(&state, None),
                    NOW
                )
                .err(),
            Some(Error::KeyLogMismatch),
            "offered with a record, but the log has none"
        );

        let mut state = LogState::default();
        state
            .verify_account(
                &offered(&record),
                Some(&record),
                &record.label,
                &log.answer(&state, Some(index)),
                NOW,
            )
            .unwrap();
        assert_eq!(
            state
                .verify_account(
                    &offered(&record),
                    None,
                    &record.label,
                    &log.answer(&state, None),
                    NOW
                )
                .err(),
            Some(Error::KeyLogMismatch),
            "this device saw a record, so it can't be downgraded to none"
        );
    }

    #[test]
    fn a_contact_can_t_step_back_to_an_older_leaf() {
        let (mut log, record, index, _) = setup();
        let mut state = LogState::default();
        let again = log.publish(record.clone());
        for leaf in [again, index] {
            let result = state.verify_account(
                &offered(&record),
                Some(&record),
                &record.label,
                &log.answer(&state, Some(leaf)),
                NOW,
            );
            assert_eq!(result.is_ok(), leaf == again, "leaf {leaf}");
        }
    }

    #[test]
    fn a_log_with_other_keys_is_an_alert() {
        let (log, _, _, _) = setup();
        let mut state = LogState::default();
        state.accept_head(&log.update(0), NOW).unwrap();
        let mut other = Log::new(50);
        other.filler(20);
        assert_eq!(
            state.accept_head(&other.update(9), NOW).err(),
            Some(Error::KeyLogMismatch)
        );
        assert_eq!(state.alert.unwrap().kind, AlertKind::LogChanged);
        assert_eq!(state.pinned_size(), 9, "the pin stays");
        state.reset();
        state.accept_head(&other.update(0), NOW).unwrap();
        assert_eq!(state.alert, None);
    }

    #[test]
    fn a_rewritten_log_is_an_alert() {
        let (log, _, _, _) = setup();
        let mut state = LogState::default();
        state.accept_head(&log.update(0), NOW).unwrap();
        let mut forked = Log::new(1);
        forked.filler(4);
        forked.leaves.push([42; LEAF_LEN]);
        forked.filler(20);
        assert_eq!(
            state.accept_head(&forked.update(9), NOW).err(),
            Some(Error::KeyLogMismatch)
        );
        assert_eq!(state.alert.unwrap().kind, AlertKind::LogInconsistent);
    }

    #[test]
    fn a_log_can_t_shrink_or_go_back_in_time() {
        let (mut log, _, _, _) = setup();
        let mut state = LogState::default();
        log.now = NOW + 10;
        state.accept_head(&log.update(0), NOW + 10).unwrap();

        let older = log.update(9);
        log.now = NOW + 5;
        let earlier = log.update(9);
        assert!(state.accept_head(&earlier, NOW + 10).is_err());
        state.alert = None;
        state.accept_head(&older, NOW + 10).unwrap();

        log.leaves.pop();
        log.now = NOW + 20;
        assert!(state.accept_head(&log.update(0), NOW + 20).is_err());
    }

    #[test]
    fn a_forged_or_stale_head_is_refused() {
        let (log, _, _, _) = setup();
        let mut state = LogState::default();
        let mut forged = log.update(0);
        forged.head.tree_size += 1;
        assert!(state.accept_head(&forged, NOW).is_err());
        assert_eq!(
            state
                .accept_head(&log.update(0), NOW + MAX_HEAD_AGE_MS + 1)
                .err(),
            Some(Error::KeyLogMismatch)
        );
        assert_eq!(state.log, None, "nothing pinned from a refused head");
        assert_eq!(state.alert, None);
    }

    fn monitored(log: &Log, record: &KeyRecord, index: u64) -> LogState {
        let mut state = LogState::default();
        state
            .check_own(record, &log.answer(&state, Some(index)), NOW)
            .unwrap();
        state
    }

    fn scan(log: &Log, state: &mut LogState, page_size: u64) -> Result<()> {
        while let Some((start, end)) = state.scan_range() {
            let done = state.apply_page(&log.page(start, end.min(start + page_size)), NOW)?;
            assert_eq!(done, end <= start + page_size);
        }
        Ok(())
    }

    #[test]
    fn monitoring_starts_at_the_accounts_own_leaf() {
        let (log, record, index, _) = setup();
        let mut state = monitored(&log, &record, index);
        assert_eq!(state.scan_range(), Some((index, 9)));
        scan(&log, &mut state, 2).unwrap();
        assert_eq!(state.scan_range(), None);
        assert_eq!(state.checked_at, NOW);
        assert_eq!(state.alert, None);
    }

    #[test]
    fn monitoring_carries_on_from_where_it_stopped() {
        let (mut log, record, index, _) = setup();
        let mut state = monitored(&log, &record, index);
        scan(&log, &mut state, 100).unwrap();
        log.filler(30);
        state
            .check_own(&record, &log.answer(&state, Some(index)), NOW)
            .unwrap();
        assert_eq!(state.scan_range(), Some((9, 39)));
        scan(&log, &mut state, 7).unwrap();
        assert_eq!(state.alert, None);
    }

    #[test]
    fn a_key_published_for_this_email_is_an_alert() {
        let (mut log, record, index, mut rng) = setup();
        let mut state = monitored(&log, &record, index);
        scan(&log, &mut state, 100).unwrap();
        // The server logs its own key under this account's label, signed by its own key.
        let mut forged = record_for(&log, &mut rng);
        forged.public_enc_key = b64_encode(&[66; 32]);
        let forged = forged.signed(&SigningKey::from_bytes(&[66; 32]));
        let at = log.publish(forged);
        log.filler(2);
        // Showing this device the old record still doesn't hide the leaf.
        state
            .check_own(&record, &log.answer(&state, Some(index)), NOW)
            .unwrap();
        assert_eq!(
            scan(&log, &mut state, 100).err(),
            Some(Error::KeyLogMismatch)
        );
        let alert = state.alert.unwrap();
        assert_eq!(alert.kind, AlertKind::ForeignRecord);
        assert_eq!(alert.leaf_index, Some(at));
    }

    #[test]
    fn a_newer_record_under_this_label_shows_at_once() {
        let (mut log, record, index, mut rng) = setup();
        let mut state = monitored(&log, &record, index);
        let mut forged = record_for(&log, &mut rng);
        forged.created_at += 1;
        let forged = forged.signed(&signing());
        let at = log.publish(forged);
        assert_eq!(
            state
                .check_own(&record, &log.answer(&state, Some(at)), NOW)
                .err(),
            Some(Error::KeyLogMismatch)
        );
        assert_eq!(state.alert.unwrap().kind, AlertKind::ForeignRecord);
    }

    #[test]
    fn hiding_a_leaf_from_a_monitor_is_an_alert() {
        let (mut log, record, index, mut rng) = setup();
        let mut state = monitored(&log, &record, index);
        scan(&log, &mut state, 100).unwrap();
        let mut forged = record_for(&log, &mut rng);
        forged.created_at += 1;
        let at = log.publish(forged.signed(&signing()));
        log.filler(2);
        state
            .check_own(&record, &log.answer(&state, Some(index)), NOW)
            .unwrap();
        // The server replaces the leaf in what it serves, keeping the signed root.
        let mut hidden = log.page(9, 12);
        let mut leaves = log.leaves[9..12].concat();
        leaves[..LEAF_LEN].copy_from_slice(&[0; LEAF_LEN]);
        hidden.leaves = b64_encode(&leaves);
        assert_eq!(
            state.apply_page(&hidden, NOW).err(),
            Some(Error::KeyLogMismatch)
        );
        assert_eq!(state.alert.unwrap().kind, AlertKind::LogInconsistent);
        assert_eq!(at, 9);
    }

    #[test]
    fn a_wrong_frontier_can_t_pass() {
        let (log, record, index, _) = setup();
        let mut state = monitored(&log, &record, index);
        let (start, end) = state.scan_range().unwrap();
        let mut page = log.page(start, end);
        page.frontier[0] = b64_encode(&[1; 32]);
        assert!(state.apply_page(&page, NOW).is_err());
        assert_eq!(state.alert.unwrap().kind, AlertKind::LogInconsistent);
    }

    #[test]
    fn bad_pages_are_refused() {
        let (log, record, index, _) = setup();
        let mut state = monitored(&log, &record, index);
        let good = log.page(index, 7);
        for page in [
            LogPage {
                start: index + 1,
                ..good.clone()
            },
            LogPage {
                leaves: String::new(),
                ..good.clone()
            },
            LogPage {
                leaves: b64_encode(&[0; LEAF_LEN - 1]),
                ..good.clone()
            },
            LogPage {
                frontier: Vec::new(),
                ..good.clone()
            },
        ] {
            assert_eq!(
                state.apply_page(&page, NOW).err(),
                Some(Error::KeyLogMismatch)
            );
        }
        let too_long = LogPage {
            leaves: b64_encode(&[0; 50 * LEAF_LEN]),
            ..good
        };
        assert!(state.apply_page(&too_long, NOW).is_err());
    }

    #[test]
    fn a_missing_own_record_is_an_alert() {
        let (log, record, _, _) = setup();
        let mut state = LogState::default();
        assert!(
            state
                .check_own(&record, &log.answer(&state, None), NOW)
                .is_err()
        );
        assert_eq!(state.alert.unwrap().kind, AlertKind::OwnRecordMissing);
    }

    #[test]
    fn a_record_for_a_previous_log_is_an_alert() {
        let (log, mut record, index, _) = setup();
        let mut state = LogState::default();
        let answer = log.answer(&state, Some(index));
        record.log_id = b64_encode(&[3; 32]);
        assert!(
            state
                .check_own(&record.signed(&signing()), &answer, NOW)
                .is_err()
        );
        assert_eq!(state.alert.unwrap().kind, AlertKind::LogChanged);
    }

    #[test]
    fn the_first_alert_stays() {
        let (log, record, _, _) = setup();
        let mut state = LogState::default();
        let _ = state.check_own(&record, &log.answer(&state, None), NOW);
        let _ = state.check_own(&record, &log.answer(&state, None), NOW + 1);
        assert_eq!(state.alert.unwrap().at, NOW);
    }

    #[test]
    fn state_survives_storage() {
        let (log, record, index, _) = setup();
        let mut state = monitored(&log, &record, index);
        scan(&log, &mut state, 100).unwrap();
        let stored = serde_json::to_string(&state).unwrap();
        let back: LogState = serde_json::from_str(&stored).unwrap();
        assert_eq!(back, state);
        let empty: LogState = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, LogState::default());
    }
}
