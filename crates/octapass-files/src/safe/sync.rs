//! Keeps a Safe the same on every device, through any [`Remote`] that stores blobs. The server sees
//! only what the folder shows: encrypted blobs under random names.
//!
//! The rules, for each object:
//!
//! - A newer record replaces an older one, unless this device has an unsynced change of its own.
//! - When both sides changed a file's content, the newer record keeps the name and the other
//!   version becomes a copy beside it: `report (conflict 2026-11-02).pdf`. No edit is lost.
//! - An edit beats a deletion: the file comes back.
//! - Renames and moves are last-writer-wins, because no content is at stake.
//!
//! Device-local notes remember which blobs the server had, so a blob missing from the server is
//! told apart from a blob the server has never seen: the first case means another device replaced
//! it, the second that this device still has to send it. A record older than this device has seen
//! is refused and reported ([`Warning::RolledBack`]).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::Future;

use octapass_core::safe::{BlobKind, ObjectKind, ObjectRecord, ROOT, blob_kind, new_object_id};
use rand_core::OsRng;
use serde::Serialize;

#[cfg(test)]
use super::SafeError;
use super::{Open, Result, Safe, Warning, blob_path, install_blob, local_blobs, remove_blob};

/// One blob on the other side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBlob {
    pub id: String,
    pub size: u64,
}

/// Where blobs are kept for other devices.
pub trait Remote: Sync {
    fn list(&self) -> impl Future<Output = Result<Vec<RemoteBlob>>> + Send;
    fn get(&self, id: &str) -> impl Future<Output = Result<Vec<u8>>> + Send;
    fn put(&self, id: &str, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + Send;
    fn delete(&self, id: &str) -> impl Future<Output = Result<()>> + Send;
    /// The largest blob this remote takes.
    fn max_blob(&self) -> u64 {
        u64::MAX
    }
}

/// What a sync did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    pub downloaded: usize,
    pub uploaded: usize,
    pub deleted: usize,
    /// Names of copies made because a file changed on two devices.
    pub conflicts: Vec<String>,
    /// Files too big for this server: they stay on this device.
    pub too_big: Vec<String>,
}

fn conflict_name(name: &str, day: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => {
            format!("{stem} (conflict {day}).{extension}")
        }
        _ => format!("{name} (conflict {day})"),
    }
}

/// `YYYY-MM-DD` of a time in milliseconds, in UTC.
fn day_of(ms: u64) -> String {
    // Howard Hinnant's civil_from_days.
    let days = (ms / 86_400_000) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let of_era = days.rem_euclid(146_097);
    let year_of_era = (of_era - of_era / 1460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * of_year + 2) / 153;
    let day = of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Runs a sync on this thread, for a [`Remote`] whose calls block instead of waiting (the phones'
/// HTTP client): such a future never has to be woken, so polling it to the end is all it takes.
pub fn block_on_ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        std::thread::yield_now();
    }
}

struct Incoming {
    blob: String,
    record: ObjectRecord,
}

impl Open {
    /// Whether this object's current state hasn't reached the server yet.
    fn dirty(&self, id: &str) -> bool {
        let blob = self
            .nodes
            .get(id)
            .map(|node| &node.blob)
            .or_else(|| self.deleted.get(id).map(|(blob, _)| blob));
        blob.is_some_and(|blob| !self.notes.synced.contains(blob))
    }

    fn current(&self, id: &str) -> Option<(String, ObjectRecord)> {
        self.nodes
            .get(id)
            .map(|node| (node.blob.clone(), node.record.clone()))
            .or_else(|| self.deleted.get(id).cloned())
    }

    /// Replaces the object's state with `incoming`, which is already on disk.
    fn adopt(&mut self, root: &std::path::Path, incoming: Incoming) -> Result<()> {
        if let Some((blob, record)) = self.current(&incoming.record.object) {
            remove_blob(root, &blob)?;
            if record.content != incoming.record.content
                && let Some(content) = &record.content
            {
                remove_blob(root, content)?;
            }
        }
        let rev = incoming.record.rev;
        let id = incoming.record.object.clone();
        self.place(incoming.blob, incoming.record);
        let seen = self.notes.seen.entry(id).or_default();
        *seen = (*seen).max(rev);
        self.notes_dirty = true;
        Ok(())
    }

    /// Keeps `loser`'s content as a new file beside the winner's.
    fn keep_copy(
        &mut self,
        root: &std::path::Path,
        loser: &ObjectRecord,
        now: u64,
        report: &mut SyncReport,
    ) -> Result<()> {
        // Each copy is a new object over the same content blob, which has this object's id in its
        // associated data: so the content must be sealed again under the new object.
        let mut plain = Vec::new();
        {
            let (mut file, mut reader) = self.content_reader(root, loser)?;
            for index in 0..octapass_core::safe::chunk_count(loser.size) {
                plain.extend_from_slice(&Self::base_chunk(loser, &mut file, &mut reader, index)?);
            }
        }
        let name = conflict_name(&loser.name, &day_of(now));
        let parent = if self.nodes.contains_key(&loser.parent) {
            loser.parent.clone()
        } else {
            ROOT.to_owned()
        };
        let record = ObjectRecord {
            object: new_object_id(&mut OsRng),
            rev: 0,
            prev: None,
            parent,
            name: name.clone(),
            kind: ObjectKind::File,
            size: 0,
            modified: loser.modified,
            content: None,
            file_key: None,
        };
        let id = record.object.clone();
        self.commit_record(root, record, None)?;
        self.write(root, &id, 0, &plain)?;
        self.flush(root, &id, loser.modified)?;
        report.conflicts.push(name);
        Ok(())
    }

    /// Takes in records that arrived from another device.
    fn merge(
        &mut self,
        root: &std::path::Path,
        mut incoming: Vec<Incoming>,
        now: u64,
        report: &mut SyncReport,
    ) -> Result<()> {
        incoming.sort_by_key(|one| one.record.rev);
        for one in incoming {
            let id = one.record.object.clone();
            let seen = self.notes.seen.get(&id).copied().unwrap_or(0);
            let Some((held_blob, held)) = self.current(&id) else {
                if one.record.rev < seen {
                    self.warnings.push(Warning::RolledBack { object: id });
                    self.drop_incoming(root, &one)?;
                } else {
                    self.adopt(root, one)?;
                }
                continue;
            };
            let dirty = self.dirty(&id);
            // At the same revision the server's order decides: whichever reached it first stands.
            let newer = one.record.rev > held.rev
                || (one.record.rev == held.rev && (dirty || one.blob > held_blob));
            let same_content = one.record.content == held.content;

            if newer && !dirty {
                self.adopt(root, one)?;
            } else if newer {
                // Both sides changed it. The record from the server stands.
                let held_file = held.kind == ObjectKind::File && !same_content;
                let incoming_deleted = one.record.kind == ObjectKind::Deleted;
                if incoming_deleted && held.kind != ObjectKind::Deleted {
                    // An edit beats a deletion: this revision follows the tombstone.
                    let mut next = held.clone();
                    next.rev = one.record.rev;
                    let (tombstone, record) = (one.blob.clone(), one.record.clone());
                    self.deleted_and_restored(root, tombstone, record, next)?;
                } else if held_file {
                    self.keep_copy(root, &held, now, report)?;
                    self.adopt(root, one)?;
                } else {
                    self.adopt(root, one)?;
                }
            } else {
                // Older than what's here. If nothing here descends from it, it's a change made
                // on another device without seeing ours, and worth keeping.
                let concurrent = !self.notes.synced.contains(&one.blob)
                    && one.record.kind == ObjectKind::File
                    && !same_content
                    && one.record.rev >= seen.saturating_sub(1).min(held.rev);
                if concurrent && held.prev.as_deref() != Some(&one.blob) {
                    self.keep_copy(root, &one.record, now, report)?;
                }
                self.drop_incoming(root, &one)?;
            }
        }
        self.rebuild();
        Ok(())
    }

    fn drop_incoming(&mut self, root: &std::path::Path, one: &Incoming) -> Result<()> {
        remove_blob(root, &one.blob)?;
        if let Some(content) = &one.record.content {
            let shared = self
                .nodes
                .get(&one.record.object)
                .is_some_and(|node| node.record.content.as_ref() == Some(content));
            if !shared {
                remove_blob(root, content)?;
            }
        }
        // Absent here, present on the server: remembered so the sync deletes it there.
        self.notes.synced.insert(one.blob.clone());
        if let Some(content) = &one.record.content {
            self.notes.synced.insert(content.clone());
        }
        self.notes_dirty = true;
        Ok(())
    }

    fn deleted_and_restored(
        &mut self,
        root: &std::path::Path,
        tombstone: String,
        record: ObjectRecord,
        mut next: ObjectRecord,
    ) -> Result<()> {
        let content = next.content.clone();
        // `commit_record` numbers the new revision after what it finds, so it must find the
        // tombstone, with the content kept.
        let (old, _) = self
            .current(&next.object)
            .expect("the caller found this object");
        remove_blob(root, &old)?;
        self.place(tombstone, record);
        next.content = content;
        self.commit_record(root, next, None)
    }
}

impl Safe {
    /// One round of sync: fetch what's new, merge it, send what's new here, delete what's been
    /// replaced. Run it with no other sync of this Safe going.
    pub async fn sync(&self, remote: &impl Remote) -> Result<SyncReport> {
        self.flush_all()?;
        let mut report = SyncReport::default();
        let max_blob = remote.max_blob();
        let remote_blobs: HashMap<String, u64> = remote
            .list()
            .await?
            .into_iter()
            .filter(|blob| blob_kind(&blob.id).is_some())
            .map(|blob| (blob.id, blob.size))
            .collect();
        let local: HashSet<String> = local_blobs(self.root())?.into_iter().collect();
        let synced = self.with(|open| Ok(open.notes.synced.clone()))?;

        // What's new over there. Blobs this device had and let go of aren't: those get deleted
        // below.
        let mut incoming = Vec::new();
        let mut wanted_content = Vec::new();
        for id in remote_blobs
            .keys()
            .filter(|id| !local.contains(*id) && !synced.contains(*id))
        {
            if blob_kind(id) != Some(BlobKind::Record) {
                continue;
            }
            let sealed = remote.get(id).await?;
            let opened = self.with(|open| Ok(open.keys.open_record(id, &sealed).ok()))?;
            let Some(record) = opened else {
                self.with(|open| {
                    open.warnings
                        .push(Warning::DamagedBlob { blob: id.clone() });
                    Ok(())
                })?;
                continue;
            };
            install_blob(self.root(), id, &sealed)?;
            report.downloaded += 1;
            if let Some(content) = &record.content
                && !local.contains(content)
            {
                wanted_content.push(content.clone());
            }
            incoming.push(Incoming {
                blob: id.clone(),
                record,
            });
        }
        for content in wanted_content {
            let bytes = remote.get(&content).await?;
            install_blob(self.root(), &content, &bytes)?;
            report.downloaded += 1;
        }

        let now = (self.clock)();
        let root = self.root().to_owned();
        self.with(|open| open.merge(&root, incoming, now, &mut report))?;

        // What this device has that the server doesn't. A record goes only after its content.
        let local: HashSet<String> = local_blobs(self.root())?.into_iter().collect();
        let (records, contents) = self.with(|open| {
            let live: Vec<ObjectRecord> = open
                .nodes
                .values()
                .map(|node| node.record.clone())
                .chain(open.deleted.values().map(|(_, record)| record.clone()))
                .collect();
            let blobs: HashMap<String, String> = open
                .nodes
                .iter()
                .map(|(id, node)| (id.clone(), node.blob.clone()))
                .chain(
                    open.deleted
                        .iter()
                        .map(|(id, (blob, _))| (id.clone(), blob.clone())),
                )
                .collect();
            Ok((blobs, live))
        })?;
        let mut held_back = HashSet::new();
        let mut uploaded_or_there: HashSet<String> = HashSet::new();
        for record in &contents {
            let Some(content) = &record.content else {
                continue;
            };
            if remote_blobs.contains_key(content) {
                uploaded_or_there.insert(content.clone());
                continue;
            }
            let path = blob_path(self.root(), content);
            let size = fs::metadata(&path)?.len();
            if size > max_blob {
                held_back.insert(record.object.clone());
                report.too_big.push(record.name.clone());
                continue;
            }
            remote.put(content, fs::read(&path)?).await?;
            report.uploaded += 1;
            uploaded_or_there.insert(content.clone());
        }
        for (object, blob) in &records {
            if remote_blobs.contains_key(blob) || held_back.contains(object) {
                if remote_blobs.contains_key(blob) {
                    uploaded_or_there.insert(blob.clone());
                }
                continue;
            }
            remote
                .put(blob, fs::read(blob_path(self.root(), blob))?)
                .await?;
            report.uploaded += 1;
            uploaded_or_there.insert(blob.clone());
        }

        // Replaced blobs: what the server has that this device let go of.
        for id in remote_blobs.keys() {
            if !local.contains(id) && !uploaded_or_there.contains(id) {
                let known = self.with(|open| Ok(open.notes.synced.contains(id)))?;
                if known {
                    remote.delete(id).await?;
                    report.deleted += 1;
                }
            }
        }

        self.with(|open| {
            open.notes.synced = uploaded_or_there;
            open.notes_dirty = true;
            open.save_notes(&root)
        })?;
        if report.too_big.len() > 1 {
            report.too_big.sort();
        }
        Ok(report)
    }
}

#[cfg(test)]
#[path = "sync/tests.rs"]
mod tests;
