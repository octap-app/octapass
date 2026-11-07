//! Reads a Safe's records into a tree, and keeps that tree usable whatever the blobs say: the
//! newest record of each object wins, leftovers are cleared, and files whose folder is gone or
//! folders that ended up inside themselves move to the top instead of disappearing.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use octapass_core::safe::{BlobKind, ObjectKind, ObjectRecord, ROOT, blob_kind};

use super::{Node, Open, Result, Warning, blob_path, local_blobs, numbered_name, remove_blob};

impl Open {
    /// Puts one record in the tree's tables, replacing the object's last. Call [`Open::rebuild`]
    /// after a batch.
    pub(crate) fn place(&mut self, blob: String, record: ObjectRecord) {
        let id = record.object.clone();
        if record.kind == ObjectKind::Deleted {
            self.nodes.remove(&id);
            self.deleted.insert(id, (blob, record));
        } else {
            self.deleted.remove(&id);
            let display_name = record.name.clone();
            self.nodes.insert(
                id,
                Node {
                    blob,
                    record,
                    display_name,
                },
            );
        }
    }

    pub(crate) fn scan(&mut self, root: &Path) -> Result<()> {
        let blobs = local_blobs(root)?;
        let mut best: HashMap<String, (String, ObjectRecord)> = HashMap::new();
        let mut losers = Vec::new();
        for blob in blobs.iter().filter(|b| blob_kind(b) == Some(BlobKind::Record)) {
            let opened = fs::read(blob_path(root, blob))
                .ok()
                .and_then(|sealed| self.keys.open_record(blob, &sealed).ok());
            let Some(record) = opened else {
                self.warnings.push(Warning::DamagedBlob { blob: blob.clone() });
                continue;
            };
            match best.get(&record.object) {
                Some((held, current)) if (current.rev, held) >= (record.rev, blob) => {
                    losers.push(blob.clone());
                }
                _ => {
                    if let Some((held, _)) = best.insert(record.object.clone(), (blob.clone(), record))
                    {
                        losers.push(held);
                    }
                }
            }
        }
        for blob in losers {
            remove_blob(root, &blob)?;
        }
        for (blob, record) in best.into_values() {
            self.place(blob, record);
        }
        // Content no record points at: left by a crash between its two writes.
        let wanted: HashSet<&str> = self
            .nodes
            .values()
            .filter_map(|node| node.record.content.as_deref())
            .collect();
        for blob in blobs.iter().filter(|b| blob_kind(b) == Some(BlobKind::Content)) {
            if !wanted.contains(blob.as_str()) {
                remove_blob(root, blob)?;
            }
        }
        self.check_seen();
        self.rebuild();
        Ok(())
    }

    fn check_seen(&mut self) {
        let mut warnings = Vec::new();
        for (object, seen) in &self.notes.seen {
            let held = self
                .nodes
                .get(object)
                .map(|node| node.record.rev)
                .or_else(|| self.deleted.get(object).map(|(_, record)| record.rev));
            match held {
                None => warnings.push(Warning::Missing {
                    object: object.clone(),
                }),
                Some(rev) if rev < *seen => warnings.push(Warning::RolledBack {
                    object: object.clone(),
                }),
                Some(_) => {}
            }
        }
        warnings.sort_by_key(|warning| format!("{warning:?}"));
        self.warnings.extend(warnings);
        for node in self.nodes.values() {
            let seen = self.notes.seen.get(&node.record.object).copied();
            if seen.is_none_or(|seen| seen < node.record.rev) {
                self.notes.seen.insert(node.record.object.clone(), node.record.rev);
                self.notes_dirty = true;
            }
        }
    }

    /// The parent to show an object under: its own, or the top if that's gone or would make a loop.
    fn effective_parent(&self, id: &str) -> String {
        let parent = &self.nodes[id].record.parent;
        let mut seen = HashSet::from([id.to_owned()]);
        let mut current = parent.clone();
        while current != ROOT {
            let Some(node) = self.nodes.get(&current) else {
                return ROOT.to_owned();
            };
            if node.record.kind != ObjectKind::Folder || !seen.insert(current.clone()) {
                return ROOT.to_owned();
            }
            current = node.record.parent.clone();
        }
        parent.clone()
    }

    /// Recomputes who's in which folder. Two objects can arrive with one name (edits on two
    /// devices); the newer ids get a number, without changing their records.
    pub(crate) fn rebuild(&mut self) {
        let mut ids: Vec<String> = self.nodes.keys().cloned().collect();
        ids.sort();
        let mut children: HashMap<String, BTreeMap<String, String>> = HashMap::new();
        for id in ids {
            let parent = self.effective_parent(&id);
            let node = self.nodes.get_mut(&id).expect("listed above");
            if parent != node.record.parent {
                node.record.parent.clone_from(&parent);
                let name = node.record.name.clone();
                if !self.warnings.contains(&Warning::Orphaned { name: name.clone() }) {
                    self.warnings.push(Warning::Orphaned { name });
                }
            }
            let names = children.entry(parent).or_default();
            let node = self.nodes.get_mut(&id).expect("listed above");
            let mut shown = node.record.name.clone();
            let mut number = 2;
            while names.contains_key(&shown) {
                shown = numbered_name(&node.record.name, number);
                number += 1;
            }
            node.display_name.clone_from(&shown);
            names.insert(shown, id);
        }
        self.children = children;
    }
}
