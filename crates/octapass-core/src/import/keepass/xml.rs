//! The KeePass XML document (`KeePassFile/Root/Group/Entry`), from inside a KDBX database or from
//! KeePass's unencrypted XML export.
//!
//! Inside a database, values marked `Protected="True"` are base64 XORed with the database's inner
//! key stream, in document order (including attachments in KDBX 3.1's `Meta/Binaries`, which use
//! the stream without being imported). The export marks the same values `ProtectedInMemory="True"`
//! and writes them in the clear. quick-xml never resolves a DTD or custom entities.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use super::kdbx::InnerStream;
use crate::import::build::{iso_date, rfc3339};

const MAX_GROUP_DEPTH: usize = 64;

#[derive(Default)]
pub(super) struct Document {
    pub groups: Vec<Group>,
    pub entries: Vec<Entry>,
    /// `Meta/RecycleBinUUID`, compared with group UUIDs as written (base64).
    pub recycle_bin: Option<String>,
}

pub(super) struct Group {
    pub uuid: String,
    pub name: String,
    pub parent: Option<usize>,
}

#[derive(Default)]
pub(super) struct Entry {
    pub group: Option<usize>,
    /// base64, as written.
    pub uuid: String,
    pub strings: Vec<Field>,
    pub tags: String,
    /// RFC 3339, like the other times.
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub expires: bool,
    pub expiry: Option<String>,
    pub attachments: usize,
    pub auto_type: AutoType,
    /// Earlier versions of the entry, oldest first.
    pub history: Vec<Entry>,
}

/// An entry's auto-type settings: `Enabled`, `DefaultSequence` and the windows of its
/// `Association`s (each association's own sequence has no place in Octa Pass).
#[derive(Default)]
pub(super) struct AutoType {
    pub disabled: bool,
    pub sequence: Option<String>,
    pub windows: Vec<String>,
}

#[derive(Default)]
pub(super) struct Field {
    pub key: String,
    pub value: String,
    pub protected: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tag {
    KeePassFile,
    Meta,
    RecycleBinUuid,
    Root,
    Group,
    Uuid,
    Name,
    Entry,
    History,
    String,
    Key,
    Value,
    Binary,
    Tags,
    Times,
    CreationTime,
    LastModificationTime,
    LastAccessTime,
    Expires,
    ExpiryTime,
    AutoType,
    Enabled,
    DefaultSequence,
    Association,
    Window,
    Other,
}

impl Tag {
    fn of(name: &str) -> Self {
        match name {
            "KeePassFile" => Self::KeePassFile,
            "Meta" => Self::Meta,
            "RecycleBinUUID" => Self::RecycleBinUuid,
            "Root" => Self::Root,
            "Group" => Self::Group,
            "UUID" => Self::Uuid,
            "Name" => Self::Name,
            "Entry" => Self::Entry,
            "History" => Self::History,
            "String" => Self::String,
            "Key" => Self::Key,
            "Value" => Self::Value,
            "Binary" => Self::Binary,
            "Tags" => Self::Tags,
            "Times" => Self::Times,
            "CreationTime" => Self::CreationTime,
            "LastModificationTime" => Self::LastModificationTime,
            "LastAccessTime" => Self::LastAccessTime,
            "AutoType" => Self::AutoType,
            "Enabled" => Self::Enabled,
            "DefaultSequence" => Self::DefaultSequence,
            "Association" => Self::Association,
            "Window" => Self::Window,
            "Expires" => Self::Expires,
            "ExpiryTime" => Self::ExpiryTime,
            _ => Self::Other,
        }
    }
}

/// `None` when the text isn't a KeePass XML document, or is damaged.
pub(super) fn parse(xml: &str, stream: &mut InnerStream) -> Option<Document> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().expand_empty_elements = true;
    let mut doc = Document::default();
    let mut path: Vec<Tag> = Vec::new();
    // Open groups, innermost last; the entry being read; one of its history versions.
    let mut groups: Vec<usize> = Vec::new();
    let mut entry: Option<Entry> = None;
    let mut old: Option<Entry> = None;
    let mut field: Option<Field> = None;
    // The text and protection of the innermost open element; reset by every start and end.
    let mut text = String::new();
    let (mut protected, mut in_memory) = (false, false);
    let mut seen_root = false;
    loop {
        match reader.read_event().ok()? {
            Event::Start(start) => {
                let tag = Tag::of(start.local_name().as_ref());
                let parent = path.last().copied();
                if parent.is_none() {
                    if seen_root || tag != Tag::KeePassFile {
                        return None;
                    }
                    seen_root = true;
                }
                text.clear();
                protected = is_true(&start, "Protected");
                in_memory = is_true(&start, "ProtectedInMemory");
                match (parent, tag) {
                    (Some(Tag::Root | Tag::Group), Tag::Group) => {
                        // Far deeper than anyone nests; it bounds the group paths built later.
                        if groups.len() >= MAX_GROUP_DEPTH {
                            return None;
                        }
                        doc.groups.push(Group {
                            uuid: String::new(),
                            name: String::new(),
                            parent: groups.last().copied(),
                        });
                        groups.push(doc.groups.len() - 1);
                    }
                    (Some(Tag::Group), Tag::Entry) => {
                        entry = Some(Entry {
                            group: groups.last().copied(),
                            ..Entry::default()
                        });
                    }
                    (Some(Tag::History), Tag::Entry) => old = Some(Entry::default()),
                    (Some(Tag::Entry), Tag::String) => field = Some(Field::default()),
                    (Some(Tag::Entry), Tag::Binary) if old.is_none() => {
                        if let Some(entry) = entry.as_mut() {
                            entry.attachments += 1;
                        }
                    }
                    _ => {}
                }
                path.push(tag);
            }
            Event::Text(t) => text.push_str(&t.xml10_content()),
            Event::CData(t) => text.push_str(&t.xml10_content()),
            Event::GeneralRef(r) => text.push(match r.resolve_char_ref().ok()? {
                Some(c) => c,
                None => match r.as_ref() {
                    "lt" => '<',
                    "gt" => '>',
                    "amp" => '&',
                    "apos" => '\'',
                    "quot" => '"',
                    _ => return None,
                },
            }),
            Event::End(_) => {
                let tag = path.pop()?;
                let parent = path.last().copied();
                let grandparent = path.len().checked_sub(2).map(|i| path[i]);
                let (was_protected, was_in_memory) = (protected, in_memory);
                (protected, in_memory) = (false, false);
                // Every protected value takes its bytes of the stream, even ones not imported.
                let unmasked = if was_protected {
                    let mut bytes = STANDARD.decode(text.trim()).ok()?;
                    stream.apply(&mut bytes);
                    Some(String::from_utf8(bytes).ok()?)
                } else {
                    None
                };
                let current = if old.is_some() {
                    old.as_mut()
                } else {
                    entry.as_mut()
                };
                match (parent, tag) {
                    (Some(Tag::Meta), Tag::RecycleBinUuid) => {
                        doc.recycle_bin = Some(text.trim().to_string()).filter(|u| !u.is_empty());
                    }
                    (Some(Tag::Group), Tag::Uuid | Tag::Name) => {
                        if let Some(&g) = groups.last() {
                            let group = &mut doc.groups[g];
                            if tag == Tag::Uuid {
                                group.uuid = text.trim().to_string();
                            } else {
                                group.name = text.clone();
                            }
                        }
                    }
                    (Some(Tag::String), Tag::Key) => {
                        if let Some(field) = field.as_mut() {
                            field.key = text.clone();
                        }
                    }
                    (Some(Tag::String), Tag::Value) => {
                        if let Some(field) = field.as_mut() {
                            field.value = unmasked.unwrap_or_else(|| text.clone());
                            field.protected = was_protected || was_in_memory;
                        }
                    }
                    (Some(Tag::Entry), Tag::String) => {
                        if let (Some(entry), Some(field)) = (current, field.take()) {
                            entry.strings.push(field);
                        }
                    }
                    (Some(Tag::Entry), Tag::Tags) => {
                        if let Some(entry) = current {
                            entry.tags = text.clone();
                        }
                    }
                    (Some(Tag::Entry), Tag::Uuid) => {
                        if let Some(entry) = current {
                            entry.uuid = text.trim().to_string();
                        }
                    }
                    (Some(Tag::AutoType), Tag::Enabled | Tag::DefaultSequence)
                        if grandparent == Some(Tag::Entry) =>
                    {
                        if let Some(entry) = current {
                            if tag == Tag::Enabled {
                                entry.auto_type.disabled = text.trim() == "False";
                            } else {
                                entry.auto_type.sequence =
                                    Some(text.trim().to_string()).filter(|s| !s.is_empty());
                            }
                        }
                    }
                    (Some(Tag::Association), Tag::Window) => {
                        if let Some(entry) = current
                            && !text.trim().is_empty()
                        {
                            entry.auto_type.windows.push(text.trim().to_string());
                        }
                    }
                    (Some(Tag::Times), _) if grandparent == Some(Tag::Entry) => {
                        if let Some(entry) = current {
                            match tag {
                                Tag::CreationTime => entry.created = time(&text),
                                Tag::LastModificationTime => entry.modified = time(&text),
                                Tag::LastAccessTime => entry.accessed = time(&text),
                                Tag::Expires => entry.expires = text.trim() == "True",
                                Tag::ExpiryTime => entry.expiry = time(&text),
                                _ => {}
                            }
                        }
                    }
                    (Some(Tag::History), Tag::Entry) => {
                        if let (Some(entry), Some(old)) = (entry.as_mut(), old.take()) {
                            entry.history.push(old);
                        }
                    }
                    (Some(Tag::Group), Tag::Entry) => doc.entries.extend(entry.take()),
                    (Some(Tag::Root | Tag::Group), Tag::Group) => {
                        groups.pop();
                    }
                    _ => {}
                }
                text.clear();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    (seen_root && path.is_empty()).then_some(doc)
}

fn is_true(start: &BytesStart, name: &str) -> bool {
    matches!(start.try_get_attribute(name), Ok(Some(a)) if a.value == "True")
}

/// Seconds between 0001-01-01 and 1970-01-01.
const UNIX_EPOCH_SECONDS: i64 = 62_135_596_800;
/// 9999-12-31T23:59:59Z, KeePass's latest date.
const MAX_SECONDS: i64 = 315_537_897_599;

/// RFC 3339 for a KeePass time: ISO 8601 text (KDBX 3.1 and the XML export) or KDBX 4's base64
/// of the seconds since 0001-01-01 (little-endian `i64`).
pub(super) fn time(text: &str) -> Option<String> {
    let text = text.trim();
    if let Some((date, time)) = text.split_once('T') {
        let mut parts = date.splitn(3, '-').map(|p| p.parse::<u32>().ok());
        let (year, month, day) = (parts.next()??, parts.next()??, parts.next()??);
        let date = iso_date(year.into(), month, day)?;
        let mut parts = time.get(..8)?.split(':').map(|p| p.parse::<u32>().ok());
        let (hour, minute, second) = (parts.next()??, parts.next()??, parts.next()??);
        return (hour < 24 && minute < 60 && second < 60)
            .then(|| format!("{date}T{hour:02}:{minute:02}:{second:02}Z"));
    }
    let bytes: [u8; 8] = STANDARD.decode(text).ok()?.try_into().ok()?;
    let seconds = i64::from_le_bytes(bytes);
    (0..=MAX_SECONDS)
        .contains(&seconds)
        .then(|| rfc3339(seconds - UNIX_EPOCH_SECONDS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(
            time("2025-10-23T08:01:02Z").as_deref(),
            Some("2025-10-23T08:01:02Z")
        );
        // 2025-10-23T00:00:00Z as KDBX 4 writes it.
        let kdbx4 = STANDARD.encode((1_761_177_600i64 + UNIX_EPOCH_SECONDS).to_le_bytes());
        assert_eq!(time(&kdbx4).as_deref(), Some("2025-10-23T00:00:00Z"));
        assert_eq!(time("2025-02-30T00:00:00Z"), None);
        assert_eq!(time("AAAAAAAAAIA="), None, "negative");
        assert_eq!(time("not a time"), None);
    }

    #[test]
    fn groups_entries_and_history() {
        let xml = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta><RecycleBinUUID>Ymlu</RecycleBinUUID></Meta>
  <Root><Group><UUID>cm9vdA==</UUID><Name>Root</Name>
    <Entry>
      <String><Key>Title</Key><Value>A &amp; B &#x1F510;</Value></String>
      <String><Key>Password</Key><Value ProtectedInMemory="True"> spaced </Value></String>
      <String><Key>Empty</Key><Value/></String>
      <Binary><Key>a.txt</Key><Value Ref="0"/></Binary>
      <Times><LastModificationTime>2025-01-02T03:04:05Z</LastModificationTime></Times>
      <History><Entry>
        <String><Key>Password</Key><Value ProtectedInMemory="True">old</Value></String>
        <Binary><Key>a.txt</Key><Value Ref="0"/></Binary>
        <Times><LastModificationTime>2024-01-02T03:04:05Z</LastModificationTime></Times>
      </Entry></History>
    </Entry>
    <Group><UUID>Ymlu</UUID><Name>Recycle Bin</Name><Entry/></Group>
  </Group></Root>
</KeePassFile>"#;
        let doc = parse(xml, &mut InnerStream::None).unwrap();
        assert_eq!(doc.groups.len(), 2);
        assert_eq!(doc.groups[1].parent, Some(0));
        assert_eq!(doc.recycle_bin.as_deref(), Some("Ymlu"));
        let entry = &doc.entries[0];
        assert_eq!(entry.strings[0].value, "A & B 🔐");
        assert_eq!(entry.strings[1].value, " spaced ");
        assert!(entry.strings[1].protected && !entry.strings[0].protected);
        assert_eq!(entry.strings[2].value, "");
        assert_eq!(entry.attachments, 1);
        assert_eq!(entry.modified.as_deref(), Some("2025-01-02T03:04:05Z"));
        assert_eq!(entry.history[0].strings[0].value, "old");
        assert_eq!(doc.entries[1].group, Some(1));
    }

    #[test]
    fn protected_values_use_the_stream_in_document_order() {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        let mut writer = chacha20::ChaCha20::new(&[7; 32].into(), &[9; 12].into());
        let mut mask = |plain: &[u8]| {
            let mut bytes = plain.to_vec();
            writer.apply_keystream(&mut bytes);
            STANDARD.encode(bytes)
        };
        // A protected attachment in Meta comes first and must be skipped over, not dropped.
        let xml = format!(
            r#"<KeePassFile><Meta><Binaries><Binary ID="0" Protected="True">{}</Binary></Binaries></Meta>
<Root><Group><Entry><String><Key>Password</Key><Value Protected="True">{}</Value></String>
<String><Key>PIN</Key><Value Protected="True">{}</Value></String></Entry></Group></Root></KeePassFile>"#,
            mask(b"attachment bytes"),
            mask("كلمة سر".as_bytes()),
            mask(b"1234"),
        );
        let mut stream = InnerStream::ChaCha20(Box::new(chacha20::ChaCha20::new(
            &[7; 32].into(),
            &[9; 12].into(),
        )));
        let doc = parse(&xml, &mut stream).unwrap();
        let values: Vec<&str> = doc.entries[0]
            .strings
            .iter()
            .map(|f| f.value.as_str())
            .collect();
        assert_eq!(values, ["كلمة سر", "1234"]);
    }

    #[test]
    fn rejects_other_documents() {
        for xml in [
            "<html><body/></html>",
            "<KeePassFile><Root>",
            "<KeePassFile/><KeePassFile/>",
            "<!DOCTYPE x [<!ENTITY e \"boom\">]><KeePassFile><Meta><Name>&e;</Name></Meta></KeePassFile>",
            "not xml",
        ] {
            assert!(parse(xml, &mut InnerStream::None).is_none(), "{xml}");
        }
    }
}
