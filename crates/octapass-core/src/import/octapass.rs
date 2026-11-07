//! Octa Pass's own exports: the JSON document and the encrypted export (see [`crate::export`]).
//!
//! Items come back exactly as they were exported, into whichever vault the user picks, except that
//! items already in the vault aren't copied again (see [`octapass_items_for`]). Attachment files
//! are only in the encrypted export: their items list them in [`ImportResult::files`], and the
//! caller uploads them once the items are saved (the old file keys open nothing elsewhere).

use serde_json::Value;

use super::build::Collector;
use super::reimport::{Exported, ItemUpdate, Restored, has_file, restore};
use super::{ExistingFile, ImportError, ImportOptions, ImportResult, ImportedFile, decode_text};
use crate::error::Error;
use crate::export::{ArchiveFiles, ExportDocument, is_archive, read_archive};
use crate::item::{Item, ItemOverview};

pub(super) fn parse(bytes: &[u8], options: &ImportOptions) -> Result<ImportResult, ImportError> {
    import_octapass(bytes, options).map(|(result, _)| result)
}

/// Imports either kind of Octa Pass export held in memory. Also returns the attachment files of an
/// encrypted export, by the `file_id` in [`ImportResult::files`] and [`ImportResult::existing_files`].
/// Items already in the vault ([`ImportOptions::existing_items`]) are matched (see
/// [`octapass_items_for`]).
pub fn import_octapass(
    bytes: &[u8],
    options: &ImportOptions,
) -> Result<(ImportResult, ArchiveFiles), ImportError> {
    if !is_archive(bytes) {
        let text = decode_text(bytes)?;
        return Ok((
            octapass_items_for(text.as_bytes(), false, options)?,
            Vec::new(),
        ));
    }
    let password = options.password.as_ref().ok_or(ImportError::new(
        Error::ImportPasswordRequired,
        "This export is encrypted. Enter the password you chose when you exported it.",
    ))?;
    let (json, files) = read_archive(bytes, password).map_err(archive_error)?;
    let mut result = octapass_items_for(&json, true, options)?;
    let present: Vec<&str> = files.iter().map(|(id, _)| id.as_str()).collect();
    let before = result.files.len() + result.existing_files.len();
    result
        .files
        .retain(|file| present.contains(&file.file_id.as_str()));
    result
        .existing_files
        .retain(|file| present.contains(&file.file_id.as_str()));
    let missing = before - result.files.len() - result.existing_files.len();
    if missing > 0 {
        result.warnings.push(missing_files(missing));
    }
    Ok((result, files))
}

/// The items of an export's JSON. With `with_files`, every attachment is listed in
/// [`ImportResult::files`] (the encrypted export); without, they're reported as left out.
pub fn octapass_items(json: &[u8], with_files: bool) -> Result<ImportResult, ImportError> {
    octapass_items_for(json, with_files, &ImportOptions::default())
}

/// As [`octapass_items`], into a vault that holds `options.existing_items`. An exported item that's
/// already there (the same id in any vault, or a duplicate in the target vault) becomes an update
/// when the export has a newer version, and is otherwise left as it is ([`ImportResult::unchanged`],
/// with a warning when the vault's version is the newer one). Its files that the vault's item
/// lacks are listed in [`ImportResult::existing_files`]; files of items that stay as they are
/// aren't brought back.
pub fn octapass_items_for(
    json: &[u8],
    with_files: bool,
    options: &ImportOptions,
) -> Result<ImportResult, ImportError> {
    let document = ExportDocument::parse(json).map_err(|error| match error {
        Error::UnsupportedVersion => ImportError::new(
            Error::UnsupportedImport,
            "This export was made by a newer version of Octa Pass. Update the app, then try again.",
        ),
        _ => ImportError::new(
            Error::InvalidImportFile,
            "This isn't an Octa Pass export. Choose the .json or .octapass file Octa Pass made.",
        ),
    })?;
    let mut out = Collector::default();
    let mut origins = Vec::new();
    let mut attached = Vec::new();
    for (number, entry) in document.items.into_iter().enumerate() {
        let Some((item, files)) = item(entry.overview, entry.details) else {
            out.skip(Some(format!(
                "Item {} skipped: it isn't a valid Octa Pass item.",
                number + 1
            )));
            continue;
        };
        origins.push((entry.id, entry.updated_at));
        attached.push(files);
        out.add(item);
    }
    let exported: Vec<Exported> = origins
        .iter()
        .map(|(id, updated_at)| Exported { id, updated_at })
        .collect();
    let mut result = out.finish();
    let now = options.now.as_deref().unwrap_or("1970-01-01T00:00:00Z");
    let items = std::mem::take(&mut result.items);
    let restored = if options.existing_items.is_empty() {
        items.into_iter().map(Restored::New).collect()
    } else {
        restore(items, &exported, options, now)
    };

    let mut left_out = 0;
    let mut kept = 0;
    for ((placed, from), files) in restored.into_iter().zip(&exported).zip(attached) {
        match placed {
            Restored::New(item) => {
                let index = result.items.len();
                result.items.push(item);
                result.source_ids.push(from.id.to_owned());
                if !with_files {
                    left_out += files.len();
                    continue;
                }
                result
                    .files
                    .extend(files.into_iter().map(|file| ImportedFile {
                        item: index,
                        file_id: file.id,
                        name: file.name,
                        media_type: file.media_type,
                        size: file.size,
                    }));
            }
            Restored::Existing {
                item_id,
                update,
                kept: kept_here,
                newer,
                details,
            } => {
                kept += usize::from(kept_here);
                match update {
                    Some(item) => result.updates.push(ItemUpdate {
                        item_id: item_id.clone(),
                        item,
                    }),
                    None => result.unchanged += 1,
                }
                if newer {
                    continue;
                }
                let missing = files
                    .into_iter()
                    .filter(|file| !has_file(&details, &file.id, &file.name, file.size));
                if !with_files {
                    left_out += missing.count();
                    continue;
                }
                result
                    .existing_files
                    .extend(missing.map(|file| ExistingFile {
                        item_id: item_id.clone(),
                        file_id: file.id,
                        name: file.name,
                        media_type: file.media_type,
                        size: file.size,
                    }));
            }
        }
    }
    if left_out > 0 {
        result.warnings.push(format!(
            "{left_out} attached {} aren't in this export: only the encrypted export includes them.",
            if left_out == 1 { "file" } else { "files" }
        ));
    }
    if kept > 0 {
        result.warnings.push(format!(
            "{kept} {} changed in the vault after this export was made, so the vault's {} kept.",
            if kept == 1 { "item" } else { "items" },
            if kept == 1 {
                "version was"
            } else {
                "versions were"
            }
        ));
    }
    Ok(result)
}

fn missing_files(count: usize) -> String {
    format!(
        "{count} attached {} missing from the export file.",
        if count == 1 { "file is" } else { "files are" }
    )
}

struct ListedFile {
    id: String,
    name: String,
    media_type: String,
    size: u64,
}

/// The item without its attachments (they're uploaded again with new keys), and the attachments.
fn item(overview: Value, mut details: Value) -> Option<(Item, Vec<ListedFile>)> {
    let overview: ItemOverview = serde_json::from_value(overview).ok()?;
    let listed = details
        .as_object_mut()
        .and_then(|details| details.remove("attachments"));
    let files = match listed {
        None => Vec::new(),
        Some(Value::Array(files)) => files
            .iter()
            .map(|file| {
                Some(ListedFile {
                    id: file.get("id")?.as_str()?.to_owned(),
                    name: file.get("name")?.as_str()?.to_owned(),
                    media_type: file
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    size: file.get("size").and_then(Value::as_u64).unwrap_or(0),
                })
            })
            .collect::<Option<Vec<_>>>()?,
        Some(_) => return None,
    };
    Some((Item::from_parts(overview, details).ok()?, files))
}

/// The import error for an encrypted export that can't be read (from [`crate::export::ArchiveReader`]).
pub fn archive_error(error: Error) -> ImportError {
    match error {
        Error::WrongImportPassword => ImportError::new(
            Error::WrongImportPassword,
            "Wrong password for this export.",
        ),
        Error::UnsupportedVersion => ImportError::new(
            Error::UnsupportedImport,
            "This export was made by a newer version of Octa Pass. Update the app, then try again.",
        ),
        Error::UnsupportedKdf => ImportError::new(
            Error::InvalidImportFile,
            "This export's encryption settings aren't ones Octa Pass uses, so it wasn't opened.",
        ),
        _ => ImportError::new(
            Error::InvalidImportFile,
            "The export file is damaged or incomplete. Export it again.",
        ),
    }
}
