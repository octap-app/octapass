//! Exports: the encrypted export (written and read a piece at a time, so a large vault never sits
//! in memory twice) and the FIDO Credential Exchange Format.

use octapass_core::export::{self, ArchiveEntry, ArchiveReader, ArchiveWriter, ExportDocument};
use octapass_core::import::{self, ImportResult};
use octapass_core::kdf::KdfParams;
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

use crate::{
    flow_finished, from_js, invalid_argument, js_error, make_error, options_from_js, to_js,
};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
/** An attachment of an imported item: upload `fileId`'s data from the export to `items[item]`. */
export type ImportedFile = { item: number; fileId: string; name: string; type: string; size: number };
/** An attachment for an item already in the vault that lacks it: upload `fileId`'s data to `itemId`. */
export type ExistingFile = { itemId: string; fileId: string; name: string; type: string; size: number };
/** What an encrypted export holds, in order: the items once, then each attachment. */
export type ExportEntry = { kind: "items"; result: ImportResult } | { kind: "file"; fileId: string; data: Uint8Array };
/** Who a CXF export belongs to. `id` is any stable id (the account id). */
export type CxfAccount = { id: string; username: string; email: string };
export type CxfExport = { json: string; exported: number; skipped: number; warnings: string[] };
"#;

/// Writes an encrypted export. Call `addItems` once with the Octa Pass JSON, then `addFile` for each
/// attachment, then `finish`; the outputs, in order, are the file.
#[wasm_bindgen]
pub struct ExportWriter {
    inner: Option<ArchiveWriter>,
}

#[wasm_bindgen]
impl ExportWriter {
    /// Runs Argon2id (256 MiB unless `kdf` says otherwise; tests pass cheaper settings).
    #[wasm_bindgen(constructor)]
    pub fn new(
        password: String,
        #[wasm_bindgen(unchecked_param_type = "KdfParams | undefined")] kdf: JsValue,
    ) -> Result<ExportWriter, JsValue> {
        let password = zeroize::Zeroizing::new(password);
        let kdf = if kdf.is_undefined() || kdf.is_null() {
            export::EXPORT_KDF
        } else {
            from_js::<KdfParams>(kdf, "kdf")?
        };
        Ok(Self {
            inner: Some(ArchiveWriter::new(&password, kdf, &mut OsRng).map_err(js_error)?),
        })
    }

    #[wasm_bindgen(js_name = addItems)]
    pub fn add_items(&mut self, json: String) -> Result<Vec<u8>, JsValue> {
        let json = zeroize::Zeroizing::new(json);
        let inner = self.inner.as_mut().ok_or_else(flow_finished)?;
        inner.add_items(json.as_bytes()).map_err(js_error)
    }

    #[wasm_bindgen(js_name = addFile)]
    pub fn add_file(
        &mut self,
        #[wasm_bindgen(js_name = attachmentId)] attachment_id: String,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        let data = zeroize::Zeroizing::new(data);
        let inner = self.inner.as_mut().ok_or_else(flow_finished)?;
        inner.add_file(&attachment_id, &data).map_err(js_error)
    }

    /// Returns the end of the file. The handle can't be used afterwards.
    pub fn finish(&mut self) -> Result<Vec<u8>, JsValue> {
        let inner = self.inner.take().ok_or_else(flow_finished)?;
        inner.finish().map_err(js_error)
    }
}

/// Reads an encrypted export a piece at a time. Throws `import_password_required`,
/// `wrong_import_password` or `invalid_import_file` with a sentence for the user. The import is
/// only complete once `finish` succeeds. `options` (`existingItems`, `vaultId`, `now`) are the
/// vault's items, so items already there come back as `updates` or `unchanged`, as `importFile`.
#[wasm_bindgen]
pub struct ExportReader {
    inner: Option<ArchiveReader>,
    options: import::ImportOptions,
}

#[wasm_bindgen]
impl ExportReader {
    #[wasm_bindgen(constructor)]
    pub fn new(
        password: String,
        #[wasm_bindgen(unchecked_param_type = "ImportOptions | undefined")] options: JsValue,
    ) -> Result<ExportReader, JsValue> {
        let options: import::ImportOptions = options_from_js(options, "import options")?;
        let password = zeroize::Zeroizing::new(password);
        if password.is_empty() {
            return Err(make_error(
                octapass_core::Error::ImportPasswordRequired.code(),
                "This export is encrypted. Enter the password you chose when you exported it.",
            ));
        }
        Ok(Self {
            inner: Some(ArchiveReader::new(&password)),
            options,
        })
    }

    #[wasm_bindgen(unchecked_return_type = "ExportEntry[]")]
    pub fn push(&mut self, bytes: &[u8]) -> Result<JsValue, JsValue> {
        let inner = self.inner.as_mut().ok_or_else(flow_finished)?;
        entries(inner.push(bytes), &self.options)
    }

    #[wasm_bindgen(unchecked_return_type = "ExportEntry[]")]
    pub fn finish(&mut self) -> Result<JsValue, JsValue> {
        let inner = self.inner.take().ok_or_else(flow_finished)?;
        entries(inner.finish(), &self.options)
    }
}

fn entries(
    entries: octapass_core::Result<Vec<ArchiveEntry>>,
    options: &import::ImportOptions,
) -> Result<JsValue, JsValue> {
    let import_error = |error: import::ImportError| make_error(error.code.code(), error.detail);
    let entries = entries.map_err(|error| import_error(import::archive_error(error)))?;
    let out = js_sys::Array::new();
    for entry in entries {
        let object = js_sys::Object::new();
        let set = |key: &str, value: JsValue| {
            // Setting a property on a fresh object can't fail.
            let _ = js_sys::Reflect::set(&object, &key.into(), &value);
        };
        match entry {
            ArchiveEntry::Items(json) => {
                let result: ImportResult =
                    import::octapass_items_for(&json, true, options).map_err(import_error)?;
                set("kind", "items".into());
                set("result", to_js(&result)?);
            }
            ArchiveEntry::File {
                attachment_id,
                data,
            } => {
                set("kind", "file".into());
                set("fileId", attachment_id.into());
                set("data", js_sys::Uint8Array::from(data.as_slice()).into());
            }
        }
        out.push(&object);
    }
    Ok(out.into())
}

/// Whether a file is an encrypted export (rather than Octa Pass's plaintext JSON).
#[wasm_bindgen(js_name = isEncryptedExport)]
pub fn is_encrypted_export(start: &[u8]) -> bool {
    export::is_archive(start)
}

/// Exports the Octa Pass JSON (`exportJson`'s output) as CXF. `exporterRpId` names the exporting
/// app's domain; `timestamp` is now, in Unix seconds.
#[wasm_bindgen(js_name = exportCxf, unchecked_return_type = "CxfExport")]
pub fn export_cxf(
    json: String,
    #[wasm_bindgen(unchecked_param_type = "CxfAccount")] account: JsValue,
    #[wasm_bindgen(js_name = exporterRpId)] exporter_rp_id: String,
    timestamp: f64,
) -> Result<JsValue, JsValue> {
    let json = zeroize::Zeroizing::new(json);
    let document = ExportDocument::parse(json.as_bytes()).map_err(js_error)?;
    let account = from_js(account, "account")?;
    if !(timestamp >= 0.0 && timestamp.fract() == 0.0) {
        return Err(invalid_argument("timestamp"));
    }
    to_js(&export::cxf::export(
        &document,
        &account,
        &exporter_rp_id,
        timestamp as u64,
    ))
}

/// Points recovery info linked to another imported item at that item's new id: `sourceIds` from
/// the import result, `newIds` the ids the items get, in the same order.
#[wasm_bindgen(js_name = relinkImportedItems, unchecked_return_type = "ItemPlaintext[]")]
pub fn relink_imported_items(
    #[wasm_bindgen(unchecked_param_type = "ItemPlaintext[]")] items: JsValue,
    #[wasm_bindgen(js_name = sourceIds)] source_ids: Vec<String>,
    #[wasm_bindgen(js_name = newIds)] new_ids: Vec<String>,
) -> Result<JsValue, JsValue> {
    let values: Vec<serde_json::Value> = options_from_js(items, "items")?;
    let mut items = values
        .into_iter()
        .map(|value| octapass_core::item::Item::from_json(&value.to_string()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(js_error)?;
    import::relink(&mut items, &source_ids, &new_ids);
    to_js(&items)
}
