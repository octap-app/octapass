//! Importing other apps' exports. Parsing happens here, on the device; nothing is sent anywhere.

use octapass_core::import::{self, ImportError, ImportOptions, ImportSource};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{from_js, make_error, options_from_js, to_js};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
export type ImportSource =
  | "chrome" | "firefox" | "safari" | "bitwarden-json" | "bitwarden-csv" | "onepassword-1pux" | "onepassword-csv"
  | "lastpass-csv" | "generic-csv" | "otpauth" | "octapass" | "cxf" | "protonpass" | "dashlane"
  | "keeper" | "nordpass" | "keepass" | "enpass" | "roboform" | "aegis" | "2fas" | "andotp" | "ente-auth" | "raivo"
  | "zoho-vault" | "avira" | "norton" | "mcafee" | "kaspersky";
/** Which column (by its header, exactly as in the file) holds each field. Unmapped columns become custom fields. */
export type ColumnMapping = {
  title?: string; url?: string; username?: string; password?: string; totp?: string; notes?: string;
  tags?: string; folder?: string; favorite?: string;
  /** Dates: Unix seconds or milliseconds, or ISO 8601. */
  created?: string; modified?: string; lastUsed?: string; passwordChanged?: string;
  /** The item's id in the app, so importing the file again updates the items. */
  id?: string;
  ignore?: string[];
};
/**
 * A login already in the vault that an authenticator import may add a one-time code to. `totp` is
 * its code, so importing a backup again doesn't add codes the vault already has.
 */
export type ExistingLogin = { id: string; title?: string; urls?: string[]; username?: string; subtitle?: string; hasTotp?: boolean; totp?: string };
export type ImportOptions = {
  /** The password of a password-protected export (Bitwarden, KeePass, Proton Pass, Octa Pass, authenticator backups). */
  password?: string;
  /** A KeePass key file, as unpadded base64url. */
  keyFile?: string;
  /** Generic CSV only. Without it, columns are recognised by name. */
  columns?: ColumnMapping;
  /** Authenticator imports (`otpauth`, Aegis, 2FAS, andOTP, Ente Auth and Raivo) only. */
  existingLogins?: ExistingLogin[];
  /**
   * The items already in the vault. Imported items that match one (by the other app's id in
   * `importedFrom`, or as a duplicate) come back in `updates` instead of `items`. Authenticator
   * backups match codes by the app's id only. Octa Pass exports match by their own item ids first,
   * in every vault, and keep an item that changed in the vault (`updatedAt`) after the export.
   */
  existingItems?: (ItemPlaintext & { id: string; vaultId?: string; updatedAt?: string })[];
  /** The vault the import goes into, when `existingItems` holds every vault's items. Only that vault's are compared, except by id for Octa Pass exports. */
  vaultId?: string;
  /** RFC 3339 now: the date of a replaced password when the file doesn't say when it changed. */
  now?: string;
};
export type ImportResult = {
  items: ItemPlaintext[];
  /** One-time codes for existing logins: set `details.totp` of `itemId` to `totp`. */
  totpUpdates: { itemId: string; totp: string }[];
  /** Short English sentences, never containing secrets. */
  warnings: string[];
  skipped: number;
  /** Octa Pass encrypted exports: attachments to upload once the items are saved. */
  files?: ImportedFile[];
  /** Octa Pass exports: each item's old id, for `relinkImportedItems`. */
  sourceIds?: string[];
  /** Items in `existingItems` that the file changes: save `item` as the new version of `itemId`. */
  updates?: { itemId: string; item: ItemPlaintext }[];
  /** Items in `existingItems` exactly as the file has them (Octa Pass exports: or changed in the vault since). */
  unchanged?: number;
  /** Octa Pass encrypted exports: files for items in `existingItems` that don't have them. */
  existingFiles?: ExistingFile[];
  /** Authenticator imports: every one-time code, for the import review and `linkImportedCodes`. */
  codes?: ImportedCode[];
};
/** A one-time code from an authenticator import: a new login (`item`, an index into `items`) or a code for an existing login (`update`, an index into `totpUpdates`). */
export type ImportedCode = { item?: number; update?: number; title: string; issuer?: string; account?: string };
/** The review's choice for `codes[code]`: add it to the login `loginId`, or keep it as a login of its own (`loginId` left out). */
export type CodeLink = { code: number; loginId?: string };
export type CsvPreview = { headers: string[]; rows: string[][]; rowCount: number; suggested: ColumnMapping; delimiter: string };
"#;

/// Parses an export file into items. Throws `invalid_import_file` (with a sentence for the user
/// as the message) when the file isn't in the chosen format, `import_password_required` /
/// `wrong_import_password` for password-protected exports.
#[wasm_bindgen(js_name = importFile, unchecked_return_type = "ImportResult")]
pub fn import_file(
    #[wasm_bindgen(unchecked_param_type = "ImportSource")] source: JsValue,
    bytes: Vec<u8>,
    #[wasm_bindgen(unchecked_param_type = "ImportOptions | undefined")] options: JsValue,
) -> Result<JsValue, JsValue> {
    let bytes = Zeroizing::new(bytes);
    let source: ImportSource = from_js(source, "import source")?;
    let options: ImportOptions = options_from_js(options, "import options")?;
    to_js(&import::import_file(source, &bytes, &options).map_err(import_error)?)
}

/// Applies the import review's choices to an authenticator import: each listed code joins the
/// chosen login, or becomes a login of its own. Codes not listed stay as they are.
#[wasm_bindgen(js_name = linkImportedCodes, unchecked_return_type = "ImportResult")]
pub fn link_imported_codes(
    #[wasm_bindgen(unchecked_param_type = "ImportResult")] result: JsValue,
    #[wasm_bindgen(unchecked_param_type = "CodeLink[]")] links: JsValue,
) -> Result<JsValue, JsValue> {
    let result: import::ImportResult = from_js(result, "import result")?;
    let links: Vec<import::CodeLink> = from_js(links, "code links")?;
    to_js(&import::link_codes(result, &links))
}

/// Headers, the first rows and a suggested column mapping, for the generic CSV mapping screen.
#[wasm_bindgen(js_name = previewCsv, unchecked_return_type = "CsvPreview")]
pub fn preview_csv(bytes: Vec<u8>) -> Result<JsValue, JsValue> {
    let bytes = Zeroizing::new(bytes);
    to_js(&import::preview_csv(&bytes).map_err(import_error)?)
}

fn import_error(error: ImportError) -> JsValue {
    make_error(error.code.code(), error.detail)
}
