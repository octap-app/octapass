#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::import::{ImportOptions, ImportSource, import_file};

// KDBX databases, the XML export and the CSV exports. With a password, so databases reach the
// key derivation and decryption (KDF settings up to the importer's caps can make a run slow:
// seed the corpus with the tiny-KDF fixtures from tests/import-fixtures).

fuzz_target!(|data: &[u8]| {
    let options = ImportOptions {
        password: Some("password".to_string().into()),
        ..ImportOptions::default()
    };
    let _ = import_file(ImportSource::KeePass, data, &options);
});
