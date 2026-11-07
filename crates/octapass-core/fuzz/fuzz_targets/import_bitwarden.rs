#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::import::{ImportOptions, ImportSource, import_file};

// With a password, so encrypted exports reach the decryption code too (with the cheapest
// accepted KDF settings, a run still takes a while: keep `-max_len` small or seed the corpus).

fuzz_target!(|data: &[u8]| {
    let options = ImportOptions {
        password: Some("password".to_string().into()),
        ..ImportOptions::default()
    };
    let _ = import_file(ImportSource::BitwardenJson, data, &options);
});
