#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::import::{ImportOptions, ImportSource, import_file};

// The plaintext JSON, and with the `OPEX` magic the encrypted export's header checks (the KDF
// parameters are validated before Argon2id runs, so most inputs stop there).

fuzz_target!(|data: &[u8]| {
    let options = ImportOptions {
        password: Some("password".to_string().into()),
        ..ImportOptions::default()
    };
    let _ = import_file(ImportSource::OctaPass, data, &options);
});
