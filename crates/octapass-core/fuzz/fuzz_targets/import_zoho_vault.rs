#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::import::{ImportOptions, ImportSource, import_file};

fuzz_target!(|data: &[u8]| {
    let _ = import_file(ImportSource::ZohoVault, data, &ImportOptions::default());
});
