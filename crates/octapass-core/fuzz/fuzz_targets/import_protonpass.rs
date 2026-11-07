#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::import::{ImportOptions, ImportSource, import_file};

// With and without a passphrase, so PGP-encrypted exports reach rPGP too. An S2K count byte of
// 255 hashes 65 MB per try: seed the corpus with protonpass-gpg.pgp, whose count is lower.

fuzz_target!(|data: &[u8]| {
    let _ = import_file(ImportSource::ProtonPass, data, &ImportOptions::default());
    let options = ImportOptions {
        password: Some("correct horse battery staple".to_string().into()),
        ..ImportOptions::default()
    };
    let _ = import_file(ImportSource::ProtonPass, data, &options);
});
