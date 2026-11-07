#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::import::{ExistingLogin, ImportOptions, ImportSource, import_file};

// With a password, so encrypted backups reach the decryption code too (the iteration count comes
// from the file, so some runs are slow: keep `-max_len` small or seed the corpus).

fuzz_target!(|data: &[u8]| {
    let options = ImportOptions {
        password: Some("password".to_string().into()),
        existing_logins: vec![ExistingLogin {
            id: "0192f0c0-0000-7000-8000-000000000001".into(),
            title: "GitHub".into(),
            urls: vec!["https://github.com".into()],
            ..ExistingLogin::default()
        }],
        ..ImportOptions::default()
    };
    let _ = import_file(ImportSource::AndOtp, data, &options);
});
