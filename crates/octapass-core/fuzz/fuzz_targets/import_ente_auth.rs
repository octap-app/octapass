#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::import::{ExistingLogin, ImportOptions, ImportSource, import_file};

// With a password, so encrypted backups reach the Argon2 and secretstream path (keep the file's
// memLimit small when seeding).

fuzz_target!(|data: &[u8]| {
    let options = ImportOptions {
        password: Some("password".to_string().into()),
        existing_logins: vec![ExistingLogin {
            id: "0192f0c0-0000-7000-8000-000000000001".into(),
            title: "GitHub".into(),
            urls: vec!["https://github.com".into()],
            totp: Some("otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP".into()),
            ..ExistingLogin::default()
        }],
        ..ImportOptions::default()
    };
    let _ = import_file(ImportSource::EnteAuth, data, &options);
});
