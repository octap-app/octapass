//! Every integration test file in one binary, so cargo links the crate and its
//! dependencies once instead of once per file. Run one file's tests with
//! `cargo test --test integration <file>::`.

mod age_interop;
mod export;
mod flow;
mod gpg;
mod import;
mod import_2fas;
mod import_aegis;
mod import_andotp;
mod import_authenticator_reimport;
mod import_avira;
mod import_bitwarden_csv;
mod import_dashlane;
mod import_enpass;
mod import_ente;
mod import_kaspersky;
mod import_keepass;
mod import_keeper;
mod import_mcafee;
mod import_nordpass;
mod import_norton;
mod import_octapass_reimport;
mod import_protonpass;
mod import_raivo;
mod import_reimport;
mod import_roboform;
mod import_zoho;
mod qr;
mod ssh;
mod ssh_sign;
mod toolkit_interop;
mod toolkit_jose;

/// A file in `tests/` that is neither a module here nor its own `[[test]]` in Cargo.toml would
/// never run (`autotests = false`), so this fails instead.
#[test]
fn every_test_file_is_built() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let main = std::fs::read_to_string(dir.join("tests/main.rs")).unwrap();
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
    for entry in std::fs::read_dir(dir.join("tests")).unwrap() {
        let path = entry.unwrap().path();
        let (Some(stem), Some("rs")) = (
            path.file_stem().and_then(|s| s.to_str()),
            path.extension().and_then(|s| s.to_str()),
        ) else {
            continue;
        };
        if stem == "main" {
            continue;
        }
        assert!(
            main.contains(&format!("mod {stem};"))
                || manifest.contains(&format!("path = \"tests/{stem}.rs\"")),
            "tests/{stem}.rs isn't built: add `mod {stem};` to tests/main.rs"
        );
    }
}
