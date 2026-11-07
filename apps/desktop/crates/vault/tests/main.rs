//! Every integration test file in one binary, so cargo links the crate and its
//! dependencies once instead of once per file. Run one file's tests with
//! `cargo test --test integration <file>::`.

mod common;

mod attachments;
mod autofill;
mod flow;
mod import;
mod local;
mod master_password;
mod shared_vaults;
mod sharing;
mod ssh_agent;
mod sso;
mod stay_unlocked;
mod tools;
mod two_step;
mod versions;
mod windows_passkey;

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
