//! Every integration test file in one binary, so cargo links the crate and its
//! dependencies once instead of once per file. Run one file's tests with
//! `cargo test --test integration <file>::`.

mod common;

mod abuse;
mod account_deletion;
mod api;
mod attachments;
mod batch;
mod breach_email;
mod devices;
mod emergency;
mod families;
mod icons;
mod item_history;
mod key_rotation;
mod live;
mod masked_email;
mod orgs;
mod password;
mod quotas;
mod security;
mod security_log;
mod self_hosting;
mod service_accounts;
mod share_links;
mod sharing;
mod sso;
mod transparency;
mod two_step;

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
