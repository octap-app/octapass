//! The package manifest and the code name the same COM class and start-up argument. If they drift,
//! Windows activates nothing and says nothing.

use octapass_windows_passkey::{ACTIVATION_ARGUMENT, PROVIDER_CLSID, PROVIDER_CLSID_TEXT};

fn manifest() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../windows/AppxManifest.xml"
    );
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn the_manifest_declares_the_providers_com_class() {
    let manifest = manifest();
    assert!(manifest.contains(&format!(r#"<com:Class Id="{PROVIDER_CLSID_TEXT}""#)));
    assert!(manifest.contains(&format!(r#"Arguments="{ACTIVATION_ARGUMENT}""#)));
    assert!(manifest.contains(r#"Category="windows.comServer""#));
}

#[test]
fn the_clsid_text_is_the_constant() {
    let text = PROVIDER_CLSID_TEXT.replace('-', "");
    assert_eq!(u128::from_str_radix(&text, 16), Ok(PROVIDER_CLSID));
}
