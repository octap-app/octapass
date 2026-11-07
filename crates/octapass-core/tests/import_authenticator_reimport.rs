//! Importing an authenticator backup again (Aegis, 2FAS, andOTP, Ente Auth, Raivo, `otpauth://`
//! lists): codes already in the vault are recognised, by the app's id or by their secret, instead
//! of being added twice; a code whose entry changed updates its login.

use std::path::PathBuf;

use octapass_core::import::{
    CodeLink, ExistingItem, ExistingLogin, ImportOptions, ImportResult, ImportSource, import_file,
    link_codes,
};
use octapass_core::item::{Item, ItemDetails};
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery staple";
const GITHUB: &str = "0192f0c0-0000-7000-8000-000000000001";

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "import-fixtures", name]
        .iter()
        .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A vault: items with ids, as the clients pass them in `existingItems` and `existingLogins`.
#[derive(Clone)]
struct Vault(Vec<(String, Item)>);

impl Vault {
    /// The GitHub login the fixtures' first code matches, without a code yet.
    fn new() -> Self {
        let github: Item = serde_json::from_value(serde_json::json!({
            "overview": { "title": "Code host", "type": "login", "urls": ["https://github.com"], "subtitle": "octo" },
            "details": { "username": "octo", "password": "hunter2" }
        }))
        .unwrap();
        Vault(vec![(GITHUB.into(), github)])
    }

    fn options(&self) -> ImportOptions {
        ImportOptions {
            password: Some(Zeroizing::new(PASSWORD.into())),
            existing_logins: self
                .0
                .iter()
                .filter_map(|(id, item)| {
                    let ItemDetails::Login(login) = &item.details else {
                        return None;
                    };
                    Some(ExistingLogin {
                        id: id.clone(),
                        title: item.overview.title.clone(),
                        urls: item.overview.urls.clone().unwrap_or_default(),
                        username: login.username.clone(),
                        has_totp: login.totp.is_some(),
                        totp: login.totp.clone(),
                        ..ExistingLogin::default()
                    })
                })
                .collect(),
            existing_items: self
                .0
                .iter()
                .map(|(id, item)| {
                    let value = serde_json::to_value(item).unwrap();
                    ExistingItem {
                        id: id.clone(),
                        overview: serde_json::from_value(value["overview"].clone()).unwrap(),
                        details: value["details"].clone(),
                        vault_id: None,
                        updated_at: None,
                    }
                })
                .collect(),
            now: Some("2026-10-25T12:00:00Z".into()),
            ..ImportOptions::default()
        }
    }

    /// Saves an import as the clients do after the review (with no changes to its choices).
    fn save(&mut self, result: ImportResult) {
        let result = link_codes(result, &[] as &[CodeLink]);
        for (at, item) in result.items.into_iter().enumerate() {
            self.0.push((format!("new-{}-{at}", self.0.len()), item));
        }
        for update in result.updates {
            let slot = self
                .0
                .iter_mut()
                .find(|(id, _)| *id == update.item_id)
                .unwrap();
            slot.1 = update.item;
        }
        for update in result.totp_updates {
            let slot = self
                .0
                .iter_mut()
                .find(|(id, _)| *id == update.item_id)
                .unwrap();
            let ItemDetails::Login(login) = &mut slot.1.details else {
                panic!()
            };
            login.totp = Some(update.totp);
        }
    }
}

fn import(source: ImportSource, bytes: &[u8], vault: &Vault) -> ImportResult {
    import_file(source, bytes, &vault.options()).unwrap_or_else(|e| panic!("{source:?}: {e}"))
}

/// The first import adds codes (one joins the GitHub login, when the file has GitHub's code);
/// the same file again adds nothing.
fn check(source: ImportSource, name: &str) {
    let bytes = fixture(name);
    let mut vault = Vault::new();
    let first = import(source, &bytes, &vault);
    let joins = usize::from(name != "otpauth.txt");
    assert_eq!(
        first.totp_updates.len(),
        joins,
        "{name}: GitHub joins the login"
    );
    assert!(!first.items.is_empty(), "{name}");
    let codes = first.codes.len();
    vault.save(first);
    let size = vault.0.len();

    let again = import(source, &bytes, &vault);
    assert!(
        again.items.is_empty() && again.updates.is_empty() && again.totp_updates.is_empty(),
        "{name}: added {:?}, changed {:?}",
        again
            .items
            .iter()
            .map(|i| &i.overview.title)
            .collect::<Vec<_>>(),
        again.updates.iter().map(|u| &u.item_id).collect::<Vec<_>>()
    );
    assert!(again.codes.is_empty(), "{name}: nothing left to review");
    assert!(
        again.unchanged >= codes,
        "{name}: {} unchanged of {codes}",
        again.unchanged
    );
    vault.save(again);
    assert_eq!(vault.0.len(), size, "{name}");
}

#[test]
fn every_authenticator_backup_imported_twice() {
    for (source, name) in [
        (ImportSource::Aegis, "aegis.json"),
        (ImportSource::Aegis, "aegis-encrypted.json"),
        (ImportSource::TwoFas, "2fas.2fas"),
        (ImportSource::AndOtp, "andotp.json"),
        (ImportSource::EnteAuth, "ente-auth.txt"),
        (ImportSource::EnteAuth, "ente-auth-encrypted.json"),
        (ImportSource::Raivo, "raivo.json"),
        (ImportSource::Raivo, "raivo-aes256.zip"),
        (ImportSource::OtpAuth, "otpauth.txt"),
    ] {
        check(source, name);
    }
}

/// Aegis entries keep their `uuid`: a changed entry updates the login it became, keeping what
/// was added in Octa Pass since (here a password), and a new entry with an old secret is still
/// the same code.
#[test]
fn aegis_entries_update_by_uuid() {
    let text = String::from_utf8(fixture("aegis.json")).unwrap();
    let mut vault = Vault::new();
    let first = import(ImportSource::Aegis, text.as_bytes(), &vault);
    let bank = first
        .items
        .iter()
        .find(|i| i.overview.title == "بنك الأمل")
        .unwrap();
    let from = bank.overview.imported_from.as_ref().unwrap();
    assert_eq!(from.source, "aegis");
    vault.save(first);
    let (bank_id, bank) = vault
        .0
        .iter_mut()
        .find(|(_, i)| i.overview.title == "بنك الأمل")
        .unwrap();
    let bank_id = bank_id.clone();
    let ItemDetails::Login(login) = &mut bank.details else {
        panic!()
    };
    login.password = Some("added later".into());

    let changed = text.replace("ملاحظة بالعربية", "ملاحظة جديدة");
    assert_ne!(changed, text);
    let again = import(ImportSource::Aegis, changed.as_bytes(), &vault);
    assert!(again.items.is_empty(), "{:?}", again.items);
    assert_eq!(again.updates.len(), 1);
    assert_eq!(again.updates[0].item_id, bank_id);
    let ItemDetails::Login(login) = &again.updates[0].item.details else {
        panic!()
    };
    assert_eq!(login.notes.as_deref(), Some("ملاحظة جديدة\nسطر ثاني"));
    assert_eq!(login.password.as_deref(), Some("added later"));
}

/// A code already on a login in another vault (only in `existingLogins`, which has each login's
/// one-time code) isn't added again, counter-based ones included.
#[test]
fn codes_in_other_vaults_count_too() {
    let mut vault = Vault::new();
    vault.save(import(ImportSource::Raivo, &fixture("raivo.json"), &vault));
    let mut options = vault.options();
    options.existing_items.clear();
    let again = import_file(ImportSource::Raivo, &fixture("raivo.json"), &options).unwrap();
    assert!(again.totp_updates.is_empty());
    assert!(again.items.is_empty(), "{:?}", again.items.len());
}
