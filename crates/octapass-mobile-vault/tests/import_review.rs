//! The import review and QR codes, against the real sync server over HTTP: one-time codes parsed
//! and kept in memory until the user links them to logins, the review forgotten when it's
//! finished, cancelled, or the vault locks; and QR codes read from a photo the (fake) photo
//! library picks, whose copy is deleted at once.

use std::io::Cursor;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use image::{GrayImage, ImageFormat, Luma};
use octapass_core::import::{CodeLink, ImportOptions, ImportSource};
use octapass_ffi::DeviceInfo;
use octapass_mobile_vault::model::{Item, ItemDraft};
use octapass_mobile_vault::native::fake::FakeNative;
use octapass_mobile_vault::vault::{read_qr_codes, summarize_qr_scans};
use octapass_mobile_vault::{Config, ErrorCode, Vault};
use qrcode::{Color, QrCode};
use serde_json::json;
use tempfile::TempDir;
use zeroize::Zeroizing;

const EMAIL: &str = "ada@example.com";
const PASSWORD: &str = "correct horse battery staple";
const GITHUB: &str =
    "otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
const MAIL: &str = "otpauth://totp/Mail:alice?secret=KRSXG5CTMVRXEZLU&issuer=Mail";

/// The secret of the `totp` field: the importer writes the link out in full.
fn totp_secret(item: &Item) -> Option<String> {
    let link = item.details.get("totp")?.as_str()?;
    let query = link.split_once('?')?.1;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("secret="))
        .map(str::to_owned)
}

struct Server {
    url: String,
    _data: TempDir,
    _runtime: tokio::runtime::Runtime,
}

impl Server {
    fn start() -> Self {
        let data = tempfile::tempdir().unwrap();
        let data_dir = data.path().to_str().unwrap().to_owned();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let url = runtime.block_on(async {
            let config = octapass_server::Config::from_lookup(|name| match name {
                "OCTAPASS_DATA_DIR" => Some(data_dir.clone()),
                "OCTAPASS_DEV_MODE" => Some("true".into()),
                "OCTAPASS_RATE_LIMITS" => Some("off".into()),
                _ => None,
            })
            .unwrap();
            let state = octapass_server::AppState::new(config).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let app =
                octapass_server::router(state).into_make_service_with_connect_info::<SocketAddr>();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            url
        });
        Self {
            url,
            _data: data,
            _runtime: runtime,
        }
    }
}

struct Phone {
    vault: Arc<Vault>,
    native: Arc<FakeNative>,
    dir: TempDir,
}

impl Phone {
    /// A phone signed up to `server`, unlocked.
    fn signed_up(server: &Server) -> Self {
        let native = Arc::new(FakeNative::default());
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(
            Config {
                data_dir: dir.path().join("group"),
                temp_dir: dir.path().join("tmp"),
                device: DeviceInfo {
                    name: "Test iPhone".into(),
                    platform: "ios".into(),
                },
                pwned_passwords_url: server.url.clone(),
            },
            native.clone(),
            Box::new(|_| {}),
        )
        .unwrap();
        let started = vault
            .start_signup(&server.url, EMAIL, secret(PASSWORD))
            .unwrap();
        let code = started.dev_verification_code.unwrap();
        vault.finish_signup(&started.signup_id, &code).unwrap();
        Self { vault, native, dir }
    }

    fn personal(&self) -> String {
        self.vault.list_vaults().unwrap()[0].id.clone()
    }

    fn login(&self, title: &str, username: &str, url: &str) -> Item {
        self.vault
            .save_item(ItemDraft {
                id: None,
                vault_id: self.personal(),
                revision: None,
                overview: json!({ "schemaVersion": 1, "type": "login", "title": title, "urls": [url] }),
                details: json!({ "schemaVersion": 1, "username": username, "password": "pw" }),
            })
            .unwrap()
    }

    fn review(&self, links: &[&str]) -> octapass_mobile_vault::vault::ImportReview {
        self.vault
            .review_import(
                ImportSource::OtpAuth,
                links.join("\n").as_bytes(),
                ImportOptions::default(),
                &self.personal(),
            )
            .unwrap()
    }

    fn item(&self, title: &str) -> Item {
        self.vault
            .live_items()
            .unwrap()
            .into_iter()
            .find(|item| item.title() == title)
            .unwrap_or_else(|| panic!("no item {title}"))
    }

    fn picked_folder_empty(&self) -> bool {
        empty(&self.dir.path().join("tmp").join("picked"))
    }
}

fn secret(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

fn empty(path: &Path) -> bool {
    std::fs::read_dir(path).map_or(true, |mut entries| entries.next().is_none())
}

fn png(image: &GrayImage) -> Vec<u8> {
    let mut png = Vec::new();
    image
        .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
        .unwrap();
    png
}

/// A PNG of `text` as a QR code, 6 pixels per module with a quiet zone.
fn qr_png(text: &str) -> Vec<u8> {
    let code = QrCode::new(text.as_bytes()).unwrap();
    let width = code.width() as u32;
    let colors = code.to_colors();
    let image = GrayImage::from_fn((width + 8) * 6, (width + 8) * 6, |x, y| {
        let (mx, my) = ((x / 6) as i64 - 4, (y / 6) as i64 - 4);
        let dark = (0..width as i64).contains(&mx)
            && (0..width as i64).contains(&my)
            && colors[(my as u32 * width + mx as u32) as usize] == Color::Dark;
        Luma([if dark { 0 } else { 255 }])
    });
    png(&image)
}

#[test]
fn a_review_saves_nothing_until_the_user_links_the_codes() {
    let server = Server::start();
    let phone = Phone::signed_up(&server);
    let github = phone.login("GitHub", "alice@example.com", "https://github.com");
    let work = phone.login("Work mail", "alice", "https://mail.example.com");

    let review = phone.review(&[GITHUB, MAIL]);
    let codes: Vec<(usize, &str, Option<&str>)> = review
        .codes
        .iter()
        .map(|code| (code.index, code.title.as_str(), code.login_id.as_deref()))
        .collect();
    assert_eq!(
        codes,
        [(0, "GitHub", Some(github.id.as_str())), (1, "Mail", None)]
    );
    assert_eq!(review.codes[1].account.as_deref(), Some("alice"));
    assert_eq!((review.other_items, review.skipped), (0, 0));
    // Never a secret in what the web view gets.
    let sent = serde_json::to_string(&review).unwrap();
    assert!(
        !sent.contains("JBSWY3DP") && !sent.contains("otpauth"),
        "{sent}"
    );
    assert!(sent.contains("\"loginId\"") && sent.contains("\"otherItems\""));
    assert_eq!(
        phone.vault.live_items().unwrap().len(),
        2,
        "nothing saved yet"
    );
    assert!(phone.item("GitHub").details.get("totp").is_none());

    // GitHub's code stays where the importer put it; Mail's joins the work login.
    let summary = phone
        .vault
        .finish_import(
            &review.id,
            &[CodeLink {
                code: 1,
                login_id: Some(work.id.clone()),
            }],
        )
        .unwrap();
    assert_eq!((summary.imported, summary.skipped), (2, 0));
    let items = phone.vault.live_items().unwrap();
    assert_eq!(items.len(), 2, "no new logins");
    assert_eq!(
        totp_secret(&phone.item("GitHub")).as_deref(),
        Some("JBSWY3DPEHPK3PXP")
    );
    assert_eq!(
        totp_secret(&phone.item("Work mail")).as_deref(),
        Some("KRSXG5CTMVRXEZLU")
    );
    assert_eq!(phone.item("Work mail").details["password"], "pw");

    phone.vault.sync().unwrap();
}

#[test]
fn a_code_unlinked_in_the_review_becomes_a_login_of_its_own() {
    let server = Server::start();
    let phone = Phone::signed_up(&server);
    phone.login("GitHub", "alice@example.com", "https://github.com");
    let review = phone.review(&[GITHUB]);
    assert!(review.codes[0].login_id.is_some());
    let summary = phone
        .vault
        .finish_import(
            &review.id,
            &[CodeLink {
                code: 0,
                login_id: None,
            }],
        )
        .unwrap();
    assert_eq!(summary.imported, 1);
    let items = phone.vault.live_items().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().any(
        |item| totp_secret(item).as_deref() == Some("JBSWY3DPEHPK3PXP")
            && item.details.get("password").is_none()
    ));
    assert!(
        items
            .iter()
            .any(|item| item.details.get("totp").is_none() && item.details["password"] == "pw")
    );
}

#[test]
fn reviews_are_forgotten_once_finished_or_cancelled_and_on_lock() {
    let server = Server::start();
    let phone = Phone::signed_up(&server);
    let expired = |id: &str| {
        phone
            .vault
            .finish_import(id, &[])
            .map(|_| ())
            .unwrap_err()
            .code
    };

    let review = phone.review(&[MAIL]);
    phone.vault.finish_import(&review.id, &[]).unwrap();
    assert_eq!(expired(&review.id), ErrorCode::ImportReviewExpired);
    assert_eq!(phone.vault.live_items().unwrap().len(), 1, "saved once");

    let review = phone.review(&[GITHUB]);
    phone.vault.cancel_import(&review.id);
    phone.vault.cancel_import(&review.id);
    assert_eq!(expired(&review.id), ErrorCode::ImportReviewExpired);

    let review = phone.review(&[GITHUB]);
    phone.vault.lock();
    assert_eq!(expired(&review.id), ErrorCode::Locked);
    phone.vault.unlock(secret(PASSWORD)).unwrap();
    assert_eq!(expired(&review.id), ErrorCode::ImportReviewExpired);
    assert_eq!(
        phone.vault.live_items().unwrap().len(),
        1,
        "nothing else saved"
    );

    phone.vault.lock();
    let locked = phone
        .vault
        .review_import(
            ImportSource::OtpAuth,
            GITHUB.as_bytes(),
            ImportOptions::default(),
            "vault",
        )
        .unwrap_err();
    assert_eq!(locked.code, ErrorCode::Locked);
}

#[test]
fn a_file_that_isnt_an_authenticator_export_is_refused_before_the_review() {
    let server = Server::start();
    let phone = Phone::signed_up(&server);
    let error = phone
        .vault
        .review_import(
            ImportSource::Aegis,
            b"not a backup",
            ImportOptions::default(),
            &phone.personal(),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidImportFile);
}

#[test]
fn qr_codes_from_a_picked_photo() {
    let server = Server::start();
    let phone = Phone::signed_up(&server);
    let pick = |name: &str, media_type: &str, contents: Vec<u8>| {
        phone
            .native
            .picks
            .lock()
            .unwrap()
            .push((name.into(), media_type.into(), contents));
    };

    pick("QR code.png", "image/png", qr_png(GITHUB));
    assert_eq!(
        phone.vault.scan_qr_photo().unwrap(),
        Some(vec![GITHUB.to_owned()])
    );
    assert!(phone.picked_folder_empty(), "the photo's copy is deleted");

    // A photo without a QR code, a file that isn't an image, and the picker closed.
    pick(
        "QR code.png",
        "image/png",
        png(&GrayImage::from_pixel(64, 48, Luma([200]))),
    );
    assert_eq!(phone.vault.scan_qr_photo().unwrap(), Some(vec![]));
    assert!(phone.picked_folder_empty());
    pick("QR code.jpg", "image/jpeg", b"not a photo".to_vec());
    assert_eq!(
        phone.vault.scan_qr_photo().unwrap_err().code,
        ErrorCode::InvalidImage
    );
    assert!(phone.picked_folder_empty());
    assert_eq!(phone.vault.scan_qr_photo().unwrap(), None);
    assert!(phone.picked_folder_empty());

    phone.vault.lock();
    assert_eq!(
        phone.vault.scan_qr_photo().unwrap_err().code,
        ErrorCode::Locked
    );
}

#[test]
fn qr_codes_from_the_web_view_and_what_they_hold() {
    assert_eq!(read_qr_codes(&qr_png(MAIL)).unwrap(), [MAIL]);
    assert_eq!(
        read_qr_codes(b"GIF89a, but not really").unwrap_err().code,
        ErrorCode::InvalidImage
    );
    let scan = summarize_qr_scans(&[MAIL, "WIFI:S:Home;;"]);
    let json = serde_json::to_value(&scan).unwrap();
    assert_eq!(json["codes"][0]["issuer"], "Mail");
    assert_eq!(json["codes"][0]["counterBased"], false);
    assert_eq!(json["other"], 1);
}
