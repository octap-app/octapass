#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use octapass_core::passkey::{Caller, ClientData, CreationOptions, PasskeyRecord, RequestOptions, create, get};
use rand_core::OsRng;

// WebAuthn options come from the page (or the app asking the phone's credential provider).
const VALID: &str = r#"{"rp":{"id":"example.com","name":"Example"},"user":{"id":"dXNlcg","name":"maya","displayName":"Maya"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-7}]}"#;

fn record() -> &'static PasskeyRecord {
    static RECORD: OnceLock<PasskeyRecord> = OnceLock::new();
    RECORD.get_or_init(|| {
        let options: CreationOptions = serde_json::from_str(VALID).unwrap();
        create(&options, &client(0), 0, &mut OsRng).unwrap().record
    })
}

fn client(selector: u8) -> ClientData {
    match selector % 3 {
        0 => ClientData::Web(Caller { origin: "https://example.com".into(), top_origin: None, frame_allowed: false }),
        1 => ClientData::Web(Caller {
            origin: "https://login.example.net".into(),
            top_origin: Some("https://example.com".into()),
            frame_allowed: true,
        }),
        _ => ClientData::Hash([9; 32]),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, json)) = data.split_first() else { return };
    let client = client(selector);
    if let Ok(options) = serde_json::from_slice::<CreationOptions>(json) {
        let _ = create(&options, &client, 0, &mut OsRng);
    }
    if let Ok(options) = serde_json::from_slice::<RequestOptions>(json) {
        let _ = get(&options, &client, record());
    }
});
