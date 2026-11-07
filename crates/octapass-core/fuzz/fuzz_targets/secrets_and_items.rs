#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::item::Item;
use octapass_core::recovery::RecoveryCode;
use octapass_core::secret_key::SecretKey;

// What people type or paste (Secret Key, recovery code), and decrypted item JSON from any client.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = SecretKey::parse(&text);
    let _ = RecoveryCode::parse(&text);
    let _ = Item::from_json(&text);
});
