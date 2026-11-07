#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::sharing::seal::{SealContext, open_key};
use x25519_dalek::StaticSecret;

// Sealed vault keys reach members through the server.
fuzz_target!(|data: &[u8]| {
    let recipient = StaticSecret::from([7; 32]);
    let context = SealContext::VaultKey {
        vault_id: "0192f0c0-0000-7000-8000-000000000001",
        recipient_account_id: "0192f0c0-0000-7000-8000-000000000002",
    };
    let _ = open_key(&recipient, &context, &String::from_utf8_lossy(data));
});
