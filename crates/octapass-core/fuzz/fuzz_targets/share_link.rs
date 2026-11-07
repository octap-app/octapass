#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::sharing::share_link;

// A share link's ciphertext comes from a server, and its key from a URL fragment anyone can edit.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (ciphertext, key) = text.split_once('#').unwrap_or((&text, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    let _ = share_link::needs_passphrase(ciphertext);
    // Without a passphrase, so a well-formed link with one fails fast instead of running Argon2id.
    let _ = share_link::open(ciphertext, key, None);
});
