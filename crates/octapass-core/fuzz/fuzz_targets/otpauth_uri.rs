#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::tools::otpauth::{OtpParams, parse_migration};
use octapass_core::tools::qr::summarize;

// otpauth:// links and Google Authenticator export QR codes, as scanned or pasted.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = OtpParams::parse(&text);
    let _ = parse_migration(&text);
    let _ = summarize(&text.split('\n').collect::<Vec<_>>());
});
