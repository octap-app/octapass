#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::tools::qr::{read_image, read_luma, summarize};

// Images chosen, pasted, dropped or captured to read QR codes from: PNG, JPEG, WebP or GIF bytes,
// and raw greyscale pixels.
fuzz_target!(|data: &[u8]| {
    if let Ok(texts) = read_image(data) {
        let _ = summarize(&texts);
    }
    if let [w, h, pixels @ ..] = data {
        let _ = read_luma(u32::from(*w), u32::from(*h), pixels);
    }
});
