#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_relay::dsn;

fuzz_target!(|data: &[u8]| {
    let _ = dsn::classify(data);
    let _ = dsn::reported_return_path(data, "relay.example");
});
