#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_relay::smtp::command;

fuzz_target!(|data: &[u8]| {
    let _ = command::parse(data);
});
