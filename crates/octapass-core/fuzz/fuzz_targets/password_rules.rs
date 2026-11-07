#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::rules::{generate_for_rules, parse};
use octapass_core::tools::generator::RandomOptions;
use rand_core::OsRng;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let rules = parse(text);
    let _ = generate_for_rules(&rules, &RandomOptions::default(), &mut OsRng);
});
