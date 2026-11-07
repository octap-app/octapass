#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use octapass_relay::smtp::read_data;
use tokio::io::BufReader;

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let mut reader = BufReader::new(data);
    let _ = runtime.block_on(read_data(&mut reader, 4096, Duration::from_secs(1)));
});
