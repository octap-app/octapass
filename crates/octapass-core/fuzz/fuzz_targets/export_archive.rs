#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::export::{ArchiveWriter, read_archive};
use octapass_core::kdf::KdfParams;

// Encrypted exports of arbitrary content open back to the same content, and flipping any one
// byte makes them fail rather than misread.

fuzz_target!(|data: &[u8]| {
    let mut rng = rand_core::OsRng;
    let mut writer = ArchiveWriter::new("pw", KdfParams::DEFAULT, &mut rng).unwrap();
    let mut file = writer.add_items(data).unwrap();
    file.extend(writer.add_file("a", data).unwrap());
    file.extend(writer.finish().unwrap());
    let (items, files) = read_archive(&file, "pw").unwrap();
    assert_eq!(items.as_slice(), data);
    assert_eq!(files[0].1.as_slice(), data);
    if !data.is_empty() {
        let at = data[0] as usize * 7 % file.len();
        file[at] ^= 1;
        assert!(read_archive(&file, "pw").is_err());
    }
});
