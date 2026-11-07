#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_core::local::{BackupSecret, DeviceProtection, LocalVault, keys::LOCAL_KDF};
use rand_core::OsRng;

// Opening with a recovery code parses the header and the sealed key without running Argon2id.
const CODE: &str = "000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FTJH8";

fuzz_target!(|data: &[u8]| {
    let protection = DeviceProtection {
        kdf: LOCAL_KDF,
        hardware_secret: Some(&[0; 32]),
    };
    let _ = LocalVault::restore_backup(data, BackupSecret::RecoveryCode(CODE), "password", protection, &mut OsRng);
});
