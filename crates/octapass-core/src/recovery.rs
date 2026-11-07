//! The recovery code: 256 random bits that can unwrap the account key (ASK) if the master
//! password or Secret Key is lost.
//!
//! Text form: the 32 bytes followed by a 2-byte checksum
//! (`SHA-256("octapass/v1/recovery-check" ‖ bytes)[0..2]`), as 55 Crockford base32 characters in
//! 11 groups of 5. The checksum catches typos before the user is told the code is wrong.

use core::fmt;

use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encoding::{crockford_decode, crockford_encode, group, strip_separators};
use crate::error::{Error, Result};
use crate::keys::{SymmetricKey, hkdf_key};

pub const RECOVERY_CODE_LEN: usize = 32;
const CHECKSUM_LEN: usize = 2;
const GROUPS: [usize; 11] = [5; 11];

#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct RecoveryCode([u8; RECOVERY_CODE_LEN]);

impl RecoveryCode {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; RECOVERY_CODE_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; RECOVERY_CODE_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RECOVERY_CODE_LEN] {
        &self.0
    }

    pub fn parse(text: &str) -> Result<Self> {
        let compact = Zeroizing::new(strip_separators(text));
        let bytes = Zeroizing::new(
            crockford_decode(&compact, RECOVERY_CODE_LEN + CHECKSUM_LEN)
                .ok_or(Error::InvalidRecoveryCode)?,
        );
        let (code, checksum) = bytes.split_at(RECOVERY_CODE_LEN);
        let mut out = [0u8; RECOVERY_CODE_LEN];
        out.copy_from_slice(code);
        let code = Self(out);
        if checksum != code.checksum() {
            return Err(Error::InvalidRecoveryCode);
        }
        Ok(code)
    }

    pub fn to_text(&self) -> Zeroizing<String> {
        let mut bytes = Zeroizing::new(self.0.to_vec());
        bytes.extend_from_slice(&self.checksum());
        let body = Zeroizing::new(crockford_encode(&bytes));
        Zeroizing::new(group(&body, &GROUPS))
    }

    /// `HKDF-SHA256(ikm = code, salt = "", info = "octapass/v1/recovery")`: wraps the ASK as
    /// `recoveryWrappedAsk`.
    pub fn wrapping_key(&self) -> SymmetricKey {
        hkdf_key(&self.0, b"", b"octapass/v1/recovery")
    }

    fn checksum(&self) -> [u8; CHECKSUM_LEN] {
        let digest = Sha256::new()
            .chain_update(b"octapass/v1/recovery-check")
            .chain_update(self.0)
            .finalize();
        [digest[0], digest[1]]
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn format_is_eleven_groups_of_five() {
        let text = RecoveryCode::from_bytes([0x42; 32]).to_text();
        let groups: Vec<&str> = text.split('-').collect();
        assert_eq!(groups.len(), 11);
        assert!(groups.iter().all(|g| g.len() == 5));
    }

    #[test]
    fn typos_are_caught_by_the_checksum() {
        let code = RecoveryCode::from_bytes([0x42; 32]);
        let text = code.to_text();
        let mut typo: Vec<char> = text.chars().collect();
        typo[3] = if typo[3] == 'A' { 'B' } else { 'A' };
        let typo: String = typo.into_iter().collect();
        assert_eq!(
            RecoveryCode::parse(&typo).unwrap_err(),
            Error::InvalidRecoveryCode
        );
        assert_eq!(
            RecoveryCode::parse("").unwrap_err(),
            Error::InvalidRecoveryCode
        );
    }

    proptest! {
        #[test]
        fn round_trip(bytes in any::<[u8; 32]>()) {
            let code = RecoveryCode::from_bytes(bytes);
            let text = code.to_text();
            prop_assert_eq!(RecoveryCode::parse(&text.to_lowercase().replace('-', " ")).unwrap(), code);
        }
    }
}
