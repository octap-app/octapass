//! Helpers for the Pwned Passwords k-anonymity range API.
//!
//! Only the first 5 hex characters of the password's SHA-1 leave the device. The response lists
//! every known suffix for that prefix (`SUFFIX:COUNT` per line, with padding entries of count 0),
//! and the match happens locally.

use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

/// The SHA-1 of a password, split for the range API. Upper-case hex, as the API returns it.
pub struct Sha1Range {
    /// The 5 characters sent to the API.
    pub prefix: String,
    /// The 35 characters looked up locally in the response.
    pub suffix: Zeroizing<String>,
}

pub fn sha1_range(password: &str) -> Sha1Range {
    let digest = Sha1::digest(password.as_bytes());
    let hex = Zeroizing::new(
        digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>(),
    );
    Sha1Range {
        prefix: hex[..5].to_string(),
        suffix: Zeroizing::new(hex[5..].to_string()),
    }
}

/// How often `suffix` appears in a range API response body; 0 if it doesn't.
pub fn count_in_range(suffix: &str, response: &str) -> u64 {
    response
        .lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(suffix))
        .and_then(|(_, count)| count.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_sha1() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let range = sha1_range("password");
        assert_eq!(range.prefix, "5BAA6");
        assert_eq!(range.suffix.as_str(), "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn counts_matches() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:10\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n";
        assert_eq!(
            count_in_range("1e4c9b93f3f0682250b6cf8331b7ee68fd8", body),
            9_545_824
        );
        assert_eq!(
            count_in_range("0000000000000000000000000000000000A", body),
            0
        );
        assert_eq!(
            count_in_range("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", body),
            0,
            "padding"
        );
    }
}
