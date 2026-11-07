//! UniFFI bindings of `octapass-core` for the iOS and Android apps and, above all, their autofill
//! extensions (iOS AutoFill Credential Provider, Android Autofill and Credential Manager
//! services), which must unlock and fill from a small native process.
//!
//! - [`OctaPassServer`]: sign-up, login (with two-step sign-in), refresh, reauth, two-step
//!   settings, account deletion and sync, over an [`HttpClient`] the app implements with
//!   `URLSession` or OkHttp.
//! - [`LocalStore`]: the encrypted local store the app and its extensions share, with device
//!   unlock (Face ID / fingerprint or the device passcode) and the 14-day password rule.
//! - [`Session`]: the unlocked account: items, autofill matching, TOTP, passkeys, and the CXF
//!   export another password manager asks for. `lock()` zeroes its keys.
//!
//! Generated bindings: `OctaPassCore` (Swift) and `app.octap.core` (Kotlin), in
//! `apps/ios/Packages/OctaPassCore` and `apps/android/core`. See `README.md` for the flows and the
//! build scripts.

uniffi::setup_scaffolding!();

mod app;
mod error;
mod http;
mod items;
pub mod key_log;
mod matching;
mod passkey;
mod password;
mod server;
mod session;
mod store;
#[cfg(feature = "test-server")]
mod test_server;
mod tools;
mod transfer;

pub use app::{
    DecryptedItem, Resolution, Resolve, attachments_of, with_attachments, without_attachments,
};
pub use error::{OctaPassError, Result};
pub use http::{HttpClient, HttpMethod, HttpRequest, HttpResponse};
pub use items::{
    CardFields, IdentityFields, Item, ItemSummary, LoginDraft, LoginFields, PasskeySummary,
};
pub use matching::MatchQuality;
pub use passkey::{
    ClientData, PasskeyAssertion, PasskeyAssertionRequest, PasskeyCreationRequest, PasskeyMatch,
    PasskeyPrfCredentialInput, PasskeyPrfInput, PasskeyPrfOutput, PasskeyPrfRequest,
    PasskeyRegistration, passkey_assertion_request_from_json, passkey_creation_request_from_json,
};
pub use password::{
    PasswordReset, PasswordResetKit, PasswordResetStart, RotatedSecretKey, TakenOver,
};
pub use server::{
    AuthTokens, DeviceInfo, LogInResult, OctaPassServer, ReauthPurpose, SecondFactorLogin,
    SecondFactorMethod, SecurityKeyInfo, ServerInfo, SignedIn, Signup, SignupMode, SsoLogin,
    TotpSetup, TwoStepStatus,
};
pub use session::{CredentialIdentity, LoginMatch, OtherLogin, Session};
pub use store::{DeviceUnlockStatus, LOCAL_SERVER_PREFIX, LocalStore};
#[cfg(feature = "test-server")]
pub use test_server::TestServer;
pub use tools::{
    GeneratorOptions, Strength, TotpCode, estimate_strength, generate_password,
    normalize_secret_key, totp_code, website_for_page,
};
pub use transfer::CredentialExport;

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

pub(crate) fn unix_seconds() -> u64 {
    now_ms() / 1000
}

/// RFC 3339 in UTC with milliseconds, as the other clients write `updatedAt` and `changedAt`.
pub(crate) fn timestamp(unix_ms: u64) -> String {
    let time = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(unix_ms) * 1_000_000)
        .expect("the clock is before the year 10000");
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    time.format(format)
        .expect("the format has no optional parts")
}

/// Unix milliseconds of an RFC 3339 time.
pub(crate) fn parse_timestamp(text: &str) -> Option<u64> {
    let time = time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339);
    u64::try_from(time.ok()?.unix_timestamp_nanos() / 1_000_000).ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn timestamps_read_back() {
        assert_eq!(
            super::parse_timestamp(&super::timestamp(1_761_177_600_123)),
            Some(1_761_177_600_123)
        );
        assert_eq!(super::parse_timestamp("not a time"), None);
    }

    #[test]
    fn timestamps_are_rfc_3339_utc() {
        assert_eq!(super::timestamp(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            super::timestamp(1_761_177_600_123),
            "2025-10-23T00:00:00.123Z"
        );
    }
}
