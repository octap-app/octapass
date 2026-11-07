//! RFC 9457 problem details, sent as `application/problem+json` for every error.

use serde::{Deserialize, Serialize};

use crate::{ItemRecord, SecondFactorChallenge, SsoChallenge};

/// Stable `type` URIs. Clients match on these, never on `title` or `detail`.
pub mod types {
    pub const INVALID_REQUEST: &str = "https://octap.app/problems/invalid-request";
    pub const UNAUTHORIZED: &str = "https://octap.app/problems/unauthorized";
    /// The single answer for every failed login, whatever the reason.
    pub const LOGIN_FAILED: &str = "https://octap.app/problems/login-failed";
    /// The password was right, and the account asks for a second step on new devices. The body's
    /// `secondFactor` says how; finish with `POST /v1/auth/login/second-factor`.
    pub const SECOND_FACTOR_REQUIRED: &str =
        "https://octap.app/problems/second-factor-required";
    /// A wrong or reused second-step code or security key. The challenge stays usable for a few
    /// more tries.
    pub const INVALID_SECOND_FACTOR: &str =
        "https://octap.app/problems/invalid-second-factor";
    /// The account was deleted. Clients must wipe their local data for it.
    pub const ACCOUNT_DELETED: &str = "https://octap.app/problems/account-deleted";
    /// A dangerous action needs a valid `X-Reauth-Token` for its purpose.
    pub const REAUTH_REQUIRED: &str = "https://octap.app/problems/reauth-required";
    pub const FORBIDDEN: &str = "https://octap.app/problems/forbidden";
    pub const NOT_FOUND: &str = "https://octap.app/problems/not-found";
    /// `GET /v1/icons/{domain}` on a server with the icon proxy turned off. Clients stop asking.
    pub const ICONS_OFF: &str = "https://octap.app/problems/icons-off";
    /// A `/v1/masked-email` route on a server without a masked email service.
    pub const MASKED_EMAIL_OFF: &str = "https://octap.app/problems/masked-email-off";
    /// The account has as many masked email aliases as the server allows.
    pub const MASKED_EMAIL_LIMIT: &str = "https://octap.app/problems/masked-email-limit";
    pub const METHOD_NOT_ALLOWED: &str = "https://octap.app/problems/method-not-allowed";
    /// The item changed on the server. The body's `current` holds the server version.
    pub const CONFLICT: &str = "https://octap.app/problems/conflict";
    /// In a batch: another operation on the same vault failed, so this one wasn't applied.
    pub const BATCH_ABORTED: &str = "https://octap.app/problems/batch-aborted";
    pub const ACCOUNT_EXISTS: &str = "https://octap.app/problems/account-exists";
    pub const VAULT_EXISTS: &str = "https://octap.app/problems/vault-exists";
    pub const PAYLOAD_TOO_LARGE: &str = "https://octap.app/problems/payload-too-large";
    /// The vault owner's item count or storage quota would be exceeded.
    pub const QUOTA_EXCEEDED: &str = "https://octap.app/problems/quota-exceeded";
    pub const PRECONDITION_REQUIRED: &str =
        "https://octap.app/problems/precondition-required";
    pub const INVALID_VERIFICATION_CODE: &str =
        "https://octap.app/problems/invalid-verification-code";
    /// A master password reset that's unknown, expired, or was already finished: start again.
    pub const RECOVERY_EXPIRED: &str = "https://octap.app/problems/recovery-expired";
    pub const SIGNUPS_CLOSED: &str = "https://octap.app/problems/signups-closed";
    pub const INVITE_REQUIRED: &str = "https://octap.app/problems/invite-required";
    pub const RATE_LIMITED: &str = "https://octap.app/problems/rate-limited";
    pub const EMAIL_UNAVAILABLE: &str = "https://octap.app/problems/email-unavailable";
    pub const UNAVAILABLE: &str = "https://octap.app/problems/unavailable";
    /// An item key was wrapped under a vault key that is no longer current: sync, reopen the
    /// vault's grant and encrypt again.
    pub const VAULT_KEY_CHANGED: &str = "https://octap.app/problems/vault-key-changed";
    /// The vault changed since the revision the request was built from.
    pub const VAULT_CHANGED: &str = "https://octap.app/problems/vault-changed";
    /// The thing being created already exists (a family, an emergency contact).
    pub const ALREADY_EXISTS: &str = "https://octap.app/problems/already-exists";
    /// A family can't have more members and pending invites.
    pub const FAMILY_FULL: &str = "https://octap.app/problems/family-full";
    /// An upload must say its size in `Content-Length`.
    pub const LENGTH_REQUIRED: &str = "https://octap.app/problems/length-required";
    pub const INTERNAL: &str = "https://octap.app/problems/internal";
    /// The password was right, and the account's organisation requires single sign-on. The body's
    /// `sso` says how; finish with `POST /v1/auth/login/sso`. SSO adds a step, never a key.
    pub const SSO_REQUIRED: &str = "https://octap.app/problems/sso-required";
    /// `login/sso` before the browser finished at the identity provider: wait and try again.
    pub const SSO_PENDING: &str = "https://octap.app/problems/sso-pending";
    /// An organisation policy forbids this for its members.
    pub const ORG_POLICY: &str = "https://octap.app/problems/org-policy";
    /// This would leave organisation vaults with nobody able to manage them. `vaultIds` lists them.
    pub const ORG_VAULT_ORPHANED: &str = "https://octap.app/problems/org-vault-orphaned";
    /// The identity provider's settings don't work.
    pub const SSO_CONFIG: &str = "https://octap.app/problems/sso-config";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Only on `conflict`: the item as currently stored on the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<ItemRecord>,
    /// Only on `second-factor-required`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_factor: Option<SecondFactorChallenge>,
    /// Only on `sso-required`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso: Option<SsoChallenge>,
    /// Only on `org-vault-orphaned`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vault_ids: Vec<String>,
}
