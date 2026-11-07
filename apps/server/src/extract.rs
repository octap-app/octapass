//! Request extractors that fail with problem+json instead of axum's plain text.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Path, Query};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::crypto::token_hash;
use crate::db::{self, sessions::Session};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(ApiError))]
pub struct ApiJson<T>(pub T);

#[derive(FromRequestParts)]
#[from_request(via(Path), rejection(ApiError))]
pub struct ApiPath<T>(pub T);

#[derive(FromRequestParts)]
#[from_request(via(Query), rejection(ApiError))]
pub struct ApiQuery<T>(pub T);

/// A valid, unexpired access token.
pub struct Authenticated(pub Session);

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;
        session_for(state, token).await.map(Authenticated)
    }
}

/// The session behind an access token. Fails with `AccountDeleted` for tokens
/// of a deleted account, so its devices know to wipe their data.
pub async fn session_for(state: &AppState, access_token: &str) -> Result<Session, ApiError> {
    let (token, now) = (access_token.trim(), db::now());
    if let Some(session) = db::sessions::find_by_access_token(&state.db, token, now).await? {
        return Ok(session);
    }
    if db::deletion::is_deleted_account_token(&state.db, &token_hash(token), now).await? {
        return Err(ApiError::AccountDeleted);
    }
    Err(ApiError::Unauthorized)
}

/// The client address used as the per-IP rate limit key.
pub struct ClientIp(pub String);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        // The last X-Forwarded-For entry is the one our own proxy appended;
        // earlier entries are whatever the client claimed.
        let forwarded = || {
            parts
                .headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .next_back()
                .and_then(|ip| ip.trim().parse::<IpAddr>().ok())
        };
        let ip = if state.config.trust_proxy {
            forwarded()
        } else {
            None
        }
        .or_else(|| {
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip())
        });
        Ok(Self(
            ip.map_or_else(|| "unknown".to_owned(), rate_limit_key),
        ))
    }
}

/// IPv6 users usually control a whole /64, so that's the unit we limit.
fn rate_limit_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_ipv6_by_prefix() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        assert_eq!(rate_limit_key(a), rate_limit_key(b));
        assert_eq!(rate_limit_key(a), "2001:db8:1:2::/64");
        assert_eq!(
            rate_limit_key("::ffff:192.0.2.1".parse().unwrap()),
            "192.0.2.1"
        );
        assert_eq!(rate_limit_key("192.0.2.1".parse().unwrap()), "192.0.2.1");
    }
}
