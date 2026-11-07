//! Cross-cutting HTTP layers: CORS, security headers and request logging that
//! never records bodies, tokens or query strings. Timeouts differ per route
//! (see `routes`).

use std::time::Duration;

use axum::Router;
use axum::extract::{MatchedPath, Request};
use axum::http::{HeaderName, HeaderValue, Method, header};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::config::Config;
use crate::state::AppState;

pub fn apply(router: Router<AppState>, config: &Config) -> Router<AppState> {
    let mut headers = vec![
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'",
        ),
        (header::CACHE_CONTROL, "no-store"),
    ];
    if config.is_https() {
        headers.push((
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=63072000; includeSubDomains",
        ));
    }

    let router = headers.into_iter().fold(router, |router, (name, value)| {
        router.layer(SetResponseHeaderLayer::if_not_present(
            name,
            HeaderValue::from_static(value),
        ))
    });
    router.layer(cors(config)).layer(
        TraceLayer::new_for_http()
            .make_span_with(|request: &Request| {
                let path = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map_or("unmatched", MatchedPath::as_str);
                tracing::info_span!("request", method = %request.method(), path)
            })
            .on_request(())
            .on_response(DefaultOnResponse::new().level(Level::INFO)),
    )
}

fn cors(config: &Config) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(config.web_origins.clone()))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::IF_MATCH,
            header::IF_NONE_MATCH,
            HeaderName::from_static(octapass_api::REAUTH_TOKEN_HEADER),
        ])
        .expose_headers([header::ETAG, header::RETRY_AFTER])
        .max_age(Duration::from_secs(600))
}
