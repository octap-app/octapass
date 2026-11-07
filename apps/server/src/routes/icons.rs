//! `GET /v1/icons/{domain}`: a website's icon, fetched by the server so clients never ask an
//! icon service. No account and no token: the request can't be tied to who asked.

use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use octapass_api::problem::Problem;

use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiPath, ClientIp};
use crate::icons::{self, ICON_TTL_MS, MISS_TTL_MS};
use crate::state::AppState;

#[utoipa::path(
    get, path = "/v1/icons/{domain}", tag = "icons",
    params(("domain" = String, Path, description = "A registrable domain or host, such as `example.com`. No scheme, path or port.")),
    responses(
        (status = 200, content_type = "image/png", description = "The site's icon as a PNG of at most 128 × 128 px. Cached for 7 days."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Not a public domain name"),
        (status = 404, body = Problem, content_type = "application/problem+json", description = "not-found: the site has no usable icon (cached for a day); icons-off: this server doesn't fetch icons"),
        (status = 429, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn icon(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiPath(raw): ApiPath<String>,
) -> Response {
    let mut response = match find(&state, &ip, &raw).await {
        Ok(Some(png)) => ([(header::CONTENT_TYPE, "image/png")], png).into_response(),
        Ok(None) => ApiError::NotFound.into_response(),
        Err(error) => return public(error.into_response()),
    };
    let max_age = if response.status().is_success() {
        ICON_TTL_MS
    } else {
        MISS_TTL_MS
    } / 1000;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={max_age}")).expect("a valid header"),
    );
    public(response)
}

async fn find(state: &AppState, ip: &str, raw: &str) -> ApiResult<Option<Vec<u8>>> {
    let Some(icons) = &state.icons else {
        return Err(ApiError::IconsOff);
    };
    state
        .icon_limiter
        .check(ip)
        .map_err(ApiError::RateLimited)?;
    let domain = icons::normalise_domain(raw)
        .ok_or_else(|| ApiError::BadRequest("domain must be a public domain name".into()))?;
    Ok(icons.get(&domain, state.clock.now()).await)
}

/// Public, cookie-free data: any page or app may read it, errors included.
fn public(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("cross-origin"),
    );
    response
}
