//! The HTTP API v1 router.

pub mod account;
pub mod attachments;
pub mod auth;
pub mod batch;
pub mod breach_email;
pub mod devices;
pub mod emergency;
pub mod families;
pub mod health_data;
pub mod icons;
pub mod masked_email;
pub mod meta;
pub mod orgs;
pub mod password;
pub mod scim;
pub mod service_accounts;
pub mod share_links;
pub mod sharing;
pub mod sso;
pub mod transparency;
pub mod two_step;
pub mod vaults;
pub mod ws;

use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::StatusCode;
use axum::routing::{delete, get, patch, post, put};
use tower_http::timeout::TimeoutLayer;

use crate::error::ApiError;
use crate::middleware;
use crate::state::AppState;
use crate::web::Web;

/// Large enough for one item with 512 KiB of encrypted details.
const MAX_BODY: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Attachments stream up to the file size limit; a stalled upload is cut off
/// sooner, after a minute without data.
const FILE_TIMEOUT: Duration = Duration::from_secs(60 * 60);

fn timeout(duration: Duration) -> TimeoutLayer {
    TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, duration)
}

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/healthz", get(meta::healthz))
        .route("/readyz", get(meta::readyz))
        .route("/v1/server-info", get(meta::server_info))
        .route("/v1/openapi.json", get(meta::openapi))
        .route("/v1/icons/{domain}", get(icons::icon))
        .route(
            "/v1/masked-email/aliases",
            get(masked_email::list).post(masked_email::create),
        )
        .route(
            "/v1/masked-email/aliases/{id}",
            patch(masked_email::set_enabled).delete(masked_email::delete),
        )
        .route(
            "/v1/masked-email/aliases/{id}/block",
            post(masked_email::block),
        )
        .route(
            "/v1/masked-email/aliases/{id}/unblock",
            post(masked_email::unblock),
        )
        .route("/v1/auth/prelogin", post(auth::prelogin))
        .route("/v1/auth/register/start", post(auth::register_start))
        .route("/v1/auth/register/finish", post(auth::register_finish))
        .route("/v1/auth/login/start", post(auth::login_start))
        .route("/v1/auth/login/finish", post(auth::login_finish))
        .route(
            "/v1/auth/login/second-factor",
            post(auth::login_second_factor),
        )
        .route("/v1/auth/login/sso", post(auth::login_sso))
        .route("/v1/sso/start/{token}", get(sso::start))
        .route("/v1/sso/callback", get(sso::callback))
        .route("/v1/auth/refresh", post(auth::refresh))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/auth/reauth/start", post(auth::reauth_start))
        .route("/v1/auth/reauth/finish", post(auth::reauth_finish))
        .route("/v1/auth/recover/start", post(password::recover_start))
        .route("/v1/auth/recover/verify", post(password::recover_verify))
        .route(
            "/v1/auth/recover/registration",
            post(password::recover_registration),
        )
        .route("/v1/auth/recover/finish", post(password::recover_finish))
        .route(
            "/v1/account",
            get(account::get_account).delete(account::delete_account),
        )
        .route("/v1/account/usage", get(account::usage))
        .route("/v1/account/password", put(password::change_password))
        .route("/v1/account/secret-key", put(password::rotate_secret_key))
        .route(
            "/v1/account/password/registration",
            post(password::change_registration),
        )
        .route(
            "/v1/account/two-step",
            get(two_step::status).delete(two_step::disable),
        )
        .route("/v1/account/two-step/totp", post(two_step::start_totp))
        .route(
            "/v1/account/two-step/totp/confirm",
            post(two_step::confirm_totp),
        )
        .route(
            "/v1/account/two-step/recovery-codes",
            post(two_step::renew_recovery_codes),
        )
        .route(
            "/v1/account/two-step/security-keys/options",
            post(two_step::security_key_options),
        )
        .route(
            "/v1/account/two-step/security-keys",
            post(two_step::add_security_key),
        )
        .route(
            "/v1/account/two-step/trusted-devices",
            delete(two_step::forget_trusted_devices),
        )
        .route(
            "/v1/account/two-step/security-keys/{id}",
            delete(two_step::remove_security_key),
        )
        .route("/v1/security-log", get(account::security_log))
        .route("/v1/security-log/exports", post(account::vault_exported))
        .route("/v1/health/breach-email", post(breach_email::lookup))
        .route("/v1/health/data", get(health_data::file))
        .route("/v1/security-log/connect", post(account::connect_events))
        .route(
            "/v1/vaults/{vault_id}/service-accounts",
            get(service_accounts::list).post(service_accounts::create),
        )
        .route(
            "/v1/vaults/{vault_id}/service-accounts/{service_account_id}",
            delete(service_accounts::revoke),
        )
        .route(
            "/v1/service-accounts/challenge",
            post(service_accounts::challenge),
        )
        .route(
            "/v1/service-accounts/session",
            post(service_accounts::session),
        )
        .route("/v1/service-accounts/sync", get(service_accounts::sync))
        .route(
            "/v1/service-accounts/items/{item_id}",
            put(service_accounts::put_item),
        )
        .route("/v1/accounts/lookup", get(sharing::lookup))
        .route("/v1/transparency/head", get(transparency::head))
        .route("/v1/transparency/label", post(transparency::label))
        .route("/v1/transparency/proof", get(transparency::proof))
        .route("/v1/transparency/entries", get(transparency::entries))
        .route("/v1/transparency/publish", post(transparency::publish))
        .route("/v1/sync", get(vaults::sync))
        .route("/v1/vaults", post(sharing::create_vault))
        .route(
            "/v1/vaults/{vault_id}/members",
            get(sharing::list_members).post(sharing::add_member),
        )
        .route(
            "/v1/vaults/{vault_id}/members/{account_id}",
            delete(sharing::remove_member),
        )
        .route(
            "/v1/vaults/{vault_id}/rotate",
            post(sharing::rotate_vault).layer(DefaultBodyLimit::max(batch::MAX_BODY)),
        )
        .route(
            "/v1/vaults/{vault_id}/items/{item_id}",
            put(vaults::put_item).delete(vaults::delete_item),
        )
        .route(
            "/v1/vaults/{vault_id}/items/{item_id}/restore",
            post(vaults::restore_item),
        )
        .route(
            "/v1/vaults/{vault_id}/items/{item_id}/history",
            get(vaults::item_history),
        )
        .route(
            "/v1/batch",
            post(batch::batch).layer(DefaultBodyLimit::max(batch::MAX_BODY)),
        )
        .route("/v1/ws", get(ws::ws))
        .route(
            "/v1/families",
            get(families::get_families).post(families::create_family),
        )
        .route("/v1/families/{family_id}", delete(families::delete_family))
        .route("/v1/families/{family_id}/invites", post(families::invite))
        .route(
            "/v1/families/{family_id}/organiser-recovery",
            post(families::enable_organiser_recovery),
        )
        .route(
            "/v1/families/{family_id}/invites/accept",
            post(families::accept_invite),
        )
        .route(
            "/v1/families/{family_id}/invites/{account_id}",
            delete(families::delete_invite),
        )
        .route(
            "/v1/families/{family_id}/members/{account_id}",
            delete(families::remove_member),
        )
        .route("/v1/orgs", get(orgs::get_orgs).post(orgs::create_org))
        .route(
            "/v1/orgs/{org_id}",
            patch(orgs::rename_org).delete(orgs::delete_org),
        )
        .route("/v1/orgs/{org_id}/members", get(orgs::list_members))
        .route(
            "/v1/orgs/{org_id}/members/{account_id}",
            patch(orgs::update_member).delete(orgs::remove_member),
        )
        .route("/v1/orgs/{org_id}/invites", post(orgs::invite))
        .route(
            "/v1/orgs/{org_id}/invites/{invite_id}",
            delete(orgs::delete_invite),
        )
        .route(
            "/v1/orgs/{org_id}/invites/{invite_id}/accept",
            post(orgs::accept_invite),
        )
        .route(
            "/v1/orgs/{org_id}/groups",
            get(orgs::list_groups).post(orgs::create_group),
        )
        .route(
            "/v1/orgs/{org_id}/groups/{group_id}",
            patch(orgs::rename_group).delete(orgs::delete_group),
        )
        .route(
            "/v1/orgs/{org_id}/groups/{group_id}/members/{account_id}",
            put(orgs::add_group_member).delete(orgs::remove_group_member),
        )
        .route(
            "/v1/orgs/{org_id}/vaults",
            get(orgs::list_vaults).post(orgs::create_vault),
        )
        .route(
            "/v1/orgs/{org_id}/vaults/{vault_id}",
            delete(orgs::delete_vault),
        )
        .route(
            "/v1/orgs/{org_id}/vaults/{vault_id}/groups/{group_id}",
            put(orgs::link_group).delete(orgs::unlink_group),
        )
        .route(
            "/v1/orgs/{org_id}/vaults/{vault_id}/grants",
            post(orgs::grant_access),
        )
        .route("/v1/orgs/{org_id}/access", get(orgs::access))
        .route("/v1/orgs/{org_id}/policies", put(orgs::put_policies))
        .route("/v1/orgs/{org_id}/events", get(orgs::events))
        .route(
            "/v1/orgs/{org_id}/sso",
            get(sso::get_sso).put(sso::put_sso).delete(sso::delete_sso),
        )
        .route("/v1/orgs/{org_id}/sso/test", post(sso::test_sso))
        .route("/v1/orgs/{org_id}/sso/saml", put(sso::put_saml))
        .route("/v1/sso/saml/{org_id}/acs", post(sso::saml_acs))
        .route("/v1/sso/saml/{org_id}/metadata", get(sso::saml_metadata))
        .route("/v1/orgs/{org_id}/scim", get(scim::get_scim))
        .route("/v1/orgs/{org_id}/scim/tokens", post(scim::create_token))
        .route(
            "/v1/orgs/{org_id}/scim/tokens/{token_id}",
            delete(scim::delete_token),
        )
        // SCIM 2.0, for identity providers, with an organisation's SCIM token (RFC 7644).
        .route(
            "/v1/scim/v2/ServiceProviderConfig",
            get(scim::service_provider_config),
        )
        .route("/v1/scim/v2/ResourceTypes", get(scim::resource_types))
        .route("/v1/scim/v2/Schemas", get(scim::schemas))
        .route(
            "/v1/scim/v2/Users",
            get(scim::list_users).post(scim::create_user),
        )
        .route(
            "/v1/scim/v2/Users/{id}",
            get(scim::get_user)
                .put(scim::replace_user)
                .patch(scim::patch_user)
                .delete(scim::delete_user),
        )
        .route(
            "/v1/scim/v2/Groups",
            get(scim::list_groups).post(scim::create_group),
        )
        .route(
            "/v1/scim/v2/Groups/{id}",
            get(scim::get_group)
                .put(scim::replace_group)
                .patch(scim::patch_group)
                .delete(scim::delete_group),
        )
        .route(
            "/v1/share-links",
            get(share_links::list).post(share_links::create),
        )
        .route(
            "/v1/share-links/{id}",
            get(share_links::view).delete(share_links::delete),
        )
        .route(
            "/v1/emergency-contacts",
            get(emergency::list).post(emergency::create),
        )
        .route("/v1/emergency-contacts/{id}", delete(emergency::delete))
        .route(
            "/v1/emergency-contacts/{id}/request",
            post(emergency::request),
        )
        .route("/v1/emergency-contacts/{id}/deny", post(emergency::deny))
        .route(
            "/v1/emergency-contacts/{id}/approve",
            post(emergency::approve),
        )
        .route(
            "/v1/emergency-contacts/{id}/release",
            get(emergency::get_release),
        )
        .route("/v1/emergency-contacts/{id}/sync", get(emergency::sync))
        .route("/v1/emergency-contacts/{id}/key", put(emergency::renew_key))
        .route(
            "/v1/emergency-contacts/{id}/takeover/registration",
            post(emergency::takeover_registration),
        )
        .route(
            "/v1/emergency-contacts/{id}/takeover",
            post(emergency::takeover),
        )
        .route("/v1/devices", get(devices::list_devices))
        .route("/v1/devices/current", patch(devices::rename_current_device))
        .route(
            "/v1/devices/current/push",
            put(devices::put_push_token).delete(devices::delete_push_token),
        )
        .route("/v1/devices/{device_id}", delete(devices::delete_device));
    let api = match &state.config.web_dir {
        Some(dir) => {
            let web = Web::new(dir, &state.config);
            api.fallback(move |request: Request| web.serve(request))
        }
        None => api.fallback(|| async { ApiError::NotFound }),
    };
    let api = api
        .method_not_allowed_fallback(|| async { ApiError::MethodNotAllowed })
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(timeout(REQUEST_TIMEOUT));
    // Bodies here are streamed to storage, with limits of their own.
    let files = Router::new()
        .route(
            "/v1/vaults/{vault_id}/items/{item_id}/attachments",
            get(attachments::list),
        )
        .route(
            "/v1/vaults/{vault_id}/items/{item_id}/attachments/{attachment_id}",
            put(attachments::upload)
                .get(attachments::download)
                .delete(attachments::delete),
        )
        .route(
            "/v1/emergency-contacts/{id}/vaults/{vault_id}/items/{item_id}/attachments/{attachment_id}",
            get(emergency::download_attachment),
        )
        .layer(DefaultBodyLimit::disable())
        .layer(timeout(FILE_TIMEOUT));

    middleware::apply(api.merge(files), &state.config).with_state(state)
}
