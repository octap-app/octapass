//! The OpenAPI 3.1 document, generated from the handlers and `octapass-api` types.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::routes::{
    account, attachments, auth, batch, breach_email, devices, emergency, families, icons,
    masked_email, meta, orgs, password, service_accounts, share_links, sharing, sso, transparency,
    two_step, vaults, ws,
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Octa Pass sync API",
        description = "Stores and syncs end-to-end encrypted vaults. The server only ever sees ciphertext. \
                       Binary values are base64url without padding; errors are application/problem+json.",
        license(name = "MIT", identifier = "MIT"),
    ),
    paths(
        meta::healthz, meta::readyz, meta::server_info, meta::openapi, breach_email::lookup,
        auth::prelogin, auth::register_start, auth::register_finish, auth::login_start, auth::login_finish,
        auth::login_second_factor, auth::login_sso, sso::start, sso::callback, auth::refresh, auth::logout, auth::reauth_start, auth::reauth_finish,
        password::recover_start, password::recover_verify, password::recover_registration,
        password::recover_finish, password::change_registration, password::change_password,
        password::rotate_secret_key,
        account::get_account, account::delete_account, account::usage, account::security_log,
        account::vault_exported, account::connect_events,
        two_step::status, two_step::start_totp, two_step::confirm_totp, two_step::renew_recovery_codes,
        two_step::disable, two_step::security_key_options, two_step::add_security_key,
        two_step::remove_security_key, two_step::forget_trusted_devices,
        vaults::sync, vaults::put_item, vaults::delete_item, vaults::restore_item, vaults::item_history,
        batch::batch, ws::ws,
        attachments::upload, attachments::download, attachments::delete, attachments::list,
        devices::list_devices, devices::rename_current_device, devices::delete_device,
        sharing::lookup, sharing::create_vault, sharing::list_members, sharing::add_member,
        sharing::remove_member, sharing::rotate_vault,
        transparency::head, transparency::label, transparency::proof, transparency::entries,
        transparency::publish,
        families::create_family, families::get_families, families::delete_family, families::invite,
        families::delete_invite, families::accept_invite, families::remove_member,
        families::enable_organiser_recovery,
        share_links::create, share_links::view, share_links::list, share_links::delete,
        emergency::create, emergency::list, emergency::delete, emergency::request, emergency::deny,
        emergency::approve, emergency::get_release, emergency::sync, emergency::download_attachment,
        emergency::renew_key, emergency::takeover_registration, emergency::takeover,
        service_accounts::create, service_accounts::list, service_accounts::revoke,
        service_accounts::challenge, service_accounts::session, service_accounts::sync,
        service_accounts::put_item,
        icons::icon,
        masked_email::list, masked_email::create, masked_email::set_enabled, masked_email::delete,
        masked_email::block, masked_email::unblock,
        orgs::create_org, orgs::get_orgs, orgs::rename_org, orgs::delete_org, orgs::list_members,
        orgs::update_member, orgs::remove_member, orgs::invite, orgs::delete_invite, orgs::accept_invite,
        orgs::list_groups, orgs::create_group, orgs::rename_group, orgs::delete_group,
        orgs::add_group_member, orgs::remove_group_member, orgs::list_vaults, orgs::create_vault,
        orgs::delete_vault, orgs::link_group, orgs::unlink_group, orgs::access, orgs::grant_access,
        orgs::put_policies, orgs::events,
        sso::get_sso, sso::put_sso, sso::delete_sso, sso::test_sso,
    ),
    // Carried over the WebSocket, so no path references them.
    components(schemas(octapass_api::ClientMessage, octapass_api::ServerMessage)),
    modifiers(&BearerAuth),
    tags(
        (name = "meta", description = "Health and server information"),
        (name = "organisations", description = "Organisations, groups, policies and single sign-on. Roles here open nothing: vault keys move only through grants"),
        (name = "auth", description = "OPAQUE sign-up and login, two-step sign-in, tokens, reauthentication, master password reset"),
        (name = "account", description = "The signed-in account, its master password, two-step sign-in settings and security log"),
        (name = "sync", description = "Revision-based pull, conditional item writes and live change notifications"),
        (name = "attachments", description = "Encrypted files kept with items"),
        (name = "devices", description = "Signed-in devices and remote sign-out"),
        (name = "sharing", description = "Shared vaults: members, signed grants, key rotation, public key lookup"),
        (name = "transparency", description = "The key log: an append-only log of account public keys that clients verify"),
        (name = "service-accounts", description = "Non-human access to one shared vault, for CI and servers. Tokens never reach the server"),
        (name = "families", description = "Families and their shared Family vault"),
        (name = "share-links", description = "One-time share links for people without an account"),
        (name = "emergency-access", description = "Emergency contacts and the request, wait and release timeline"),
        (name = "icons", description = "Website icons, fetched by the server from the sites themselves. No account needed"),
        (name = "masked-email", description = "The server's own masked email service, when it has one (`maskedEmailRelay` in server info)"),
    )
)]
pub struct ApiDoc;

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some("Opaque access token, valid for 15 minutes"))
                    .build(),
            ),
        );
    }
}

/// The document as pretty-printed JSON, as checked in at `apps/server/openapi.json`.
pub fn json() -> String {
    ApiDoc::openapi()
        .to_pretty_json()
        .expect("the OpenAPI document serialises")
        + "\n"
}
