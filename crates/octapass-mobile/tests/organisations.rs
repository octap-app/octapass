//! Organisations through `OctaPassVault` and the real sync server (in-process), as the native apps
//! call them: an owner and a member on two phones, the reviewed step that seals a vault's key, the
//! policies the apps apply themselves, and leaving, removing and deleting.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use octapass_mobile::items::{ItemDetails, ItemType, LoginDetails, new_item_draft};
use octapass_mobile::list::ItemFilter;
use octapass_mobile::organisations::{ClientPolicies, ConfirmedGrant, OrgPolicies, OrgRole};
use octapass_mobile::platform::{CredentialIdentity, DeviceLock, NativePlatform, VaultObserver};
use octapass_mobile::sharing::VaultRole;
use octapass_mobile::transfer::ExportFormat;
use octapass_mobile::vault::{DevicePlatform, SessionSnapshot, SyncState, VaultConfig};
use octapass_mobile::{ErrorCode, OctaPassVault, Result};
use tempfile::TempDir;

const OWNER: &str = "ada@example.com";
const MEMBER: &str = "grace@example.com";
const ADMIN: &str = "linus@example.com";
const PASSWORD: &str = "correct horse battery staple";

struct Server {
    url: String,
    _data: TempDir,
    runtime: tokio::runtime::Runtime,
}

impl Server {
    fn start() -> Self {
        let data = tempfile::tempdir().unwrap();
        let data_dir = data.path().to_str().unwrap().to_owned();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let url = runtime.block_on(async {
            let config = octapass_server::Config::from_lookup(|name| match name {
                "OCTAPASS_DATA_DIR" => Some(data_dir.clone()),
                "OCTAPASS_DEV_MODE" => Some("true".into()),
                "OCTAPASS_RATE_LIMITS" => Some("off".into()),
                _ => None,
            })
            .unwrap();
            let state = octapass_server::AppState::new(config).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let app =
                octapass_server::router(state).into_make_service_with_connect_info::<SocketAddr>();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            url
        });
        Self {
            url,
            _data: data,
            runtime,
        }
    }

    fn wait<T>(&self, call: impl Future<Output = Result<T>>) -> T {
        self.runtime.block_on(call).unwrap()
    }

    fn fail<T: std::fmt::Debug>(&self, call: impl Future<Output = Result<T>>) -> ErrorCode {
        self.runtime.block_on(call).unwrap_err().code()
    }
}

/// The Keychain and the device lock, in memory.
#[derive(Default)]
struct Platform {
    secrets: Mutex<HashMap<String, String>>,
    device_secrets: Mutex<HashMap<String, Vec<u8>>>,
}

impl NativePlatform for Platform {
    fn secret(&self, name: String) -> Result<Option<String>> {
        Ok(self.secrets.lock().unwrap().get(&name).cloned())
    }

    fn set_secret(&self, name: String, value: String) -> Result<()> {
        self.secrets.lock().unwrap().insert(name, value);
        Ok(())
    }

    fn delete_secret(&self, name: String) -> Result<()> {
        self.secrets.lock().unwrap().remove(&name);
        Ok(())
    }

    fn device_lock(&self) -> DeviceLock {
        DeviceLock {
            available: false,
            label: String::new(),
        }
    }

    fn store_device_secret(&self, name: String, secret: Vec<u8>) -> Result<()> {
        self.device_secrets.lock().unwrap().insert(name, secret);
        Ok(())
    }

    fn device_secret(&self, name: String, _reason: String) -> Result<Vec<u8>> {
        self.device_secrets
            .lock()
            .unwrap()
            .get(&name)
            .cloned()
            .ok_or_else(|| ErrorCode::DeviceUnlockFailed.into())
    }

    fn delete_device_secret(&self, name: String) -> Result<()> {
        self.device_secrets.lock().unwrap().remove(&name);
        Ok(())
    }

    fn verify_user(&self, _reason: String) -> Result<()> {
        Err(ErrorCode::DeviceUnlockUnsupported.into())
    }

    fn store_stay_unlocked_key(&self, _name: String, _key: Vec<u8>) -> Result<()> {
        Ok(())
    }

    fn stay_unlocked_key(&self, _name: String) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn delete_stay_unlocked_key(&self, _name: String) -> Result<()> {
        Ok(())
    }

    fn set_credential_identities(&self, _identities: Vec<CredentialIdentity>) -> Result<()> {
        Ok(())
    }

    fn chip_available(&self) -> bool {
        false
    }

    fn create_chip_key(&self, _name: String) -> Result<Option<octapass_mobile::platform::ChipKey>> {
        Ok(None)
    }

    fn chip_secret(&self, _name: String, _context: Vec<u8>) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn delete_chip_key(&self, _name: String) -> Result<()> {
        Ok(())
    }

    fn low_memory(&self) -> bool {
        true
    }

    fn backup_folder_files(&self, _folder: String) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    fn write_backup_file(&self, _folder: String, _name: String, _source: String) -> Result<()> {
        Ok(())
    }

    fn delete_backup_file(&self, _folder: String, _name: String) -> Result<()> {
        Ok(())
    }
}

struct Events;

impl VaultObserver for Events {
    fn session_changed(&self, _snapshot: SessionSnapshot) {}
    fn items_changed(&self) {}
    fn sync_changed(&self, _state: SyncState) {}
    fn sharing_changed(&self) {}
}

/// One person's phone, signed up on the server.
struct Phone {
    vault: Arc<OctaPassVault>,
    _dir: TempDir,
}

impl Phone {
    fn sign_up(server: &Server, email: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = OctaPassVault::new(
            VaultConfig {
                data_dir: dir.path().join("group").to_string_lossy().into(),
                temp_dir: dir.path().join("tmp").to_string_lossy().into(),
                device_name: "Test iPhone".into(),
                platform: DevicePlatform::Ios,
                pwned_passwords_url: server.url.clone(),
                web_vault_url: "https://vault.octap.app".into(),
                default_server_url: "https://vault.octap.app".into(),
                cache_dir: dir.path().join("icons").to_string_lossy().into(),
            },
            Arc::new(Platform::default()),
            Arc::new(Events),
        )
        .unwrap();
        let phone = Self { vault, _dir: dir };
        let started = server.wait(phone.v().start_signup(
            server.url.clone(),
            email.into(),
            PASSWORD.into(),
        ));
        let code = started.dev_verification_code.expect("a development server");
        server.wait(phone.v().finish_signup(started.signup_id, code));
        phone
    }

    fn v(&self) -> Arc<OctaPassVault> {
        self.vault.clone()
    }

    fn save_login(&self, server: &Server, vault_id: &str, title: &str) {
        let mut draft = new_item_draft(ItemType::Login, vault_id.into());
        draft.title = title.into();
        draft.details = ItemDetails::Login {
            login: LoginDetails {
                username: Some("deploy".into()),
                password: Some("hunter2".into()),
                ..LoginDetails::default()
            },
        };
        server.wait(self.v().save_item(draft));
    }

    fn titles_in(&self, server: &Server, vault_id: &str) -> Vec<String> {
        let filter = ItemFilter {
            vault_id: Some(vault_id.into()),
            ..ItemFilter::default()
        };
        server
            .wait(self.v().list_items(filter))
            .into_iter()
            .map(|item| item.title)
            .collect()
    }

    fn vault_ids(&self, server: &Server) -> Vec<String> {
        server.wait(self.v().sync());
        server
            .wait(self.v().list_vaults())
            .into_iter()
            .map(|vault| vault.id)
            .collect()
    }

    fn personal_vault(&self, server: &Server) -> String {
        server.wait(self.v().list_vaults())[0].id.clone()
    }

    fn account_id(&self, server: &Server) -> String {
        server
            .wait(self.v().lookup_account(self.email(server)))
            .account_id
    }

    fn email(&self, _server: &Server) -> String {
        self.vault.snapshot().email.unwrap()
    }
}

fn no_policies() -> OrgPolicies {
    OrgPolicies {
        require_two_step: false,
        require_sso: false,
        sso_max_age_hours: 168,
        disable_share_links: false,
        disable_emergency_access: false,
        disable_export: false,
        max_auto_lock_minutes: None,
        min_password_length: None,
    }
}

/// The member has an invitation and accepts it.
fn join(server: &Server, phone: &Phone) {
    let state = server.wait(phone.v().get_organisation());
    let invite = state.invitations.first().expect("an invitation").clone();
    let joined = server.wait(phone.v().accept_org_invite(invite.org_id, invite.id));
    assert_eq!(joined.name, "Acme");
}

#[test]
fn an_owner_shares_an_organisation_vault_with_a_member_from_the_phone() {
    let server = Server::start();
    let owner = Phone::sign_up(&server, OWNER);
    let member = Phone::sign_up(&server, MEMBER);

    // Nobody is in one at first; the owner creates it.
    let state = server.wait(owner.v().get_organisation());
    assert!(state.organisation.is_none() && state.invitations.is_empty());
    let created = server.wait(owner.v().create_organisation(" Acme ".into()));
    assert_eq!(
        (created.name.as_str(), created.role),
        ("Acme", OrgRole::Owner)
    );

    // An invite, seen and accepted on the member's phone.
    server.wait(
        owner
            .v()
            .invite_org_member(MEMBER.to_uppercase(), OrgRole::Member),
    );
    let invited = server.wait(member.v().get_organisation());
    assert_eq!(invited.invitations.len(), 1);
    assert_eq!(invited.invitations[0].org_name, "Acme");
    assert_eq!(invited.invitations[0].invited_by.as_deref(), Some(OWNER));
    let listed = server.wait(owner.v().list_org_members());
    assert_eq!(listed.invites[0].email, MEMBER);
    join(&server, &member);
    let listed = server.wait(owner.v().list_org_members());
    assert!(listed.invites.is_empty());
    let me = listed.members.iter().find(|m| m.email == OWNER).unwrap();
    let them = listed.members.iter().find(|m| m.email == MEMBER).unwrap();
    assert!(me.is_you && !them.is_you);
    assert_eq!(them.role, OrgRole::Member);
    let member_id = them.account_id.clone();

    // A member can't run it.
    assert_eq!(
        server.fail(member.v().create_org_group("Mine".into())),
        ErrorCode::NotAllowed
    );

    // A group, a vault linked to it, and an item in the vault.
    let group = server.wait(owner.v().create_org_group("Engineering".into()));
    server.wait(
        owner
            .v()
            .add_org_group_member(group.id.clone(), member_id.clone()),
    );
    let vault = server.wait(owner.v().create_org_vault("Deploy".into()));
    assert_eq!(vault.name, "Deploy");
    owner.save_login(&server, &vault.id, "Deploy key");
    server.wait(owner.v().sync());
    server.wait(owner.v().link_org_vault_group(
        vault.id.clone(),
        group.id.clone(),
        VaultRole::Read,
    ));
    let vaults = server.wait(owner.v().list_org_vaults());
    let listed = vaults.iter().find(|v| v.id == vault.id).unwrap();
    assert_eq!(listed.name.as_deref(), Some("Deploy"));
    assert_eq!(listed.groups[0].group_id, group.id);
    assert_eq!(listed.groups[0].role, VaultRole::Read);
    assert!(
        !member.vault_ids(&server).contains(&vault.id),
        "linking gives no key"
    );

    // The review: the fingerprint is computed on the owner's phone from the member's keys.
    let reviews = server.wait(owner.v().org_access());
    let review = reviews.iter().find(|r| r.vault_id == vault.id).unwrap();
    assert!(review.can_apply);
    assert_eq!(review.vault_name.as_deref(), Some("Deploy"));
    let grant = &review.grants[0];
    assert_eq!(
        (grant.email.as_str(), grant.role),
        (MEMBER, VaultRole::Read)
    );
    let expected = server.wait(member.v().my_fingerprint());
    assert_eq!(grant.fingerprint.digits, expected.digits);
    assert!(!grant.verified && !grant.key_changed);

    // A fingerprint other than the one on screen seals nothing.
    let wrong = ConfirmedGrant {
        account_id: member_id.clone(),
        fingerprint_digits: "0000 0000 0000 0000 0000 0000".into(),
    };
    assert_eq!(
        server.fail(owner.v().apply_org_access(vault.id.clone(), vec![wrong])),
        ErrorCode::UntrustedVault
    );
    assert!(!member.vault_ids(&server).contains(&vault.id));

    // The right one: the member opens the vault and sees the item, read-only.
    let right = ConfirmedGrant {
        account_id: member_id.clone(),
        fingerprint_digits: grant.fingerprint.digits.clone(),
    };
    assert_eq!(
        server.wait(owner.v().apply_org_access(vault.id.clone(), vec![right])),
        1
    );
    assert!(member.vault_ids(&server).contains(&vault.id));
    let theirs = server
        .wait(member.v().list_vaults())
        .into_iter()
        .find(|v| v.id == vault.id)
        .unwrap();
    assert_eq!(
        (theirs.name.as_str(), theirs.role),
        ("Deploy", VaultRole::Read)
    );
    assert!(!theirs.untrusted);
    assert_eq!(member.titles_in(&server, &vault.id), ["Deploy key"]);
    let reviews = server.wait(owner.v().org_access());
    assert!(
        reviews
            .iter()
            .all(|r| r.vault_id != vault.id || r.grants.is_empty())
    );

    // The activity log names what happened, never what's in a vault.
    let events: Vec<String> = server
        .wait(owner.v().org_events())
        .into_iter()
        .map(|event| event.event_type)
        .collect();
    for wanted in [
        "org-created",
        "member-joined",
        "vault-created",
        "access-granted",
    ] {
        assert!(events.iter().any(|e| e == wanted), "{wanted} in {events:?}");
    }

    // Policies the apps apply: the member's phone keeps them, and follows them.
    let policies = OrgPolicies {
        disable_export: true,
        max_auto_lock_minutes: Some(15),
        min_password_length: Some(40),
        ..no_policies()
    };
    let saved = server.wait(owner.v().set_org_policies(policies));
    assert_eq!(saved, policies);
    assert_eq!(member.v().client_policies(), ClientPolicies::default());
    server.wait(member.v().sync());
    assert_eq!(
        member.v().client_policies(),
        ClientPolicies {
            disable_export: true,
            max_auto_lock_minutes: Some(15),
            min_password_length: Some(40),
        }
    );
    assert_eq!(
        server.fail(
            member
                .v()
                .change_master_password(PASSWORD.into(), "too short for the organisation".into())
        ),
        ErrorCode::OrgPolicy
    );
    member.save_login(&server, &member.personal_vault(&server), "My own login");
    let exported = server.wait(member.v().export_vault(ExportFormat::Json, None, None));
    let text = std::fs::read_to_string(&exported).unwrap();
    assert!(text.contains("My own login"));
    assert!(
        !text.contains("Deploy key"),
        "the organisation's vault stays out"
    );
    let exported = server.wait(owner.v().export_vault(ExportFormat::Csv, None, None));
    assert!(
        !std::fs::read_to_string(&exported)
            .unwrap()
            .contains("Deploy key")
    );

    // Leaving: the vault goes at once, and so do the policies.
    server.wait(member.v().leave_organisation(false));
    assert!(
        server
            .wait(member.v().get_organisation())
            .organisation
            .is_none()
    );
    assert!(!member.vault_ids(&server).contains(&vault.id));
    assert_eq!(member.v().client_policies(), ClientPolicies::default());
    let vaults = server.wait(owner.v().list_org_vaults());
    assert!(
        vaults
            .iter()
            .find(|v| v.id == vault.id)
            .unwrap()
            .rotation_pending
    );
    server.wait(owner.v().rotate_org_vault(vault.id.clone()));
    let vaults = server.wait(owner.v().list_org_vaults());
    assert!(
        !vaults
            .iter()
            .find(|v| v.id == vault.id)
            .unwrap()
            .rotation_pending
    );

    // Deleting needs the master password, and the name typed.
    assert_eq!(
        server.fail(
            owner
                .v()
                .delete_org_vault("wrong password".into(), vault.id.clone())
        ),
        ErrorCode::InvalidCredentials
    );
    server.wait(
        owner
            .v()
            .delete_org_vault(PASSWORD.into(), vault.id.clone()),
    );
    assert!(!owner.vault_ids(&server).contains(&vault.id));
    assert!(server.wait(owner.v().list_org_vaults()).is_empty());
    assert_ne!(
        server
            .runtime
            .block_on(
                owner
                    .v()
                    .delete_organisation(PASSWORD.into(), "Acne".into())
            )
            .err()
            .map(|e| e.code()),
        None
    );
    server.wait(
        owner
            .v()
            .delete_organisation(PASSWORD.into(), "Acme".into()),
    );
    assert!(
        server
            .wait(owner.v().get_organisation())
            .organisation
            .is_none()
    );
}

#[test]
fn members_roles_groups_and_admin_settings() {
    let server = Server::start();
    let owner = Phone::sign_up(&server, OWNER);
    let admin = Phone::sign_up(&server, ADMIN);
    let member = Phone::sign_up(&server, MEMBER);
    server.wait(owner.v().create_organisation("Acme".into()));
    server.wait(owner.v().rename_organisation("Acme".into()));

    // Declined and cancelled invites leave nothing behind.
    server.wait(owner.v().invite_org_member(MEMBER.into(), OrgRole::Member));
    let invite = server.wait(member.v().get_organisation()).invitations[0].clone();
    server.wait(member.v().decline_org_invite(invite.org_id, invite.id));
    assert!(
        server
            .wait(member.v().get_organisation())
            .invitations
            .is_empty()
    );
    server.wait(owner.v().invite_org_member(MEMBER.into(), OrgRole::Member));
    let pending = server.wait(owner.v().list_org_members()).invites[0]
        .id
        .clone();
    server.wait(owner.v().cancel_org_invite(pending));
    assert!(
        server
            .wait(member.v().get_organisation())
            .invitations
            .is_empty()
    );

    // An admin, then a change of role.
    server.wait(owner.v().invite_org_member(ADMIN.into(), OrgRole::Admin));
    join(&server, &admin);
    let admin_id = admin.account_id(&server);
    assert_eq!(
        server
            .wait(admin.v().get_organisation())
            .organisation
            .unwrap()
            .role,
        OrgRole::Admin
    );
    server.wait(
        owner
            .v()
            .set_org_member_role(admin_id.clone(), OrgRole::Member),
    );
    server.wait(
        owner
            .v()
            .set_org_member_role(admin_id.clone(), OrgRole::Admin),
    );

    // Groups: rename, members in and out, delete.
    let group = server.wait(admin.v().create_org_group("Ops".into()));
    server.wait(
        admin
            .v()
            .rename_org_group(group.id.clone(), "Operations".into()),
    );
    server.wait(
        admin
            .v()
            .add_org_group_member(group.id.clone(), admin_id.clone()),
    );
    let groups = server.wait(owner.v().list_org_groups());
    assert_eq!(groups[0].name, "Operations");
    assert_eq!(groups[0].members, std::slice::from_ref(&admin_id));
    server.wait(
        admin
            .v()
            .remove_org_group_member(group.id.clone(), admin_id.clone()),
    );
    let vault = server.wait(admin.v().create_org_vault("Admin's".into()));
    server.wait(admin.v().link_org_vault_group(
        vault.id.clone(),
        group.id.clone(),
        VaultRole::Write,
    ));
    server.wait(
        admin
            .v()
            .unlink_org_vault_group(vault.id.clone(), group.id.clone()),
    );
    server.wait(admin.v().delete_org_group(group.id));
    assert!(server.wait(owner.v().list_org_groups()).is_empty());

    // The owner can't open the admin's vault: it shows part of its id instead of a name.
    let listed = server.wait(owner.v().list_org_vaults());
    let theirs = listed.iter().find(|v| v.id == vault.id).unwrap();
    assert_eq!(theirs.name, None);
    assert!(vault.id.ends_with(&theirs.short_id));
    assert_eq!(theirs.manager_count, 1);

    // Removing the only person who can manage a vault asks first.
    assert_eq!(
        server.fail(owner.v().remove_org_member(admin_id.clone(), false)),
        ErrorCode::OrgVaultOrphaned
    );
    server.wait(owner.v().remove_org_member(admin_id, true));
    assert!(
        server
            .wait(admin.v().get_organisation())
            .organisation
            .is_none()
    );

    // Settings only an owner sees: no SSO yet, SCIM tokens made and revoked.
    let sso = server.wait(owner.v().org_sso());
    assert!(sso.protocol.is_none() && !sso.callback_url.is_empty());
    let token = server.wait(owner.v().create_org_scim_token("Entra ID".into()));
    assert!(!token.secret.is_empty());
    let scim = server.wait(owner.v().org_scim());
    assert_eq!(scim.tokens[0].name, "Entra ID");
    assert!(scim.base_url.contains("scim"));
    server.wait(owner.v().revoke_org_scim_token(token.token.id));
    assert!(server.wait(owner.v().org_scim()).tokens.is_empty());
    assert_eq!(
        server.fail(
            owner
                .v()
                .save_org_saml(octapass_mobile::organisations::SamlSettings {
                    metadata_xml: Some("not metadata".into()),
                    entity_id: None,
                    sso_url: None,
                    certificates: Vec::new(),
                })
        ),
        ErrorCode::SsoConfig
    );
}
