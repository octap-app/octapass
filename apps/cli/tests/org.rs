//! `octapass org`: running an organisation from the command line against a real server. The one
//! command that seals a key, `org access apply`, seals only to people confirmed with the
//! fingerprint computed on this device, in a terminal or with `--person EMAIL=FINGERPRINT`.

use crate::common;

use common::{Cli, OtherDevice, PASSWORD, Run, server_without_limits as server};
use serde_json::Value;

const OWNER: &str = "ada@example.com";
const MEMBER: &str = "grace@example.com";

fn waiting<'a>(reviews: &'a Value, vault_id: &str) -> &'a Value {
    reviews
        .as_array()
        .unwrap()
        .iter()
        .find(|review| review["vaultId"] == vault_id)
        .unwrap_or_else(|| panic!("nothing waiting for {vault_id}: {reviews}"))
}

#[tokio::test]
async fn an_owner_runs_the_organisation_from_the_cli() {
    let server = server().await;
    let owner_device = OtherDevice::sign_up_as(&server, OWNER).await;
    let member_device = OtherDevice::sign_up_as(&server, MEMBER).await;
    let owner = Cli::new(&server);
    owner.login_as(OWNER, &owner_device.secret_key).await.ok();
    let member = Cli::new(&server);
    member
        .login_as(MEMBER, &member_device.secret_key)
        .await
        .ok();

    owner.run(&["org", "create", "Acme"]).await.ok();
    let shown = owner.run(&["--json", "org", "show"]).await.ok().json();
    assert_eq!(shown["organisation"]["name"], "Acme");
    assert_eq!(shown["organisation"]["role"], "owner");

    // An invite, accepted by the member on their own computer.
    owner.run(&["org", "invite", MEMBER]).await.ok();
    let invited = member.run(&["--json", "org", "show"]).await.ok().json();
    let invite = invited["invitations"][0]["id"].as_str().unwrap().to_owned();
    let listed = member.run(&["org", "show"]).await.ok();
    assert!(
        listed.stdout.contains("from ada@example.com"),
        "{listed:#?}"
    );
    member.run(&["org", "join", &invite]).await.ok();
    let members = owner.run(&["org", "members"]).await.ok();
    assert!(members.stdout.contains(MEMBER), "{members:#?}");

    // A member can't run it.
    let refused = member.run(&["org", "group", "create", "Mine"]).await;
    assert_ne!(refused.code, 0);
    assert!(
        refused.stderr.contains("role doesn't allow"),
        "{refused:#?}"
    );

    // A group, a vault linked to it, and the reviewed step that seals.
    owner
        .run(&["org", "group", "create", "Engineering"])
        .await
        .ok();
    owner
        .run(&["org", "group", "add", "Engineering", MEMBER])
        .await
        .ok();
    let created = owner.run(&["org", "vault", "create", "Deploy"]).await.ok();
    let vault_id = created.stdout.trim().to_owned();
    owner
        .run(&[
            "org",
            "vault",
            "link",
            "Deploy",
            "Engineering",
            "--role",
            "read",
        ])
        .await
        .ok();
    member_device.vault.sync().await.unwrap();
    assert!(
        !member_device
            .vault
            .list_vaults()
            .unwrap()
            .iter()
            .any(|vault| vault.id == vault_id),
        "linking gives no key"
    );

    let reviews = owner
        .run(&["--json", "org", "access", "list"])
        .await
        .ok()
        .json();
    let review = waiting(&reviews, &vault_id);
    assert_eq!(review["canApply"], true);
    assert_eq!(review["vaultName"], "Deploy");
    let grant = &review["grants"][0];
    assert_eq!(grant["email"], MEMBER);
    let digits = grant["fingerprint"]["digits"].as_str().unwrap().to_owned();
    let expected = member_device.vault.my_fingerprint().unwrap().digits;
    assert_eq!(
        digits, expected,
        "computed on the owner's device from the member's keys"
    );

    // In a terminal: shown one by one, and nothing sealed without a yes.
    let declined = owner
        .run_with(
            &["org", "access", "apply", "Deploy"],
            Run {
                interactive: true,
                answers: vec!["n".into()],
                ..Run::default()
            },
        )
        .await
        .ok();
    assert!(
        declined.asked[0].contains(MEMBER) && declined.asked[0].contains(&digits),
        "{declined:#?}"
    );
    assert!(declined.stderr.contains("Nothing sealed"), "{declined:#?}");

    // Without a terminal, a script names the fingerprint it checked; a wrong one seals nothing.
    let wrong = owner
        .run(&[
            "org",
            "access",
            "apply",
            "Deploy",
            "--person",
            &format!("{MEMBER}=0000 0000 0000 0000 0000 0000"),
        ])
        .await;
    assert_ne!(wrong.code, 0);
    assert!(wrong.stderr.contains("Nothing was sealed"), "{wrong:#?}");

    let not_named = owner.run(&["org", "access", "apply", "Deploy"]).await;
    assert_ne!(not_named.code, 0, "no terminal and nobody named");

    let applied = owner
        .run(&[
            "org",
            "access",
            "apply",
            "Deploy",
            "--person",
            &format!("{MEMBER}={digits}"),
        ])
        .await
        .ok();
    assert!(
        applied.stderr.contains("Sealed the vault to 1 person"),
        "{applied:#?}"
    );

    member_device.vault.sync().await.unwrap();
    assert!(
        member_device
            .vault
            .list_vaults()
            .unwrap()
            .iter()
            .any(|vault| vault.id == vault_id)
    );

    // Removing the member takes the vault away at once and asks for a rotation.
    owner.run(&["org", "remove", MEMBER]).await.ok();
    let vaults = owner
        .run(&["--json", "org", "vault", "list"])
        .await
        .ok()
        .json();
    assert_eq!(vaults[0]["rotationPending"], true, "{vaults}");
    owner.run(&["org", "rotate", "Deploy"]).await.ok();
    let vaults = owner
        .run(&["--json", "org", "vault", "list"])
        .await
        .ok()
        .json();
    assert_eq!(vaults[0]["rotationPending"], false, "{vaults}");
    member_device.vault.sync().await.unwrap();
    assert!(
        !member_device
            .vault
            .list_vaults()
            .unwrap()
            .iter()
            .any(|vault| vault.id == vault_id)
    );
}

#[tokio::test]
async fn policies_sso_and_scim_are_set_from_the_cli() {
    let server = server().await;
    let owner_device = OtherDevice::sign_up_as(&server, OWNER).await;
    let owner = Cli::new(&server);
    owner.login_as(OWNER, &owner_device.secret_key).await.ok();
    owner.run(&["org", "create", "Acme"]).await.ok();

    let set = owner
        .run(&["org", "policy", "set", "disable-export", "on"])
        .await
        .ok();
    assert!(
        set.stdout.contains("disable-export            on"),
        "{set:#?}"
    );
    let bad = owner
        .run(&["org", "policy", "set", "no-such-thing", "on"])
        .await;
    assert_ne!(bad.code, 0);
    // Requiring SSO waits for a finished test sign-in.
    let early = owner
        .run(&["org", "policy", "set", "require-sso", "on"])
        .await;
    assert_ne!(early.code, 0);
    assert!(early.stderr.contains("test sign-in"), "{early:#?}");

    // SAML from a certificate file; the server never fetches the sign-in URL.
    let certificate = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../server/src/saml/fixtures/idp-cert.pem"
    );
    owner
        .run(&[
            "org",
            "sso",
            "saml",
            "--entity-id",
            "https://idp.example.com/saml",
            "--sso-url",
            "https://idp.example.com/sso",
            "--certificate",
            certificate,
        ])
        .await
        .ok();
    let shown = owner.run(&["org", "sso", "show"]).await.ok();
    assert!(shown.stdout.contains("SAML 2.0"), "{shown:#?}");
    assert!(shown.stdout.contains("SAML ACS (HTTP-POST)"), "{shown:#?}");
    let test = owner.run(&["org", "sso", "test"]).await.ok();
    assert!(test.stdout.contains("/v1/sso/start/"), "{test:#?}");

    // A SCIM token, shown once.
    let created = owner
        .run(&["--json", "org", "scim", "token", "create", "Okta"])
        .await
        .ok()
        .json();
    let secret = created["secret"].as_str().unwrap();
    assert!(secret.starts_with("opscim_"));
    let shown = owner.run(&["org", "scim", "show"]).await.ok();
    assert!(
        shown.stdout.contains("/v1/scim/v2") && shown.stdout.contains("Okta"),
        "{shown:#?}"
    );
    assert!(!shown.stdout.contains(secret));
    let id = created["id"].as_str().unwrap();
    owner
        .run(&["org", "scim", "token", "revoke", id])
        .await
        .ok();

    let events = owner.run(&["org", "events"]).await.ok();
    for event in [
        "scim-token-created",
        "scim-token-revoked",
        "sso-changed",
        "policies-changed",
    ] {
        assert!(events.stdout.contains(event), "{event}: {events:#?}");
    }

    // Deleting asks for the master password again.
    let deleted = owner
        .run_with(
            &[
                "--password-stdin",
                "org",
                "delete",
                "--confirm-name",
                "Acme",
            ],
            Run {
                stdin: format!("{PASSWORD}\n"),
                ..Run::default()
            },
        )
        .await
        .ok();
    assert!(deleted.stderr.contains("deleted"), "{deleted:#?}");
    let shown = owner.run(&["--json", "org", "show"]).await.ok().json();
    assert!(shown.get("organisation").is_none(), "{shown}");
}
