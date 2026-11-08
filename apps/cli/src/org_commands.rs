//! `octapass org …`: running an organisation from the command line, on the same engine as the
//! desktop app (`octapass-desktop-vault`, `vault/organisations.rs`). Roles, groups, policies, SSO
//! and SCIM are server-side settings and open nothing. The one command that seals a vault key,
//! `org access apply`, shows each person's fingerprint (computed here) and seals only to the people
//! confirmed, in a terminal one by one, or by `--person EMAIL=FINGERPRINT` in a script.

use octapass_api::{
    OrgGroupRecord, OrgPolicies, OrgRole, OrgSamlRequest, OrgSsoRecord, OrgSsoRequest, VaultRole,
};
use octapass_desktop_vault::vault::{ConfirmedGrant, OrgAccessReview, OrgMember, OrgVault};
use serde_json::{Value, json};

use super::*;
use crate::cli::{
    GroupRoleArg, OrgAccessCommand, OrgCommand, OrgGroupCommand, OrgPolicyCommand, OrgRoleArg,
    OrgScimCommand, OrgScimTokenCommand, OrgSsoCommand, OrgVaultCommand,
};

fn org_role(role: OrgRoleArg) -> OrgRole {
    match role {
        OrgRoleArg::Member => OrgRole::Member,
        OrgRoleArg::Admin => OrgRole::Admin,
        OrgRoleArg::Owner => OrgRole::Owner,
    }
}

fn group_role(role: GroupRoleArg) -> VaultRole {
    match role {
        GroupRoleArg::Read => VaultRole::Read,
        GroupRoleArg::Write => VaultRole::Write,
        GroupRoleArg::Manage => VaultRole::Manage,
    }
}

fn to_json(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("records serialize")
}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

fn parse_on_off(name: &str, value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Ok(true),
        "off" | "false" | "no" | "0" => Ok(false),
        _ => Err(CliError::usage(format!(
            "{name} is on or off, not `{value}`."
        ))),
    }
}

fn parse_optional_number(name: &str, value: &str) -> Result<Option<u32>> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| CliError::usage(format!("{name} is a number or `none`, not `{value}`.")))
}

/// Changes one policy by its command-line name.
fn set_policy(policies: &mut OrgPolicies, name: &str, value: &str) -> Result<()> {
    match name {
        "require-two-step" => policies.require_two_step = parse_on_off(name, value)?,
        "require-sso" => policies.require_sso = parse_on_off(name, value)?,
        "disable-share-links" => policies.disable_share_links = parse_on_off(name, value)?,
        "disable-emergency-access" => {
            policies.disable_emergency_access = parse_on_off(name, value)?;
        }
        "disable-export" => policies.disable_export = parse_on_off(name, value)?,
        "sso-max-age-hours" => {
            policies.sso_max_age_hours = value.parse().map_err(|_| {
                CliError::usage("sso-max-age-hours is a number of hours, 0 to 8760.")
            })?;
        }
        "max-auto-lock-minutes" => {
            policies.max_auto_lock_minutes = parse_optional_number(name, value)?
        }
        "min-password-length" => policies.min_password_length = parse_optional_number(name, value)?,
        _ => {
            return Err(CliError::usage(format!(
                "There's no policy called `{name}`. See `octapass org policy set --help`."
            )));
        }
    }
    Ok(())
}

fn policy_lines(policies: &OrgPolicies) -> Vec<String> {
    let number =
        |value: Option<u32>| value.map_or_else(|| "none".to_owned(), |value| value.to_string());
    vec![
        format!(
            "require-two-step          {}   (enforced by the server)",
            on_off(policies.require_two_step)
        ),
        format!(
            "require-sso               {}   (enforced by the server; owners are exempt)",
            on_off(policies.require_sso)
        ),
        format!("sso-max-age-hours         {}", policies.sso_max_age_hours),
        format!(
            "disable-share-links       {}   (enforced by the server)",
            on_off(policies.disable_share_links)
        ),
        format!(
            "disable-emergency-access  {}   (enforced by the server)",
            on_off(policies.disable_emergency_access)
        ),
        format!(
            "disable-export            {}   (applied by apps)",
            on_off(policies.disable_export)
        ),
        format!(
            "max-auto-lock-minutes     {}   (applied by apps)",
            number(policies.max_auto_lock_minutes)
        ),
        format!(
            "min-password-length       {}   (applied by apps)",
            number(policies.min_password_length)
        ),
    ]
}

/// `EMAIL=FINGERPRINT`, with the fingerprint's digits in any grouping.
fn parse_person(text: &str) -> Result<(String, String)> {
    let (who, digits) = text
        .split_once('=')
        .ok_or_else(|| CliError::usage(format!("`{text}` isn't EMAIL=FINGERPRINT.")))?;
    let digits: String = digits.chars().filter(char::is_ascii_digit).collect();
    if digits.len() != 24 {
        return Err(CliError::usage(format!(
            "The fingerprint for {who} must be its 24 digits, as `octapass org access list` shows them."
        )));
    }
    Ok((who.trim().to_lowercase(), digits))
}

fn compact(digits: &str) -> String {
    digits.chars().filter(char::is_ascii_digit).collect()
}

fn find_member<'a>(members: &'a [OrgMember], query: &str) -> Result<&'a OrgMember> {
    let query = query.trim().to_lowercase();
    members
        .iter()
        .find(|member| member.record.account_id == query || member.record.email == query)
        .ok_or_else(|| CliError::not_found(format!("No member \"{query}\".")))
}

fn find_group<'a>(groups: &'a [OrgGroupRecord], query: &str) -> Result<&'a OrgGroupRecord> {
    let mut found = groups
        .iter()
        .filter(|group| group.id == query || group.name.eq_ignore_ascii_case(query));
    match (found.next(), found.next()) {
        (Some(group), None) => Ok(group),
        (Some(_), Some(_)) => Err(CliError::new(
            Exit::Ambiguous,
            format!("More than one group is called \"{query}\". Use its id instead."),
        )),
        (None, _) => Err(CliError::not_found(format!("No group called \"{query}\"."))),
    }
}

/// By name (if this account can open it), id, or the short id an admin without the key sees.
fn find_org_vault<'a>(vaults: &'a [OrgVault], query: &str) -> Result<&'a OrgVault> {
    let mut found = vaults.iter().filter(|vault| {
        vault.record.id == query
            || vault.short_id == query
            || vault
                .name
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case(query))
    });
    match (found.next(), found.next()) {
        (Some(vault), None) => Ok(vault),
        (Some(_), Some(_)) => Err(CliError::new(
            Exit::Ambiguous,
            format!("More than one vault matches \"{query}\". Use its id instead."),
        )),
        (None, _) => Err(CliError::not_found(format!(
            "No organisation vault \"{query}\"."
        ))),
    }
}

fn vault_label(name: Option<&str>, short_id: &str) -> String {
    match name {
        Some(name) => format!("{name} ({short_id})"),
        None => format!("vault …{short_id} (you can't open it)"),
    }
}

impl App {
    pub(crate) async fn org(&mut self, command: OrgCommand) -> Result<Option<i32>> {
        if self.service_token().is_some() {
            return Err(CliError::usage(format!(
                "Organisations are run by people: unset {SERVICE_TOKEN_ENV} and sign in."
            )));
        }
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let vault = opened.vault.clone();
        match command {
            OrgCommand::Show => {
                let state = vault.get_organisation().await?;
                if self.global.json {
                    self.out_json(&to_json(&state))?;
                    return Ok(None);
                }
                match &state.organisation {
                    Some(org) => {
                        self.out(&format!("{}  ({})", org.name, org.id))?;
                        self.out(&format!(
                            "Your role: {}   Members: {}",
                            org.role.as_str(),
                            org.member_count
                        ))?;
                        if org.access_withheld {
                            self.out("Its vaults are withheld from you: you're breaking a policy (two-step sign-in).")?;
                        }
                        for line in policy_lines(&org.policies) {
                            self.out(&format!("  {line}"))?;
                        }
                    }
                    None => self.note("You're not in an organisation."),
                }
                for invitation in &state.invitations {
                    self.out(&format!(
                        "Invitation {} to {} as {}{}. Accept with `octapass org join {}`.",
                        invitation.id,
                        invitation.org_name,
                        invitation.role.as_str(),
                        invitation
                            .invited_by
                            .as_deref()
                            .map(|by| format!(", from {by}"))
                            .unwrap_or_else(|| ", from its identity provider".to_owned()),
                        invitation.id,
                    ))?;
                    for line in policy_lines(&invitation.policies) {
                        self.out(&format!("  {line}"))?;
                    }
                }
                if !state.invitations.is_empty() {
                    self.note("Joining shares nothing from your personal vault. The organisation's owners are entitled to every organisation vault.");
                }
            }
            OrgCommand::Create { name } => {
                let org = vault.create_organisation(&name).await?;
                self.note(&format!("Made {} with you as its owner.", org.name));
                if self.global.json {
                    self.out_json(&to_json(&org))?;
                }
            }
            OrgCommand::Rename { name } => {
                vault.rename_organisation(&name).await?;
                self.note("Renamed.");
            }
            OrgCommand::Delete { confirm_name } => {
                let password = self.master_password()?;
                vault.delete_organisation(password, &confirm_name).await?;
                self.note("The organisation and all its vaults were deleted.");
            }
            OrgCommand::Join { invite } => {
                let state = vault.get_organisation().await?;
                let invitation = state
                    .invitations
                    .iter()
                    .find(|invitation| invitation.id == invite)
                    .ok_or_else(|| {
                        CliError::not_found("No such invitation. See `octapass org show`.")
                    })?;
                let org = vault.accept_org_invite(&invitation.org_id, &invite).await?;
                self.note(&format!(
                    "You joined {} as {}. Its policies apply from now on.",
                    org.name,
                    org.role.as_str()
                ));
            }
            OrgCommand::Decline { invite } => {
                let state = vault.get_organisation().await?;
                let invitation = state
                    .invitations
                    .iter()
                    .find(|invitation| invitation.id == invite)
                    .ok_or_else(|| {
                        CliError::not_found("No such invitation. See `octapass org show`.")
                    })?;
                vault
                    .decline_org_invite(&invitation.org_id, &invite)
                    .await?;
                self.note("Declined.");
            }
            OrgCommand::Leave { orphan_vaults } => {
                vault.leave_organisation(orphan_vaults).await?;
                self.note("You left the organisation. Its vaults are gone from this device.");
            }
            OrgCommand::Members => {
                let listed = vault.list_org_members().await?;
                if self.global.json {
                    self.out_json(&to_json(&listed))?;
                    return Ok(None);
                }
                let rows: Vec<[String; 5]> = listed
                    .members
                    .iter()
                    .map(|member| {
                        let you = if member.is_you { " (you)" } else { "" };
                        [
                            format!("{}{you}", member.record.email),
                            member.record.role.as_str().to_owned(),
                            on_off(member.record.two_step).to_owned(),
                            if member.record.sso_linked {
                                "linked"
                            } else {
                                "—"
                            }
                            .to_owned(),
                            member.record.account_id.clone(),
                        ]
                    })
                    .collect();
                for line in format_table(["EMAIL", "ROLE", "TWO-STEP", "SSO", "ACCOUNT ID"], &rows)
                {
                    self.out(&line)?;
                }
                if !listed.invites.is_empty() {
                    self.out("")?;
                    let rows: Vec<[String; 4]> = listed
                        .invites
                        .iter()
                        .map(|invite| {
                            [
                                invite.email.clone(),
                                invite.role.as_str().to_owned(),
                                invite.expires_at.clone(),
                                invite.id.clone(),
                            ]
                        })
                        .collect();
                    for line in format_table(["INVITED", "ROLE", "EXPIRES", "INVITE ID"], &rows) {
                        self.out(&line)?;
                    }
                }
            }
            OrgCommand::Invite { email, admin } => {
                let role = if admin {
                    OrgRole::Admin
                } else {
                    OrgRole::Member
                };
                vault.invite_org_member(&email, role).await?;
                self.note(&format!(
                    "Invited {email} as {}, if they aren't a member already.",
                    role.as_str()
                ));
            }
            OrgCommand::Uninvite { invite } => {
                let listed = vault.list_org_members().await?;
                let wanted = invite.trim().to_lowercase();
                let found = listed
                    .invites
                    .iter()
                    .find(|pending| pending.id == wanted || pending.email == wanted)
                    .ok_or_else(|| CliError::not_found("No such invite."))?;
                vault.cancel_org_invite(&found.id).await?;
                self.note(&format!("Cancelled the invite for {}.", found.email));
            }
            OrgCommand::Role { member, role } => {
                let listed = vault.list_org_members().await?;
                let target = find_member(&listed.members, &member)?;
                vault
                    .set_org_member_role(&target.record.account_id, org_role(role))
                    .await?;
                self.note(&format!(
                    "{} is now {}.",
                    target.record.email,
                    org_role(role).as_str()
                ));
                if org_role(role) == OrgRole::Owner {
                    self.note("As an owner they're entitled to every organisation vault: a key holder applies that with `octapass org access apply`.");
                }
            }
            OrgCommand::Remove {
                member,
                orphan_vaults,
            } => {
                let listed = vault.list_org_members().await?;
                let target = find_member(&listed.members, &member)?;
                let email = target.record.email.clone();
                vault
                    .remove_org_member(&target.record.account_id, orphan_vaults)
                    .await?;
                self.note(&format!("Removed {email}. They lost its vaults at once; rotate their keys with `octapass org access list` and `octapass org rotate`."));
            }
            OrgCommand::Group(command) => self.org_group(&vault, command).await?,
            OrgCommand::Vault(command) => self.org_vault(&vault, command).await?,
            OrgCommand::Access(command) => self.org_access(&vault, command).await?,
            OrgCommand::Rotate { vault: query } => {
                let vaults = vault.list_org_vaults().await?;
                let target = find_org_vault(&vaults, &query)?;
                vault.rotate_org_vault(&target.record.id).await?;
                self.note("The vault has a new key. People who lost access can't open anything added from now on.");
            }
            OrgCommand::Policy(command) => {
                let org = vault
                    .get_organisation()
                    .await?
                    .organisation
                    .ok_or_else(|| CliError::not_found("You're not in an organisation."))?;
                match command {
                    OrgPolicyCommand::Show => {
                        if self.global.json {
                            self.out_json(&to_json(&org.policies))?;
                        } else {
                            for line in policy_lines(&org.policies) {
                                self.out(&line)?;
                            }
                        }
                    }
                    OrgPolicyCommand::Set { name, value } => {
                        let mut policies = org.policies;
                        set_policy(&mut policies, &name, &value)?;
                        let saved = vault.set_org_policies(&policies).await?;
                        for line in policy_lines(&saved) {
                            self.out(&line)?;
                        }
                    }
                }
            }
            OrgCommand::Sso(command) => self.org_sso(&vault, command).await?,
            OrgCommand::Scim(command) => self.org_scim(&vault, command).await?,
            OrgCommand::Events => {
                let events = vault.org_events().await?;
                if self.global.json {
                    self.out_json(&to_json(&events))?;
                    return Ok(None);
                }
                let rows: Vec<[String; 4]> = events
                    .iter()
                    .map(|event| {
                        let actor = match &event.actor {
                            Some(actor) => actor.clone(),
                            None if event.event_type.starts_with("scim-") => {
                                "identity provider".to_owned()
                            }
                            None => "—".to_owned(),
                        };
                        [
                            event.created_at.clone(),
                            event.event_type.clone(),
                            actor,
                            event.subject.clone().unwrap_or_default(),
                        ]
                    })
                    .collect();
                for line in format_table(["WHEN", "EVENT", "BY", "SUBJECT"], &rows) {
                    self.out(&line)?;
                }
            }
        }
        Ok(None)
    }

    async fn org_group(&mut self, vault: &Vault, command: OrgGroupCommand) -> Result<()> {
        let groups = vault.list_org_groups().await?;
        match command {
            OrgGroupCommand::List => {
                if self.global.json {
                    return self.out_json(&to_json(&groups));
                }
                let members = vault.list_org_members().await?.members;
                let email = |id: &String| {
                    members
                        .iter()
                        .find(|member| &member.record.account_id == id)
                        .map_or_else(|| id.clone(), |member| member.record.email.clone())
                };
                for group in &groups {
                    let people: Vec<String> = group.members.iter().map(email).collect();
                    self.out(&format!("{} ({})", group.name, group.id))?;
                    self.out(&format!(
                        "  {}",
                        if people.is_empty() {
                            "nobody yet".to_owned()
                        } else {
                            people.join(", ")
                        }
                    ))?;
                }
                if groups.is_empty() {
                    self.note("No groups.");
                }
            }
            OrgGroupCommand::Create { name } => {
                let group = vault.create_org_group(&name).await?;
                self.note(&format!("Made {}.", group.name));
                if self.global.json {
                    self.out_json(&to_json(&group))?;
                } else {
                    self.out(&group.id)?;
                }
            }
            OrgGroupCommand::Rename { group, name } => {
                let target = find_group(&groups, &group)?;
                vault.rename_org_group(&target.id, &name).await?;
                self.note("Renamed.");
            }
            OrgGroupCommand::Delete { group } => {
                let target = find_group(&groups, &group)?;
                vault.delete_org_group(&target.id).await?;
                self.note("Deleted. Its members lost the vaults only it gave them.");
            }
            OrgGroupCommand::Add { group, member } => {
                let target = find_group(&groups, &group)?;
                let members = vault.list_org_members().await?.members;
                let person = find_member(&members, &member)?;
                vault
                    .add_org_group_member(&target.id, &person.record.account_id)
                    .await?;
                self.note(&format!(
                    "Added {} to {}. They get its vaults when a key holder runs `octapass org access apply`.",
                    person.record.email, target.name
                ));
            }
            OrgGroupCommand::Remove { group, member } => {
                let target = find_group(&groups, &group)?;
                let members = vault.list_org_members().await?.members;
                let person = find_member(&members, &member)?;
                vault
                    .remove_org_group_member(&target.id, &person.record.account_id)
                    .await?;
                self.note(&format!(
                    "Took {} out of {}. They lost the vaults only it gave them.",
                    person.record.email, target.name
                ));
            }
        }
        Ok(())
    }

    async fn org_vault(&mut self, vault: &Vault, command: OrgVaultCommand) -> Result<()> {
        match command {
            OrgVaultCommand::List => {
                let vaults = vault.list_org_vaults().await?;
                if self.global.json {
                    return self.out_json(&to_json(&vaults));
                }
                let groups = vault.list_org_groups().await?;
                let group_name = |id: &str| {
                    groups
                        .iter()
                        .find(|group| group.id == id)
                        .map_or(id, |group| group.name.as_str())
                        .to_owned()
                };
                let rows: Vec<[String; 5]> = vaults
                    .iter()
                    .map(|entry| {
                        let linked: Vec<String> = entry
                            .record
                            .groups
                            .iter()
                            .map(|link| {
                                format!("{} ({})", group_name(&link.group_id), link.role.as_str())
                            })
                            .collect();
                        [
                            vault_label(entry.name.as_deref(), &entry.short_id),
                            entry.record.member_count.to_string(),
                            entry.record.manager_count.to_string(),
                            if entry.record.rotation_pending {
                                "rotate"
                            } else {
                                "—"
                            }
                            .to_owned(),
                            if linked.is_empty() {
                                "—".to_owned()
                            } else {
                                linked.join(", ")
                            },
                        ]
                    })
                    .collect();
                for line in format_table(["VAULT", "MEMBERS", "MANAGERS", "KEY", "GROUPS"], &rows) {
                    self.out(&line)?;
                }
            }
            OrgVaultCommand::Create { name } => {
                let created = vault.create_org_vault(&name).await?;
                self.note(&format!(
                    "Made {}. Link groups to it, then apply access.",
                    created.name
                ));
                self.out(&created.id)?;
            }
            OrgVaultCommand::Delete { vault: query } => {
                let vaults = vault.list_org_vaults().await?;
                let target = find_org_vault(&vaults, &query)?.record.id.clone();
                let password = self.master_password()?;
                vault.delete_org_vault(password, &target).await?;
                self.note("Deleted the vault and everything in it.");
            }
            OrgVaultCommand::Link {
                vault: query,
                group,
                role,
            } => {
                let vaults = vault.list_org_vaults().await?;
                let target = find_org_vault(&vaults, &query)?.record.id.clone();
                let groups = vault.list_org_groups().await?;
                let linked = find_group(&groups, &group)?;
                vault
                    .link_org_vault_group(&target, &linked.id, group_role(role))
                    .await?;
                self.note(&format!(
                    "Linked {}. Its members get the vault when a key holder runs `octapass org access apply`.",
                    linked.name
                ));
            }
            OrgVaultCommand::Unlink {
                vault: query,
                group,
            } => {
                let vaults = vault.list_org_vaults().await?;
                let target = find_org_vault(&vaults, &query)?.record.id.clone();
                let groups = vault.list_org_groups().await?;
                let linked = find_group(&groups, &group)?;
                vault.unlink_org_vault_group(&target, &linked.id).await?;
                self.note("Unlinked. Members who had the vault only through this group lost it.");
            }
        }
        Ok(())
    }

    fn print_review(&mut self, review: &OrgAccessReview) -> Result<()> {
        let label = vault_label(review.vault_name.as_deref(), &review.short_id);
        let state = match (review.can_apply, review.rotate) {
            (true, true) => "you can apply this; the key should be rotated",
            (true, false) => "you can apply this",
            (false, true) => "a vault manager has to apply this and rotate the key",
            (false, false) => "a vault manager has to apply this",
        };
        self.out(&format!("{label}: {state}"))?;
        for grant in &review.grants {
            let check = if grant.key_changed {
                "KEYS CHANGED since you verified them"
            } else if grant.verified {
                "verified on this device"
            } else {
                "not verified: compare with them"
            };
            let upgrade = if grant.upgrade {
                ", replacing a lower role"
            } else {
                ""
            };
            self.out(&format!(
                "  {} as {}{upgrade}",
                grant.email,
                grant.role.as_str()
            ))?;
            self.out(&format!(
                "    fingerprint {}  ({check})",
                grant.fingerprint.digits
            ))?;
        }
        Ok(())
    }

    async fn org_access(&mut self, vault: &Vault, command: OrgAccessCommand) -> Result<()> {
        let reviews = vault.org_access().await?;
        match command {
            OrgAccessCommand::List => {
                if self.global.json {
                    return self.out_json(&to_json(&reviews));
                }
                if reviews.is_empty() {
                    self.note("Nothing is waiting.");
                }
                for review in &reviews {
                    self.print_review(review)?;
                }
            }
            OrgAccessCommand::Apply {
                vault: query,
                people,
            } => {
                let wanted = query.to_lowercase();
                let review = reviews
                    .iter()
                    .find(|review| {
                        review.vault_id == query
                            || review.short_id == query
                            || review
                                .vault_name
                                .as_deref()
                                .is_some_and(|name| name.to_lowercase() == wanted)
                    })
                    .ok_or_else(|| {
                        CliError::not_found(format!("Nothing is waiting for \"{query}\"."))
                    })?
                    .clone();
                if !review.can_apply {
                    return Err(CliError::usage(
                        "You don't hold this vault's key with the manage role: a vault manager has to apply it.",
                    ));
                }
                let confirmed = if people.is_empty() {
                    if !self.context.terminal.interactive() {
                        return Err(CliError::usage(
                            "Name each person with --person EMAIL=FINGERPRINT, or run this in a terminal to review them one by one.",
                        ));
                    }
                    self.print_review(&review)?;
                    self.note("The list comes from the server. Seal only to people you expect, and compare fingerprints with them if you haven't.");
                    let mut confirmed = Vec::new();
                    for grant in review.grants.iter().filter(|grant| !grant.key_changed) {
                        let prompt = format!(
                            "Seal to {} ({}, {})? [y/N] ",
                            grant.email,
                            grant.role.as_str(),
                            grant.fingerprint.digits
                        );
                        let answer = self.context.terminal.ask(&prompt).map_err(input_error)?;
                        if matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
                            confirmed.push(ConfirmedGrant {
                                account_id: grant.account_id.clone(),
                                fingerprint: grant.fingerprint.clone(),
                            });
                        }
                    }
                    confirmed
                } else {
                    let mut confirmed = Vec::new();
                    for person in &people {
                        let (who, digits) = parse_person(person)?;
                        let grant = review
                            .grants
                            .iter()
                            .find(|grant| grant.email == who || grant.account_id == who)
                            .ok_or_else(|| {
                                CliError::not_found(format!("{who} isn't waiting for this vault."))
                            })?;
                        if compact(&grant.fingerprint.digits) != digits {
                            return Err(CliError::usage(format!(
                                "{who}'s keys give fingerprint {}, not the one you named. Nothing was sealed.",
                                grant.fingerprint.digits
                            )));
                        }
                        confirmed.push(ConfirmedGrant {
                            account_id: grant.account_id.clone(),
                            fingerprint: grant.fingerprint.clone(),
                        });
                    }
                    confirmed
                };
                if confirmed.is_empty() {
                    self.note("Nothing sealed.");
                    return Ok(());
                }
                let count = vault.apply_org_access(&review.vault_id, &confirmed).await?;
                self.note(&format!(
                    "Sealed the vault to {count} {}.",
                    if count == 1 { "person" } else { "people" }
                ));
                if review.rotate {
                    self.note(&format!(
                        "Someone lost access to it: run `octapass org rotate {}` next.",
                        review.vault_id
                    ));
                }
            }
        }
        Ok(())
    }

    fn print_sso(&mut self, record: &OrgSsoRecord) -> Result<()> {
        if self.global.json {
            return self.out_json(&to_json(record));
        }
        match (record.protocol, &record.saml) {
            (Some(octapass_api::SsoProtocol::Saml), Some(saml)) => {
                self.out("SAML 2.0")?;
                self.out(&format!("  Identity provider  {}", saml.entity_id))?;
                self.out(&format!("  Sign-in URL        {}", saml.sso_url))?;
                for certificate in &saml.certificates {
                    let expiry = certificate.not_after.as_deref().unwrap_or("unknown");
                    self.out(&format!(
                        "  Certificate        {} (expires {expiry})",
                        certificate.sha256
                    ))?;
                }
            }
            (Some(_), _) => {
                self.out("OpenID Connect")?;
                self.out(&format!(
                    "  Issuer             {}",
                    record.issuer.as_deref().unwrap_or("—")
                ))?;
                self.out(&format!(
                    "  Client id          {}",
                    record.client_id.as_deref().unwrap_or("—")
                ))?;
                self.out(&format!(
                    "  Client secret      {}",
                    if record.has_client_secret {
                        "saved"
                    } else {
                        "none (public client)"
                    }
                ))?;
            }
            (None, _) => self.out("No SSO settings.")?,
        }
        self.out(&format!(
            "  Tested             {}",
            record
                .tested_at
                .as_deref()
                .unwrap_or("not since the last change")
        ))?;
        self.out("Register at your identity provider:")?;
        self.out(&format!(
            "  OpenID Connect redirect URI  {}",
            record.callback_url
        ))?;
        let sp = &record.saml_service_provider;
        self.out(&format!("  SAML entity id / metadata    {}", sp.entity_id))?;
        self.out(&format!("  SAML ACS (HTTP-POST)         {}", sp.acs_url))?;
        Ok(())
    }

    async fn org_sso(&mut self, vault: &Vault, command: OrgSsoCommand) -> Result<()> {
        match command {
            OrgSsoCommand::Show => {
                let record = vault.org_sso().await?;
                self.print_sso(&record)?;
            }
            OrgSsoCommand::Oidc {
                issuer,
                client_id,
                client_secret,
            } => {
                let client_secret = if client_secret {
                    let secret = self.file_password("Client secret: ", false)?;
                    Some(secret.to_string())
                } else {
                    None
                };
                let record = vault
                    .save_org_sso(&OrgSsoRequest {
                        issuer,
                        client_id,
                        client_secret,
                    })
                    .await?;
                self.note("Saved. Run `octapass org sso test` before requiring SSO.");
                self.print_sso(&record)?;
            }
            OrgSsoCommand::Saml {
                metadata,
                entity_id,
                sso_url,
                certificate,
            } => {
                let read = |path: &PathBuf| {
                    fs::read_to_string(path).map_err(|error| {
                        CliError::usage(format!("Couldn't read {}: {error}", path.display()))
                    })
                };
                let request = match metadata {
                    Some(path) => OrgSamlRequest {
                        metadata_xml: Some(read(&path)?),
                        ..OrgSamlRequest::default()
                    },
                    None => {
                        if entity_id.is_none() || certificate.is_empty() {
                            return Err(CliError::usage(
                                "Give --metadata FILE, or --entity-id, --sso-url and --certificate FILE.",
                            ));
                        }
                        OrgSamlRequest {
                            metadata_xml: None,
                            entity_id,
                            sso_url,
                            certificates: certificate.iter().map(read).collect::<Result<_>>()?,
                        }
                    }
                };
                let record = vault.save_org_saml(&request).await?;
                self.note("Saved. Run `octapass org sso test` before requiring SSO.");
                self.print_sso(&record)?;
            }
            OrgSsoCommand::Test => {
                let url = vault.test_org_sso().await?;
                self.note("Open this in a browser and sign in at your identity provider. It works for 10 minutes.");
                self.out(&url)?;
            }
            OrgSsoCommand::Remove => {
                vault.remove_org_sso().await?;
                self.note("Removed the SSO settings and every member's link to the provider.");
            }
        }
        Ok(())
    }

    async fn org_scim(&mut self, vault: &Vault, command: OrgScimCommand) -> Result<()> {
        match command {
            OrgScimCommand::Show => {
                let scim = vault.org_scim().await?;
                if self.global.json {
                    return self.out_json(&to_json(&scim));
                }
                self.out(&format!("SCIM base URL: {}", scim.base_url))?;
                let rows: Vec<[String; 4]> = scim
                    .tokens
                    .iter()
                    .map(|token| {
                        [
                            token.name.clone(),
                            token.created_at.clone(),
                            token
                                .last_used_at
                                .clone()
                                .unwrap_or_else(|| "never".to_owned()),
                            token.id.clone(),
                        ]
                    })
                    .collect();
                if rows.is_empty() {
                    self.note(
                        "No tokens yet: make one with `octapass org scim token create NAME`.",
                    );
                }
                for line in format_table(["NAME", "CREATED", "LAST USED", "ID"], &rows) {
                    self.out(&line)?;
                }
            }
            OrgScimCommand::Token {
                command: OrgScimTokenCommand::Create { name },
            } => {
                let created = vault.create_org_scim_token(&name).await?;
                if self.context.stdout_is_terminal {
                    self.note("Warning: showing the token in the terminal. It's shown only now.");
                }
                self.note("Give it to your identity provider as the SCIM bearer token. It can invite and remove members and groups, never open a vault. Octa Pass can't show it again.");
                if self.global.json {
                    let mut value = to_json(&created.token);
                    value["secret"] = json!(created.secret);
                    self.out_json(&value)?;
                } else {
                    self.out(&created.secret)?;
                }
            }
            OrgScimCommand::Token {
                command: OrgScimTokenCommand::Revoke { id },
            } => {
                vault.revoke_org_scim_token(&id).await?;
                self.note("Revoked. The identity provider can't use it any more.");
            }
        }
        Ok(())
    }
}
