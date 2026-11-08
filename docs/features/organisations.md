---
title: Organisations
description: Run a team on Octa Pass with organisations, groups, policies and shared vaults, while the server and your admins still can't read anyone's passwords.
status: in-progress
sidebar:
  order: 8
---

:::note[In progress]
The server and the web vault have organisations, groups, policies and [single sign-on](/docs/features/single-sign-on/). Organisation vaults open in every app, because they are shared vaults. Running an organisation happens in the web vault for now, and the iPhone, iPad, Mac and Android apps have no single sign-on step yet. SCIM and SAML aren't built. See [not yet](#not-yet).
:::

An organisation gathers a team's people, shared vaults and rules. It adds no new key, so being an admin opens nothing: nobody can read a vault without a key sealed to them on a device that already holds it.

## Roles

| Role | Can do |
|---|---|
| **Member** | Use the vaults they've been given |
| **Admin** | Invite and remove members, manage groups, create vaults and link groups to them |
| **Owner** | All of that, plus policies, single sign-on, roles and deleting the organisation |

Each account is in one organisation at a time. An account can be in a family as well.

Members keep their own account. Nobody in an organisation can read a personal vault or reset a master password, and anyone can leave. The last owner has to make someone else an owner, or delete the organisation.

## Inviting people

Admins invite by email, as a member or an admin. An invitation can reach an address with no account yet: whoever signs up with that address finds it waiting. Invitations last 14 days. The app shows the organisation's rules before you accept, so joining is an informed choice.

## Vaults and groups

An organisation vault is a [shared vault](/docs/features/sharing/) that belongs to the organisation. Its name is encrypted inside it, so an admin who can't open it sees only part of its id.

A group is a list of people. Link a group to a vault with a role (view, edit or manage), and everyone in the group should have that vault.

**Should have** matters here. The server knows who is in a group, but it can't give anyone a key. So adding someone puts them on a list for review:

1. Someone who can manage the vault opens **Organisation**, and sees **Access to review**.
2. Their device shows each person with a fingerprint it worked out itself.
3. They confirm the people they recognise, and their device seals the vault's key to exactly those people.

That review can't be skipped. The list comes from the server, so sealing to it blindly would let a hostile server add itself. Compare fingerprints with someone if you can: it's what [sharing](/docs/features/sharing/) relies on too.

**Taking access away doesn't wait.** Leaving a group or the organisation, or a group being unlinked, stops the server handing over that vault at once. A manager then changes the vault's key, because that person may still have the old one. Lowering a role also removes the vault at once, until a manager gives the lower role, because a role is part of the signed grant and the server can't rewrite one.

### Owners and leavers

Organisation owners are entitled to every organisation vault, as vault owners. Otherwise someone leaving could take a vault with them if they were its only key holder. This reaches organisation vaults only, and it still goes through the same review.

If a change would leave a vault with nobody able to manage it, Octa Pass stops and says so. Going ahead leaves that vault unreadable to everyone, and an owner can only delete it. Zero-knowledge means there's no way around that.

## Policies

Owners set these under **Organisation → Policies**. A policy restricts what members do. It can never move a key.

### Enforced by the server

These hold whatever app someone uses.

| Policy | What it does |
|---|---|
| Require two-step sign-in | Organisation vaults are withheld from anyone without [two-step sign-in](/docs/features/two-step-sign-in/), and they can't turn it off. Their personal vault isn't touched. |
| Require single sign-on | Members also sign in through your [identity provider](/docs/features/single-sign-on/). |
| Turn off share links | Members can't create [share links](/docs/features/sharing/). |
| Turn off emergency access | Members can't add [emergency contacts](/docs/features/emergency-access/), and existing contacts can't reach organisation vaults. |

### Applied by the apps

These rely on the app following them, and a modified app can ignore them. Don't rely on them alone.

| Policy | What it does |
|---|---|
| Leave organisation vaults out of exports | Exports hold personal vaults only. |
| Longest auto-lock | Members can't choose a longer auto-lock, or none. |
| Shortest master password | Checked when a new password is set. The server never sees a master password, so it can't check. |

The web vault applies these today. The other apps don't apply all of them yet. See [what's not built yet](#not-yet).

## Activity

Admins can see who did what under **Activity**: invitations, members, roles, groups, vault links and policy changes, kept for a year. It never holds vault contents.

## What the server sees

Organisation names, group names, who is in which group, roles, policies and the activity log are plain metadata on the server: it needs them to route access and enforce policy. Don't put secrets in them. See [what the server sees](/docs/security/what-the-server-sees/).

## Deleting

Deleting an organisation needs your master password and its typed name, and deletes all its vaults for everyone. Members keep their accounts and personal vaults.

If the only owner deletes their account, the longest-serving admin (or else member) becomes owner, and vaults other people are in live on. An organisation goes with its last member.

## Not yet

- Running an organisation from the desktop, phone or extension apps. The sign-in step works in the web vault, extension, Windows and Linux app and CLI; the iPhone, iPad, Mac and Android apps have it in their core but no screen yet.
- Provisioning from an identity provider (SCIM), and SAML. Only OpenID Connect is built.
- Admin account recovery. It would be a path to a member's keys, so it isn't offered.
