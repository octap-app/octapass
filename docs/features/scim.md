---
title: SCIM provisioning
description: Let your identity provider invite, group and remove organisation members over SCIM 2.0. It manages who should be in your organisation, and it can never open a vault.
status: in-progress
sidebar:
  order: 10
---

:::note[In progress]
SCIM works in the server, and owners manage its tokens in the web vault, the Windows and Linux app and the CLI. It's tested with requests shaped like Microsoft Entra ID's and Okta's, not yet against those services themselves.
:::

An [organisation](/docs/features/organisations/) can let its identity provider keep its members and groups in step with the company directory, over SCIM 2.0. Microsoft Entra ID, Okta, OneLogin, JumpCloud and many others speak it.

## What it can and can't do

SCIM changes who **should** be in your organisation. It never moves a key.

| The provider… | What happens in Octa Pass |
|---|---|
| Adds a person | They get an invitation by email. They see your organisation's rules and accept on their own device, like any invitation. If they're already a member, they're linked to the provider straight away. |
| Puts a person in a group | Once they're a member, they're in that group. They get the group's vaults when someone who holds a vault's key reviews and gives access, as always. |
| Takes a person out of a group | They lose the vaults only that group gave them, at once, and those vaults are marked for a new key. |
| Deactivates or deletes a person | Their invitation is cancelled, or they're removed from the organisation at once, losing its vaults. Their own account and personal vault stay theirs. |
| Deletes a group | The group goes, and with it the vaults it gave. |

It can't:

- **Remove an owner.** An owner leaves by hand, so a broken provider or a stolen token can't lock your organisation out. The activity log records the attempt.
- **Open or share a vault.** The provider decides who's on the list; a key holder still checks each person's fingerprint and gives access on their own device.
- **Make anyone a member, or change roles.** Only the person can accept an invitation, and only an owner sets roles.
- **See or change groups you made in Octa Pass.** It manages only the groups it created.

Removing someone through SCIM goes ahead even if it leaves a vault with nobody able to manage it: access has to stop. Octa Pass records that in the activity log, and an owner can then delete the vault.

## Setting it up

You need to be an owner.

1. In Octa Pass, open **Organisation → Provisioning**. Copy the **SCIM base URL**.
2. Make a token and give it a name, such as the provider's. Copy it now: it's shown only once.
3. At your provider, add SCIM provisioning to your Octa Pass application with that base URL and the token as a bearer token (Entra ID calls it the secret token). Map the user name and the work email; Octa Pass invites the primary or work email, else the user name if it's an email address.
4. Assign the people and groups that should be in Octa Pass, and start provisioning.

From the command line:

```sh
octapass org scim token create "Entra ID"
octapass org scim show
octapass org scim token revoke <id>
```

Revoke a token you no longer use. An organisation can have up to 10.

## Users who already have an account

Provisioning matches people by email. Someone whose Octa Pass account uses another address gets an invitation at the address the provider sent; they can accept it after changing their account's email, or the provider can send the address they use. Someone in another organisation can't accept until they leave it, because an account is in one organisation at a time.

## For the provider's admin

- Endpoints: `/Users` and `/Groups` with `GET`, `POST`, `PUT`, `PATCH` and `DELETE`, plus `/ServiceProviderConfig`, `/ResourceTypes` and `/Schemas`.
- Filters: `userName`, `externalId`, `emails`, `displayName` and `id`, with `eq` only. Pages of up to 200.
- `PATCH` takes `add`, `replace` and `remove`, with or without a `path`, including `members[value eq "…"]`. Booleans sent as strings (`"False"`) are understood.
- No bulk operations, sorting, ETags or password changes. Attributes Octa Pass doesn't keep, such as titles and phone numbers, are accepted and ignored.
- Errors use SCIM's error format, with `scimType` where it applies (`uniqueness`, `invalidFilter`, `invalidValue`).

## What the server keeps

For each provisioned person: the user name, email, display name and the provider's `externalId`. For each provisioned group: its name and `externalId`. Tokens are kept only as hashes. These are organisation metadata, as group names already are. See [what the server sees](/docs/security/what-the-server-sees/).
