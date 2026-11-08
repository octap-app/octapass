---
title: Identity providers
description: "What a self-hosted Octa Pass server needs for single sign-on with OpenID Connect or SAML, and for SCIM provisioning: the public URL, the reverse proxy, network access and what to give your provider."
status: in-progress
sidebar:
  order: 10
---

:::note[In progress]
OpenID Connect, SAML and SCIM all work on a self-hosted server and are tested against stand-ins, not yet against real identity providers. Organisation owners set them up in the web vault, the Windows and Linux app or the CLI.
:::

[Single sign-on](/docs/features/single-sign-on/) and [SCIM provisioning](/docs/features/scim/) need nothing switched on: each organisation's owners set them up. What the server needs from you is an address your identity provider and your members' browsers can reach.

## The public URL

Set `OCTAPASS_PUBLIC_URL` to the address people use, such as `https://pass.example.com`. Every address you give a provider is built from it:

| What | Address |
|---|---|
| OpenID Connect redirect URI | `<public URL>/v1/sso/callback` |
| SAML entity ID and metadata | `<public URL>/v1/sso/saml/<organisation id>/metadata` |
| SAML assertion consumer service | `<public URL>/v1/sso/saml/<organisation id>/acs` |
| SCIM base URL | `<public URL>/v1/scim/v2` |

Each organisation's settings page shows them. If you change the public URL later, register the new addresses at the provider, run a test sign-in again, and expect members to link again if the SAML entity ID changed.

## The reverse proxy

Pass these through unchanged, with their methods and bodies:

- `GET /v1/sso/start/…` and `GET /v1/sso/callback`, for OpenID Connect.
- `GET /v1/sso/saml/…/metadata` and `POST /v1/sso/saml/…/acs`. The provider's page posts the browser's form there, from the provider's own address: don't block cross-site `POST`s to it, and keep bodies up to 1 MiB.
- Everything under `/v1/scim/v2/`, with the `Authorization` header. Providers send `GET`, `POST`, `PUT`, `PATCH` and `DELETE`.

Set `OCTAPASS_TRUST_PROXY=true` behind a proxy, so the per-address limits see real addresses. Wrong SCIM tokens and SSO pages count against those limits.

## Network access

- **OpenID Connect:** the server fetches the issuer's discovery document and calls its token endpoint, over HTTPS, at public addresses only. For a provider on your own network, set `OCTAPASS_SSO_PRIVATE_NETWORK=on` ([configuration](/docs/self-hosting/configuration/)).
- **SAML:** the server never contacts the provider. Owners paste its metadata, and the browser carries the sign-in. The provider only needs to reach the browser.
- **SCIM:** the provider calls your server, so it needs to reach the SCIM base URL. A cloud provider such as Entra ID or Okta needs a public address, or its own on-premises agent.

Plain `http://` addresses work only with `OCTAPASS_DEV_MODE`, for testing.

## What's stored

The OpenID Connect client secret is sealed under the server's secret. SAML certificates, SCIM token hashes and what SCIM provisions are organisation metadata in the database, backed up with it. None of it can open a vault: members still unlock with their master password and Secret Key, and keys reach people only through grants made on a key holder's device.

## Database migration

The SAML and SCIM tables come with migration `0015_org_provisioning`, applied on startup on SQLite and PostgreSQL alike. Existing OpenID Connect settings keep working unchanged.
