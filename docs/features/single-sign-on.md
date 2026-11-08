---
title: Single sign-on
description: Connect Octa Pass to your identity provider with OpenID Connect or SAML 2.0. SSO adds a sign-in step, and your master password and Secret Key still unlock your vault.
status: in-progress
sidebar:
  order: 9
---

:::note[In progress]
Single sign-on works in the server and the web vault, and the browser extension, the Windows and Linux app and the CLI can finish the sign-in step. The Mac, iPhone, iPad and Android apps can't yet: they say where to sign in instead. It has been tested against a small OpenID Connect provider and a stand-in SAML provider in the test suite, not yet against Okta, Entra ID, Google Workspace, ADFS or Keycloak themselves.
:::

An [organisation](/docs/features/organisations/) can ask its members to sign in through its identity provider, using OpenID Connect or SAML 2.0. Okta, Microsoft Entra ID, Google Workspace, Keycloak, Authentik, ADFS and most others speak one or both. Prefer OpenID Connect when your provider offers both: it's simpler, and SAML's XML signatures are where SAML implementations tend to go wrong.

## SSO is for signing in, not for unlocking

**Your master password and Secret Key still unlock your vault, on every device.** SSO decides only whether a sign-in may go on.

That's deliberate. An identity provider's answer is a statement, not a secret: anyone who runs or breaks into the provider can produce it. If that answer could release a key, they'd have the key too, and Octa Pass would no longer be zero-knowledge. So SSO adds a step after your master password and never replaces it. Neither your identity provider nor the Octa Pass server gets any path to your vault.

The most a hostile provider can do is refuse sign-ins, or wave through one that already had your master password and Secret Key.

## Signing in

1. Enter your email, master password and Secret Key as usual.
2. Octa Pass asks you to open your organisation's sign-in page in a browser.
3. Sign in there. The last page shows a 6-digit code, the device it's for and a warning.
4. Type the code into Octa Pass. If your account has [two-step sign-in](/docs/features/two-step-sign-in/), that comes next.

The code ties that browser to your device. If someone stole your master password and Secret Key and sent you the link, finishing it would show the code on your screen, not theirs. Read the device name on that page, and never share the code.

Unlocking afterwards works as before, including [device unlock](/docs/features/biometric-unlock/).

Every so often a device has to go through the provider again: 7 days by default, set by the organisation. Someone disabled at the provider is locked out within that time. Removing them from the organisation works at once.

## Setting it up with OpenID Connect

You need to be an owner. From the command line it's `octapass org sso oidc --issuer … --client-id … --client-secret`, then `octapass org sso test`.

1. At your provider, create an OpenID Connect web application using the authorization code flow, with scopes `openid` and `email`.
2. In Octa Pass, open **Organisation → Single sign-on**, and register the **redirect URI** shown there at your provider.
3. Enter the issuer URL, client ID and client secret, and save. The server fetches the issuer's discovery document, so a wrong address fails here. A public client with PKCE needs no secret.
4. Choose **Test sign-in** and finish it in the browser.
5. Under **Policies**, turn on **Require single sign-on**.

Saving new settings needs a new test, and they can't change while single sign-on is required.

**Owners are exempt** from the step, so a provider outage or a wrong setting can't lock your organisation out.

The first time a member signs in, Octa Pass links the provider's account to theirs when the emails match and the provider doesn't mark the email unverified. After that the provider's subject id decides. Use a work email for the Octa Pass account, or the link can't be made. Switching to another provider, or between OpenID Connect and SAML, clears every link, and each member links again at their next sign-in.

## Setting it up with SAML

You need to be an owner.

1. In Octa Pass, open **Organisation → Single sign-on** and choose **SAML 2.0**. It shows what to register at your provider: the **entity ID** (also the address of Octa Pass's metadata, for providers that import it) and the **assertion consumer service URL**, which uses the HTTP-POST binding.
2. At your provider, create a SAML application with those two values. Have it sign the assertion or the whole response with SHA-256 (the default almost everywhere), and send a persistent or email NameID, plus the email as the NameID or an `email` or `mail` attribute. Encrypted assertions aren't supported: the response travels over HTTPS.
3. Paste the provider's metadata XML into Octa Pass, or fill in its entity ID, its single sign-on URL (HTTP-Redirect) and its signing certificate. Save.
4. Choose **Test sign-in**, then turn on **Require single sign-on** under **Policies**, as for OpenID Connect.

From the command line: `octapass org sso saml --metadata idp-metadata.xml`, or `--entity-id … --sso-url … --certificate idp.pem`, then `octapass org sso test`.

Only the certificates you saved are trusted: a key sent along with a sign-in is ignored. While your provider rolls its key over, save both certificates (its metadata usually lists both). Sign-ins started from the provider's own portal (IdP-initiated) don't work: start from Octa Pass.

## Self-hosting

With OpenID Connect the server talks to your provider directly, over HTTPS, and only to public addresses. For a provider on your own network, set [`OCTAPASS_SSO_PRIVATE_NETWORK=on`](/docs/self-hosting/configuration/). With SAML the server never contacts your provider: the browser carries everything.

`OCTAPASS_PUBLIC_URL` must be right, because the redirect URI, the SAML entity ID and the assertion consumer service URL are built from it. See [identity providers](/docs/self-hosting/identity-providers/).

The client secret is sealed under the server's own secret. The server can read it by design: it opens your provider's token endpoint, never a vault.

## How SAML responses are checked

A SAML response is XML signed with XML Signature, which is easy to get subtly wrong. Octa Pass keeps to a narrow, strict subset:

- No DTDs, and limits on size and depth. Every ID in the response must be unique.
- Exactly one assertion, directly in the response. A signature must sit inside the element it signs and point at it, and every signature present must check out against a certificate you saved.
- SHA-256 or stronger, RSA (2048 bits or more) or ECDSA. SHA-1 is refused.
- The response must answer the request Octa Pass sent, for this organisation, within its time limits, with this organisation's audience and address.

Even a forged response would only pass the SSO step, which comes after the master password and Secret Key: it can't unlock anything.

## Why the ID token's signature isn't checked

The server gets the ID token straight from the provider's token endpoint over TLS, authenticated with the client secret and PKCE. OpenID Connect Core 3.1.3.7 allows TLS to establish the issuer in this flow. The server checks `iss`, `aud`, `azp`, `exp`, `iat` and `nonce`, and refuses unsigned tokens. This keeps JWKS handling and an RSA implementation out of the server.
