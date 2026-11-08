---
title: Masked email
description: Create a unique forwarding email alias for each account with Octa Pass, using SimpleLogin, addy.io, Firefox Relay, Fastmail, DuckDuckGo or Forward Email.
status: beta
sidebar:
  order: 8
---

A masked email is an alias like `shop.x7k2@alias-provider.com` that forwards to your real inbox. Giving each site its own alias keeps your real address private, makes spam traceable, and lets you turn off one alias without affecting anything else.

## Providers

Octa Pass connects to the provider you already use, with **your own API token**. The token is stored encrypted in your vault, like a password, and syncs to your other devices. Calls go **straight from your device to the provider**: the Octa Pass server never sees the token or your aliases.

| Provider | API | Web vault | Extension | Desktop and mobile apps |
|---|---|---|---|---|
| SimpleLogin (also self-hosted) | REST, API key | Yes | Yes | Yes |
| addy.io (also self-hosted) | REST, API token, alias domain | Yes | Yes | Yes |
| Fastmail Masked Email | JMAP, API token with the Masked Email scope | Yes | Yes | Yes |
| Forward Email | REST, API token, your domain | Yes | Yes | Yes |
| Firefox Relay | REST, API token | No | Yes | Yes |
| DuckDuckGo Email Protection | API token | No | Yes | Yes |

Browsers only let a web page call another site's API when that site allows it (CORS). Firefox Relay and DuckDuckGo don't, so they can't be used from the web vault. You can still connect them there; use them from the extension or the apps. The extension already has access to the sites it fills, so connecting a provider asks for no new permission. The apps call these two providers from their native side, and only the providers' own API addresses.

A self-hosted SimpleLogin or addy.io server needs an `https://` address, and must allow calls from the web vault's address if you want to use it there.

Proton Pass aliases will be added when a public API exists.

## Connecting a provider

1. Make an API token in your provider's account settings. For Fastmail, give the token the **Masked Email** scope.
2. In the web vault or an app, open **Masked email**; in the extension, open **Settings**.
3. Pick the provider, paste the token, and for addy.io and Forward Email enter the domain new aliases should use. Select **Connect**.

**Disconnect** removes the token from your vault. Aliases you already made keep working; manage them with your provider.

## Using it

- **On sign-up forms (extension):** in an email field, choose **Use a masked email** from the Octa Pass menu. The extension makes a new alias with the site's domain as its description and fills it in. When you then save the login (or use a suggested password), the login is saved with the alias as its username and its [recovery email](/docs/features/recovery-info/), linked to the provider. Without a connected provider, the entry shows *Needs setup*.
- **In the item editor:** the mail button next to **Username** makes an alias for the login's first website and uses it as the username and recovery email. The one next to **Recovery email** sets only the recovery email.
- **In the generator:** **Make a masked email** creates an alias for any website and lets you copy it.
- **Aliases in use** (on the Masked email page) lists each alias your logins use, with its provider and the logins that use it. It is built from the [recovery map](/docs/features/recovery-info/#recovery-map) on your device.

The first connected provider that works where you are is used, unless you pick another one in the generator.

## Turning an alias off or deleting it

**Aliases in use** has **Turn off**, **Turn on** and **Delete** for each alias, in the web vault and the desktop and mobile apps. The request goes straight from your device to the provider, with your token.

- **Turn off** stops mail to the alias, and **Turn on** starts it again. The list is built from your vault, not from the provider, so it can't show whether an alias is on right now. Both buttons are always there, and pressing one twice changes nothing.
- **Delete** asks first, then has the provider delete the alias. The login keeps the address as plain text, because that's still what the site has on record. Only its link to the alias goes, and it drops off the list. If you still sign in with that address, change it on the site first.

| Provider | Turn off and on | Delete |
|---|---|---|
| SimpleLogin, addy.io, Fastmail, Forward Email, Firefox Relay | Yes | Yes |
| DuckDuckGo | At duck.com | At duck.com |

The provider must be connected on this account. As with making aliases, the web vault can't reach Firefox Relay. An alias that a provider gave no id for can only be changed on the provider's site. Providers may treat deletion differently: some keep a deleted address reserved so nobody else can claim it.

## Errors

| You see | What to do |
|---|---|
| The provider turned down the API token | The token was revoked, mistyped or lacks a scope. Make a new one and connect again. |
| Too many aliases in a short time | Your provider's rate limit. Wait a few minutes. |
| Your browser blocks this provider on web pages | Use the extension or the apps for Firefox Relay and DuckDuckGo. |
| Couldn't reach the provider | Check your connection; a self-hosted server must allow calls from this page. |

## An Octa Pass alias service

Octa Pass has its own mail forwarder, [the relay](/docs/self-hosting/relay/). It's built and tested, and it's **off by default**. **The hosted Octa Pass service doesn't run it**, and it hasn't been used with real mail yet: running it for the public needs a domain, a mail provider and an abuse process that haven't been decided. Self-hosters can turn it on for their own server.

On a server with the relay, each alias forwards to your account's email, and you can reply through it. Messages pass through without being stored, but email isn't end-to-end encrypted: they're readable by the relay while they're forwarded. Your vault isn't affected. See [what the relay stores](/docs/self-hosting/relay/#what-it-stores).

## What Octa Pass won't do

Octa Pass doesn't read your inbox or SMS, and it won't offer masked phone numbers. Verification codes sent by SMS are filled by iOS and Android themselves. Masked email isn't available in a [local vault](/docs/features/local-vault/), because it needs an account.
