---
title: What the server sees
description: An honest list of the metadata the Octa Pass server can see, such as email, item counts and timestamps, and everything it can never see, like passwords and notes.
status: in-progress
sidebar:
  order: 6
---

:::note[In progress]
The sync server and the apps keep to the "never sees" list: every app encrypts with the same Rust core before anything is sent. An end-to-end test signs up in the web vault, saves a login, and checks that the server's database files don't contain its title, website, username, password or note. The rest of the list is the design and will become the basis of the privacy policy.
:::

End-to-end encryption hides your vault contents, but a sync server still needs some information to work. Here is the complete list.

## The server can see

- Your account email, account creation date, and quota usage
- How many vaults and items you have, the size of each encrypted item, and when items change. That includes the hidden item that keeps [how often you use items](/docs/features/quick-lists/#how-uses-are-kept): the server sees when it's saved, a few seconds after you use something, but not which item you used.
- How many files each item has, the size of each encrypted file, and when it was added
- Which accounts share which vaults (needed to deliver keys)
- Your public keys and signed key record, and which [key log](/docs/security/post-quantum-and-key-log/) labels your devices ask about
- IP addresses and user agents of requests, kept **7 days** for abuse prevention, then deleted
- Whether you have [two-step sign-in](/docs/features/two-step-sign-in/) turned on, and the names of your security keys. To check codes it keeps your authenticator app's secret, sealed under a key derived from its own secret, and your security keys' public keys.
- Device names as you typed them (to be encrypted in 1.0)
- If you're in an [organisation](/docs/features/organisations/): its name, group names, who is in which group, each member's role, which groups reach which vaults, its policies and activity log, its identity provider's address and client id (or SAML entity id, sign-in URL and signing certificates), each member's subject id at that provider, and what [SCIM](/docs/features/scim/) provisioned: user names, emails, display names, the provider's ids and group names. Vault names and everything inside a vault stay encrypted.
- Your account security log (sign-ins, exports, emergency access events). An export's entry has the device's name and platform, the time, the format (JSON, CSV, CXF or encrypted) and whether the file holds your attachments, never anything from the file itself.

- For a [Safe](/docs/features/octa-pass-safe/) with sync turned on: how many encrypted blobs it holds, their sizes, and when they change. Whether a blob is a record or file contents shows in its id. Which file a blob belongs to doesn't.
- For each [service account](/docs/features/service-accounts/): its id, vault, role, dates, public keys and sealed vault key, and when it fetched or saved. Not its name, and not which secrets it decrypted.
- That [Octa Pass Connect](/docs/features/connect/) handed out a secret, and when. The entry itself is a blob only you can open.

### Only on a server with the masked email relay

The [masked email relay](/docs/self-hosting/relay/) is off by default, and the hosted service doesn't run it. On a server that turns it on, its operator can also see:

- Each alias, which account it belongs to, whether it's on, and how many messages it forwarded, blocked and replied to
- The addresses of people who have written to your aliases, sealed under the relay's secret, so someone with that secret can read them
- **Mail itself, in plaintext, while it's being forwarded.** Email isn't end-to-end encrypted. Messages are held in memory only and are never written to a disk or a log, but whoever runs the relay could read them as they pass

None of this touches your vault: the relay has no access to it, and the site an alias is for stays encrypted there.

## The server can never see

- Item titles, full URLs, usernames, passwords and notes. Website icons are the one exception for addresses: see the table below.
- TOTP secrets and passkeys saved in your vault
- Card numbers, identities and addresses
- Tags, folder and vault names
- Attachment names and contents
- Your master password, Secret Key, recovery code or any decryption key

## Optional features that send data

| Feature | What's sent | To whom |
|---|---|---|
| [Breached password check](/docs/security/breach-checks/) | The first 5 hex characters of a SHA-1 hash, padded | Have I Been Pwned, directly from your device. A proxy through your server is planned. |
| [Email breach alerts](/docs/security/breach-checks/#email-breach-alerts-opt-in) (opt-in, off by default) | Your account email and masked email aliases, at most once a day. The server handles them in memory and doesn't store them. | Your Octa Pass server, then Have I Been Pwned |
| [Website icons](/docs/features/website-icons/) (on by default, can be turned off on each device) | The domain of each item with a website, without your account or a token | Your Octa Pass server, which fetches the icon from the site itself. No icon service sees your list. |
| Masked email | The site's domain as the alias description, sent from your device. The token is in your vault, encrypted; our server never sees it. | Your chosen alias provider, with your token |
| Masked email through [the relay](/docs/self-hosting/relay/) (off by default) | Your account id and email, and the mail sent to your aliases as it passes through. No site name. | The relay on your Octa Pass server, then your mailbox |
| Crash reports (opt-in, planned) | Scrubbed technical data, no vault content | Octa Pass |

Octa Pass has no analytics and no advertising, so nothing else is collected.

## Legal requests

If compelled, the project can hand over only the ciphertext and metadata listed above. A transparency report will be published twice a year.
