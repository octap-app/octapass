---
title: Sharing
description: Share passwords safely with Octa Pass using shared vaults with roles, free family plans for up to 6 people, and expiring one-time share links.
status: in-progress
sidebar:
  order: 7
---

:::note[In progress]
Shared vaults, families and share links work in the web vault, the browser extension's Octa Pass tab, the desktop apps and the iPhone, iPad and Android apps, on the [sync API](/docs/developers/sync-api/#sharing). The iPhone, iPad, Android and Mac apps check people's keys against the [key log](#shared-vaults) but don't show its badges or alerts yet.
:::

For a team, see [organisations](/docs/features/organisations/): its vaults are shared vaults, and groups say who should have them.

All sharing is end-to-end encrypted. The server routes encrypted keys between accounts but can't open them.

## Shared vaults

Create a vault and invite other Octa Pass users by email. In the web vault, open **Sharing** in the sidebar and choose **New shared vault**, then add people on the vault's page. Its name is encrypted inside the vault like an item, so the server never sees it.

| Role | Can |
|---|---|
| Read | View, copy and fill items |
| Write | Also create, edit and delete items |
| Manage | Also add and remove members |
| Owner | Also make and remove owners. The person who creates the vault is its owner. |

**How it works:** the vault has its own random Vault Key. Your device seals that key to each member's public keys (X25519 and, once their account has one, [ML-KEM-768](/docs/security/post-quantum-and-key-log/)) and signs the grant with your signing key (Ed25519). The grant names the vault, the member and their role, so the server can't change a role or pass a grant to someone else without breaking the signature, and every member's device checks it before using the key. See [encryption](/docs/security/encryption/).

**Inviting** works only for people who already have an Octa Pass account. Inviting an email that has no account looks exactly the same to you as inviting one that does, and nothing is stored.

**Removing a member** creates a new Vault Key, re-wraps every item key in the vault, and re-seals the new key to the remaining members, all at once. Item contents aren't re-encrypted: each item keeps its own item key, which the removed person can no longer unwrap. Anything they already saw should be treated as known to them, so Octa Pass suggests changing the most sensitive passwords.

**Verifying people:** every account has a short fingerprint, shown as six groups of four digits or as eight emoji with names to read aloud. Yours is at the top of the **Sharing** page. When you add someone, Octa Pass shows their fingerprint first: compare it with them in person or over a call, and tick **It matches**. Members you haven't verified are marked **Not verified** until you compare them. Your device remembers what you verified; if someone's keys ever change, they show as not verified again.

**The key log** checks people's keys without a call. Every account's public keys go into an append-only log, and your device checks a person's keys against it before sealing anything to them. Each member shows as **In key log**, **Not in key log yet** or **Key log check failed**, and a failed check stops the share. Your own devices also read the log, so if a key is ever published for your email that you didn't make, **Sharing** shows an alert. It adds to comparing fingerprints and doesn't replace it: see [what it can't catch](/docs/security/post-quantum-and-key-log/#what-the-key-log-cant-catch). Phone apps run these checks but don't show the badges yet.

**Checking grants:** every Octa Pass app checks the signature on its copy of each shared vault's key before using it: the web vault, the phone apps and their autofill, the desktop app and the browser extension. If the check fails, the vault shows as **unverified** and stays closed, with a warning, until someone who manages it adds you again.

**Moving and copying items:** an item's **More actions** menu has **Move to…** and **Copy to…** for any other vault you can edit. A move puts a copy, encrypted for the new vault, in place and sends the original to the Trash.

## Families

- Free, up to **6 members**, the organiser included. Each person can be in one family.
- The organiser invites members by email, and a shared **Family** vault is created automatically. Everyone also keeps their private vault.
- Members can leave at any time, and the organiser can remove them; the Family vault then gets a new key, as above. Pending invitations get the new key in the same step, so they still work.
- In the web vault, the family lives in **Sharing → Family**: create it, invite people (after comparing their fingerprint), accept or decline invitations, and leave or remove people. The organiser can also delete the family, which deletes the Family vault for everyone.

### Organiser recovery

Optional, and off unless a member turns it on under **Sharing → Family**. The organiser can't turn it on for anyone.

- The member compares the organiser's fingerprint and picks a waiting period of 1 to 30 days. Their account key is then sealed to the organiser.
- It works like [emergency access](/docs/features/emergency-access/): the organiser asks, the member gets daily emails and can deny it, and it opens after the wait.
- The organiser **can't read** the member's vault. All they can do is [reset the account](/docs/features/emergency-access/#takeover), which signs the member out everywhere, emails them and fills their security log, and gives the organiser the new password and Recovery Kit.
- It ends when the member turns it off, leaves or is removed, or the family is deleted.
- If the organiser is already the member's emergency contact, remove them as a contact first.

## One-time share links

Share one item with anyone, even without an Octa Pass account.

In the web vault, open the item and choose **More actions → Share a copy**.

1. Your device encrypts a snapshot of the item with a random key. The snapshot leaves out the item's previous passwords.
2. Only the ciphertext is uploaded.
3. You get a link like `https://octap.app/s/<id>#<key>`. The part after `#` never reaches the server.

| Option | Range |
|---|---|
| Expiry | 1 hour to 30 days |
| Maximum views | 1 to 100 |
| Access passphrase | Optional (protected with Argon2id) |

The server deletes a link at its last view or when it expires, and you can delete it earlier. Use a passphrase when the link travels somewhere that keeps history, such as a group chat, and send the passphrase another way.

The person you send it to opens the link in the web vault, signed in or not. Nothing is fetched until they choose **Show the item**, because each fetch counts as a view, so link previews in chat apps don't use one up. The item is decrypted in their browser and shown read-only, with copy buttons. A link made on a self-hosted server names that server in the link (`?server=`), and the page says which server it came from. Links made in the desktop app open in the hosted web vault, or, on a self-hosted server, in the web vault that server serves.

Your open links are listed under **Sharing → Share links**, with their expiry and how many views are left, and you can revoke any of them there.

## Teams and organisations

[Organisations](/docs/features/organisations/) add groups, policies and [single sign-on](/docs/features/single-sign-on/) for teams, on top of shared vaults.
