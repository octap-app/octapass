---
title: Emergency access
description: Let a trusted person access your Octa Pass vault in an emergency after a waiting period you control, with view-only or takeover access you can deny at any time.
status: in-progress
sidebar:
  order: 10
---

:::note[In progress]
The web vault, the desktop app and the native iPhone and Android apps have emergency access, including takeover, on the [sync API](/docs/developers/sync-api/#emergency-access). Push notifications come next; for now the notices are emails.
:::

Emergency access lets someone you trust reach your vault if something happens to you, without giving them access today.

## How it works

1. You choose a contact who has an Octa Pass account, and a **waiting period of 1 to 30 days**.
2. Your device seals your account key, or one chosen vault's key, to the contact's public key. The server stores this sealed copy but can't open it.
3. When your contact requests access, you get an email right away and a reminder **every day** of the waiting period.
4. You can **deny** the request at any time, even after the key was released, which ends your contact's access through the server. You can also approve it early.
5. If you don't respond, the server releases the sealed key when the period ends. Your contact's device decrypts it and can then read what's in scope.

Your contact can't open the sealed key before it's released: the server only hands it over afterwards, and only to them. The key is sealed to them alone, so nobody else (including the server) can use it. If you chose one vault, your contact gets that vault's key and nothing that could open your other vaults.

Each contact you add gets an email, so adding contacts is limited: about 10 at once, then one every 15 minutes. Removing a contact and adding them again counts as a new one.

## In the web vault

Open **Emergency access** in the sidebar.

- **Add a trusted contact:** enter their email, compare the fingerprint Octa Pass shows with them, then pick the waiting period, what they can open (everything, or one vault you own) and the access level.
- **Your trusted contacts** shows each contact and any request. While a request waits you can **Deny** it or **Give access now**; after release, **Take back access** denies it.
- **People who trust you** lists the people who chose you. You can **Ask for access**, see when it opens, and once it's released **Open vault** shows their items read-only, decrypted on your device. Files attached to those items can be downloaded too; each one is decrypted on your device. **Stop being their contact** ends it from your side.

- **Reset their account** appears for a takeover contact once access is released. See [takeover](#takeover).

Your security log is under **Settings → Security → Security log**.

## Access levels

| Level | What the contact can do |
|---|---|
| View | Read the items in the shared scope |
| Takeover | Reset your master password and take over the account |

Takeover needs access to your whole account, so it isn't available for a single vault.

Every change is recorded in your account's security log: adding or removing a contact, and every request, denial, approval, release and takeover. Either of you can end the arrangement at any time.

## Takeover

Takeover has the same waiting period, reminders and denial as view access. Your contact can use it only after the key is released, and you can stop it until then. Once they do:

- They enter **their own** master password, so a stolen session on their device isn't enough, and a new master password for your account.
- Your device sessions end everywhere. Your old master password, Secret Key and recovery code stop working.
- **Two-step sign-in is turned off.** You're assumed to be unreachable, so a code from your phone would make this impossible. It protects access to your encrypted data, which your contact already has by then. You're emailed, and it shows in your security log.
- Your contact gets the new Recovery Kit. It's the only copy. If this was to help you back in, they give it to you.
- Their emergency record ends. Other contacts keep working.

**This can't be undone, and the server can't reverse it.** Your contact has held your account key since the release, and rotating vault keys doesn't change that, because the account key opens the new ones. If you get your account back and no longer trust them, move your items to a new account. Your protection is the waiting period, so choose someone you'd trust with everything, and a wait long enough to notice the emails.

## After a vault key changes

A contact with one vault holds a sealed copy of that vault's key. When the key is [rotated](/docs/security/account-recovery/#rotating-vault-keys), by you or a manager of the vault, their copy no longer opens anything new. **Your trusted contacts** shows it, with **Renew access**. Compare their fingerprint again, as when you added them. Octa Pass never renews this by itself: it would have to trust the server about which key to seal to.

Contacts for your whole account aren't affected.

## Related

- [Recovery Kit](/docs/getting-started/recovery-kit/): your own way back in
- [Families](/docs/features/sharing/#organiser-recovery): optional organiser recovery
- [Account recovery](/docs/security/account-recovery/): how all recovery paths fit together
