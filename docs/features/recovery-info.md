---
title: Recovery info
description: Record each account's recovery email, recovery phone, backup codes and security questions in Octa Pass, and see your recovery map to spot weak links.
status: beta
sidebar:
  order: 9
---

Most accounts can be taken over through their recovery path: whoever controls your recovery email or phone can often reset the password. Octa Pass records that path for each login, so you can see and protect it.

## Fields on every login

| Field | Details |
|---|---|
| Recovery email | Typed in, picked from an email in one of your Identities, or a [masked email](/docs/features/masked-email/) made for the login |
| Recovery phone | Typed in, or picked from a phone number in one of your Identities |
| Backup codes | A list. Mark each code as *used*. You're warned when two or fewer remain. |
| Security questions | Question and answer. Answers are hidden like passwords. **Random answer** makes one from the [generator](/docs/features/password-generator/): five random words, which are much safer than a true answer and can still be read out to a support agent. |
| 2FA method | TOTP in Octa Pass, another authenticator app, SMS, email, hardware key or passkey |

A recovery email or phone picked from an Identity, or made as a masked email, stays **linked**: the login shows where it came from ("From the identity *Personal details*", "Masked email from SimpleLogin"). Typing over it, or **Unlink**, removes the link.

## Recovery map

The recovery map (in **Health → View the recovery map**) groups your logins by recovery email and phone:

> 14 accounts can be reset through ali@example.com.

If that email account is compromised, those are the accounts at risk. A login counts when its recovery email or phone is that address or number, and also when it **signs in with** that email, since sites send password resets there. Phone numbers are grouped by their digits, so spacing doesn't matter.

For each email, the map looks for the email account's own login in your vault (for example your Google login for a Gmail address) and shows whether it has two-step sign-in. Each login's page also says how many other logins its recovery email can reset.

The map is built on your device from your decrypted vault, like the rest of the [security dashboard](/docs/features/security-dashboard/). Nothing about it is sent anywhere.

## Dashboard checks

- **Recovery email without two-step sign-in.** The email account's own login is in your vault and has no one-time code, passkey or other second step, while other logins can be reset through it. Turn on two-step sign-in for that email account first: it protects every login behind it.
- **Recovery email in a breach: not built.** There is no public way to check an email address without sending it to someone. Opt-in [email breach alerts](/docs/security/breach-checks/#email-breach-alerts-opt-in) check your account email and your masked email aliases, because those are yours. Other recovery emails aren't sent, so a recovery email that's neither of those isn't checked.

## Tips

- Protect your main email with 2FA, ideally a passkey or hardware key. It's the key to most of your accounts.
- Prefer TOTP or passkeys to SMS codes where a site allows it.
- Store backup codes when you turn on 2FA anywhere.
- Give each site its own masked email, so one leaked address can't be used to reset the others.
