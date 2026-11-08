---
title: Password generator
description: Generate strong random passwords and memorable passphrases in Octa Pass, with per-site password rules, ambiguity filters and the EFF large wordlist.
status: beta
sidebar:
  order: 5
---

The generator is available in every app, in the extension's save prompt, and in the CLI (`octapass generate`). It uses the operating system's secure random number generator.


## Suggested passwords while you sign up

When you create an account on a website, Octa Pass offers a strong password right in the form:

1. Focus the password field of a sign-up or change-password form. Octa Pass shows **Use suggested password** with a preview.
2. Choose it. Octa Pass fills the password (and the "confirm password" field) and **saves the login right away**, before you submit, so a dismissed prompt or crashed tab can't lose it.
3. After the sign-up succeeds, the login is confirmed. If you never finish signing up, the unconfirmed draft disappears after 7 days.

Suggestions follow your generator defaults and adapt to each site's rules (allowed characters, length limits) when they're known. They're generated on your device. On change-password forms, your old password is filled in for you and kept in the item's password history.

| Where | Suggested passwords |
|---|---|
| Browser extension (Chrome, Edge, Firefox, Safari) | Yes, in the form |
| Android | Yes, in the autofill suggestions for new-password fields |
| Mac and iPhone | Where Apple allows third-party password managers to fill or save new passwords; otherwise from the quick generator |
| Windows and Linux apps | From the quick-access window and auto-type |

## Random passwords

| Option | Default |
|---|---|
| Length | 20 (range 8–128) |
| Uppercase, lowercase, digits, symbols | All on |
| Avoid ambiguous characters (`l`, `1`, `O`, `0`…) | Off |
| Minimum digits / symbols | 1 each |

## Passphrases

| Option | Default |
|---|---|
| Wordlist | EFF large wordlist (7,776 words, about 12.9 bits per word) |
| Words | 5 |
| Separator | `-` |
| Capitalise | Off |
| Include a number | Off |

Five EFF words give about 64 bits of entropy, which is a good choice for a master password you have to type.

## Per-site rules

Some sites reject certain characters or limit length. Octa Pass applies known site requirements from Apple's open `password-rules` dataset, so generated passwords are accepted the first time. The dataset ships with the app; your sites are never looked up anywhere.

- **Browser extension:** suggested passwords also follow the form field's own `passwordrules`, `minlength`, `maxlength` and `pattern`.
- **Android:** the Autofill suggestion on sign-up forms follows the site's rules.
- **Login editor, every app:** the generator follows the rules of the login's first website when you make a password. Your length and character settings stay wherever the site allows them. Passphrases aren't changed.

If a site's rules contradict each other, Octa Pass ignores them and gives you a password in your usual settings.

## Password history

Every time a password changes, the old one is kept in the item's password history. You can restore it if a site didn't accept the change.
