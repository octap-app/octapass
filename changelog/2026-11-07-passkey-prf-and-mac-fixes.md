---
title: Passkeys answer PRF; fixes for Safes and the Mac app's browser and SSH connections
date: 2026-11-07
summary: Octa Pass passkeys now support the WebAuthn PRF extension, so the browser extension's Touch ID unlock passkey can be kept in Octa Pass on a Mac or iPhone; Safes kept on one device stay there, synced ones sync on their own on the Mac, iPhone and Android, and the Mac app connects to Firefox and starts its SSH agent.
tags: [core, mobile, desktop, extension, cli]
---

**Passkeys with PRF.** Every passkey Octa Pass makes now has its own PRF secret, kept in the login's encrypted details with the private key. Sites that derive a key from a passkey (the WebAuthn PRF extension) work with one kept in Octa Pass. On macOS 15 and iOS 18 the AutoFill extension passes the PRF inputs and outputs through Apple's API. That includes the browser extension's own **Unlock with Touch ID** passkey, which Octa Pass used to refuse because its site is the extension, not a web address. CXF exports carry the secret as `hmacCredentials`. Passkeys made before this have no secret and sign in as before. See [passkeys](/docs/features/passkeys/) and [plan 05](https://github.com/octapass/octapass/blob/main/plans/05-clients-and-autofill.md).

**Safes:**

- **A Safe kept on one device** is listed only on that device. Its key syncs with your vault, as every Safe's does, so your other devices used to list it too, with none of its files. Safes made before this don't record their device, so they show wherever their folder is.
- **Deleting a Safe** that another device had already deleted works. It used to fail and leave the Safe listed until the vault next synced.
- **Synced Safes sync on their own** in the Mac, iPhone and Android apps: a few seconds after you change one, in the app or in Finder or Files, after each vault sync, and every two minutes while the vault is unlocked. Before, only **Sync now** did.

See [Octa Pass Safe](/docs/features/octa-pass-safe/#sync).

**Mac app:**

- **SSH agent:** it no longer fails with "operation not permitted". It tried to change its socket folder's permissions, and the sandbox doesn't allow that for the app's group container, which already has the right ones.
- **Firefox:** Settings → Browser extension → Connect lists Firefox even when Firefox hasn't made `~/Library/Application Support/Mozilla` yet. The app now creates it when Firefox is in Applications, and the sandbox exception covers that folder (plan 19).
- **Health:** a check's list, the recovery map and an item's list of logins sharing its password close when you pick something else in the sidebar. They used to stay in the right-hand column, beside All items or Safes.
- **AutoFill:** when it can't save a passkey because it isn't for a website, it says so, and suggests Passwords or a security key. It also writes the real reason for any failure to the system log.

**Browser extension:** the long "Unlock with Touch ID in the desktop app" button wraps instead of running past its edge.
