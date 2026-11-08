---
title: Threat model
description: The Octa Pass threat model, covering database breaches, malicious servers, phishing, clickjacking, lost devices, supply chain attacks and quantum computing.
status: in-progress
sidebar:
  order: 5
---

:::note[Design document]
This threat model is reviewed at every development phase, and it describes the design. Mitigations that aren't built yet are listed [below the table](#not-built-yet). Suggestions are welcome: see [contributing](/docs/contributing/overview/).
:::

| Threat | What the attacker gets | Mitigation |
|---|---|---|
| **Database breach** | Emails, OPAQUE records, ciphertext, public keys, metadata | The Secret Key makes offline cracking impossible. Argon2id adds cost even if a Secret Key also leaks from a device. |
| **Malicious or compelled server operator** | Everything a breach gives, plus the ability to serve modified code | Released native apps and extensions will be signed and reproducible. **The web vault is the weak point**, because the server delivers its code. Mitigations: Subresource Integrity, reproducible builds with published hashes, a check by the extension that verifies web vault hashes, and documentation recommending the apps for highest assurance. |
| **Hostile or breached identity provider** | Can refuse sign-ins, or pass one that already had the master password and Secret Key | [Single sign-on](/docs/features/single-sign-on/) runs after OPAQUE and takes no part in deriving keys, so it gives no path to a vault. |
| **Malicious organisation admin** | Member lists, group names, policies | Admin roles open nothing. An admin reads only vaults they hold a grant for, and can lock someone out of organisation vaults but not read personal ones. Owners' access to organisation vaults is stated before joining. |
| **Server adds a fake person to a group** | A key holder's device is asked to seal to them | Applying access always shows each person and a locally computed fingerprint for a person to confirm. |
| **Network attacker** | Nothing useful | TLS 1.3, HSTS preload. OPAQUE keeps the password off the wire even if TLS were broken. |
| **Phishing site** | Nothing | Autofill suggests only logins for the page's own host, a domain above it or a host below it, on the same registrable domain (Public Suffix List); logins for other parts of the domain only when you pick them. Never in cross-origin iframes without approval, user gesture required. HTTP sign-in prompts are answered only for the login's exact origin (and realm), after a first approval, and never for frames or requests another site started. Passkeys are bound to their site by design. |
| **Clickjacking the extension's UI** | Tricking you into filling | In-page UI rendered in the top layer or an extension frame; visibility and opacity checks on the target field and on Octa Pass's own UI; refusal to fill when the page tampers with Octa Pass elements; confirmation for fills triggered by synthetic events. |
| **Website scripts reading filled values** | Values in the page | Fill only into the matched form, only after a gesture. No password or TOTP filling on `http://` without a warning. The one exception, off by default: the extension's [filling when a page opens](/docs/features/autofill/#filling-when-a-page-opens), limited to `https://` pages and logins saved for their exact address. With it on, the page can read the filled login before you do anything. |
| **Stolen master password and Secret Key** (phished, or read off a device) | A sign-in on a new device | [Two-step sign-in](/docs/features/two-step-sign-in/) asks new devices for an authenticator code, a security key or a recovery code. Wrong codes pause it and email the owner. |
| **Lost or stolen device** | The encrypted local cache | Auto-lock, hardware-backed keys, remote sign-out (revokes refresh tokens; the local cache stays encrypted). With [Stay unlocked](/docs/features/biometric-unlock/#stay-unlocked-while-youre-logged-in) on, the key stored on a locked or switched-off device opens nothing without the phone unlocked or you logged in to the computer. If Octa Pass is still running, its open vault stays in memory while the device is locked, with no lock timer to close it. |
| **Someone using your unlocked device** | With Stay unlocked on (the default in the apps and the extension): opening Octa Pass, filling your logins and seeing your passwords. With it off: nothing without your device lock or master password | Exporting, your Secret Key and your account settings still ask for your device lock or master password, every time. Your master password is still asked every 14 days. Turn Stay unlocked off for the lock timer and a prompt to open. |
| **Stolen [service account](/docs/features/service-accounts/) token** | That one vault, until it's revoked | The token is a key: keep it in your CI system's secret store. It's bound to one shared vault, read-only by default, can expire, and every fetch is in the security log. Revoking cuts server access at once and rotates the vault key; secrets already read must be changed. |
| **Local program asking [Connect](/docs/features/connect/) for secrets** | What you approved it for | Socket or loopback only, per-client approval showing the real program where the system can tell, a token bound to that program, and every hand-out logged. Web pages can't reach it. |
| **Someone holding a locked device, or a page script sending forms** | Can add saves to the [locked-save inbox](/docs/features/autofill/#saving-while-octa-pass-is-locked), but can't read them or anything else | Saves are sealed to your account's public key. New items from it are tagged **Unconfirmed** for review; an existing login only gets a new password, with the old one kept in its history; nothing is deleted. At most 50 wait at once. |
| **Malware on an unlocked device** | Potentially everything | Out of scope, as for every password manager. Exposure is limited by clipboard auto-clear, minimal decrypted data in memory, and no secrets in logs or crash reports. With Stay unlocked on, malware running as you can open the vault, as it can open your browser's saved passwords; with it off, a locked vault gives it only encrypted data. The device-lock prompt before revealing doesn't stop malware that reads memory. |
| **Malicious shared-vault member** | Items in that vault | Can't escalate beyond the vault. Removal rotates the vault key and re-wraps item keys. Owners and managers can also rotate on demand. |
| **Emergency contact or organiser turning hostile** | With takeover, the account after the waiting period | The grantor is emailed at once and daily, and can deny until the takeover happens. The takeover needs the contact's own password as well as their private key, is logged, and signs the grantor out, so it can't happen quietly. It can't be undone: the waiting period is the protection. Organiser recovery is opt-in and gives no reading. |
| **Server rollback or item swapping** | Old versions served as current | Associated data prevents swaps. Signed vault manifests with increasing revision numbers (1.0) let clients detect rollback. |
| **Supply-chain attack** | A malicious dependency or build | Lockfiles, `cargo vet`, `cargo deny`, npm provenance, minimal dependencies in the core, two-person release approval, reproducible builds, SBOM. |
| **Quantum computers (harvest now, decrypt later)** | Keys sealed with X25519 alone: older grants, and grants to accounts with no ML-KEM key yet | 256-bit symmetric layers are already safe. New seals are [hybrid X25519 + ML-KEM-768](/docs/security/post-quantum-and-key-log/). Older grants stay classical until the vault's next key rotation. Not yet reviewed by an outside cryptographer. |
| **Server swaps someone's public key** | A vault key sealed to the server instead of the member | Comparing fingerprints, and the [key log](/docs/security/post-quantum-and-key-log/), which puts a swapped key where its real owner's devices see it. On a server with [witnesses](/docs/self-hosting/key-log-witnesses/), they catch a server showing different people different logs; without them, the log can't. Not yet reviewed by an outside cryptographer. |

## Not built yet

Today these mitigations from the table are designs, not code. All are required for 1.0:

- **Malicious server:** reproducible builds, Subresource Integrity and the extension's web vault check. Until they exist, nothing proves the code you're served is the published code, so treat a self-hosted server you trust, or the signed apps once they're released, as the safer choice.
- **Server rollback:** signed vault manifests. Associated data already stops swaps, but rollback isn't detected yet.
- **Supply chain:** `cargo vet`, `cargo deny`, npm provenance, two-person release approval and SBOMs. Lockfiles and minimal dependencies are in place.
- **Network attacker:** HSTS is sent over HTTPS, but the preload listing waits on the domain.

## Out of scope

- A device fully controlled by an attacker while unlocked
- Users giving their master password, Secret Key and second step to an attacker
- Weaknesses in the operating system's own secure hardware

See also [what the server sees](/docs/security/what-the-server-sees/) and [encryption](/docs/security/encryption/).
