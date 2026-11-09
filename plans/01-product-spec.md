# 01 — Product spec

What Octa Pass does, for whom, and in what order. Priorities are:

- **P0**: needed for the first public alpha
- **P1**: needed for 1.0
- **P2**: required for 1.0, built after P1

**Scope decision (maintainer, 2026-11-02):** everything planned for after 1.0 (roadmap phases 7 and 8, every P2 item in plan 01, all of plan 16) is inside 1.0. P2 still says what comes last, but it's required for 1.0. See [plan 09](09-roadmap.md). No P2 label in any plan means "optional" or "later" any more, unless the row itself says a decision is still needed.

## Positioning

**One line:** Octa Pass keeps everything sensitive in one place only you can open: every login, passkey and one-time code you own, and the SSH keys, secrets, IDs, cards and files that sit beside them, synced to every browser, phone and computer and encrypted so only you can read it.

**Not just a password manager (maintainer, 2026-11-08).** Octa Pass does everything a password manager does, but the website, README and store listings lead with the wider idea: one encrypted place for everything sensitive. Say "password manager" where people search for one (and where it's simply accurate), never as the whole description. The item types, Safes, file encryption and developer tools are the proof, so show them.

**The product is the free hosted service.** Most people never think about servers: they create an account, install the apps and are done. Open source is a trust feature (anyone can audit the code). Self-hosting is an extra for organisations and enthusiasts, and uses the same apps.

**Audience**
1. **Everyday people** who want a free password manager that works everywhere, including those leaving 1Password, LastPass or Dashlane over price or trust.
2. **Families** who need to share some logins and keep others private.
3. **Developers** who want a CLI and SSH keys.
4. **Organisations and self-hosters** who must run their own server (secondary).
5. **Small teams** (P2, in 1.0).

**Principles**
1. **Zero-knowledge.** We can't read your vault, even if we wanted to or were ordered to.
2. **Free and effortless first.** The hosted service is the default everywhere and needs no setup. It runs the published MIT code, and self-hosters get every feature.
3. **No lock-in.** Full export in open formats, always free.
4. **No ads, no trackers.** Not on the website, not in the apps.
5. **Safe by default.** Autofill never runs silently on a domain that doesn't match exactly.

## Item types

Every item has: title, tags, favourite flag, folder/vault, notes, custom fields (text, hidden, URL, date, email, phone, TOTP), attachments (P1), password history, created/updated timestamps. All of these are encrypted.

| Item type | Key fields | Priority |
|---|---|---|
| **Login** | username, password, website URLs (multiple, with match rules), TOTP secret, passkeys, linked masked email, **recovery info** | P0 |
| **Passkey** (stored inside a Login or standalone) | rpId, credential ID, user handle, private key (ES256/EdDSA), counter, created | P0 (browser), P1 (mobile/desktop OS) |
| **Secure note** | rich text (Markdown) | P0 |
| **Payment card** | cardholder, number, expiry, CVV, PIN, brand (auto-detected), billing address link | P0 |
| **Identity** | name, birth date, gender, emails, phones, addresses, company, job title, national ID numbers | P0 |
| **Address** | standalone address book entries for form fill | P0 |
| **Bank account** | bank, account holder, IBAN/account number, routing/SWIFT, PIN | P1 |
| **Document** | file + metadata (encrypted attachment) | P1 |
| **SSH key** | private key, public key, fingerprint, key type, passphrase | P1 (storage), P2 (SSH agent, built in the desktop app; required for 1.0) |
| **API credential** | key, secret, host, expiry, type | P1 |
| **Wi-Fi network** | SSID, password, security type, hidden network flag; show as QR so guests can join (see QR codes) | P1 |
| **Environment** | project and stage, ordered variables (name, value, concealed flag, note); loaded by the CLI into commands, files and a shell hook (see [16](16-developer-toolkit-and-files.md)) | P1 (web, extension, CLI) |
| **Software licence** | product, key, licensed to, version, order info | P1 |
| **ID documents** (passport, driver's licence, national ID) | number, issuer, issue/expiry dates, scans | P1 |
| **Crypto wallet** | wallet name, seed phrase (hidden), addresses | P2 |
| **Database / server** | host, port, user, password, connection string | P2 |
| **Custom template** | user-defined fields | P2 |

### Recovery info (per login), from "email/phone verification"

Every Login can record how the account is recovered:

- **Recovery email**, linked to an Identity's email or a masked email alias
- **Recovery phone**, linked to an Identity's phone
- **Backup codes**: stored as a list, each code can be marked *used*; warns when ≤ 2 remain
- **Security questions**: question + answer; the generator can produce random answers
- **2FA method in use**: TOTP in Octa Pass / authenticator app / SMS / email / hardware key / passkey

**Recovery map** (P1) is a view that groups logins by recovery email/phone: *"14 accounts can be reset through ali@example.com."* The security dashboard flags a recovery email that has itself appeared in a breach, or that has no 2FA.

### Masked email (P1)

- Generate a unique alias per login from the save/generate dialog.
- **Phase A:** use existing alias providers through their APIs with the user's own token: SimpleLogin, addy.io, Firefox Relay, Fastmail Masked Email, DuckDuckGo Email Protection, Forward Email, and Proton Pass aliases (when a public API exists).
- **Phase B (P2):** run our own forwarding service on an Octa Pass domain. This needs anti-abuse, bounce handling and reputation management; see plan 10. The 2026-11-02 decision puts it inside 1.0's scope, but whether to run it at all was never decided: that question is still open in [plan 00](00-idea-review.md).

## Feature list

### Local mode (use without an account)
| Feature | Priority |
|---|---|
| **"Use on this device only"** at first launch, next to "Create account" and "Sign in": no email, no server, nothing ever sent | P1 (phase 2: extension first, then desktop and mobile) |
| Works fully offline: autofill, suggested passwords, generator, TOTP, passkeys, health check (password breach check needs the internet but sends only a hash prefix), import/export, device unlock | P1 |
| Not available: sync, sharing, families, emergency access, masked email, email breach alerts, web vault | — |
| **Encrypted backup file** (`.octapass-backup`): prompted on first setup and every 30 days, or automatic to a folder the user picks (e.g. iCloud Drive, Dropbox, OneDrive). Restore on any device. | P1 |
| **"Turn on sync"**: creates an account and uploads the existing vault (re-wrapped, nothing re-entered); the device becomes a normal synced device | P1 |
| Several local vaults on one device | P2 |

### Vault and accounts
| Feature | Priority |
|---|---|
| Sign up with email + master password; email verification | P0 |
| Secret Key generation + printable **Recovery Kit** (PDF) | P0 |
| Recovery code (lets you reset your master password without the server reading data) | P0 |
| Multiple vaults (Personal, plus user-created) | P0 |
| Folders/tags, favourites, search (local, encrypted index) | P0 |
| Sidebar quick lists above the vaults: Recently created, Pinned, Favourites, Frequently used, Recently used, Recently modified | P1 |
| Nearby: items saved with a place, listed when the device is close to it (places are encrypted items; the device works out where it is) | P2 |
| Password history per item, item version history (last 10 revisions) | P1 |
| Trash with 30-day restore | P0 |
| Attachments (1 GB free quota per account, see plan 10) | P1 |
| Change master password, rotate Secret Key, rotate vault keys | P1 |
| **Delete account**: re-confirm with master password + typed email, offer export first, then permanently delete the account, every vault, item, attachment, device and token in one transaction; wipe local data on every device; confirmation email; backups age out within 30 days | P0 |
| Device list with remote sign-out | P1 |

### QR codes (show and scan)

Every QR code is generated **on the device** (no QR web service) and shown full screen with the screen brightness raised on phones. It hides itself after 60 seconds or when the app is locked.

| Item | QR content (standard) | Use | Re-confirm first? | Priority |
|---|---|---|---|---|
| Wi-Fi network | `WIFI:T:WPA;S:<ssid>;P:<password>;H:<hidden>;;` | Guests join by pointing their camera, with no typing | No (Wi-Fi passwords are meant to be shared at home) | P1 |
| Wi-Fi, guest mode | Same, plus a one-time [share link](06-health-sharing-aliases.md) QR | Share for a day without giving the item | No | P1 |
| Identity / contact | vCard 4.0 (`BEGIN:VCARD…`), choose which fields | Share contact details | No | P1 |
| One-time code (TOTP) | `otpauth://totp/<issuer>:<account>?secret=…&issuer=…` | Move a 2FA code to another authenticator or device | **Yes** (master password or device unlock) | P1 |
| Bank account | EPC QR (SEPA credit transfer, `BCD` format) with IBAN, name, optional amount/reference | Let someone pay you from their banking app | No | P2 |
| Crypto wallet | `bitcoin:` / `ethereum:` address URI, **address only, never the seed phrase** | Receive payments | No | P2 |
| **Any login (default when no standard exists)** | **The password as plain text**. A switch adds the username on a second line, or picks another field | Scanning shows the text with a Copy button on any phone camera, so the password reaches a TV, console, smart device or another person without typing | **Yes**, plus a warning that cameras can see the screen | P1 |
| Secure note or custom field | The chosen field as plain text | Same | **Yes** for hidden fields | P1 |
| Website | The login URL | Open the site on another device | No | P1 |
| Recovery Kit | Email, server, Secret Key (exists) | Set up a new device | (Already in the kit) | P0 |
| Share link | The one-time link (plan 06) | Hand an item to someone in person | No | P1 |

**Wi-Fi joins directly, two ways:**
- **Guests (QR):** the `WIFI:` QR is the format phone cameras understand natively. iPhone and Android show "Join network …?" and connect in one tap, so the password is never shown or typed. Windows 11 and macOS camera/scan tools support it too.
- **Your own devices (Connect button):** a Wi-Fi item has **Connect**, which joins the network from the app itself. iOS uses `NEHotspotConfiguration` (Hotspot Configuration entitlement). Android uses `WifiNetworkSuggestion` / `ACTION_WIFI_ADD_NETWORKS` (Android 11+, one confirmation). macOS uses CoreWLAN. Windows uses the Native Wi-Fi API (`WlanSetProfile` + `WlanConnect`). Linux uses NetworkManager over D-Bus. Optional **"Add to all my devices"** pushes the network to every signed-in phone and computer (each confirms once, as the OS requires). The web vault and extension can't join networks; they show the QR instead. (P1, with the apps.)
- **NFC tag (Android, P2):** write the Wi-Fi details to an NFC tag, so guests just tap their phone.

**Rule: every item has "Show as QR code".** If a scan-to-act standard exists (Wi-Fi, contact, one-time code, bank transfer, wallet address, URL), that's the default. Otherwise the QR carries **the password itself**. Every QR also has a **"Password only"** switch, for devices that don't understand a standard (an old phone, a printer, a smart TV, or a Wi-Fi network you want to type in by hand).

**Never as QR:** payment card numbers and CVVs, seed phrases, the master password, recovery codes (except inside the Recovery Kit).

**Scanning QR codes** (phone camera, or a QR visible on screen for desktop and the extension) creates or fills items: Wi-Fi QR → Wi-Fi item, `otpauth://` and Google Authenticator export → one-time codes, vCard → identity, Recovery Kit QR → sign-in. Scanned content is parsed on the device and never sent anywhere.

### Generators and codes
| Feature | Priority |
|---|---|
| Random password generator (length 8–128, default 20; character sets, avoid ambiguous) | P0 |
| Passphrase generator (EFF large wordlist, default 5 words joined by `-`; capitalisation, numbers) | P0 |
| **Suggested strong password** on sign-up and change-password forms: one tap fills it into both password fields and saves the login (see plan 05) | P0 (browser), P1 (Android, macOS), iOS as Apple allows |
| Per-site password rules (from Apple's open `password-rules` dataset), so suggestions are accepted the first time | P1 |
| TOTP (RFC 6238): SHA-1/256/512, 6–8 digits, custom period; Steam Guard codes | P0 |
| Add TOTP from QR on screen (extension/desktop), camera (mobile), `otpauth://` URI | P0 |
| Copy TOTP after autofilling the password (browser/mobile) | P0 |
| HOTP (RFC 4226) | P2 |

### Autofill
| Feature | Priority |
|---|---|
| Browser: fill login forms, multi-step logins, TOTP fields | P0 |
| Browser: save/update prompt on submit | P0 |
| Browser: identity, address and card forms | P0 |
| Browser: passkey create/get (WebAuthn interception) | P0 |
| iOS/macOS: system AutoFill provider (passwords, passkeys, one-time codes) | P1 |
| Android: Autofill Service + Credential Manager provider (passkeys) | P1 |
| Windows: passwords via extension and auto-type | P1 |
| Windows: passkey plugin provider (Windows 11) | P2 |
| Linux: extension + auto-type hotkey | P1 |
| Domain matching rules: this host with the domains above and hosts below it (default since 2026-11-05, plan 05 History), base domain, exact host, starts-with, regex, never | P0 |
| Equivalent domains (e.g. `google.com` = `youtube.com`; user-editable) | P1 |

### Security
| Feature | Priority |
|---|---|
| Biometric unlock: see **Device unlock** below | P1 |
| **Device unlock**: unlock with whatever the device uses to unlock itself: Face ID / Touch ID / fingerprint, **or the device's own passcode / PIN / password** when there's no biometric (iPhone passcode, Android screen lock, Windows Hello PIN, Mac login password). Works in the apps, the autofill extensions, the browser extension and the web vault (via a passkey). No separate Octa Pass PIN. Devices with **no lock at all** follow Google Password Manager: an unlocked vault fills without a prompt, and the master password opens it after a restart (plan 03, the two device-auth gates). Design in plan 03 | P1 (apps, extension); web vault: device unlock only (M1) |
| Auto-lock timer, lock on sleep/screen lock, clipboard auto-clear. **Stay unlocked while logged in to this device** (plan 18, on by default in the apps and the extension, never in the web vault): no timer and no lock with the device; opening and filling don't ask, revealing and copying ask once, exporting and the account always ask. Off, or on a device with no lock, the timer and the lock on sleep/screen lock apply | P0 |
| Breached password check (HIBP Pwned Passwords k-anonymity) | P0 |
| Weak / reused / old password detection (zxcvbn-style strength estimator) | P0 |
| Missing 2FA (2fa.directory dataset), passkey available (passkeys.directory) | P1 |
| Insecure `http://` URLs, expiring cards/IDs | P1 |
| Email breach alerts for the account email and aliases (opt-in, HIBP API, server-proxied) | P1 |
| Two-factor for the Octa Pass account itself (TOTP, WebAuthn security key) | P1 |
| New-device sign-in email alerts | P0 |

### Sharing
| Feature | Priority |
|---|---|
| Shared vaults with other Octa Pass users (view / edit / manage) | P1 |
| Families (up to 6 members, free) with a shared family vault | P1 |
| One-time / expiring share link for a single item (key in URL fragment) | P1 |
| Emergency access (trusted contact, waiting period 1–30 days) | P1 |
| Teams/organisations with groups, policies, SSO | P2 |

### Import / export
See [07-import-export](07-import-export.md). P0: Chrome/Edge, Firefox, Safari/Apple Passwords, Bitwarden, 1Password, LastPass, generic CSV. P1: the rest, plus CXF.

### Developer
| Feature | Priority |
|---|---|
| CLI: login, unlock, list, get, generate, TOTP, inject secrets into env/run | P0 (dogfooding) |
| `op://`-style secret references in config files (`octapass://vault/item/field`) | P1 |
| SSH agent (desktop app serves keys; an approval lasts 15 minutes, plan 16 History) | P2, built (branch `m25-cli-ssh-git`); required for 1.0 |
| Public, documented sync API for self-hosters and third-party clients | P1 |

### Quality
| Requirement | Priority |
|---|---|
| Offline access with encrypted local cache | P0 |
| i18n: English and Arabic (RTL) at launch, community translations via Weblate | P0 (framework), P1 (languages) |
| Accessibility: WCAG 2.2 AA, screen readers, full keyboard use | P0 |
| Dark/light/system themes | P0 |

## Non-goals

- Ads, analytics SDKs, third-party trackers.
- Reading users' email inboxes or SMS.
- Masked phone numbers.
- Storing data anywhere unencrypted, including "metadata for search".
- A proprietary "pro" edition with closed features.

## Success measures (for the first year after public beta)

- Zero vault-data exposure incidents.
- Third-party audit published, with every high-severity finding fixed before 1.0.
- 95%+ successful imports from the top 7 providers (measured with opt-in, content-free error reports).
- Autofill success on the top 500 login pages, measured by an automated test corpus (see plan 05).

## History
- 2026-11-02: everything planned for after 1.0 is now inside 1.0 (maintainer decision). P2 items are required for 1.0: crypto wallet, database/server and custom template item types, several local vaults, HOTP, the EPC bank and wallet-address QR codes, NFC tags, the Windows passkey provider, teams and organisations, the SSH agent, masked email Phase B. Labels stay as they were so they keep showing the order of work; only their meaning changes. Roadmap and estimates are in plan 09.
- 2026-11-02 (branch `m25-item-types`, maintainer decision of the same day: everything after 1.0 is inside 1.0): the remaining item types are built in the core, `@octapass/vault-client`, the web vault, the extension and desktop (which reuse the web screens), the Tauri phone app's QR codes, `octapass-mobile`, the native iPhone and Android apps, and reading in the CLI. Types: `bankAccount`, `apiCredential`, `softwareLicense`, `idDocument` (`documentType` `passport | driverLicense | nationalId | other`; scans are its attachments), `cryptoWallet`, `database` (keeps password history), `custom` and `customTemplate`. Decisions:
  - **One field table, not one screen per type.** `crates/octapass-core/src/item_fields.rs` says what each type holds and how it shows, and the apps build one editor and one detail view from it. The web vault keeps the same table in `packages/vault-client/src/itemFields.ts`; `crates/octapass-core/tests/vectors/item-fields.json` makes both prove they agree, validation included. Native apps get it through `fieldSpecs` and a single `ItemDetails.structured` case.
  - **A custom type is a hidden `customTemplate` item** holding field names and kinds (`text | hidden | multiline | url | date | email | phone | totp`), never values, and synced and shared like any item. Making a `custom` item copies the fields, so items outlive their template. A kind this version doesn't know counts as hidden. Templates are kept out of lists unless asked for by type.
  - **Dates are `YYYY-MM-DD`** in `expiryDate`, `issueDate`, `purchaseDate` and `birthDate`, unlike a card's `MM/YY`. `port` is text, so a value another app exported isn't lost; the editor checks 1 to 65535. Choice fields keep words another app used.
  - **Secrets:** every `secret` and `secretLong` field is hidden, kept exactly as typed and never used as a subtitle or searched; the connection string and API key count as secrets. Long secrets are hidden in the editor too (the web vault asks for identity first; the native apps use their existing reveal, which doesn't ask). The seed phrase is hidden like a password; it gets no extra step beyond that.
  - **QR (plan's table above):** EPC QR version 002, UTF-8, for a valid IBAN in a SEPA country with an account holder's name, with an optional amount and reference; a bank account outside SEPA gets its IBAN as text on phones and no code in the web vault. `bitcoin:` (BIP 21) and `ethereum:` (EIP-681) only for addresses of the right shape; another chain's address shows as plain text. Wallets offer addresses and nothing else: a wallet's custom fields get no code because a seed could be in one, and a value with a space is refused as an address when saving and never shown as a code. The Rust and TypeScript versions share `tests/vectors/payment-qr.json`.
  - **Not built here:** expiry warnings for ID documents, licences and API credentials (m25-health; read `expiryDate`), breach and strength checks on database passwords, autofill from the new types, creating items of these types from the CLI (it has no generic create). Scanning a `bitcoin:` or EPC code into an item isn't in the plan and isn't built.
- 2026-10-25: environments are an item type (branch `m23-environments`, maintainer request). An environment holds a project (optional), a stage (`development`, `staging`, `production`, `testing`, `preview`, `local` or a custom name) and an ordered list of `KEY`/value pairs, each with a concealed flag (on by default) and an optional note; no project is a loose variable, a project without a stage is that project's shared set. Load order is shared set, stage, named environments, `--env-file` files, then `octapass://` references; later wins. A production stage loaded without naming it on the command line asks first. Item type `environment` is in the core, `@octapass/vault-client`, the web vault, the extension popup (which reuses the web screens) and the CLI; search matches titles and variable names, never values. The CLI adds `env list|show|set|unset|create|import|export|diff|hook|allow|deny`, `run --env/--project/--stage/--env-file-out`, `inject`, `octapass.toml` and a shell hook; files it writes are `0600` (Windows: one inherited entry replaced for the user) and never overwritten without `--force`, and secrets are never written to the system's persistent environment. Docs: `docs/features/environments.md`. The native phone apps, desktop-specific screens and third-party importers are not part of this branch.
- 2026-10-24: attachments (P1) and the Document item type built (branch `m7-attachments`): files on any item, attached by button or drag and drop, downloaded and decrypted on the device, removed; Document items (a file plus notes) in the editor and item view; storage use in Settings. 1 GiB per account and 100 MiB per file, as stored, both configurable on self-hosted servers. Web vault and desktop app; the mobile apps keep files intact but can't open or add them yet, and local vaults (no server) have no attachments. Exports list files by name, type and size but don't include them yet (the ZIP export in plan 07 is still to come). Share links leave files out.
- 2026-10-24: recovery info links, the recovery map and masked email Phase A built (branch `m8-recovery-masked`). A login's recovery email can be linked to an Identity's email or a masked email alias (`recovery.emailSource`), its phone to an Identity's phone (`recovery.phoneSource`). The recovery map groups logins by recovery email and phone, and also counts the email a login signs in with (sites send resets there); it finds each email's own login (by username and mail site, e.g. a Gmail address on google.com) and flags it when it has no 2FA. **Not built:** the "recovery email in a breach" check, because no breach check today works without sending the address (HIBP has no public k-anonymity search for emails); security questions; the alias list's per-alias actions (disable, delete). Masked email is not offered in local mode.
- 2026-10-24: attachments in the iPhone and Android apps (branch `m8-mobile-attachments`): add from the document picker, the system photo picker or the camera; open in Quick Look (iPhone) or the app the user picks (Android), which can share the file; remove; storage use in Settings. Offline, files are encrypted and kept on the phone, open from there, and upload after their item. File changes made on a phone merge over another device's edit of the same item instead of becoming a conflicting copy.
- 2026-10-24 (branch `m9-loose-ends`): the passphrase word list stays the EFF large list (changing it is a maintainer decision, not made here). Tests in the core generator and in `packages/vault-client/src/data` now pin what it gives: 7,776 = 6^5 unique words, log2(7776) ≈ 12.925 bits per uniformly picked word, about 64.6 bits for the default five words and 38.8 for the minimum of three.
- 2026-10-24: item lists sort and group (branch `m10-list-sort`, maintainer feedback). One "Sort and group" menu per list: sort by name A–Z or Z–A (`Intl.Collator` for the UI language, base sensitivity, numeric; ties by id), date added or last changed; group by type (fixed order, the default for All items, Favourites and vaults), first letter (Latin, Arabic with alef forms folded, `#` for the rest; the default for one-type lists, which don't offer type), vault (with several vaults) or none. Remembered per device and per list in `localStorage` (`octapass:list`), not synced. Search results stay ungrouped in name order with a note, the trash keeps deletion order, and the extension's This site view keeps match order. A "Favourites first" toggle was left out: favourites have their own list. Docs: `docs/features/sorting-and-grouping.md`.
- 2026-10-24: logins for the same website share one row in item lists (branch `m13-site-groups`, maintainer feedback after a ~900-login import). Two or more logins whose first URL has the same host (scheme, case, a leading `www.`, a trailing dot and the path ignored; a non-default port kept; subdomains apart, no registrable-domain grouping) become one row: avatar, host, "N accounts", chevron. It opens inline with the logins indented under it, on every platform (no sheet or separate screen, maintainer decision), stays open while unlocked (in memory only, since hosts are vault data) and opens by itself when one of its logins is selected. It sits inside the current section, by host in name order or at its newest / last-changed login in date order, and under its host's letter when grouped by letter. Only logins are combined. "Combine accounts for the same website" in the Sort and group menu, on by default, per device (`octapass:combineSites`). Search, the extension's This site view and autofill menus stay one row per item. Docs: `docs/features/sorting-and-grouping.md`.
- 2026-10-24: a One-time codes category (branch `m13-site-groups`, maintainer request): `/items/codes` lists every item whose summary has `hasTotp` (logins with a code, and code-only items such as unmatched authenticator imports), next to Passkeys with a count. `hasTotp` was already on every summary (web, desktop and mobile crates), so there's no new field: the list filter is `ItemFilter.totp`. Rows show the live code with a countdown ring as a copy button beside the item link (the item is opened only for its code, as the detail view does). Logins for one website are not combined there, so every code stays visible. The extension gets a Codes tab. Docs: `docs/features/totp.md`.
- 2026-10-24: Wi-Fi networks are an item type (branch `m14-wifi`, maintainer request). `wifi` in the core (`WifiDetails`) and `@octapass/vault-client`: `ssid`, `security` (`open | wep | wpa | wpaWpa2 | wpa2 | wpa2Wpa3 | wpa3 | wpa2Enterprise | wpa3Enterprise`), `password`, `hidden`, Enterprise `eapMethod`, `phase2`, `username`, `identity`, `serverDomain`, `caCertificate`, the flags `captivePortal`, `managed` (the user's note; the editor explains Apple's "Managed" = installed by a configuration profile) and `hotspot`, `notes`, `customFields`, `passwordHistory`. The overview's subtitle is always the SSID, so apps match networks without opening details. Personal Hotspot is a flag, not a security type (a hotspot is WPA2/WPA3 underneath). `WIFI:` codes use `T:WPA` for every WPA kind, `WEP`, `nopass`, `H:true`; Enterprise networks get no join code. Older Wi-Fi items (password items, or logins with nothing login-only, with an SSID field) move to the type on unlock (`upgradeLegacyWifiItems`, run by the shared app layout), in writable vaults only. Connected and in-range marks, saved-network import and "Save this network?" are in the apps only; what each platform allows is in `docs/features/wifi.md`.
- 2026-10-24 (branch `m10-qr-totp`): adding one-time codes from QR codes built everywhere. One reader in the core (`tools::qr`, `rqrr` for detection and decoding, `image` for PNG/JPEG/WebP/GIF behind the `qr-images` feature): images over 2048 px are scaled down, a median filter and an adaptive threshold handle grainy photos, inverted codes are tried, every code in the picture is returned; `summarize` sorts texts into one-time codes (`otpauth://`, and Google Authenticator exports joined across their `batch_index`/`batch_size` parts), broken codes and other QR codes. **Chosen `rqrr` over `rxing`**: pure Rust, small and maintained, while `rxing` ports all of ZXing's barcode formats, which we don't need. The web vault's WASM leaves the image decoders out (about 400 KB) and decodes with the browser (`createImageBitmap` → pixels → `readQrPixels`): its module grows from 2.40 to 2.56 MB (0.96 to 1.06 MB compressed) for the QR reader and the review; the extension, desktop, phones and CLI link the decoders. Sources: extension visible-tab capture and image context menu, macOS screen region (`screencapture -i`, Screen Recording permission requested once, never changed by us), phone camera and photo picker, and an image file, drop or paste in every app. Logins show **Add one-time code** in view mode; code-only items show **Link to a login** (moves the `otpauth://` link, trashes the item; no undo toast because the UI has no undo pattern, the trash restores it). Wi-Fi and vCard scanning stay phone-only.
- 2026-11-02 (branch `m25-key-rotation`): "rotate Secret Key" and "rotate vault keys" are built, in the server, web vault, desktop app, CLI and native apps. Emergency takeover and opt-in family organiser recovery too. See plan 03 and plan 06 History.
- 2026-10-25 (branch `m19-master-password`): the recovery code (P0) now resets the master password, and "Change master password" (P1) is in the web vault's Settings → Security. Reset is offered on the sign-in and lock screens of the web vault and the extension (in a tab, since reading the email closes the popup). Rotating the Secret Key alone and rotating vault keys are not built. The desktop, phone (Tauri and native) apps and the CLI now offer both (the CLI has `octapass change-master-password` and `octapass reset-master-password`). Design in plan 03 History.
- 2026-10-25: SSH keys are built now rather than after 1.0 (maintainer decision; plan 16 has the details). Wave 1 (branch `m22-ssh-keys`): the `sshKey` type (`privateKey` in OpenSSH form without a passphrase, `publicKey`, `keyType`, `fingerprint`, `comment`, an optional `passphrase` for copies written out of the vault, `notes`, `customFields`; the list subtitle is the fingerprint) in the core, the web vault, the extension popup and the CLI, with generate, import from a file or paste, and export. The SSH agent, the desktop app's `~/.ssh` integration and the native phone screens are wave 2.
- 2026-11-02 (branch `m25-platform-extras`): watch apps built for Apple Watch and Wear OS, showing one-time codes the phone computes and sends for 15 minutes at a time; the seed stays on the phone. Off by default, per phone. Design and reasons in plan 05 History; docs in `docs/features/watch.md`.
- 2026-11-02 (branch `m25-platform-extras`): the **Windows 11 passkey plugin provider** is built in the desktop app, off by default, and needs the app's MSIX package; every use asks for Windows Hello. It has not run on real Windows. Design and decisions in plan 05 History.
- 2026-11-02 (branch `m25-platform-extras`): masked email Phase B's forwarding service is built as `apps/relay`, off by default and not deployed; decisions in plan 06 History, the operator's open questions in plan 10. Whether the hosted service ever runs it is still the maintainer's decision.
- 2026-11-02 (branch `m25-platform-extras`): the alias list's per-alias actions noted as not built on 2026-10-24 are built: turn off, turn on and delete, in the web vault, desktop app and native phone apps. Details in plan 06 History. Importers for Zoho Vault, Avira, Norton, McAfee True Key and Kaspersky are built, as best effort (plan 07 History).
- 2026-11-02 (branch `m25-health`): the security dashboard's remaining checks are built: `http://` logins, expiring cards, IDs and passports, passkey available, backup codes running out, old passwords, dismissing warnings, one-click change password, and opt-in email breach alerts for the account email and aliases. The note above still holds: no check works without sending the address, so that one is off by default, disclosed before it's turned on, and needs an HIBP key on the server (plan 03 History). A recovery email that's neither the account email nor an alias still isn't checked. Details in plan 06 History.
- 2026-11-02 (branch `m25-vault-features`): vault features finished, all within plan 03. **Version history:** the last 10 versions of an item are kept by the server as ciphertext (plan 04 History); **Version history** on an item lists them and restores one as an ordinary edit. Restoring keeps the current files, passkeys and favourite flag, keeps the password history growing and never moves a HOTP counter back. Local vaults keep none yet. **Equivalent domains** are a hidden `equivalentDomains` item (`groups`, `excludedDefaults`), one per account in a personal vault, edited in Settings; matching reads every copy, because two devices can each make one before they sync, and the core refuses public suffixes, addresses and text that isn't a domain, on saving and again on reading. **Security questions** are `recovery.securityQuestions` (`question`, `answer`); **Random answer** is a five-word passphrase, because support agents read answers aloud. Enpass's question and answer pairs and Keeper's `securityQuestion` fields import into it. **Match rules:** `urlMatch` is in the editors, read at fill time as well as for suggestions. **HOTP** is a working code in the `totp` field (`otpauth://hotp/`); the stored counter is the next one to use (RFC 4226's counter 0 is the first code, as in Aegis), and it's saved before a code is shown, so a code is never handed out twice. A counter move sends `skipHistory`, so it doesn't push real edits out of the 10 versions. Imports keep HOTP as codes, not hidden fields; older imports stay hidden fields until the link is copied into the code field. **Wi-Fi guest mode:** **Share for a day** makes a one-time share link (24 hours, one view) and shows it as a QR. **NFC tags (Android):** the Wi-Fi Simple Configuration credential (`application/vnd.wfa.wsc`), which Android's NFC service joins from; the app warns first that a tag isn't encrypted. WEP, WPA3-only and Enterprise are refused because Android's tap-to-join doesn't read them, and iPhones don't join from tags.
- 2026-11-02 (branch `m25-teams`): teams/organisations with groups, policies and SSO built (plan 03, "Organisations and single sign-on"; plan 04 and plan 15 History). Roles owner, admin, member; one organisation per account, as with families. SSO is sign-in only: an extra step after the master password, OpenID Connect only. Not built: SCIM, SAML, admin account recovery, running an organisation outside the web vault. Docs: `docs/features/organisations.md`, `docs/features/single-sign-on.md`.
- 2026-11-02 (branch `m25-local-mode`): local mode, backups, Turn on sync and several local vaults on one device in the desktop app and the native phone apps. Design in plans 03, 05 and 17 History. The browser extension keeps one local vault.
- 2026-11-04 (branch `claude/sharp-ptolemy-0ouy33`, maintainer request): the sidebar's Vaults section gets quick lists between All items and the vaults, in the maintainer's order: Recently created, Nearby, Pinned, Favourites, Frequently used, Recently used, Recently modified, then the vaults and New shared vault. Maintainer decisions: they are **sidebar lists** (not more choices in the Sort menu); **Pinned is a list of its own**, a synced `pinned` flag on the item like `favorite`, with no effect on other lists' order; **uses are synced and encrypted** (plan 03 History), not kept per device; **every app** (web vault, desktop, iOS, Android, with the extension counting fills). Recently created, Frequently used, Recently used and Recently modified keep their own order, show 50 items and have no Sort menu; a search looks through what they show. A use is copying a field, filling, or opening the website; viewing or revealing isn't. **Nearby is not built**: it needs places saved with items and the location permission, so it shows as "Soon" and goes nowhere. Docs: `docs/features/quick-lists.md`.
- 2026-11-08 (maintainer request): **Nearby** is built, the last P2 item. Decisions:
  - **A place is an item of type `place`**, not a list on the vault: it syncs, versions, shares with a vault, goes to the trash, imports and exports like any item, and renaming a place is one edit. Its overview holds `title` (the name) and `place` (`latitude`, `longitude`, `radius` in metres, `networks`: SSIDs), so lists can match without decrypting details; its details hold `notes`. It's kept out of item lists like `equivalentDomains` (`HIDDEN_ITEM_TYPES`). Any item links to places with `places`, a list of place ids in its overview, so one place holds many items and an item can be at several places. A Wi-Fi item linked to a place lends the place its network, and a Wi-Fi item whose network the place names is listed there without a link.
  - **Where the device is**, worked out on the device in `octapass_core::places` (shared by the WASM build, the desktop app and `octapass-mobile`): the connected Wi-Fi network matching a place's networks, else one location reading within the place's radius, plus the reading's accuracy capped at 500 m (so a rough city-wide fix doesn't put the device everywhere). Radius default 150 m, kept within 25 m to 10 km. A network match wins over a location.
  - **The list:** the places the device is at first ("Now nearby: Office"), Wi-Fi matches before location matches; then the other places, nearest first when the location is known, each with a rough distance worked out on the device; places with no point (or every place, without a reading) follow in name order. Each place shows its items in a section per type, in the lists' type order, each section by name. Places with no items are listed too. Without Wi-Fi or a location, every place is listed, none marked, and the list says why.
  - **Location is foreground only**: one reading when Nearby opens or the app comes forward, never in the background, never watched or kept. Off until turned on in the web vault and the Windows and Linux app (Settings → Nearby, or **Use my location** in Nearby); on phones, tablets and the Mac, the system's when-in-use prompt the first time Nearby opens. No map tiles or geocoding: users name places and type or capture coordinates (plan 03, *Nearby*).
  - **Suggest a place when saving** (maintainer, 2026-11-08): after a new item is saved while the device is at a place, "You're at Office. Add this item to it?" (Add, Not now). Asked once per item; only places every reader of the item can see (in the item's vault, or any place for a personal-vault item); not when Wi-Fi and location tell nothing; a per-device setting turns it off. Built in the web vault, the desktop app and both phone apps' editors. Not offered for items saved by autofill or an import (the extension and the phones' autofill extensions can't read location or Wi-Fi, and an import is many items): see plan 09.
  - **Shared vaults:** a place there is seen by every member; saving one with a point warns "Everyone in this vault will see where this place is".
  - **The extension** shows the web vault's Nearby (its full-page vault is the web vault's UI) without a location: extensions can't see Wi-Fi, and asking for `geolocation` would add an install-time permission for everyone.
  - **Import and export** carry places (Octa Pass JSON and encrypted exports); `relink` points items' `places` at the places' new ids. CSV leaves places out.
  - The native Mac app shares the iPhone's screens and reads the location with CoreLocation; it doesn't read the Wi-Fi network yet (its `WifiRadar` is a stand-in). The Windows and Linux app reads Wi-Fi through its `wifi` crate and the location from its web view, where the web view offers one.
- 2026-11-08: organisations gain SAML 2.0 sign-in (beside OpenID Connect, still a step after the master password), SCIM 2.0 provisioning of members and groups, and administration from the CLI and the Windows and Linux app (plan 03, plan 15 History). Admin account recovery and group keys stay out.
- 2026-11-08: the rest of the newer item types (the 2026-11-02 entry's "Not built here"). **Expiry warnings** cover every type with an expiry date: cards, ID documents, software licences and API credentials (`expiryDate`), with the same 60-day window, dismissal and strings, in the web vault, extension, desktop and phones (`packages/vault-client/src/tools/health.ts`, the desktop vault's and `octapass-mobile-vault`'s `EXPIRING_TYPES`). Certificates keep their own renewal reminders. **Autofill** from bank accounts, databases, licences, ID documents and wallet addresses in the browser extension, and databases in desktop auto-type: decisions in plan 05 History. **`octapass create`** makes every type that's typed in: bank accounts, API credentials, licences, ID documents, wallets (`address.<network>`), databases, custom items (`--template`) and templates, with the core's field table (`item_fields`), its choices and its checks; certificates and keys point to their own commands. Docs: `docs/features/item-types.md`, `docs/features/autofill.md`, `docs/platforms/cli.md`.
