# 17a — Native parity checklist: web vault vs iOS vs Android

Plan 17, phase 3. Every web vault feature against the two native apps. **Status:** every row is closed except the ones whose Note says Open or Decision needed, and the four rows marked Partial, each explained in its Note.

Audited 2026-11-02 on branch `m25-native-parity`, base commit `c6314ad`.

**Status values.** Yes. No. Partial. N/A (does not apply on phones, with the reason). **Not in web** (no such feature on the web, so nothing to match). **In progress** (SSH keys and environments, m25).

**Paths.** `web:` = `apps/web/src/`. `ios:` = `apps/ios/OctaPass/`. `and:` = `apps/android/app/src/main/kotlin/app/octapass/android/`.

**Method.** All web screens were read in full. Most iOS screens were read in full. Android item, list, editor, files, sidebar, Wi-Fi, emergency, settings and masked email were read in full; the other Android screens by grep (see Limits at the end). A diff of the shared string keys used by each client found the leads, and each was then checked in code.

The audit was made by reading code. Rows marked closed were changed afterwards on the same branch; line references in the remaining notes are from the base commit.

---

## Sign-in & onboarding

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Sign in: email, master password | web:screens/auth/SignIn.tsx:128 | Yes | Yes | |
| Prefill last remembered account and its server | SignIn.tsx:24-30 | Yes | Yes | |
| Secret Key asked only on an unknown device | SignIn.tsx:63,151 | Yes | Yes | |
| Choose server: hosted or self-hosted URL | ServerPicker.tsx:18 | Yes | Yes | iOS relies on the server call to reject http; message is the same |
| "Signing in to…" with Change link | SignIn.tsx:168 | Yes | Yes | |
| Pending two-step survives closing the app | SignIn.tsx:40 | Yes | Yes | |
| Two-step: authenticator code | TwoStepForm.tsx:87 | Yes | Yes | |
| Two-step: recovery code | TwoStepForm.tsx:103 | Yes | Yes | |
| Two-step: security key | TwoStepForm.tsx:119 | N/A | N/A | Web vault only (plan 03, plan 06) |
| Two-step: start over | TwoStepForm.tsx:80 | Yes | Yes | |
| Forgot master password from sign-in and lock | SignIn.tsx:146; Lock.tsx:156 | Yes | Yes | m19 |
| Reset: email, code, recovery code, new password, new kit, two-step | ResetPassword.tsx | Yes | Yes | From plan history and UI tests; screens not read line by line |
| Sign-up: email, password, strength, confirm, server | SignUp.tsx:76 | Yes | Yes | |
| Sign-up: blocks weak password, signups-closed error | SignUp.tsx:91,103 | Yes | Yes | |
| Sign-up: step progress | SignUp.tsx:22 | Yes | Yes | |
| Sign-up: email code, dev code shown, change email | SignUp.tsx:151 | Yes | Yes | |
| Recovery Kit sheet with QR | RecoveryKitSheet.tsx:14 | Yes | Yes | Native also saves or shares a PDF |
| Kit: print | SignUp.tsx:210 | Yes | Yes | |
| Kit: "I saved it" gate | SignUp.tsx:214 | Yes | Yes | |
| Done step with facts | SignUp.tsx:223 | Yes | Yes | |
| Scan kit QR at sign-in to fill email, server, Secret Key | kit text only (RecoveryKitSheet.tsx:7) | No | No | Decision needed. Nothing parses `octapass://setup`, web included: add a parser to the API, or change the kit's text. |
| Device unlock offer after sign-in, one reminder | screens/vault/DeviceUnlockOffer.tsx | Yes | Yes | |
| Account deleted goodbye screen | AccountDeleted.tsx | Yes | Yes | Closed in m25-native-parity. |

## Unlock & lock

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Unlock with master password | Lock.tsx:117 | Yes | Yes | |
| Unlock with device, auto-start once | Lock.tsx:52-66 | Yes | Yes | |
| Use master password instead | Lock.tsx:102 | Yes | Yes | |
| Password required after 14 days (notice) | Lock.tsx:108 | Yes | Yes | |
| Device-unlock failure falls back to password | Lock.tsx:37-45 | Yes | Yes | |
| Sign out from lock screen | Lock.tsx:82 | Yes | Yes | |
| "App open" gate honoured (`requireDeviceAuthOnAppOpen`) | Lock.tsx:59 | Yes | Yes | Closed in m25-native-parity. |
| Auto-lock after inactivity | lib/useAutoLock.ts:9 | Yes | Yes | Touches count as activity |
| Lock on background | useAutoLock.ts:18 | Yes | Yes | |
| Lock now button | Sidebar.tsx:78; SettingsPage.tsx:132 | Yes | Yes | |
| Stay unlocked while logged in (plan 18): the switch, on by default, its text, the gates greyed out under it | web:screens/settings/DeviceAuthSection.tsx (desktop, extension) | Yes | Yes | Not in the web vault (plan 18). Both gates show greyed out under it (iOS had only the open gate until 2026-11-08). The key: iOS Keychain `WhenPasscodeSetThisDeviceOnly`, Android Keystore `setUnlockedDeviceRequired(true)`, both through `NativePlatform.storeStayUnlockedKey` in `octapass-mobile`. |
| Stay unlocked: opens without a prompt, autofill fills without one | web:screens/auth/Lock.tsx (`unlockStayUnlocked`) | Yes | Yes | AutoFill extension and Android services use `LocalStore.unlockStayUnlocked`. |
| Reveal and copy don't ask while the vault is open (plan 03, 2026-11-06) | web:lib/identityGate.tsx (`unlockCoversReveal`) | Yes | Yes | However the vault opened; export, the Secret Key and the account settings ask every time. |
| Stay unlocked: falls back without a device lock, says why | DeviceAuthSection.tsx (`StayUnlockedRow`) | Yes | Yes | "Set a passcode…" / "Set a screen lock…"; the 14-day check stops it until the master password is typed. |
| Identity gate on reveal | screens/vault/Fields.tsx:66 | Yes | Yes | Closed in m25-native-parity. Since 2026-11-05 a checked unlock covers it until the vault locks (`confirmReveal`, plan 03 History); still asks with the open gate off or no device lock. |
| Identity gate on copy of secrets | Fields.tsx:23,54 | Yes | Yes | Closed in m25-native-parity. Covered by a checked unlock since 2026-11-05, as reveal. |
| Identity gate on Secret Key show and copy | SettingsPage.tsx:209-221 | Yes | Yes | Closed in m25-native-parity. Asks every time (`confirmIdentity`). |
| Identity gate on export | ExportDialog.tsx:80 | Yes | Yes | Closed in m25-native-parity. Asks every time (`confirmIdentity`). |
| Identity gate before QR | n/a | Yes | Yes | Native only. The only current use of `confirmUser` |

## Item list

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Scopes: all, favourites, passkeys, codes, trash, vault, type | lib/scope.ts:11 | Yes | Yes | |
| Scopes: pinned, and the smart lists (created, frequent, used, changed) | lib/scope.ts:8 | Yes | Yes | Smart lists come from `smartList`; no Sort menu there. Not built or run on a device yet |
| Sidebar: quick lists above the vaults, Nearby included | Sidebar.tsx:73 | Yes | Yes | Counts on Pinned and Favourites only |
| Nearby: the place the device is at first, items by type, other places nearest first with distances, why none is here | Nearby.tsx | Yes | Yes | The core orders and groups (`nearby`). The Mac matches by location only (no Wi-Fi reader yet) |
| Nearby: Places manager and editor (networks, Use my current location, radius, note, shared-vault warning) | Nearby.tsx | Yes | Yes | |
| Nearby: Places on an item (Add to a place, remove) and Add an item here | Nearby.tsx | Yes | Yes | `setItemPlace`; new item drafts carry `places` |
| Nearby: offer a new item the place you're at, and the setting to turn it off | Nearby.tsx | Yes | Yes | Per device, on by default. Not offered after autofill saves |
| Sidebar: vaults with counts and badges | Sidebar.tsx:87 | Yes | Yes | |
| Sidebar: new shared vault | Sidebar.tsx:92 | Yes | Yes | |
| Sidebar: categories with counts | Sidebar.tsx:103 | Yes | Yes | SSH and environment rows in progress |
| Sidebar: tools | Sidebar.tsx:110 | Yes | Yes | |
| Sidebar: health score ring | Sidebar.tsx:123 | **Partial** | Yes | iPad row has no score; iPhone has only the Health tab (ios:Vault/MainView.swift:222). The view's doc comment claims the score |
| Sidebar: account email | Sidebar.tsx:131 | Yes | Yes | |
| Primary tabs | VaultLayout.tsx:82 | Yes | Yes | |
| Search field with count placeholder | ItemsPage.tsx:154 | Yes | Yes | Rust search covers title, subtitle, URLs, tags |
| Search ignores grouping, note shown | ItemsPage.tsx:87,206 | Yes | Yes | |
| Result count announced to screen readers | ItemsPage.tsx:222 | Yes | Yes | Closed in m25-native-parity. |
| Sort menu: 5 sorts, per-list | SortMenu.tsx:69 | Yes | Yes | |
| Group by: type, letter, vault, none | listArrangement.ts:27 | Yes | Yes | |
| Group by project | listArrangement.ts:29 | In progress | In progress | Rust done; see last section |
| Combine accounts for one website | SortMenu.tsx:86 | Yes | Yes | |
| Sticky section headers with count | ItemSections.tsx:78 | Yes | Yes | |
| Site row opens in place, kept while unlocked | SiteGroup.tsx:14 | Yes | Yes | |
| Site row auto-opens when holding the open item | SiteGroup.tsx:20 | N/A | Yes | iPhone navigates away. iPad split view could use it, not done |
| Row: icon, title, star, subtitle | ItemsPage.tsx:254 | Yes | Yes | |
| Row: shared vault tag | ItemsPage.tsx:267 | Yes | Yes | |
| Row: passkey and code flags | ItemsPage.tsx:272 | Yes | Yes | |
| Codes list: live code, ring, tap to copy | LiveCode.tsx | Yes | Yes | iOS spaces only 6-digit codes (ios:Items/FieldRows.swift:158); web splits any length |
| Wi-Fi list: Connected / In range mark on rows | ItemsPage.tsx:271 | Yes | Yes | Closed in m25-native-parity. |
| Wi-Fi list: In range section first | ItemsPage.tsx:89 | Yes | Yes | Closed in m25-native-parity. |
| Wi-Fi list: refresh | Wifi.tsx:93 | Yes | Yes | Closed in m25-native-parity. |
| Wi-Fi list: bring in from device (explainer) | Wifi.tsx:94,309 | Yes | Yes | Closed in m25-native-parity. |
| Wi-Fi list: location permission note | ItemsPage.tsx:208 | Yes | Yes | Closed in m25-native-parity. |
| Members button on shared or family vault list | ItemsPage.tsx:133 | Yes | Yes | Closed in m25-native-parity. |
| Untrusted vault warning | ItemsPage.tsx:207 | Yes | Yes | |
| New item menu by type | ItemsPage.tsx:139 | Yes | Yes | |
| New item blocked in read-only or untrusted vault | ItemsPage.tsx:66 | Yes | Yes | Android's Scan button is still shown there (and:ui/vault/ItemsScreen.kt:204) |
| Scan QR from new-item area | ItemsPage.tsx:148 | Yes | Yes | |
| Empty states by scope | ItemsPage.tsx:297 | Yes | Yes | |
| Empty vault: Import button | ItemsPage.tsx:322 | Yes | Yes | Closed in m25-native-parity. |
| Load failure with Try again | ItemsPage.tsx:213 | Yes | Yes | |
| Trash note, days left per row | ItemsPage.tsx:205,250 | Yes | Yes | |
| Bulk select | none | Not in web | Not in web | |
| Empty trash / delete forever | none | Not in web | Not in web | Server purges after 30 days |
| Folders, collections | none | Not in web | Not in web | Vaults and tags only |
| Tag filter | none | Not in web | Not in web | Tags are searchable, not a filter |
| Keyboard shortcuts, arrow keys, skip link, shortcut hints | ItemsPage.tsx:93,113,335 | N/A | N/A | No keyboard-first use |
| Live update on change | useItems.ts:10 | Yes | Yes | |
| Legacy Wi-Fi password items upgraded to Wi-Fi type | lib/wifi.ts:163 | **No** | **No** | Open. Web converts in the background; native only displays them. Needs a port to the API. |

## Item view

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Header: icon, title, host or type, encrypted badge | ItemDetail.tsx:201 | Yes | Yes | |
| Favourite | ItemDetail.tsx:170 | Yes | Yes | iOS in More menu |
| Pin | ItemDetail.tsx:190 | Yes | Yes | More menu on both; iOS also swipes. Not built or run on a device yet |
| Copying a field or opening the website counts a use | lib/usage.tsx:37; lib/clipboard.ts:38 | Yes | Yes | `recordItemUse`; saved at once when the app goes to the background. The AutoFill extension and the Autofill service don't count uses |
| Move to trash | ItemDetail.tsx:178 | Yes | Yes | |
| Edit | ItemDetail.tsx:179 | Yes | Yes | |
| Restore from trash, notice | ItemDetail.tsx:185,194 | Yes | Yes | |
| Read-only notice | ItemDetail.tsx:199 | Yes | Yes | |
| More: share link, move, copy | ItemDetail.tsx:152 | Yes | Yes | |
| Copy username, URL (no auto-clear) | Fields.tsx:54 | Yes | Yes | |
| Password reveal and copy | Fields.tsx:61 | Yes | Yes | Closed in m25-native-parity. |
| Clipboard auto-clear 30 s | lib/clipboard.ts:5 | Yes | Yes | Fixed on web; a configurable timeout is Not in web |
| Live TOTP, ring, seconds left | Fields.tsx:116 | Yes | Yes | |
| Add one-time code without opening the editor | ItemDetail.tsx:138; otp/AddCodeDialog.tsx | Yes | Yes | Closed in m25-native-parity. |
| Link a code-only item to a login | ItemDetail.tsx:143 | Yes | Yes | Android in More menu |
| Website links, multiple, open and copy | ItemDetail.tsx:283 | Yes | Yes | |
| HTTP realm shown | ItemDetail.tsx:291 | Yes | Yes | Closed in m25-native-parity. |
| Passkeys list | ItemDetail.tsx:294 | Yes | Yes | |
| Recovery: 2FA method, email, phone | ItemDetail.tsx:351 | Yes | Yes | |
| Recovery: linked alias or identity | ItemDetail.tsx:339 | Yes | Yes | |
| Recovery: "also resets N logins" link to map | ItemDetail.tsx:345 | Yes | Yes | Closed in m25-native-parity. |
| Recovery: backup codes show/hide, left count, used state | ItemDetail.tsx:360 | Yes | Yes | |
| Custom fields, hidden ones | ItemDetail.tsx:312 | Yes | Yes | |
| Notes | ItemDetail.tsx:320 | Yes | Yes | iOS hides notes behind reveal (stricter) |
| Password history reveal | ItemDetail.tsx:387 | Yes | Yes | |
| Card face and fields | ItemDetail.tsx:407 | Yes | Yes | |
| Identity fields, address | ItemDetail.tsx:436 | Yes | Yes | |
| Secure note | ItemDetail.tsx:252 | Yes | Yes | |
| Wi-Fi: fields, enterprise, about flags | Wifi.tsx:104 | Yes | Yes | |
| Wi-Fi: Connected mark | Wifi.tsx:119 | Yes | Yes | |
| Wi-Fi: In range with signal bars | Wifi.tsx:56 | N/A | Yes | iOS gives apps no scan results |
| Wi-Fi: QR | Wifi.tsx:146 | Yes | Yes | Full-screen sheet |
| Wi-Fi: Connect | apps only | Yes | Yes | |
| Tags | ItemDetail.tsx:220 | Yes | Yes | |
| Meta: in vault, updated, created | ItemDetail.tsx:458 | Yes | Yes | |
| Meta: shared vault with member count | ItemDetail.tsx:465 | Yes | Yes | Closed in m25-native-parity. |
| Meta: password changed date | ItemDetail.tsx:470 | Yes | Yes | Closed in m25-native-parity. |
| Meta: last used date | ItemDetail.tsx:471 | Yes | Yes | Closed in m25-native-parity. |
| Not found / load failed states | ItemDetail.tsx:84 | Yes | Yes | |

## Item editor

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Title, per-type placeholder | ItemEditor.tsx:162 | Yes | Yes | |
| Validation errors, count banner | ItemEditor.tsx:111 | Yes | Yes | Via Rust `validateDraft` |
| Discard changes prompt | ItemEditor.tsx:213 | Yes | Yes | |
| New login for a saved site and username: asks before a copy | ItemEditor.tsx (`findSameLogin`) | **Partial** | **Partial** | Rust `sameLogin`. Keep editing or Save a copy; no Open it, which on the phones would leave the form without the discard prompt. Written 2026-11-04 without a Mac or the Android SDK: not compiled or run yet |
| New in Favourites starts favourite | ItemEditor.tsx:60 | Yes | Yes | Closed in m25-native-parity. |
| New in Pinned starts pinned | ItemEditor.tsx:63 | Yes | Yes | |
| Vault choice, locked on edit | ItemEditor.tsx:197 | Yes | Yes | |
| Tags, comma list | ItemEditor.tsx:208 | Yes | Yes | |
| Favourite switch | ItemEditor.tsx:209 | Yes | Yes | |
| Pinned switch | ItemEditor.tsx:241 | Yes | Yes | |
| Username only on Login type | EditorSections.tsx:111 | **Partial** | Yes | iOS also shows it on Password items (ios:Items/ItemEditor.swift:271) |
| Password masked, with reveal | EditorSections.tsx:123 | Yes | Yes | Closed in m25-native-parity. |
| Generate password | EditorSections.tsx:128 | Yes | Yes | |
| Strength hint | EditorSections.tsx:130 | Yes | Yes | |
| One-time code field | EditorSections.tsx:133 | Yes | Yes | |
| HTTP realm field | EditorSections.tsx:147 | Yes | Yes | Closed in m25-native-parity. |
| Websites: add, remove, validate | EditorSections.tsx:160 | Yes | Yes | iOS allows zero rows; web keeps one |
| Website match rules | none | Not in web | Not in web | Plan 17 History |
| Masked email for username | EditorSections.tsx:119 | Yes | Yes | Closed in m25-native-parity. |
| Masked email for recovery email | EditorSections.tsx:316 | Yes | Yes | Closed in m25-native-parity. |
| Recovery: 2FA method | EditorSections.tsx:295 | Yes | Yes | |
| Recovery: email, phone | EditorSections.tsx:308 | Yes | Yes | |
| Recovery: typing breaks the source link | EditorSections.tsx:313 | Yes | Yes | Closed in m25-native-parity. |
| Recovery: pick from identities | EditorSections.tsx:267 | Yes | Yes | Closed in m25-native-parity. |
| Recovery: linked label and Unlink | EditorSections.tsx:254 | Yes | Yes | Closed in m25-native-parity. |
| Backup codes: add, edit, mark used, remove | EditorSections.tsx:350 | Yes | Yes | |
| Backup codes: paste many | EditorSections.tsx:361 | Yes | Yes | Closed in m25-native-parity. |
| Custom fields: add, hidden, remove | EditorSections.tsx:443 | Yes | Yes | |
| Custom fields: reorder | none | Not in web | Not in web | Only environment variables reorder |
| Passkeys read-only | EditorSections.tsx:196 | Yes | Yes | iOS only on Login type; web also on Password |
| Notes | EditorSections.tsx:213 | Yes | Yes | |
| Auto-type settings | EditorSections.tsx:186 | N/A | N/A | Desktop only (`service.autoType`) |
| Card fields | EditorSections.tsx:471 | Yes | Yes | Closed in m25-native-parity. |
| Identity fields | EditorSections.tsx:493 | Yes | Yes | Closed in m25-native-parity. |
| Note editor | EditorSections.tsx:530 | Yes | Yes | |
| Document: notes | EditorSections.tsx:539 | Yes | Yes | |
| Wi-Fi: SSID kept exactly, security, hidden | EditorSections.tsx:566 | Yes | Yes | |
| Wi-Fi: security hints | EditorSections.tsx:587,595 | Yes | Yes | Closed in m25-native-parity. |
| Wi-Fi: generate and strength | EditorSections.tsx:597,599 | Yes | Yes | Closed in m25-native-parity. |
| Wi-Fi: enterprise fields | EditorSections.tsx:605 | Yes | Yes | Closed in m25-native-parity. |
| Wi-Fi: about flags, custom fields, notes | EditorSections.tsx:641 | Yes | Yes | |
| Save network offer arrives prefilled | ItemEditor.tsx:50 | Yes | Yes | Closed in m25-native-parity. |

## Files

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| List with name, size, type | Files.tsx:108 | Yes | Yes | |
| Open or download | Files.tsx:162 | Yes | Yes | Quick Look; system viewer |
| Add from Files, Photos, Camera (item view) | Files.tsx:83 | Yes | Yes | |
| Remove with confirm | Files.tsx:216 | Yes | Yes | |
| Waiting for upload (offline) | Files.tsx:188 | Yes | Yes | |
| Uploading row | Files.tsx:203 | Yes | Yes | iOS: spinner on the button |
| Downloading note | Files.tsx:188 | Yes | Yes | Closed in m25-native-parity. |
| Files in the editor: add while editing | Files.tsx:297 | Partial | Yes | On iOS an existing item's files are added on its own screen, at once; the editor does new items. |
| Files in the editor: mark to remove, keep | Files.tsx:338 | Partial | Yes | On iOS an existing item's files are removed on its own screen, at once. |
| New item (any type) with files | ItemEditor.tsx:194 | Yes | Yes | Closed in m25-native-parity. |
| Document must keep one file | ItemEditor.tsx:115 | Partial | Yes | iOS checks new documents only; item view can remove the last file, as on web |
| Drag and drop | Files.tsx:23 | N/A | N/A | No file drag on phones |
| Storage usage | SettingsPage.tsx:239 | Yes | Yes | |

## Generator

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Password or passphrase | GeneratorPanel.tsx:87 | Yes | Yes | |
| Length 8 to 64 | GeneratorPanel.tsx:100 | Yes | Yes | |
| Upper, lower, digits, symbols | GeneratorPanel.tsx:101 | Yes | Yes | |
| Avoid ambiguous | GeneratorPanel.tsx:105 | Yes | Yes | |
| Passphrase words 3 to 10 | GeneratorPanel.tsx:109 | Yes | Yes | iOS stepper |
| Separator | GeneratorPanel.tsx:112 | Yes | Yes | |
| Capitalize, include number | GeneratorPanel.tsx:119 | Yes | Yes | |
| Strength and bits | GeneratorPanel.tsx:76 | Yes | Yes | |
| Regenerate, copy | GeneratorPanel.tsx:81 | Yes | Yes | |
| Options remembered, never the value | GeneratorPanel.tsx:21 | Yes | Yes | |
| Digits and symbols coloured | GeneratorPanel.tsx:35 | Yes | Yes | Closed in m25-native-parity. |
| Use this password from editor | EditorSections.tsx:217 | Yes | Yes | |
| Generates locally note | GeneratorPage.tsx:15 | Yes | Yes | |
| Make a masked email on Generator | GeneratorPage.tsx:16 | Yes | Yes | Closed in m25-native-parity. |

## One-time codes & QR

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Scan: camera | QrCapture.tsx:71 | Yes | Yes | |
| Scan: photo | QrCapture.tsx:71 | Yes | Yes | |
| Scan: image file | QrCapture.tsx:90 | Yes | Yes | |
| Paste setup link | QrCapture.tsx:107 | Yes | Yes | |
| Paste bare key (add to one login) | AddCodeDialog.tsx:49 | Yes | Yes | Closed in m25-native-parity. |
| Paste or drop screenshot | QrCapture.tsx:32,51 | N/A | N/A | Photo picker covers it |
| Google Authenticator export, parts counted | QrCapture.tsx:130 | Yes | Yes | |
| Counter-based codes flagged | AddCodeDialog.tsx:90; ScanCodesDialog.tsx:154 | Yes | Yes | |
| Review: each code joins a login or stays separate | otp/ImportReviewList.tsx:33 | Yes | Yes | |
| Login picker: search title, user, site | otp/LoginPicker.tsx:20 | Yes | Yes | |
| Login picker: Password-type items | LoginPicker.tsx:16 | Yes | Yes | Closed in m25-native-parity. |
| Login picker: only writable vaults | LoginPicker.tsx:15 | Yes | Yes | Closed in m25-native-parity. |
| Login picker: logins with a code unavailable | LoginPicker.tsx:72 | Yes | Yes | |
| Link code to login, old item trashed | otp/LinkToLoginDialog.tsx | Yes | Yes | |
| `otpauth://` links open the app | apps only | Yes | Yes | |

## Health & recovery map

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Score ring, verdict, count, checked at | HealthPage.tsx:59 | Yes | Yes | |
| Check again | HealthPage.tsx:26 | Yes | Yes | |
| Breach check unavailable warning | HealthPage.tsx:75 | Yes | Yes | |
| Five stat tiles | HealthPage.tsx:77 | Yes | Yes | |
| Tile jumps to its section | HealthPage.tsx:80 | Yes | Yes | Closed in m25-native-parity. |
| Weak, reused, breached, missing 2FA, recovery lists | HealthPage.tsx:89 | Yes | Yes | |
| Rows open the item | HealthPage.tsx:173 | Yes | Yes | |
| How breach checks work link | HealthPage.tsx:114 | **No** | **No** | Open. `SITE_URL` is still the placeholder `octap.app`: add once the public address is decided. |
| Refresh after edits | lib/health.tsx:43 | Yes | Yes | Closed in m25-native-parity. |
| Recovery map: contact, count, logins | RecoveryMapPage.tsx:52 | Yes | Yes | |
| Recovery map: masked, account two-step tags | RecoveryMapPage.tsx:60 | Yes | Yes | |
| Recovery map: from identity | RecoveryMapPage.tsx:69 | Yes | Yes | |
| Recovery map: empty state, breach gap note | RecoveryMapPage.tsx:37,44 | Yes | Yes | |

## Masked email

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Connected providers list | MaskedEmailPage.tsx:45 | Yes | Yes | |
| Disconnect with confirm | MaskedEmailPage.tsx:62 | Yes | Yes | |
| Connect: all providers, token, get-token link | MaskedEmailPage.tsx:78 | Yes | Yes | |
| Connect: domain, self-hosted URL | MaskedEmailPage.tsx:130 | Yes | Yes | |
| Blocked here notices | MaskedEmailPage.tsx:54,110 | N/A | N/A | Browser CORS only (`usableIn`) |
| Make alias for a site, copy | MaskedEmailPage.tsx:156 | Yes | Yes | |
| Choose provider when several | MaskedEmailPage.tsx:187 | Yes | Yes | Closed in m25-native-parity. |
| Aliases in use, links to logins | MaskedEmailPage.tsx:216 | Yes | Yes | |

## Sharing

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Your fingerprint | SharingPage.tsx:57 | Yes | Yes | |
| Shared vaults list with role | SharingPage.tsx:73 | Yes | Yes | Closed in m25-native-parity. |
| New shared vault | CreateVaultDialog.tsx | Yes | Yes | |
| Members: open vault | VaultMembersPage.tsx:78 | Yes | Yes | |
| Members: untrusted warning | VaultMembersPage.tsx:84 | Yes | Yes | Closed in m25-native-parity. |
| Members: family vault notice with link | VaultMembersPage.tsx:85 | Yes | Yes | Closed in m25-native-parity. |
| Members: rename | VaultMembersPage.tsx:91 | Yes | Yes | Closed in m25-native-parity. |
| Members: list, verified badge, unverified count | VaultMembersPage.tsx:93 | Yes | Yes | |
| Members: date added | VaultMembersPage.tsx:197 | Yes | Yes | Closed in m25-native-parity. |
| Members: compare and verify fingerprint | VaultMembersPage.tsx:202,227 | Yes | Yes | Closed in m25-native-parity. |
| Members: change role | VaultMembersPage.tsx:209 | Yes | Yes | Closed in m25-native-parity. |
| Members: remove (rotates key) | VaultMembersPage.tsx:221 | Yes | Yes | Closed in m25-native-parity. |
| Members: invite with role and fingerprint | VaultMembersPage.tsx:107 | Yes | Yes | Closed in m25-native-parity. |
| Members: leave | VaultMembersPage.tsx:122 | Yes | Yes | |
| Members: last owner can't leave | VaultMembersPage.tsx:65,125 | Yes | Yes | Closed in m25-native-parity. |
| Move or copy to another vault | MoveCopyDialog.tsx | Yes | Yes | Web opens the new copy afterwards; native stays |

## Families

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Create | FamilyPanel.tsx:34 | Yes | Yes | |
| Invitations: accept, decline | FamilyPanel.tsx:66 | Yes | Yes | iOS omits the invited-on date |
| Members and roles | FamilyPanel.tsx:104 | Yes | Yes | |
| Count (members plus invites) of max | FamilyPanel.tsx:93,98 | Yes | Yes | Closed in m25-native-parity. |
| Open family vault | FamilyPanel.tsx:99 | Yes | Yes | |
| Remove member, cancel invite | FamilyPanel.tsx:117,135 | Yes | Yes | |
| Invite with fingerprint, full notice | FamilyPanel.tsx:145 | Yes | Yes | |
| Leave, delete | FamilyPanel.tsx:161 | Yes | Yes | |

## Share links

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Create: expiry, views 1 to 100, passphrase | ShareLinkDialog.tsx:89 | Yes | Yes | |
| Link ready: copy, passphrase reminder | ShareLinkDialog.tsx:64 | Yes | Yes | iOS also has share sheet; Android has no share button |
| Manage links shortcut | ShareLinkDialog.tsx:77 | Yes | Yes | Closed in m25-native-parity. |
| List: expires, views, passphrase | SharingPage.tsx:109 | Yes | Yes | |
| List: tap opens the item | SharingPage.tsx:127 | Yes | Yes | Closed in m25-native-parity. |
| Revoke | SharingPage.tsx:142 | Yes | Yes | |
| Open a share link in the app | SharedLinkPage.tsx | **No** | **No** | Decision needed. The API exists; apps need universal links and app links. |

## Emergency access

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| How it works | EmergencyPage.tsx:41 | Yes | Yes | |
| Trusted contacts list with scope, level, wait | EmergencyPage.tsx:87 | Yes | Yes | |
| Requested: approve, deny | EmergencyPage.tsx:109 | Yes | Yes | |
| Released: deny | EmergencyPage.tsx:125 | Yes | Yes | |
| Remove contact | EmergencyPage.tsx:104 | Yes | Yes | iOS swipe only |
| Add: find, fingerprint | EmergencyPage.tsx:152 | Yes | Yes | |
| Add: wait days | EmergencyPage.tsx:17,157 | Yes | Yes | Closed in m25-native-parity. |
| Add: scope (owned vaults only) | EmergencyPage.tsx:148 | **Partial** | Yes | iOS lists all vaults (ios:Sharing/EmergencyView.swift:156) |
| Add: view or takeover | EmergencyPage.tsx:171 | Yes | Yes | |
| Received list with status | EmergencyPage.tsx:193 | Yes | Yes | |
| Request with confirm, toast with release date | EmergencyPage.tsx:252 | **Partial** | Yes | iOS toast shows contact creation date (EmergencyView.swift:85) |
| Step down | EmergencyPage.tsx:212,257 | Yes | Yes | iOS: swipe, confirm button says Remove |
| Open released vault | EmergencyVaultPage.tsx | Yes | Yes | |
| Grouped by vault, sorted | EmergencyVaultPage.tsx:74 | Yes | Yes | Closed in m25-native-parity. |
| Rows with avatar and subtitle | EmergencyVaultPage.tsx:85 | Yes | **Partial** | Android: title only |
| Item fields read-only | EmergencyVaultPage.tsx:104 | Yes | Yes | |
| Grantor's files | EmergencyVaultPage.tsx:105; Files.tsx:236 | Yes | Yes | Closed in m25-native-parity. |

## Settings

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Theme | SettingsPage.tsx:102 | Yes | Yes | |
| Language | SettingsPage.tsx:50 | Yes | Yes | |
| Website icons | SettingsPage.tsx:65 | Yes | Yes | |
| Auto-lock choices | SettingsPage.tsx:119 | Yes | Yes | |
| Lock on hide | SettingsPage.tsx:129 | Yes | Yes | |
| Device unlock toggle | DeviceUnlockRow.tsx | Partial | Yes | iOS hides the row when unsupported; web and Android explain why |
| Lock now | SettingsPage.tsx:132 | Yes | Yes | |
| Change master password | ChangePassword.tsx | Yes | Yes | |
| Secret Key show, copy, hide | SettingsPage.tsx:202 | Yes | Yes | Closed in m25-native-parity. |
| Device auth section: rule text | DeviceAuthSection.tsx:41 | Yes | Yes | Closed in m25-native-parity. |
| Device auth: app-open switch | DeviceAuthSection.tsx:55 | Yes | Yes | Closed in m25-native-parity. |
| Device auth: autofill switch and warning | DeviceAuthSection.tsx:63 | Yes | Yes | Closed 2026-11-08. `Settings.deviceAuthOnAutofill`; off, the AutoFill extension and Android services fill through a fill key the app keeps only while its vault is unlocked (plan 03 History 2026-11-08). Greyed out under stay unlocked and when lockless, as on the web. |
| Device auth: lockless notice | DeviceAuthSection.tsx:76 | Yes | Yes | Closed in m25-native-parity. |
| Wi-Fi: offer switch | WifiSection.tsx:19 | Yes | Yes | Closed in m25-native-parity. |
| Wi-Fi: forget Never list | WifiSection.tsx:21 | Yes | Yes | Closed in m25-native-parity. |
| Wi-Fi: save offer (Save, Not now, Never) | Wifi.tsx:330 | Yes | Yes | Closed in m25-native-parity. |
| AutoFill on phone | platform section | Yes | Yes | Native only |
| Two-step: turn on, QR, setup key, confirm | TwoStepSection.tsx:73,275 | Yes | Yes | |
| Two-step: change authenticator | TwoStepSection.tsx:80 | Yes | Yes | |
| Two-step: add security key | TwoStepSection.tsx:88 | N/A | N/A | Web vault only |
| Two-step: list and remove keys | TwoStepSection.tsx:94 | Yes | Yes | Closed in m25-native-parity. |
| Two-step: recovery codes left, new codes | TwoStepSection.tsx:117 | Yes | Yes | |
| Two-step: codes shown once, saved gate, copy | TwoStepSection.tsx:315 | Yes | Yes | |
| Two-step: forget trusted devices | TwoStepSection.tsx:122 | Yes | Yes | |
| Two-step: turn off | TwoStepSection.tsx:129 | Yes | Yes | |
| About | SettingsPage.tsx:192 | Yes | Yes | |
| Clear clipboard timeout | none | Not in web | Not in web | Fixed at 30 s |

## Devices & log

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Device list, current, platform, last seen | DevicesSection.tsx:68 | Yes | Yes | |
| Rename this device | DevicesSection.tsx:58 | Yes | Yes | iOS: swipe or long press |
| Sign out other device with confirm | DevicesSection.tsx:36 | Yes | Yes | iOS: swipe or long press |
| Signed-in date tooltip | DevicesSection.tsx:78 | N/A | N/A | Hover only |
| Security log: list, details, empty | SecurityLogPage.tsx:39 | Yes | Yes | Closed in m25-native-parity. |

## Import & export

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Export: encrypted, JSON, CSV, CXF | ExportDialog.tsx:39 | Yes | Yes | |
| Export: password rules | ExportDialog.tsx:67 | Yes | Yes | |
| Export: warning for plain formats | ExportDialog.tsx:115 | Yes | Yes | |
| Import: every source, grouped, per-source help | ImportPanel.tsx:26 | Yes | Yes | |
| Import: password, on demand if required | ImportPanel.tsx:222 | Yes | Yes | iOS uses "file password" label for Octa Pass exports |
| Import: KeePass key file | ImportPanel.tsx:231 | Yes | Yes | |
| Import: code review for authenticators | ImportPanel.tsx:118 | Yes | Yes | Closed in m25-native-parity. |
| Import: warnings in review | ImportPanel.tsx:177 | Yes | Yes | |
| Import: summary, skipped, files, delete reminder | ImportPanel.tsx:240 | Yes | Yes | |

## Account

| Feature | Web location | iOS | Android | Note |
|---|---|---|---|---|
| Email | SettingsPage.tsx:177 | Yes | Yes | |
| Server name and version | SettingsPage.tsx:269 | Yes | Yes | Closed in m25-native-parity. |
| Storage | SettingsPage.tsx:239 | Yes | Yes | Closed in m25-native-parity. |
| Sign out | SettingsPage.tsx:180 | Yes | Yes | |
| Delete: summary, shared vault warning | DeleteAccount.tsx:79 | Yes | Yes | |
| Delete: export first | DeleteAccount.tsx:101 | Yes | Yes | iOS via the export sheet |
| Delete: email and password | DeleteAccount.tsx:122 | Yes | Yes | iOS omits the email mismatch message |
| Delete: wipes local preferences | DeleteAccount.tsx:58 | Yes | Yes | |

---

## SSH keys and environments

Built in m25-native-parity. These are the web edges outside the two type screens, each handled.

| Edge | Web location | iOS | Android |
|---|---|---|---|
| Sidebar rows: environment then SSH key, between Wi-Fi and Documents | Sidebar.tsx:36-37 | Yes | Yes |
| Type icons: server, key | Sidebar.tsx:22-23 | Yes | Yes |
| New item order differs: Wi-Fi, SSH key, Document, Environment | lib/scope.ts:9 | Yes | Yes |
| Sidebar order must be its own list | Sidebar.tsx:27 | Yes | Yes |
| Environment list defaults to grouping by project | listArrangement.ts:22 | Yes | Yes |
| Project section label, empty key is `env.noProject`, last | ItemSections.tsx:21; listOrder.ts:191 | Yes | Yes |
| `ListGrouping.project` label in the sort menu | SortMenu.tsx:70 | Yes | Yes |
| Project and stage filters on the list | ItemsPage.tsx:79-84,175-204 | Yes | Yes |
| No matches state with Clear filters | ItemsPage.tsx:216 | Yes | Yes |
| Stage chip on rows, coloured by stage | ItemsPage.tsx:262 | Yes | Yes |
| Title from SSH comment when empty | editorModel.ts:45,292 | Yes | Yes |
| Subtitle: project and stage; fingerprint | editorModel.ts:222-228 | Yes | Yes |
| Secret confirm before showing a private key (`guard`) | ItemDetail.tsx:216,263 | Yes | Yes |
| Same fields appear read-only in emergency and share viewers | EmergencyVaultPage.tsx:104; SharedLinkPage.tsx:151 | Yes | Yes |

---

## Native-only, not gaps

Item QR codes for logins and cards, swipe actions (iOS), long-press copy (iOS), Quick Look, Wi-Fi Connect, scanning contacts and networks into items, Credential Exchange, AutoFill and credential services, app-switcher cover (iOS), `FLAG_SECURE` (Android), AutoFill prompt on the list (Android).

## Limits of this audit

- Nothing was built or run. Everything is from reading code; no behaviour was seen on a device.
- Read by grep only, not line by line: Android sign-in, sign-up, lock, reset, two-step dialogs, export, delete, import, sharing screens, health, generator, scan. iOS `PasswordResetView`, `SignUpView`, `RecoveryKitView`, `QrSheet`.
- "No" on the device-auth gates covers the app and the crate only. The iOS AutoFill extension and Android autofill services were not audited.
- `add_emergency_contact` does not check ownership in the mobile crate. Whether the server refuses a non-owned vault scope was not confirmed.
- Tablet layouts, Dynamic Type, TalkBack and VoiceOver were not assessed, except where a string or label was plainly missing.
