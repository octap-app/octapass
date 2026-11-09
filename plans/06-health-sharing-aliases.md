# 06 — Security dashboard, sharing, masked email, emergency access

Details for the features that sit on top of the core vault.

**Scope decision (maintainer, 2026-11-02):** everything planned for after 1.0 (roadmap phases 7 and 8, every P2 item in plan 01, all of plan 16) is inside 1.0. P2 still says what comes last, but it's required for 1.0. See [plan 09](09-roadmap.md).

## Security dashboard ("Health")

All checks run **on the device** after unlock, except the opt-in email breach check. Password results are never uploaded. Dismissals and email breach results are stored encrypted in the vault (History, 2026-11-02).

| Check | Source | Severity |
|---|---|---|
| Password found in breaches | Pwned Passwords range API (k-anonymity, padded) | High |
| Reused password (same or trivially similar) | Local comparison of keyed hashes | High |
| Weak password | zxcvbn-style estimator (Rust port in core), < 50 bits of guesses = weak | Medium |
| Account email or alias appeared in a breach (opt-in) | HIBP breach API via server proxy | Medium |
| Website supports 2FA but no TOTP is stored | 2fa.directory dataset (bundled, refreshed weekly) | Low |
| Website supports passkeys but none is stored | passkeys.directory dataset | Low |
| `http://` login URL | Local | Low |
| Card/ID/passport expiring in 60 days | Local | Info |
| Recovery email with no 2FA, or itself breached | Recovery map + checks above | Medium |
| Backup codes running out (≤ 2 unused) | Recovery info | Info |
| Password not changed for a year | Password history | Info |

**UX:** score out of 100, grouped lists, one-click "change password" that opens the site's change-password URL (`/.well-known/change-password`), then a generator and update flow. Users can dismiss individual warnings; dismissed ones leave the score and stay listed so they can be restored.

Datasets (2fa.directory, passkeys.directory, Apple password rules, equivalent domains, PSL) are bundled into each release and refreshed by a signed data update. No per-user lookups.

## Sharing

### Shared vaults
- The owner creates a vault → random Vault Key → seals it to each member's X25519 public key → signs the grant with their Ed25519 key.
- **Roles:** `read` (view/copy/fill), `write` (edit items), `manage` (add/remove members).
- **Removing a member:** new Vault Key, re-wrap all item keys (not re-encrypting item bodies), re-seal to the remaining members. Items the removed member already saw should be considered known; the UI suggests rotating sensitive passwords.
- **Key verification:** each account has a short fingerprint (emoji/words). Users can compare fingerprints out of band; an unverified key shows a warning. P2 (required for 1.0): key transparency log.

### Families
- Free, up to 6 members. The organiser invites by email, and a shared "Family" vault is created automatically.
- **Optional organiser recovery** (opt-in per member): the member's ASK is sealed to the organiser, so the organiser can help recover the account. It's off by default and shown clearly.

### One-time share links
- Encrypt the item snapshot with a random key → upload ciphertext → link `https://<host>/s/<id>#<key>`. The fragment never reaches the server.
- Options: expiry (1 hour–30 days), max views (1–100), optional access passphrase (Argon2id).
- Works for people without an account. The viewer page is a tiny static page with strict CSP.

## Masked email aliases

**Phase A (P1): provider integrations.** The user connects a provider with their own API token, which is stored encrypted in their vault.

| Provider | API |
|---|---|
| SimpleLogin | REST, API key |
| addy.io | REST, API token |
| Firefox Relay | REST, API token |
| Fastmail Masked Email | JMAP, API token |
| DuckDuckGo Email Protection | API token |
| Forward Email | REST, API token |
| Proton Pass aliases | When Proton publishes a public alias API |

- In the generator and the save prompt: *"Use a masked email"* → creates an alias with the site's domain as the description → fills it and links it to the Login.
- The alias list view shows which logins use which alias, using the recovery map.

**Phase B (P2, inside 1.0's scope, decision still needed): our own alias service.** Inbound MX on a dedicated domain, forwarding to the verified account email, reply-through support, per-alias disable. It needs bounce/complaint handling, SPF/DKIM/DMARC/ARC, SRS rewriting, abuse desk, and outbound reputation. Run it as a separate service (`apps/relay`) so the vault server stays simple. Costs are in plan 10.

## Emergency access

- The grantor picks a contact (an existing Octa Pass account) and a waiting period of 1–30 days. The grantor's ASK, or a chosen vault's key, is sealed to the contact's public key and stored on the server.
- The contact requests access → the grantor gets email + push notifications daily → the grantor can deny at any time → after the waiting period the server releases the sealed key → the contact decrypts it client-side.
- Access level: view only, or takeover (lets them reset the master password).
- Every request and release goes into the grantor's security log.

### Takeover design (2026-11-02, branch `m25-key-rotation`)

Recorded before coding, at the maintainer's request. It builds on the release flow above and doesn't change it: the waiting period, the daily reminders and the grantor's denial all apply as they do for view.

**Who can.** Only the contact of a **released** record whose access level is `takeover` and whose scope is `account`. A vault-scoped contact holds no account key, so `takeover` with a vault scope is refused when the contact is added; a row from before this change with that combination stays view only.

**The flow, on the contact's device:**
1. `GET …/release` gives the sealed ASK and the grantor's bundle. The contact's X25519 key opens the ASK, and opening the private keys proves it's this bundle's ASK (`open_emergency_account`).
2. The contact types a new master password. `new_credentials` makes a **fresh** Secret Key, recovery code and account salt, and wraps the same ASK. Nothing is re-encrypted.
3. `POST …/takeover/registration` runs the OPAQUE registration under the grantor's email; it stores nothing.
4. `POST …/takeover`, with an `X-Reauth-Token` for the **contact's** account (purpose `emergency-takeover`) and an Ed25519 signature by the **grantor's** signing key.

**What the server checks, in one transaction:** the contact's reauth token; the record is still released, takeover, account scope (a denial that landed first wins); and the signature, over:

```text
message = "openpass/v1/emergency-takeover" ‖ 0x00 ‖ for each field: len (u32 BE) ‖ UTF-8 bytes
fields  = recordId, grantorId, contactId, currentAccountSalt,
          registrationUpload, accountSalt, wrappedAsk, recoveryWrappedAsk
```

The signature means a contact's stolen session can't do this: it needs the contact's password for the reauth and the contact's private key to open the ASK that signs. `currentAccountSalt` is the grantor's salt as stored now, read inside the transaction, which makes the request stateless and single use: any credentials change, including the takeover itself, invalidates it. A signature on a changed salt is refused with `403`, and the contact has to read the release again.

**What it changes, all in that transaction:**
- The grantor's OPAQUE record, KDF, salt, wrapped ASK and recovery wrapping.
- Every device of the grantor is signed out, and trusted devices are forgotten.
- **Two-step sign-in is turned off**, with its codes and security keys. This is the one departure from a recovery-code reset, which never skips it: the grantor is by assumption unreachable, so keeping it would make takeover impossible for anyone who turned it on. It protects access to ciphertext, and a released contact already has that ciphertext, so nothing new is exposed; and the grantor chose takeover knowingly, with a waiting period. `two-step-disabled` is logged and the grantor is emailed.
- The record is **deleted**, so the contact's read access through it ends: from then on it's a normal sign-in to the account. Other contacts' sealed keys stay valid, because the ASK doesn't change.
- `emergency-takeover` goes in the grantor's log, naming the contact. The grantor's address gets an email.

**The new Recovery Kit** (password, Secret Key, recovery code) is shown to the contact, full screen, before anything else. It's the only copy. In a recovery the contact hands it to the grantor; the plan 03 table's "Everything" row works this way.

**It can't be undone by the server, and the ASK stays known.** The old password, Secret Key and recovery code stop working. The contact has held the ASK since the release, and rotating vault keys doesn't remove that, since the ASK wraps the new keys. If the grantor gets the account back and no longer trusts the contact, the docs say to move the items to a new account. The grantor's defence is the waiting period and the denial, which is why a takeover contact shows a warning when it's added.

### Organiser recovery design (2026-11-02, branch `m25-key-rotation`)

The plan 03 recovery table says the organiser holds a sealed copy of the ASK and releases it after a waiting period, so it **is** an emergency record, with these differences:

- Created by the **member**, opted in per member, with their own waiting period (1–30 days), by `POST /v1/families/{familyId}/organiser-recovery`. The server fixes the contact to the family's organiser, the scope to `account` and the level to `takeover`, and marks the record `organiserRecovery`. The organiser can't turn it on for anyone.
- The member's device seals the ASK to the organiser after showing the organiser's fingerprint, as for any contact. The seal context is the existing `emergency:<member>:<organiser>:ask`.
- **The organiser gets no read access.** `…/sync` and attachment downloads answer `403` for these records. The only thing a release allows is the reset, which signs the member out, emails them and fills their log, so it can't happen quietly.
- If the organiser is already the member's emergency contact, enabling answers `409 already-exists` (one record per pair): the member removes that contact first.
- Leaving the family, being removed from it or the family being deleted removes the record in the same transaction, logged as `organiser-recovery-disabled` in the member's log. The organiser role can't move, so no other change of organiser exists.
- Logged as `organiser-recovery-enabled` and `organiser-recovery-disabled`; request, denial and release use the emergency events; the reset is `emergency-takeover`.

## Account 2FA (protecting the Octa Pass account)

- TOTP (in any authenticator app), WebAuthn security keys and passkeys. TOTP turns it on; security keys are an extra, web vault only (see plan 03 History, 2026-10-24).
- 10 single-use recovery codes, shown once in Settings when it's turned on (the Recovery Kit is made at sign-up, before 2FA exists, so users keep the codes with it).
- Organisations (P2, required for 1.0) can require 2FA by policy.

## History
- 2026-11-02: the scope decision above brings the key transparency log, organisations and teams into 1.0. Phase B is different: the decision moved it inside 1.0's scope but didn't settle whether to run a mail service at all (deliverability, abuse desk, cost). It stays open in plan 00 and nobody should build `apps/relay` until it's answered.
- 2026-10-24: masked email Phase A and the recovery checks built (branch `m8-recovery-masked`).
  - **Token storage:** each connected provider is a vault item of the new type `maskedEmailProvider` (provider, token, optional self-hosted `baseUrl` and alias `domain`). It's encrypted and synced like any item; item lists, search, counts and the FFI's list leave it out; the CSV export skips it (the JSON export keeps it). Disconnecting moves it to the trash.
  - **Calls:** always from the client to the provider, never through our server. SimpleLogin (`Authentication` header, `/api/alias/random/new?hostname=`), addy.io (bearer, `/api/v1/aliases` with domain and description), Firefox Relay (`Token`, `/api/v1/relayaddresses/`), Fastmail (JMAP session, then `MaskedEmail/set` with `forDomain`), DuckDuckGo (bearer, `quack.duckduckgo.com/api/email/addresses`, no description), Forward Email (basic auth with the token as user name, `/v1/domains/{domain}/aliases`). The description is the site's registrable domain. 401/403, 429 (with `Retry-After`) and other errors map to their own error codes.
  - **Where each works:** checked with CORS preflights on 2026-10-23: SimpleLogin, addy.io, Fastmail and Forward Email allow web pages; Firefox Relay and DuckDuckGo don't. The web vault says so and won't call them. The extension calls from its service worker and pages (it already has host access, so no optional permission is requested). The desktop and mobile apps call the six providers' own API hosts from Rust (`masked_email_request`, allowlisted in `octapass_core::tools::masked_email`, HTTPS only, no redirects) and self-hosted servers through the web view.
  - **Linking:** an alias made in the editor becomes the username and recovery email with `emailSource: { kind: 'alias', provider, aliasId }`; in the extension the alias is remembered for 30 minutes per tab and site, and the next login saved there with that username gets it as its recovery email.
  - **Alias list:** built from the recovery map (contacts linked to an alias), so it needs no provider list calls and works for DuckDuckGo too.
  - **Dashboard:** "recovery email without 2FA" is a Health group, not part of the score. "Recovery email breached" isn't built: there's no privacy-preserving email breach check (see plan 01 History).
- 2026-10-24 (branch `m9-loose-ends`): emergency contacts can download the grantor's attachments from the vaults in scope once access is released (server route in plan 04 History). The client keeps the last sync it opened for each contact, checks the release again on every download, and decrypts with the released key: the grantor's own session (account scope, freed afterwards) or the released vault key (vault scope). The web vault's emergency view lists an item's files with download buttons. Zero-knowledge is unchanged: the server streams ciphertext only.
- 2026-11-02 (branch `m25-platform-extras`): masked email Phase B built as `apps/relay` (`octapass-relay`), its own service with its own database, off unless configured, not deployed, not run on real mail. Decisions:
  - **No spool.** A message is forwarded inside the SMTP transaction: 250 only after the smart host took it, 451 on temporary failure so the sender retries, 550 on permanent ones. Bodies never reach a disk or a log. With no queue, a transaction takes **one recipient**; a second `RCPT` gets 452 and the sender retries it alone (RFC 5321 4.5.3.1.10), so the reply to DATA is always one message's fate and nothing is ever partly delivered.
  - **The return path names the alias, not the sender.** It has SRS0's shape (`srs0=hash=time=f|r=alias`, HMAC-SHA256 cut to 50 bits, days wrapping at 1024, 21 days old at most, lowercase base32), but classic SRS exists to send a bounce back to the original sender, which is what must never happen here: a bounce from the user's mailbox names their real address. So bounces end at the relay and the sender's address isn't in the path at all. Null-sender mail to an alias is refused: real delivery failures come to the return path.
  - **Hard and soft:** by enhanced status. 5.7.x, 5.3.x, 5.6.x, 5.2.2 and 5.2.3 are soft, because a policy or content refusal says nothing about the mailbox, and counting those as hard would let a blocked sender switch off someone's forwarding. A reply's bounce counts for nothing, since it's about the stranger's address. Complaints count on either kind. Pauses set `paused_at` conditionally, so each pause reports true once, even when reports race, and that one true sends the one notice. A notice has a null return path and isn't retried. Turning an alias on ends its pause and the account's, and resets the counts.
  - **Forwarded headers:** dropped rather than allowed, since the user is the audience, but everything a mail client answers directly goes, or it would send the real address around the relay: Cc and other To addresses (kept as `X-OctaPass-Original-To/Cc`, so Reply All reaches only the original sender), read receipts, `mailto:` list links (`List-Unsubscribe` keeps web links only). `From :` with a space counts as `From`. **Replies** are the opposite: a short allowlist (subject, threading, MIME), a new Message-ID, a new Date in UTC. The body isn't touched, so a signature or quoted address in it goes out; base64 and quoted-printable parts can't be rewritten safely, and the docs say so. `References` can contain the user's own earlier Message-IDs, which show their mail host.
  - **Proving a reply:** the envelope and the From header must both be the account's address, and SPF or DKIM must pass aligned with it (the same domain or one under the other, with no public suffix list). Automatic mail (`Auto-Submitted`, `Precedence: bulk`) never goes out.
  - **DMARC:** only `p=reject` failures are refused, as decided; `quarantine` is forwarded with the result in `Authentication-Results`. Several From addresses, or none, are refused, because DMARC exempts them. A temporary DNS failure lets the message through.
  - **SMTP:** only `CRLF . CRLF` ends DATA, and any bare CR or LF refuses the whole message, so smuggled messages never exist. Anything buffered behind `STARTTLS` ends the connection (CVE-2011-0411). No PIPELINING, VRFY, EXPN or SMTPUTF8.
  - **Crates:** `mail-auth` 0.15 (SPF, DKIM, DMARC, ARC, from Stalwart) and `mail-parser` 1.0 for MIME. Hand-written versions were ruled out. Its default `aws-lc-rs` backend is used rather than `rust-crypto`: the signing key is long-lived and signs on demand for anyone who sends mail, so it needs constant-time RSA, which the `rsa` crate doesn't promise (RUSTSEC-2023-0071). The cost is a C library in this one binary, plus `hickory-resolver`; the vault server doesn't link them. `tokio-rustls` gets the `ring` provider explicitly, since both are linked. DNS for tests goes through the verifiers' own cache trait, so tests run the real verifiers.
  - **Vault server:** routes under `/v1/masked-email` proxy to the relay's loopback API with a bearer token, passing the session's account id and email; a request body can't name a destination. `maskedEmailRelay` in server info is the capability flag. The account's email is sent on every list and create, so **an email change reaches the relay on the next call**; the server has no email change today, so there's no separate hook. Account deletion queues a row in `relay_deletions` inside the deleting transaction and retries with backoff, because the relay holds the account's email and contacts and must forget them even if it's down at that moment.
  - **Alias ids** are 60 random bits and the alias's own local part; aliases aren't user-chosen, and a deleted one isn't kept (a random reissue is negligible). No descriptions, by design: which site an alias is for stays in the vault.
  - **Not built:** client wiring (in the main thread of this branch); content or reputation filtering; DSNs for mail refused at the end of DATA (the sending system makes those); several relay instances (rate limits are in memory); rewriting bodies.
- 2026-11-02 (branch `m25-platform-extras`): **per-alias actions**. `MaskedEmailService.setAliasEnabled` and `deleteAlias` (`providers.ts`), with a Rust port for the native apps (`crates/octapass-mobile/src/masked_email.rs`, `setAliasEnabled`, `deleteAlias`, `canManageAlias`). Calls go from the device to the provider as before, so the token and aliases still never reach our server. Calls, checked against each provider's public API docs on 2026-11-02: SimpleLogin `GET /api/aliases/{id}` then `POST …/toggle` only if the state differs (it has no set-state call), `DELETE /api/aliases/{id}`; addy.io `POST /api/v1/active-aliases`, `DELETE /api/v1/active-aliases/{id}`, `DELETE /api/v1/aliases/{id}`; Firefox Relay `PATCH` and `DELETE /api/v1/relayaddresses/{id}/`; Fastmail `MaskedEmail/set` with `state`; Forward Email `PUT` and `DELETE /v1/domains/{domain}/aliases/{id}`. DuckDuckGo has no such call, and an alias whose `aliasId` fell back to its address has no id to call with: both say to use the provider's site. Decisions: the recovery contact gains `aliasId`; the list stays built from the recovery map with no provider list calls, so it doesn't know an alias's state and offers both Turn off and Turn on; delete asks first, then removes `emailSource` from the logins linked to that alias and keeps the address as text (the site still has it), only after the provider accepted; a 404 on delete counts as done, so a retry after a partial failure finishes. The native HTTP allowlists (`masked_email_request` in the desktop and Tauri phone vaults) now allow PUT, PATCH and DELETE, still only to the providers' API hosts. **Not verified:** none of these calls has been made against a live provider; all tests use fakes, and web CORS for DELETE, PATCH and PUT was not preflighted, so a provider that refuses them from a web page would show "couldn't reach the provider" in the web vault.
- 2026-11-02 (branch `m25-health`): the rest of the dashboard table built in `packages/vault-client/src/tools/health.ts`, and again in Rust for the native apps (`crates/octapass-mobile/src/health.rs`). Both produce the same warning keys, so a dismissal made on one device holds on another. Decisions the table left open:
  - **Score.** `http://` logins count (penalty 0.85, as missing 2FA). Old passwords, passkeys available, expiring items and backup codes are Info and don't. Neither do email breaches: they aren't about an item.
  - **`http://`** skips this device and the local network (`localhost`, `.local`, `.lan`, `.home.arpa`, single-label names, private and link-local addresses): a router can't get a certificate, so the warning couldn't be acted on. It would drown out the real ones.
  - **Old passwords:** a year since the password changed (the newer of an imported date and the history, else when the item was created; never `updatedAt`). A reminder, not a rotation rule: NIST SP 800-63B advises against forced rotation, so it stays out of the score.
  - **Expiry:** cards use `expiry` (the end of that month); passports, licences and national IDs are the `idDocument` type from `m25-item-types`, with `expiryDate`. API credentials and software licences have a date too but aren't checked: the table says cards and IDs. Expired items stay listed.
  - **Passkey data:** a snapshot of passkeys.2fa.directory (the directory's current home; CC BY 4.0, 2factorauth), reduced to 386 registrable domains in `data/passkey-domains.ts` by `tools/health-data/`. The signed data update in this plan isn't built; it's refreshed with each release, by hand.
  - **Dismissals** are keys like `weak:<item>:<version>`, where the version is what the warning is about (the password's date in whole seconds, the expiry date, the number of codes left, the URL), so a new fact brings the warning back. Dismissed warnings don't count against the score. A reused group is dismissed whole and comes back whole when another login joins it.
  - **Where they live:** one hidden item of type `healthSettings` in the personal vault, not a field on each login. A field would make a new version of the login, could conflict with an edit on another device, wouldn't work in a read-only shared vault, and would show as a change in date sort. Writes run one at a time on a device; two devices at once leave a conflict copy, which the reader merges (dismissals are a union, the alerts come from the newest) and the next write folds away. The type is hidden like `maskedEmailProvider`, and unlike that one **no export includes it**, in any format: importing it would turn email breach alerts on for another account without anyone choosing that. The CLI's lists leave it out too. The core needs no change: it's a type "from a newer client".
  - **Change password:** the URL is built from the login's first website, always `https` on the public internet, and opened by the user's click with no referrer. No client probes whether the site supports it: that would tell the site, or a server, which sites are in the vault. The dialog says what to do if the page doesn't exist.
  - **Email breach alerts:** `POST /v1/health/breach-email`, not `GET` as planned, so the address stays out of URLs. Security decisions are in plan 03 History. Checked at most every 24 hours, at most 50 addresses, one at a time; results replace the last ones only when every address answered. Alias addresses come from the recovery map, as the alias list does.
  - **Still not built:** "recovery email itself breached" for an address that's neither the account email nor an alias, because that sends a third address the user never agreed to; and the backup reminder in plan 05.
- 2026-11-04: Health in the web vault, the desktop app and the extension's tab is an overview, not one long page: the score, the alerts, and a tile per check with its count. Each tile opens that check's list at `/health/<check>` (`weak`, `reused`, `breached`, `two-step`, `recovery-emails`, `insecure`, `old`, `passkeys`, `expiring`, `backup-codes`, `email-breaches`), and the dismissed warnings are at `/health/dismissed`; `/health/recovery` stays the recovery map. The tiles that always show are the ones that count towards the score, plus recovery emails; the rest appear once they find something, and email breach alerts whenever the switch is offered, since its page is where the switch is. In the extension's tab, Health and its pages share one report, so moving between them doesn't check again. The Tauri phone app gets the pages with the web routes. The native apps do the same with their own navigation: on iOS a row per check pushes `HealthCheckView`, which reads the shared `HealthStore`; on Android a tile pushes `Route.HealthCheck`, whose screen loads the report as the other Health screens do, and runs dismissals and password saves on `AppModel.scope` so Back straight after doesn't cancel them.
- 2026-11-02 (branch `m25-key-rotation`): takeover and organiser recovery built as designed above, in the core (`Session::sign_takeover`), the server, the web vault, the desktop app, `octapass-mobile` and the native apps. Changes found while building: sign-in everywhere now prefers a Secret Key the user types over the one the device remembers, because a device that remembers the old key otherwise had no way in after a rotation elsewhere (the web vault offers "My Secret Key changed"). A takeover, and a Secret Key rotation, check whether a lost answer landed (the record is gone; the salt matches), because the new kit is the only copy.
- 2026-11-02 (branch `m25-teams`): organisations can require 2FA by policy, as planned above: the server withholds organisation vaults from a member without it and refuses turning it off. Details in plan 03.
- 2026-11-05 (maintainer request): **the reused-password warning on the login.** A login in one of Health's reused groups says so at the top of its page in the web vault (and so the desktop app and the extension's vault tab), iOS and Android: "Password used on 3 other logins", "If one of these sites leaks it, the others are open too. Give each its own password.", **See them**. The list has the group's other logins (title, username and website), each opening its item, with **Change password** (the site's `/.well-known/change-password` where `changePasswordUrl` finds one, then the generator: `ChangePasswordDialog` on the web, the generator sheet and `updatePassword` on the phones). Decisions: a group is the same password whatever the username, as Health's check is, though the maintainer described it as "username and password"; nothing is computed per item, the warning reads the report the app already has (web `useHealthReport`, iOS `HealthStore`, Android the item screen's `healthReport()`, which the recovery counts already loaded), so a group dismissed in Health shows nothing, and the extension popup, which has no Health, shows nothing either. The website shown is the host of the entry's change-password address, which is the login's first website, so `HealthEntry` didn't change.
- 2026-11-08: the three Health items left after `m25-health` are built.
  - **Recovery email breached.** It needed an address the user hadn't agreed to send, so it has **its own opt-in**: `emailBreachAlerts.recoveryEmails` in `healthSettings`, a second switch on the email breach alerts page ("Also check my other recovery emails") with its own disclosure, offered only while alerts are on. With it, a check sends the recovery map's other email contacts (recovery emails and email usernames that reset at least one login and aren't aliases) after the account email and aliases, within the same 50-address cap. Changing it either way forgets the results, so the next check (run at once) holds exactly what was agreed to; turning alerts off drops it too. A check that raced a change of the opt-in keeps nothing, as for a change of the alerts switch. The report's `recoveryBreached` lists every recovery email with a finding that isn't dismissed, whichever kind of address it is: the breach titles, how many logins it resets, and the inbox's own login when the vault has it (otherwise the row has no item and opens nothing). Warning key `recoveryBreached:<address>:<titles, sorted, comma-joined>`, so a new breach brings a dismissed one back. Not in the score, like `recoveryNo2fa`. It's a check of its own (`/health/recovery-breached`, iOS `.recoveryBreached`, Android `RecoveryBreached`), shown once it finds something. Same in TypeScript and `octapass-mobile` (`setRecoveryEmailChecks`). What the server sees is in plan 03 History.
  - **Signed passkey data (and 2FA data).** One file carries both site lists, so the hand-curated 2FA list updates the same way. Format: `{ payload, signature }`, the payload base64 of `{ format: 1, version, issuedAt, passkeyDomains, twoFactorDomains }`, the signature Ed25519 over `"openpass/v1/health-data" ‖ 0x00 ‖ payload`. The public key is pinned in `packages/vault-client/src/tools/healthData.ts` and `octapass_core::health_data` (same checks in both, tested for a bad signature, another key, no context, rollback, malformed files and an unknown format). The private key never enters the repository; it's the maintainer's, and `tools/health-data/sign.mjs --keygen` makes a new one (then both pinned copies change in one release). `sign.mjs --key <pem>` signs the lists in `passkey-domains.ts` and `two-factor-domains.ts` into the bundled copy (`packages/vault-client/src/data/health-data.json`, which every client and the server compile in) and the published copy (`apps/website/public/data/health-data.json`); `--check` verifies both against the lists. Version 1 is signed with this change.
  - **Rollback:** versions are whole numbers that only go up (the tool refuses otherwise). A client uses a file only when it's newer than the lists in use (the bundled copy or the stored update), so the bundled copy of a newer release always beats an older stored file. A stored copy is checked again whenever it's read, so a changed file on the device falls back to the bundled lists. There's no expiry: a server can hold updates back (a freeze), and the worst case is the release's own lists, which is what clients had before.
  - **Where updates come from:** the account's own server, `GET /v1/health/data`, public and the same for everyone, so asking says nothing about the vault. Not the project's site directly, because the web vault's CSP allows only its own origin, a static site can't promise CORS headers, and self-hosters would otherwise contact us; the server already mirrors website icons for the same reasons. The server serves its bundled copy, or a newer one it fetched from `OCTAPASS_HEALTH_DATA_URL` (off unless set; daily by default; verified with the pinned key before it's served; no redirects; 1 MiB at most). Clients ask at most once a day: the remote engine (web vault and extension, kept in the engine's store, verified with WebCrypto's Ed25519, so a browser without it keeps the bundled lists), the desktop app in Rust (`health-data.json` in its data folder), and the phones in `octapass-mobile` (`health-data.json` in the App Group or app storage). Local vaults have no server and keep the bundled lists. `buildHealthReport` takes the lists as `deps.data`, `octapass-mobile` as `build_report_with`.
  - **Backup reminder:** see plan 05 History.
