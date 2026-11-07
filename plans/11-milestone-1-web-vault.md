# 11 — Milestone 1: the web vault (build contract)

The first thing people can **see and use**: a working web vault at `apps/web`, backed by the real Rust crypto core (WASM) and a real sync server. Three workstreams run in parallel in separate worktrees, then an integration step wires them together. This file is the contract between them: if code and this file disagree, fix one of them on purpose and note it here.

## Workstreams and ownership

Each workstream only creates or edits files it owns. That keeps merges clean.

| Workstream | Branch | Owns | Must not touch |
|---|---|---|---|
| **A. Web UI** | `m1-web-ui` | `apps/web/**`, `packages/ui/**`, `packages/vault-client/**` | Rust code, `apps/website`, root `package.json` |
| **B. Crypto core + WASM** | `m1-core-crypto` | root `Cargo.toml`, `rust-toolchain.toml`, `crates/octapass-core/**`, `crates/octapass-wasm/**`, `packages/core/**` | `apps/**`, `crates/octapass-api/**` |
| **C. Sync server** | `m1-sync-server` | `apps/server/**`, `crates/octapass-api/**`, plus an identical root `Cargo.toml` (below) | `crates/octapass-core`, `crates/octapass-wasm`, `apps/web` |
| **D. Integration** (after A, B, C) | `m1-integration` | `packages/vault-client/src/remote/**`, `apps/web/src/worker/**`, e2e tests | — |

Shared rules for all workstreams:
- Read `AGENTS.md`. **Never add an AI as author or co-author** in commits. Commit to your own branch at meaningful checkpoints with clear messages. Don't push, don't merge, don't rebase other branches.
- Don't edit the root `package.json`; run things with `pnpm --filter <pkg> …`. Lockfile conflicts are resolved at merge time.
- Add a `changelog/2026-MM-DD-<slug>.md` entry for your workstream when it reaches a usable state.
- Update the matching docs page `status` from `planned` to `in-progress` only for things you actually built.

### Root `Cargo.toml` (B and C both create exactly this)

```toml
[workspace]
resolver = "3"
members = ["crates/*", "apps/server"]

[workspace.package]
edition = "2024"
license = "MIT"
repository = "https://github.com/octapass/octapass"

[workspace.dependencies]
opaque-ke = { version = "=4.0.1", default-features = false, features = ["ristretto255", "serde"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
thiserror = "2"
rand_core = { version = "0.6", features = ["getrandom"] }
zeroize = { version = "1", features = ["derive"] }
```

If a crate version in `[workspace.dependencies]` doesn't resolve, fix it in your branch and record the change in this section's history below.

## Crypto parameters (from plan 03, made exact)

- **Encoding:** all binary values on the wire and in JSON are **base64url without padding**.
- **Normalisation:** master password is NFKD-normalised (not trimmed). Email is trimmed and lowercased.
- **Argon2id:** m = 65536 KiB, t = 3, p = 1, output 32 bytes. `salt = HKDF-SHA256(ikm = account_salt, salt = "openpass/v1", info = email)[0..16]`.
- **Secret Key:** 16 random bytes. Text form `OP1-` + Crockford base32 of the 16 bytes (26 chars) grouped `6-6-5-5-4` with `-`. Parsing ignores case, spaces and dashes.
- `sk_key = HKDF-SHA256(ikm = secret_key_bytes, salt = account_salt, info = "openpass/v1/secret-key")` (32 bytes). *(Changed from plan 03's `salt = account_id`: the account salt is known before login, the account id isn't.)*
- `combined = pw_key ‖ sk_key`. `AUK = HKDF(ikm = combined, salt = "", info = "openpass/v1/auk")`. `auth_secret = HKDF(ikm = combined, salt = "", info = "openpass/v1/auth")`.
- **AEAD:** XChaCha20-Poly1305. Envelope = `version (0x01) ‖ key_id (16 bytes) ‖ nonce (24) ‖ ciphertext‖tag`. AAD = UTF-8 of `"openpass/v1|" + context`, where context is e.g. `item:<vaultId>:<itemId>:overview`, `item:<vaultId>:<itemId>:details`, `itemkey:<vaultId>:<itemId>`, `vaultkey:<vaultId>`, `ask`, `privkeys`, `recovery`.
- **Key ids:** first 16 bytes of `SHA-256("openpass/v1/keyid" ‖ key)`.
- **Keys:** ASK, vault keys, item keys = 32 random bytes. Account X25519 + Ed25519 keypairs generated at sign-up; private keys encrypted with ASK.
- **Recovery code:** 32 random bytes plus a 2-byte checksum (`SHA-256("openpass/v1/recovery-check" ‖ bytes)[0..2]`), shown as 55 Crockford base32 chars in 11 groups of 5 (documented in `crates/octapass-core/README.md`). `recovery_wrapped_ask = AEAD(key = HKDF(recovery_bytes, info = "openpass/v1/recovery"), ASK, context "recovery")`.
- **OPAQUE (RFC 9807) via `opaque-ke 4.0.1`:** `OprfCs = Ristretto255`, `KeyExchange = TripleDh<Ristretto255, Sha512>`, `Ksf = Identity` (Argon2id already ran on the client). The OPAQUE password input is `auth_secret`. The credential identifier is the normalised email. Server setup persists across restarts.
- **Test vectors** live in `crates/octapass-core/tests/vectors/*.json` and are published in the docs later.

## HTTP API v1 (C implements, D consumes)

JSON, camelCase. Errors are `application/problem+json` with `type` (stable URI under `https://octap.app/problems/…`), `title`, `status`, `detail`. Auth is `Authorization: Bearer <accessToken>` (opaque random token, 15 min) plus a refresh token (30 days, rotated on use).

| Method & path | Body → Response |
|---|---|
| `GET /healthz`, `GET /readyz` | → `200` |
| `GET /v1/server-info` | → `{ name, version, apiVersion: 1, signups: "open"\|"invite"\|"closed", pushRelay: bool }` |
| `POST /v1/auth/prelogin` | `{ email }` → `{ kdf: { algorithm: "argon2id", memoryKib, iterations, parallelism }, accountSalt }`. Unknown emails get a deterministic fake salt (HMAC of a server secret), so accounts can't be enumerated. |
| `POST /v1/auth/register/start` | `{ email, registrationRequest }` → `{ registrationResponse, verificationRequired: true }`. Sends a 6-digit email code. In dev mode (`OCTAPASS_DEV_MODE=true`) the code is also logged and returned as `devVerificationCode`. |
| `POST /v1/auth/register/finish` | `{ email, verificationCode, registrationUpload, account: AccountBundle, personalVault: { id, wrappedVaultKey } }` → `{ accountId }` |
| `POST /v1/auth/login/start` | `{ email, credentialRequest }` → `{ loginId, credentialResponse }` |
| `POST /v1/auth/login/finish` | `{ loginId, credentialFinalization, device: { name, platform } }` → `{ accessToken, refreshToken, expiresIn, account: AccountBundle }`. Responds `401` with one generic problem type for any failure. |
| `POST /v1/auth/refresh` | `{ refreshToken }` → `{ accessToken, refreshToken, expiresIn }` |
| `POST /v1/auth/logout` | → `204` (revokes this device's tokens) |
| `GET /v1/account` | → `AccountBundle` |
| `POST /v1/auth/reauth/start` | (authenticated) `{ credentialRequest }` → `{ reauthId, credentialResponse }`. A fresh OPAQUE login with the master password, for dangerous actions. |
| `POST /v1/auth/reauth/finish` | (authenticated) `{ reauthId, credentialFinalization, purpose: "delete-account" }` → `{ reauthToken, expiresIn: 300 }`. Single use, bound to the account and purpose. |
| `DELETE /v1/account` | (authenticated) header `X-Reauth-Token: <reauthToken>`, body `{ confirmEmail }` (must equal the account email) → `204`. See *Account deletion* below. |
| `GET /v1/sync?since=<vaultId>:<rev>,…` | → `{ vaults: VaultRecord[], items: ItemRecord[], deleted: { vaultId, itemId, revision }[] }` |
| `PUT /v1/vaults/{vaultId}/items/{itemId}` | header `If-Match: "<rev>"` (or `If-None-Match: *` to create). Body `{ encryptedItemKey, overview, details }` → `{ revision }`, or `409` with the current `ItemRecord` |
| `DELETE /v1/vaults/{vaultId}/items/{itemId}` | header `If-Match` → `{ revision }` (soft delete: `deletedAt` set, 30-day trash, tombstone kept 90 days) |
| `POST /v1/vaults/{vaultId}/items/{itemId}/restore` | → `{ revision }` |

```ts
type AccountBundle = {
  accountId?: string;              // present in responses
  email: string;
  kdf: { algorithm: 'argon2id'; memoryKib: number; iterations: number; parallelism: number };
  accountSalt: string;
  wrappedAsk: string;              // ASK sealed by AUK
  publicEncKey: string;            // X25519
  publicSignKey: string;           // Ed25519
  wrappedPrivateKeys: string;      // sealed by ASK
  recoveryWrappedAsk: string;
};
type VaultRecord = { id: string; type: 'personal' | 'shared'; revision: number; wrappedVaultKey: string; role: 'owner' | 'write' | 'read' };
type ItemRecord = { id: string; vaultId: string; revision: number; encryptedItemKey: string; overview: string; details: string; updatedAt: string; deletedAt?: string };
```

IDs are UUIDv7 strings generated by the client. The server stores ciphertext only and never logs bodies.

## Account deletion (required)

Deleting an account removes **the account and everything in it**. It can't be undone.

**Server (C), in one database transaction:**
1. Verify the access token, the single-use `X-Reauth-Token` (purpose `delete-account`, at most 5 minutes old) and `confirmEmail`.
2. Delete: the account row, OPAQUE record, wrapped keys and public keys, all devices, sessions and refresh tokens, verification codes, every personal vault with all its items, item history, tombstones and attachments, and the user's membership in any shared vault. Shared vaults the user solely owns are deleted with their items. Later: share links, emergency-access grants and family membership.
3. Keep **nothing** that identifies the user. The only record is an anonymous daily counter of deletions.
4. After commit, send a "Your Octa Pass account was deleted" email (dev mode: log it) and free the email address for reuse immediately.
5. Other devices: their next request gets `401` with problem type `…/problems/account-deleted`. Clients must then wipe all local data for that account.
6. Backups: deleted data ages out of encrypted backups within 30 days (backup rotation). The docs and privacy policy say so.
7. Tests: after deletion, prelogin behaves like an unknown email (fake salt), login fails, sync returns 401 account-deleted, no row in any table references the account id, and the same email can register again.

**Client (A in the UI, D for real):** Settings → Account → **Delete account**.
1. Explain what will be deleted (count of items, vaults, devices) and that it's permanent. List any shared vaults that will disappear for other members.
2. Offer **Export my vault first** (encrypted JSON or CSV).
3. Ask the user to type their account email and enter their master password (this runs the reauth flow), then press **Delete account permanently** (red, the only destructive button).
4. On success, wipe IndexedDB, caches, in-memory keys and the session on this device, then show a final "Your account has been deleted" screen with a link back to the start.
5. Errors (wrong password, network) keep everything intact and say exactly what to do.

## Device unlock in the web vault (required)

Quick unlock with **the device's own lock**: Touch ID / Face ID / fingerprint, or the **Windows Hello PIN, device passcode or computer password** when there's no biometric. In the browser this is done with a platform passkey and the WebAuthn **PRF** extension. No Octa Pass PIN, and no server changes.

**Enable** (Settings → Security → "Unlock with this device"; only while unlocked):
1. `navigator.credentials.create` with `rp.id = location.hostname`, `rp.name = "Octa Pass"`, a random 16-byte `user.id`, `user.name = email`, ES256 + RS256, `authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "discouraged" }`, `extensions: { prf: { eval: { first: SHA-256("openpass/v1/device-unlock") } } }`. The salt is a constant in the code, so nothing is awaited between the click and the prompt (Safari needs the click).
2. If the PRF extension isn't supported, say so plainly and keep the master password ("This browser can't unlock with your device yet. Chrome, Edge, Safari 18+ and Firefox 139+ can.").
3. If `create` already returned `prf.results.first` (Safari, Firefox on macOS), that is the 32-byte PRF output: one prompt. Otherwise `navigator.credentials.get` with that credential, `userVerification: "required"`, the same `prf.eval.first`. If that second prompt is refused (NotAllowedError, e.g. no fresh click), keep the new credential and show **Finish with {method}**; its click runs the `get` again for the same credential (`deviceUnlockConfirm`).
4. Core: `device_key = HKDF(ikm = prf_output, salt = device_salt (16 random bytes), info = "openpass/v1/device-unlock")`, `wrappedAsk = AEAD(device_key, ASK, context "device-unlock")`.
5. Store `{ accountId, credentialId, deviceSalt, wrappedAsk, enabledAt, lastPasswordUnlockAt }` in IndexedDB. Nothing goes to the server.

**Unlock:** the lock screen starts the device prompt automatically (with **Use master password** always visible). `get` with `allowCredentials = [credentialId]` → PRF output → unwrap ASK → session.

**Rules:** master password required every 14 days (`lastPasswordUnlockAt`); the stored record is deleted on sign-out, account deletion, master password change and 401 account-deleted/session-revoked; per browser, never synced; disabling deletes it. Labels adapt: "Touch ID" on Mac, "Windows Hello" on Windows, "Face ID / passcode" on iPhone, generic "your device" otherwise.

**Who builds what:** B exposes in WASM `Session.enableDeviceUnlock(prfOutput) -> { deviceSalt, wrappedAsk }` and `unlockWithDeviceKey(prfOutput, deviceSalt, wrappedAsk, accountBundle) -> Session` (plus test vectors). A adds to `VaultService`: `getUnlockMethods(): Promise<{ deviceUnlockSupported: boolean; deviceUnlockEnabled: boolean; label: string }>`, `enableDeviceUnlock(): Promise<void>`, `disableDeviceUnlock(): Promise<void>`, `unlockWithDevice(): Promise<void>`. The mock implements the **real WebAuthn PRF flow** (it's all client-side), wrapping its fake ASK with WebCrypto, so the UX can be tested now in Chrome or Safari.

## Item model (A defines the TS types, B mirrors them in Rust serde, D maps)

Plaintext item JSON, split into **overview** (needed for lists and autofill matching) and **details** (everything else):

```ts
type ItemType = 'login' | 'secureNote' | 'card' | 'identity' | 'password';
interface ItemOverview { title: string; type: ItemType; urls?: string[]; subtitle?: string; tags?: string[]; favorite?: boolean }
interface LoginDetails { username?: string; password?: string; totp?: string /* otpauth:// URI or base32 */; notes?: string;
  passkeys?: { rpId: string; userName: string; createdAt: string }[];            // display only in M1
  recovery?: { email?: string; phone?: string; backupCodes?: { code: string; used: boolean }[]; twoFactorMethod?: 'totp' | 'sms' | 'email' | 'key' | 'passkey' | 'none' };
  customFields?: { label: string; value: string; hidden: boolean }[]; passwordHistory?: { password: string; changedAt: string }[] }
interface SecureNoteDetails { notes: string }
interface CardDetails { cardholder?: string; number?: string; expiry?: string /* MM/YY */; cvv?: string; pin?: string; brand?: string; notes?: string }
interface IdentityDetails { firstName?: string; lastName?: string; email?: string; phone?: string; address?: { line1?: string; line2?: string; city?: string; region?: string; postalCode?: string; country?: string }; birthDate?: string; notes?: string }
```

`schemaVersion: 1` is stored inside both overview and details. Unknown fields must round-trip untouched.

## UI ↔ data contract: `VaultService` (A defines in `packages/vault-client`, A ships a mock, D ships the real one)

```ts
export interface VaultService {
  // Server + account
  getServerInfo(serverUrl: string): Promise<ServerInfo>;
  startSignup(input: { serverUrl: string; email: string; password: string }): Promise<{ signupId: string; devVerificationCode?: string }>;
  finishSignup(input: { signupId: string; verificationCode: string }): Promise<{ recoveryKit: RecoveryKit }>; // signs the user in
  signIn(input: { serverUrl: string; email: string; password: string; secretKey?: string }): Promise<void>; // secretKey needed on a new device
  lock(): void;
  unlock(password: string): Promise<void>;
  signOut(): Promise<void>;
  getAccountSummary(): Promise<{ email: string; itemCount: number; vaultCount: number; deviceCount: number; sharedVaultsOwned: string[] }>;
  deleteAccount(input: { confirmEmail: string; password: string }): Promise<void>; // re-authenticates, deletes everything server-side, wipes local data, signs out
  getSession(): SessionState;                       // 'signedOut' | 'locked' | 'unlocked' + account email + server
  onSessionChange(cb: (s: SessionState) => void): () => void;

  // Vault
  listVaults(): Promise<Vault[]>;
  listItems(filter?: { vaultId?: string; type?: ItemType; query?: string; trash?: boolean; favorites?: boolean }): Promise<ItemSummary[]>;
  getItem(id: string): Promise<Item>;
  saveItem(item: ItemDraft): Promise<Item>;         // create or update; handles conflicts by saving a conflict copy
  deleteItem(id: string): Promise<void>;            // to trash
  restoreItem(id: string): Promise<void>;
  onItemsChange(cb: () => void): () => void;

  // Tools (run locally, never send secrets)
  generatePassword(opts: GeneratorOptions): string;
  estimateStrength(password: string): { score: 0 | 1 | 2 | 3 | 4; guessesLog10: number; feedback?: string };
  totpCode(totp: string, at?: number): { code: string; period: number; remaining: number };
  checkBreached(password: string): Promise<number>; // count from the k-anonymity range API, 0 = not found
  getHealthReport(): Promise<HealthReport>;          // weak, reused, breached, missing 2FA
  exportVault(format: 'json' | 'csv'): Promise<Blob>;
  importFile(source: 'chrome' | 'bitwarden-json' | 'onepassword-csv' | 'generic-csv', file: File): Promise<{ imported: number; skipped: number; warnings: string[] }>;
}
```

A may refine names and add types (`RecoveryKit`, `GeneratorOptions`, `HealthReport`, …) but must keep the shape and document every change in this file.

## Definition of done for milestone 1

1. `pnpm --filter @octapass/web dev` opens a vault UI that matches the website's design language. The full flow works against the mock: sign up → Recovery Kit → vault → add/edit/delete items → generator → TOTP → health → export → lock/unlock (password and **device unlock**) → **delete account**.
2. `cargo test --workspace` passes, with crypto test vectors. `pnpm --filter @octapass/core build` produces the WASM package, and a Node test proves the signup→login→encrypt→decrypt flow in WASM.
3. `cargo run -p octapass-server` serves the API above on SQLite, with integration tests for register, login, sync, conflicts, delete/restore and **account deletion** (nothing left behind).
4. Integration (D): the web vault runs on the real WASM + server. Signing up in the browser creates an account whose items the server stores only as ciphertext. A Playwright e2e test proves it.

## History
- 2026-10-23: created.
- 2026-10-23: added re-authentication endpoints and the full account deletion spec (user requirement).
- 2026-10-23: added device unlock (Touch ID / Windows Hello / device passcode via passkey PRF) to the web vault (user requirement). No separate Octa Pass PIN.
- 2026-10-24: device unlock failed to turn on in Firefox 158 and Safari 27 on macOS ("The device prompt was closed"). Fixed by asking for the PRF output in `create` (`prf.eval`) and using it when it comes back. Both browsers then need one Touch ID prompt, and setup and unlock were confirmed on the real sensor. The back-to-back `get` that followed `create` is gone in those browsers; where a browser still needs it and refuses, **Finish with** asks for one more click. Errors keep the browser's reason (`NotAllowedError: …`) and show it. A failure while turning it on is `deviceUnlockSetupFailed`, not "stopped working". Firefox has PRF on macOS 15+ since 139 (Mozilla bug 1935280). Its macOS code passes an empty salt to the system for `prf: {}`, which the eval at creation also avoids.
- 2026-10-23 (B, crypto core): implementation decisions and deviations.
  - **Root `Cargo.toml`:** committed exactly as above, and every `[workspace.dependencies]` version resolved. On branch `m1-core-crypto` alone the workspace doesn't load, because `apps/server` belongs to C; B tested with an uncommitted stub there. It resolves once C is merged. `Cargo.lock` from B lists that stub as `octapass-server 0.0.0`; regenerate the lockfile at merge.
  - **Recovery code:** "8 groups of 5" (200 bits) can't hold 32 bytes. It's 32 bytes + a 2-byte typo checksum = 55 Crockford chars in 11 groups of 5. The wrapping key is `HKDF-SHA256(ikm = code, salt = "", info = "openpass/v1/recovery")` (salt wasn't specified).
  - **Unspecified details, now fixed:** `accountSalt` is 16 random bytes. `wrappedPrivateKeys` seals `x25519_secret (32) ‖ ed25519_seed (32)`. HKDF calls with no salt in this file use the empty salt. OPAQUE uses the default identifiers (both public keys) and no context string, on both sides.
  - **KDF parameters from prelogin are bounded on the client:** memory 64 MiB–1 GiB, iterations 3–16, parallelism 1–4, otherwise `unsupported_kdf`. A malicious server can't weaken Argon2id or freeze the client. C must not hand out weaker parameters, including for fake salts.
  - **Ids in AAD contexts** must be UUIDs and are written lower-case hyphenated, so a crafted id can't inject `:` into a context.
  - **Item model:** `password` items use the login details shape. Unknown item types round-trip as raw JSON. `schemaVersion: 1` is added when missing.
  - **Reauth:** `octapass_core::opaque::ReauthClient` and WASM `Session.startReauth(password, secretKey)` → `ReauthFlow` (`credentialRequest`, `finish(credentialResponse)` → `credentialFinalization`). It reuses the login code, checks the password locally before sending anything, and leaves the session untouched. On the server it's an ordinary OPAQUE login (`ServerLogin` with the account's password file).
  - **Server-side OPAQUE helper:** feature `opaque-server` of `octapass-core` exposes `opaque::server::OpaqueServer` (setup generate/serialize, registration, login incl. fake responses for unknown accounts) with the exact ciphersuite. C may depend on it; it's optional.
  - **WASM API:** documented in `crates/octapass-wasm/README.md`. `Signup.finish` returns `{ registrationUpload, account, personalVault }`; D adds `email` and `verificationCode`. A wrong password surfaces as `login_failed` everywhere (local unlock, OPAQUE login, reauth).
  - **Device unlock:** `Session.enableDeviceUnlock(prfOutput: Uint8Array)` → `{ deviceSalt, wrappedAsk }` (base64url) and the static `Session.unlockWithDeviceKey(prfOutput, deviceSalt, wrappedAsk, account)` → `Session`, plus `deviceUnlockPrfInput()` for `prf.eval.first`. Unlock also checks that the unwrapped ASK opens the bundle's private keys. Failures throw `device_unlock_failed`. Test vector: `crates/octapass-core/tests/vectors/device-unlock.json`.
- 2026-10-23 (C, sync server): clarifications and choices made while implementing the API. D and B should read these.
  - **`accountSalt` is exactly 16 bytes.** The server rejects other lengths so the fake prelogin salts (16 bytes, HMAC of a server secret) are indistinguishable from real ones. B must generate 16-byte account salts.
  - **OPAQUE identifiers and context are the opaque-ke defaults (none)** on both sides. Credential identifier = normalised email (the server normalises again: trim + lowercase).
  - **`409` bodies are problem+json** (`type …/problems/conflict`) with the stored `ItemRecord` in a `current` member, rather than a bare `ItemRecord`. Creating with `If-None-Match: *` over an existing item (including one in the trash) is also a `409`.
  - `If-Match` must be a quoted revision (`"41"`). A write with neither header gets `428 precondition-required`. Item write responses also carry `ETag: "<rev>"`. `If-Match` on an unknown item is `404`. Deleting a trashed item or restoring a live one is a no-op returning the current revision.
  - `GET /v1/sync` always returns **every** vault the account can access; `items` includes trashed items (with `deletedAt`); `deleted` lists only items purged from the trash (tombstones). Vaults missing from `since` are returned in full.
  - The server checks shapes it can see: wrapped keys and item fields must be version 1 envelopes (≥ 57 bytes, first byte `0x01`); public keys 32 bytes; ids canonical lowercase UUIDs; KDF at least m = 65536, t = 3, p = 1 (at most 1 GiB / 64 / 16). Limits: body 1 MiB, `overview` 64 KiB, `details` 512 KiB decoded.
  - `loginId` / `reauthId` are single use, valid 2 minutes, held in memory only (a restart fails in-flight logins).
  - Sign-up with an email that already has an account: identical `register/start` response; the owner gets an "account exists" email instead of a code (dev mode still returns a code); `register/finish` with a valid code then answers `409 account-exists`. Five wrong codes invalidate the code.
  - A rotated refresh token presented again revokes the whole session (theft detection). Refresh tokens are not yet bound to a device Ed25519 key as plan 03 describes; that stays planned (M1 uses the opaque rotating tokens this contract specifies).
  - Account deletion: missing/expired/used/foreign reauth token → `403 reauth-required`; `confirmEmail` mismatch → `400 invalid-request` and the reauth token stays usable. Besides the daily counter, the server keeps **SHA-256 hashes of the deleted account's outstanding tokens** (no account id, email or device data) until those tokens would have expired, so other devices get `401 account-deleted`. The `vaults.created_by` column was dropped so nothing references a deleted account.
  - Extra settings: `OCTAPASS_SMTP_FROM`, `OCTAPASS_TRUST_PROXY` (use the last `X-Forwarded-For` hop for rate limits), `OCTAPASS_LOG`. Without SMTP and outside dev mode, `register/start` answers `503 email-unavailable`. `OCTAPASS_SIGNUPS=invite` uses `octapass-server admin invite <email>`.
  - Extra problem types: `account-deleted`, `reauth-required`, `account-exists`, `vault-exists`, `invalid-verification-code`, `signups-closed`, `invite-required`, `email-unavailable`, `precondition-required`, `payload-too-large`, `rate-limited` (with `Retry-After`). Full list in `docs/developers/sync-api.md` and `octapass_api::problem::types`.
  - The root `Cargo.toml` is exactly as above; every version resolved. The server uses tower-http 0.6 and utoipa 5.
- 2026-10-23 (A, web UI): `VaultService` as built in `packages/vault-client/src/types.ts`. Same shape, with these refinements:
  - `totpCode` returns `Promise<TotpCode>`: HMAC runs through WebCrypto, which is async (the WASM core can be sync, but async covers both).
  - Added `rememberedAccounts(): RememberedAccount[]` (accounts whose Secret Key is stored on this device, so sign-in shows the Secret Key field only on a new device) and `getSecretKey(): Promise<string>` (signed-in devices can show the Secret Key, plan 03).
  - `estimateStrength().feedback` is a `StrengthFeedback` code (`tooShort`, `commonPassword`, …), not English text, so the UI can translate it.
  - `getUnlockMethods()` also returns `platform: 'mac' | 'windows' | 'ios' | 'android' | 'other'` (the UI translates the label by platform) and `passwordRequired` (the 14-day rule is due).
  - `listItems` filter adds `passkeys?: boolean` for the Passkeys category.
  - New types: `Item` / `ItemDraft` (`id`, `vaultId`, `revision`, timestamps, `overview`, `details`), `ItemSummary` (overview fields plus `favorite`, `hasTotp`, `hasPasskey`, never secrets), `Vault` (`id`, `name`, `type`, `role`, `members?`), `GeneratorOptions` (discriminated union of `password` and `passphrase` options), `HealthReport` (`score`, `checked`, `weak` with score, `reused` groups, `breached` with count, `breachCheckCompleted`, `missing2fa`, `generatedAt`), `RecoveryKit` (`email`, `serverUrl`, `secretKey`, `recoveryCode`, `createdAt`), `AccountSummary`, `UnlockMethods`.
  - `schemaVersion: 1` is a typed field on `ItemOverview` and every details type. The editor spreads the original overview/details before applying edits, so unknown fields round-trip (tested).
  - Errors are `VaultError` with a stable `code` (`invalidCredentials`, `secretKeyRequired`, `invalidSecretKey`, `emailTaken`, `invalidVerificationCode`, `signupExpired`, `signupsClosed`, `insecureServerUrl`, `serverUnreachable`, `locked`, `notFound`, `readOnlyVault`, `invalidImportFile`, `emailMismatch`, `deviceUnlockUnsupported`, `deviceUnlockCancelled`, `deviceUnlockFailed`, `passwordRequired`). D maps server problem types onto these codes; the UI maps codes to messages.
  - `Vault.name` and members aren't in `VaultRecord`: D needs encrypted vault metadata (or a fixed "Personal" name) to fill them.
  - Import warnings are short English strings (the contract's `string[]`); they aren't translated yet.
- 2026-10-23 (A): mock-only choices D should know about: the recovery code is temporarily 32 random bytes as 52 Crockford characters in groups of four (B owns the real format); the mock's key hierarchy is PBKDF2 + AES-GCM standing in for Argon2id + XChaCha20 (random ASK wraps the vault; the password key and the device key each wrap the ASK); signing out forgets this device's Secret Key, so signing in again needs the Recovery Kit; the breach check calls `api.pwnedpasswords.com` directly (plan 03's proxy doesn't exist yet; the base URL is configurable).
- 2026-10-23 (A): device unlock follows the spec above. The WebAuthn code (`packages/vault-client/src/mock/webauthn.ts`) is real, not mocked, and can move out of `mock/` for D unchanged; only the ASK wrapping moves into WASM. Not built because there's nothing to hook them to yet: removing the record on master password change (no password change flow in M1) and on `401 account-deleted` (D).
- 2026-10-23 (A): account deletion offers "Export my vault first" as plaintext JSON or CSV, because encrypted export isn't in the interface yet.
- 2026-10-23 (D, integration): the web vault runs on the WASM core and the sync server. Decisions and deviations:
  - **Where things live.** `packages/vault-client/src/remote/`: `VaultEngine` (session, HTTP client, sync, item encryption through `@octapass/core`) is host-neutral. It gets storage (`KeyValueStore`), `fetch`, a cross-context lock and an event sink from its host, and never touches `window`, `document` or `Worker`, so the extension service worker and the desktop shell can host it later. `protocol.ts` is the only postMessage layer (method allowlist, `VaultError` codes carried across). `RemoteVaultService` is the page side. `worker.ts` hosts the engine in a dedicated worker; `apps/web/src/worker/vault.worker.ts` is the Vite entry. The ownership table said `apps/web/src/worker/**`; the worker logic lives in vault-client so it's testable and reusable, and the app keeps only the entry.
  - **What crosses to the page:** session state, remembered accounts (email + server), list summaries, the item being viewed or edited, and the display strings of the Recovery Kit. The WASM `Session`, the access token and the decrypted index stay in the worker. WebAuthn can't run in a worker, so the page runs the passkey prompts and hands the 32-byte PRF output to the worker as a transferred buffer; the worker zeroes it after use.
  - **Strength and the generator run on the page, in TypeScript**, not in WASM: `VaultService.estimateStrength` and `generatePassword` are synchronous and the UI translates `StrengthFeedback` codes, which zxcvbn-rs doesn't produce. The health report uses the same TypeScript estimator in the worker so scores match. TOTP runs in WASM in the worker. The breach check stays direct to HIBP from the worker (the TypeScript k-anonymity checker with padding).
  - **zxcvbn is behind a `strength` cargo feature** (default on) in `octapass-core` and `octapass-wasm`. `dist/web` builds without it: the module drops from 3.0 MB to about 790 KB (1.2 MB → 320 KB gzipped). `dist/node` keeps `estimateStrength`. The worker preloads the module after the page has rendered.
  - **Vault names:** M1 has no vault metadata, so the personal vault is shown as "Personal" (shared vaults as "Shared vault").
  - **`createdAt`** isn't in `ItemRecord`; it's read from the item id (UUIDv7 carries its creation time). `uuidv7Time` was added to vault-client.
  - **Storage (IndexedDB `octapass`, one key/value store):** remembered accounts with their Secret Key, the signed-in session (account bundle + refresh token), ciphertext records per account for offline viewing, and the device unlock record. The access token is memory only and dropped on lock. A reload comes back locked; unlocking with the password is local (Argon2id on the cached bundle), then the refresh token is rotated under a Web Lock so two tabs never present the same token (which the server would treat as theft). If the refresh token is rejected during a password unlock, the worker logs in again with the keys it just derived; otherwise (device unlock, background calls) the session ends and the Secret Key stays remembered.
  - **Sync:** a full pull on unlock and sign-in, then `since=` pulls on focus, on becoming visible, every 30 s while visible and after each write. Writes update the local index at once. A 409 takes the server's version and saves the draft as "(conflicting copy)" (no field merge yet). A delete that hits a 409 retries against the current revision. Offline, unlock opens the cached ciphertext and writes fail with `serverUnreachable` (no offline queue in M1).
  - **Errors:** new `VaultError` codes `serverError`, `rateLimited`, `sessionExpired`, `accountDeleted`, `reauthRequired`, with UI messages. Problem types map as in `remote/http.ts`. `401 account-deleted` on any request wipes this browser's data for the account (Secret Key and device unlock record included) and signs out. `429` waits once when `Retry-After` ≤ 5 s; otherwise it fails with `rateLimited`, and background sync pauses until `Retry-After` has passed.
  - **Sign-up:** `register/start` runs in `startSignup` and `signup.finish()` is called right after (it works once), so a mistyped code can be retried. `emailTaken` surfaces at `finishSignup` (`409 account-exists`), as the server doesn't reveal it earlier.
  - **Sign-out** revokes the tokens (`POST /v1/auth/logout`) and forgets the Secret Key on this browser, like the mock, so signing in again here needs the Recovery Kit.
  - **`getAccountSummary().deviceCount` is 1**: the API has no device list yet. `sharedVaultsOwned` is empty (no shared vaults in M1).
  - **Import** encrypts each item and PUTs it with `If-None-Match: *`, four at a time; failures become warnings and count as skipped. The `POST /v1/batch` endpoint stays planned.
  - **Device unlock:** `webauthn.ts` and `idb.ts` moved out of `mock/` unchanged and are shared. The record holds `{ accountId, credentialId, deviceSalt, wrappedAsk, enabledAt, lastPasswordUnlockAt }`; the wrapping is `Session.enableDeviceUnlock` / `Session.unlockWithDeviceKey`.
  - **Server fixes (C's code), each with a test:** `register/start` and `login/start` took two tokens from the per-IP bucket per request; now one. New `OCTAPASS_RATE_LIMITS=off`, accepted only with `OCTAPASS_DEV_MODE=true`, for test suites that sign in many times from one address.
  - **Web app:** `VITE_VAULT_BACKEND=remote|mock` (default remote; component tests pin mock), `VITE_SERVER_URL` (default `http://localhost:8080` in dev with the remote backend, the hosted URL otherwise). `pnpm --filter @octapass/web dev:stack` runs both halves. The "You're all set" screen no longer promises example items, which only the mock seeds.
  - **Tests:** `pnpm --filter @octapass/vault-client test:server` runs the real service against a real `octapass-server` (Node WASM build, fake-indexeddb). `pnpm --filter @octapass/web e2e` is the Playwright suite (playwright-core, system Chrome, CDP virtual authenticator with PRF).
- 2026-10-24: milestone 5 (plan 15, workstream O) extended the contract additively: `VaultRole` gained `manage`; `Vault.type` is the new `VaultType` (`personal | shared | family`); `Vault` gained `untrusted`; `VaultMember` gained `accountId`, `fingerprint`, `verified`, `isYou`, `addedAt`; `VaultService` gained the optional `sharing: SharingService` (devices, shared vaults and members, families, share links, emergency access, the security log). `AccountSummary.deviceCount` now comes from `GET /v1/devices`. Details in plan 15's history.
- 2026-10-24: attachments (branch `m7-attachments`) extended the contract additively: `ItemType` gained `document` (`DocumentDetails { notes?, attachments? }`); every details type gained `attachments?: Attachment[]` (`{ id, name, type, size, key }`, `key` being the file key wrapped by the item key); `VaultErrorCode` gained `fileTooLarge`; `VaultService` gained an optional `attachments?: AttachmentService` (`addAttachment`, `getAttachment`, `removeAttachment`, `getStorageUsage`), implemented by the remote and mock services and by `TauriVaultService` when created with `{ attachments: true }` (the desktop app; the phone app leaves it off). The list in `details.attachments` changes only through those calls: `saveItem` keeps the stored list on edits and drops it from new items and conflict copies, which couldn't open the files. Files are read and encrypted in the worker in 1 MiB slices and downloads are decrypted as they stream; `copyItem` and `moveItem` re-encrypt files for the new item. Share-link snapshots and exports leave out file keys.
- 2026-10-23: desktop auto-type (branch `m8-desktop-autotype`, plan 13) extended the contract additively: `LoginDetails` gained `autoType?: AutoTypeSettings` (`{ sequence?, windowTitles? }`); `VaultService` gained an optional `autoType?: AutoTypeService` (`{ shortcut }`), which `TauriVaultService` has when created with `{ autoType: true }` (the desktop app) and which makes the item editor show its Auto-type section; `checkAutoTypeSequence`, `DEFAULT_AUTO_TYPE_SEQUENCE` and `PASSWORD_AUTO_TYPE_SEQUENCE` in `autoType.ts` mirror the desktop's sequence parser. Other clients keep `autoType` untouched.
- 2026-10-24: item model and `VaultService` additions for recovery info and masked email (branch `m8-recovery-masked`): `ItemType` gains `maskedEmailProvider` (hidden from lists unless filtered by type); `RecoveryInfo` gains `emailSource` and `phoneSource` (`RecoverySource`); `HealthReport` gains `recovery` (the recovery map, `RecoveryContact[]`) and `recoveryNo2fa`; `VaultService` gains the optional `maskedEmail: MaskedEmailService`; new error codes `maskedEmailNotSetUp`, `maskedEmailBlocked`, `maskedEmailToken`, `maskedEmailRateLimited`, `maskedEmailUnreachable` and `maskedEmailFailed`. See plan 06 History.
- 2026-10-24: mobile attachments (branch `m8-mobile-attachments`) extended the contract additively: `AttachmentService` gained an optional `native?: NativeFiles` for hosts whose files never pass through the page (the phone apps): `sources` (`FileSource`: `files | photos | camera`), `pick(source)` returning `PickedFile` descriptions (`{ id, name, type, size }`, no contents), `attachPicked`, `discardPicked` and `open` (decrypt for the system viewer; resolves once it's closed). `Attachment` gained `pending?: true` (saved on the phone, waiting to upload; never stored), and `VaultErrorCode` gained `noFileViewer` and `cameraUnavailable`. With `native` present the web vault's Files section shows the phone's pickers instead of a file input and drop area, and Open instead of Download; the editor deletes picked files that weren't saved. `TauriVaultService` takes `{ attachments: true, nativeFiles: true }` for the phone app.
- 2026-10-24: `ItemSummary` gained `createdAt` (additive; the item's creation time, which hosts derive from the UUIDv7 id) so lists can sort by date added (branch `m10-list-sort`, plan 01 History). New exports `sortItems`, `arrangeItems`, `firstLetter`, `nameCollator`, `LIST_SORTS`, `LIST_GROUPINGS`, `TYPE_SECTION_ORDER` and `OTHER_LETTER`.
- 2026-10-24: import fidelity (branch `m14-import-fidelity`, plan 07 History) extended the contract additively: `ItemOverview` gained `createdAt?`, `updatedAt?`, `lastUsedAt?` (the dates the app an item was imported from recorded; shown instead of the sync record's dates, and `updatedAt` is dropped by an edit that doesn't set a new one) and `importedFrom?: ImportedFrom` (`{ source, id }`, the import source and the item's id there); `LoginDetails` gained `passwordChangedAt?` and `httpRealm?`; `ImportResult` gained `updated?` and `unchanged?`. New export `itemDates(item)`. `withPasswordHistory` now also drops the stale imported `updatedAt`, and doesn't add the old password when the draft already added it. No schema version change: older clients keep the new fields untouched as unknown fields.
- 2026-10-24: the `wifi` item type (branch `m14-wifi`, plan 01 History), additive: `ItemType` gained `wifi` with `WifiDetails` (and `WifiSecurity`, `WifiEapMethod`, `WifiPhase2`); for Wi-Fi rows `ItemSummary.subtitle` is the SSID. `VaultService` gained an optional `wifi?: WifiService` for hosts that can see the device's Wi-Fi (the desktop and phone apps): `platform`, `features` (`current`, `nearby`, `savedNetworks`, `joins`), `permission()`/`requestPermission()` (`granted | denied | prompt | unsupported`), `currentNetwork()`, `nearbyNetworks(rescan?)` (`WifiSighting`: `ssid`, `signal` 0–100), optional `savedNetworks()`, `readSavedPasswords(ssids)` (`DeviceWifiNetwork`) and `onJoin(cb)`. New exports in `wifi.ts`: `parseWifiQr`, `wifiQrText`, `wifiDraft`, `parseWifiSecurity`, `upgradeLegacyWifi`, `upgradeLegacyWifiItems`, `inRangeFirst`, `sightingsByName`, `signalBars`, `wifiSsid`, `emptyWifi`, `isEnterprise`, `hasPassword`, `keepsPasswordHistory` (Wi-Fi keeps password history like logins). `TYPE_SECTION_ORDER` puts `wifi` after secure notes. Web: the Wi-Fi category, editor (`WifiSection`), view (`WifiFields`, with the join QR code where the host isn't a phone), marks and in-range section in lists, import dialog, "Save this network?" and Settings → Wi-Fi (`wifiOffers`; offers and "never" list in `localStorage` `octapass:wifi-offers`, device-only).
- 2026-10-24: website icons (branch `m13-site-icons`): `VaultService` gained an optional `fetchSiteIcon(serverUrl, domain)` for hosts whose web view can't call the server (the Tauri apps, through a `site_icon` command); everyone else uses `fetch`. The loader, device cache and `iconDomain` are in `@octapass/vault-client` (`siteIcons.ts`); `Settings` gained `showSiteIcons` (default on). See plan 04 and 03 History.
- 2026-11-02 (branch `m25-vault-features`): `VaultService` gains optional `itemVersions`, `restoreItemVersion`, `nextHotpCode`, `setHotpCounter`, `equivalentDomains`, `saveEquivalentDomains` and `generatePasswordForSite`. The model gains `ItemOverview.urlMatch`, `ItemSummary.urlMatch`, `RecoveryInfo.securityQuestions`, `ItemType` `equivalentDomains` (hidden), `ItemVersion`, `HotpCode`, `EquivalentDomains`, and `DeviceAuthSettings.requireReauthForCvv`. The Tauri phone app, due for removal, doesn't offer them: its screens hide what its service lacks.
- 2026-11-04 (branch `claude/sharp-ptolemy-0ouy33`): quick lists and usage (plan 01 and plan 03 History), additive, no schema version change. `ItemOverview.pinned?`, `ItemSummary.pinned?` (missing from an older native host means not pinned) and `ItemFilter.pinned?`; `restoredVersion` keeps the current pin, share links and copies into another vault drop it (`withoutPin`). New hidden type `usageStats` (`UsageStatsDetails`, in `HIDDEN_ITEM_TYPES`, left out of every export). `usage.ts` exports `createUsageTracker(vault)` (`record`, `read`, `flush`, `clear`, `onChange`) over the generic `VaultService` calls, so the remote, mock and Tauri hosts need nothing new; `readUsageStats`, `mergeUsage`, `addUses`, `pruneUsage`; and `smartListItems(items, list, usage)` for `SmartList` (`created`, `frequent`, `used`, `changed`, `SMART_LIST_LIMIT` 50). The web vault's scopes gain `pinned` and `{ kind: 'smart' }` (`/items/created`, `/items/frequent`, `/items/used`, `/items/changed`); `useCopy` counts a use inside `ItemUseProvider`, and the extension's popup sends its uses to the service worker (`recordItemUse`), which also counts fills.
