# octapass-core

The Octa Pass crypto core: key derivation, encryption, OPAQUE client flows, the item model, local mode and backups, importers, URL matching, password rules and the local tools (TOTP, generator, strength, breach check). Every client shares it: the web vault through [`octapass-wasm`](../octapass-wasm/), and later the desktop, mobile and CLI apps natively.

It's pure Rust with no I/O. Callers pass in randomness (`rand_core::CryptoRngCore`) and the current time, so the same code runs natively, in WebAssembly and in deterministic tests. Key material lives in types that zero themselves on drop, and none of them print secrets in `Debug` output. Error messages are fixed strings and never contain secrets.

The design is in [`plans/03-security-model.md`](../../plans/03-security-model.md) and the exact parameters in [`plans/11-milestone-1-web-vault.md`](../../plans/11-milestone-1-web-vault.md). This file documents what is implemented, byte for byte.

## Modules

| Module | What it does |
|---|---|
| `encoding` | base64url without padding, Crockford base32 (Secret Key, recovery code), RFC 4648 base32 (TOTP secrets) |
| `kdf` | Email and password normalisation, Argon2id, HKDF, AUK and `auth_secret` |
| `secret_key` | Secret Key generation, text form and parsing |
| `recovery` | Recovery code generation, text form, parsing and its wrapping key |
| `credentials` | A new master password for an account (change or reset): new salt and wrappings of the same ASK, and the reset's signature |
| `keys` | `SymmetricKey` (256-bit, zeroized) and key ids |
| `envelope` | XChaCha20-Poly1305 envelope with key id and associated-data contexts |
| `account` | `NewAccount` (everything sign-up creates), `AccountBundle`, X25519/Ed25519 key pairs, UUIDv7 ids |
| `opaque` | OPAQUE client flows (registration, login, reauth); the server half behind the `opaque-server` feature |
| `device` | Device unlock: the device key from a passkey's WebAuthn PRF output |
| `session` | `Session`: the unlocked account. Opens vault keys, encrypts and decrypts items. Dropping it locks. |
| `item` | The plaintext item model, with unknown fields preserved |
| `attachment` | Files kept with items: per-file keys wrapped by the item key, chunked streaming encryption |
| `sharing` | Shared vaults (sealed, signed grants; key rotation), key fingerprints, one-time share links, emergency access |
| `transparency` | The key log: signed key records, RFC 9162 Merkle proofs, VOPRF labels and what clients check |
| `passkey` | Software WebAuthn authenticator: ES256 and EdDSA passkeys stored in logins, attestation `none`, origin and `rpId` checks |
| `tools` | `totp`, `otpauth` (incl. Google Authenticator export), `generator`, `strength` (zxcvbn), `breach` (Pwned Passwords range API) |
| `local` | Local mode: `LocalVault` (a vault with no account), the Local Unlock Key, turning on sync |
| `backup` | `.octapass-backup` files and the backup recovery code |
| `import` | Importers for other apps' exports, CSV preview and column mapping |
| `matching` | Registrable domains (Public Suffix List), match modes, equivalent domains, ranking |
| `rules` | Apple's `passwordrules` syntax, the per-site dataset, a generator that satisfies rules |

## Formats

All binary values on the wire and in JSON are **base64url without padding**.

### Normalisation

- **Email:** trimmed and lower-cased (`str::to_lowercase`). Used in the Argon2 salt, as the OPAQUE credential identifier and in the account bundle.
- **Master password:** Unicode NFKD, **not** trimmed.

### Key derivation

```text
account_salt = 16 random bytes, generated at sign-up (AccountBundle.accountSalt)
argon2_salt  = HKDF-SHA256(ikm = account_salt, salt = "octapass/v1", info = email)[0..16]
pw_key       = Argon2id v1.3(NFKD(password), argon2_salt, m = 65536 KiB, t = 3, p = 1, 32 bytes)
sk_key       = HKDF-SHA256(ikm = secret_key (16 bytes), salt = account_salt, info = "octapass/v1/secret-key")
AUK          = HKDF-SHA256(ikm = pw_key ‖ sk_key, salt = "", info = "octapass/v1/auk")
auth_secret  = HKDF-SHA256(ikm = pw_key ‖ sk_key, salt = "", info = "octapass/v1/auth")
```

HKDF outputs are 32 bytes unless noted. KDF parameters come from the server at prelogin, so clients check them before use: memory 64 MiB to 1 GiB, iterations 3 to 16, parallelism 1 to 4. Anything weaker than the defaults is refused (`unsupported_kdf`), so a malicious server can't make offline guessing cheaper; anything far larger is refused so it can't freeze the client.

### Secret Key

16 random bytes. Text form: `OP1-` followed by the 26-character Crockford base32 encoding (most significant bit first, 2 zero padding bits), grouped `6-6-5-5-4`:

```text
OP1-000G40-R40M30-E2091-85GR3-8E1W      (bytes 00 01 02 … 0f)
```

Parsing ignores case, spaces and dashes, accepts the Crockford aliases (`O` → `0`, `I`/`L` → `1`), allows the `OP1` prefix to be left out, and rejects non-zero padding bits so each key has one spelling.

### Recovery code

32 random bytes. Text form: the bytes followed by a 2-byte checksum, `SHA-256("octapass/v1/recovery-check" ‖ bytes)[0..2]`, encoded as 55 Crockford base32 characters in **11 groups of 5**:

```text
000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FTJH8      (bytes 00 01 02 … 1f)
```

The checksum catches typos before the user is told the code doesn't work. Parsing ignores case, spaces and dashes. The code's wrapping key is `HKDF-SHA256(ikm = bytes, salt = "", info = "octapass/v1/recovery")`, and `recoveryWrappedAsk = AEAD(wrapping key, ASK, context "recovery")`.

### Envelope

```text
version (0x01) ‖ key_id (16) ‖ nonce (24) ‖ ciphertext ‖ tag (16)
```

XChaCha20-Poly1305 with a random 192-bit nonce. `key_id = SHA-256("octapass/v1/keyid" ‖ key)[0..16]`; opening checks it first and reports `wrong_key` without trying to decrypt. The associated data is the UTF-8 of `"octapass/v1|" + context`:

| Context | Key | Plaintext |
|---|---|---|
| `ask` | AUK | ASK (32 bytes) |
| `recovery` | recovery wrapping key | ASK |
| `device-unlock` | device key | ASK |
| `local-ask` | Local Unlock Key | ASK of a local vault |
| `local-vault` | ASK | a local vault's body JSON |
| `backup-recovery` | backup recovery key | backup key (32 bytes) |
| `chip-secret` | key from the X25519 exchange with the desktop app | a device chip's secret (32 bytes), on its way to the browser extension |
| `privkeys` | ASK | `x25519_secret (32) ‖ ed25519_seed (32)` |
| `vaultkey:<vaultId>` | ASK | vault key (32 bytes) |
| `itemkey:<vaultId>:<itemId>` | vault key | item key (32 bytes) |
| `item:<vaultId>:<itemId>:overview` | item key | overview JSON |
| `item:<vaultId>:<itemId>:details` | item key | details JSON |
| `attachmentkey:<vaultId>:<itemId>:<attachmentId>` | item key | file key (32 bytes) |
| `attachment:<vaultId>:<itemId>:<attachmentId>` | file key | every chunk of a file (see [Attachments](#attachments)) |

Vault and item ids must be UUIDs and are written in lower-case hyphenated form. Requiring a UUID keeps `:` out of contexts, so a crafted id can't make two contexts collide. New ids are UUIDv7 (`account::new_id`).

### Account

At sign-up, `NewAccount::create` generates the Secret Key, account salt, ASK, an X25519 key pair (sharing) and an Ed25519 key pair (signatures), the recovery code, and the personal vault (UUIDv7 id + key wrapped by the ASK). The `AccountBundle` the server stores has only public keys and ciphertext:

| Field | Content |
|---|---|
| `email`, `kdf`, `accountSalt` | Inputs to key derivation |
| `wrappedAsk` | ASK sealed by the AUK (`ask`) |
| `publicEncKey`, `publicSignKey` | X25519 and Ed25519 public keys, 32 bytes each |
| `wrappedPrivateKeys` | Private keys sealed by the ASK (`privkeys`) |
| `recoveryWrappedAsk` | ASK sealed by the recovery wrapping key (`recovery`) |

When a session opens, the private keys are checked against the public keys in the bundle (`key_mismatch`), so a server can't pair our private keys with public keys of its choosing. If the AUK can't open the ASK (wrong password or Secret Key) the error is `login_failed`; for a wrong recovery code it's `invalid_recovery_code`.

### New credentials

`Session::new_credentials(password, secret_key, new_recovery_code, kdf)` keeps the ASK and returns a `CredentialsUpdate` (`kdf`, a fresh `accountSalt`, `wrappedAsk` under the new AUK, and `recoveryWrappedAsk` under a new recovery code when asked for) plus the new `AccountKeys` for OPAQUE registration. `secret_key: None` makes a new Secret Key. Nothing else in the bundle changes, and no vault or item is re-encrypted.

A reset with the recovery code has no session on the server, so `Session::sign_recovery` signs the update with the account's Ed25519 key:

```text
message = "octapass/v1/account-recovery" ‖ 0x00 ‖ for each field: len (u32 BE) ‖ UTF-8 bytes
fields  = accountId, challenge, registrationUpload, accountSalt, wrappedAsk, recoveryWrappedAsk
```

### Device unlock

```text
prf_input  = SHA-256("octapass/v1/device-unlock")          (WebAuthn extensions.prf.eval.first)
device_key = HKDF-SHA256(ikm = prf_output (32 bytes), salt = device_salt (16 random bytes), info = "octapass/v1/device-unlock")
wrappedAsk = AEAD(device_key, ASK, context "device-unlock")
```

`Session::enable_device_unlock` makes a fresh device salt each time. `Session::unlock_with_device_key` fails with `device_unlock_failed` unless the key opens the wrapped ASK **and** that ASK opens the bundle's private keys. The salt and wrapped ASK stay on the device and never go to the server.

### OPAQUE

RFC 9807 via `opaque-ke` 4.0.1 with `OctaPassCipherSuite`: `OprfCs = Ristretto255`, `KeyExchange = TripleDh<Ristretto255, Sha512>`, `Ksf = Identity` (Argon2id already ran on the client). The password input is `auth_secret`; the credential identifier is the normalised email. Client and server identities are the defaults (their public keys) and there is no context string. Every message is the base64url of the `opaque-ke` serialization, exactly as the HTTP API fields carry it.

| Client | HTTP field |
|---|---|
| `RegistrationClient::start` → | `registrationRequest` |
| `RegistrationClient::finish(registrationResponse)` → | `registrationUpload` |
| `LoginClient::start` → | `credentialRequest` |
| `LoginClient::finish(credentialResponse)` → | `credentialFinalization` |
| `ReauthClient::start` / `finish` | the same, for `/v1/auth/reauth/*` |

`ReauthClient` re-runs the login with the master password before a dangerous action (deleting the account). The server answers with a single-use reauth token, so the current session isn't replaced.

The `opaque-server` feature adds `opaque::server::OpaqueServer` (setup generation and persistence, registration, login with fake responses for unknown accounts). The tests use it, and a server can use it to get exactly the same ciphersuite.

## Items

`item::Item` mirrors the TypeScript item model: `{ overview, details }`, where details are typed by `overview.type` (`login`, `secureNote`, `card`, `identity`, `document`; `password` items use the login fields). Both halves carry `schemaVersion` (1, filled in when missing). Fields this version doesn't know are kept in `extra` and written back untouched, at every level, and unknown item types round-trip as raw JSON. `Session::encrypt_item` reuses the item's key when given its current `encryptedItemKey`, and generates a new one otherwise.

## Attachments

`attachment` encrypts files kept with an item (any type; a `document` item is one file plus notes). Each file gets a random 32-byte **file key**, wrapped by the item key with context `attachmentkey:<vaultId>:<itemId>:<attachmentId>`. The item's details list the file as `{ id, name, type, size, key }` (`key` is the wrapped file key, `size` the plaintext bytes), so the name and type are as private as the rest of the item. Wrapping by the item key rather than the vault key means a vault key rotation, which re-wraps item keys, leaves files readable untouched.

The file is encrypted with the STREAM construction over XChaCha20-Poly1305, so it's never held whole in memory twice:

```text
file    = header ‖ chunk_0 ‖ … ‖ chunk_n
header  = 0x01 ‖ key_id(file key) (16) ‖ nonce_prefix (19 random bytes)
chunk_i = XChaCha20-Poly1305(file key, nonce = nonce_prefix ‖ u32_be(i) ‖ last, aad = "octapass/v1|attachment:<vaultId>:<itemId>:<attachmentId>")
```

Every chunk holds exactly 65,536 bytes of plaintext except the last, which holds 0 to 65,536 and is the only one with `last = 0x01`. An empty file is one empty last chunk. The encrypted size is `36 + n + 16 × max(1, ⌈n / 65536⌉)` (`attachment::encrypted_len`). `Encryptor::push` returns whatever ciphertext is ready (it holds back the newest full chunk, since it can't know yet whether that one is last) and `finish` seals the rest. `Decryptor::push` returns verified plaintext of each complete chunk; only `finish` proves the file is whole, so callers must discard everything if it fails (`decryption_failed` for truncation, reordering, extra chunks or another item's file; `wrong_key` when the header's key id doesn't match). `Session::new_attachment` and `Session::open_attachment` unwrap the item key from its `encryptedItemKey` and wrap or unwrap the file key.

## Octa Pass Safe

`safe` is the format of the encrypted drive: pure code, with the engine that stores blobs in `octapass-files`. A Safe is a flat set of blobs with random UUID names; a file or folder is an object whose newest **record** blob says where it is, and a file's record names its **content** blob. Blobs are never rewritten, so every revision has a new file key and nonce prefix. See the format at the top of `src/safe.rs` and `docs/security/encryption.md`. Vectors: `tests/vectors/safe.json`.

## Passkeys

`passkey` is a WebAuthn Level 3 authenticator for the browser extension, the web vault and the iOS and Android apps. Options come in and responses go out in the spec's JSON forms (`PublicKeyCredentialCreationOptionsJSON` / `PublicKeyCredentialRequestOptionsJSON` → `RegistrationResponseJSON` / `AuthenticationResponseJSON`), with base64url binary fields.

**Who wrote the client data.** Every call takes a `ClientData`. `Web(Caller)` is a page: the core checks the caller as below and writes `clientDataJSON`. `Hash([u8; 32])` is the SHA-256 of the `clientDataJSON` that iOS (`ASPasskeyCredentialRequest`) or Android (Credential Manager) wrote after verifying the calling app or browser itself: the core signs that hash and leaves `clientDataJSON` empty in the response for the platform to fill in. There's no origin to check then, so the request must name its `rpId`, which must be a domain and not a public suffix. Everything else is the same in both modes: `allowCredentials`, `excludeCredentials`, the flags, the counter and the stored record. A new login from a platform request gets `https://<rpId>` as its URL.

**Who may ask.** For a page, the `Caller` is the page's origin, the top-level origin when it's in an iframe, and whether the user allowed that frame. The origin must be `https` (or `http://localhost`) with a domain host, not an IP address. The `rpId` (default: the origin's host) must equal the host or be a registrable-domain suffix of it, checked against the Public Suffix List (`psl` crate): `login.example.com` may use `example.com`, nobody may use `com`, `co.uk` or `github.io`. A cross-origin frame is refused (`passkey_frame_not_allowed`) unless allowed; then `clientDataJSON` carries `crossOrigin: true` and `topOrigin`.

**Create.** Picks the first of the RP's `pubKeyCredParams` it supports: ES256 (`-7`, P-256) or EdDSA (`-8`, Ed25519); an empty list means ES256. The credential ID is 16 random bytes; the user handle must be 1–64 bytes.

```text
authenticatorData = SHA-256(rpId) ‖ flags ‖ signCount (u32 BE, always 0) ‖ attestedCredentialData
flags             = UP 0x01 | UV 0x04 | BE 0x08 | BS 0x10 | AT 0x40 (create: 0x5d, get: 0x1d)
attestedCredentialData = AAGUID (16) ‖ len(credentialId) (u16 BE) ‖ credentialId ‖ COSE_Key
AAGUID            = c9a07734-1d0b-4c72-8ff5-45e0daa2064f
COSE_Key (ES256)  = { 1: 2, 3: -7, -1: 1, -2: x (32), -3: y (32) }
COSE_Key (EdDSA)  = { 1: 1, 3: -8, -1: 6, -2: x (32) }
attestationObject = { "fmt": "none", "attStmt": {}, "authData": authenticatorData }
clientDataJSON    = {"type":"webauthn.create"|"webauthn.get","challenge":…,"origin":…,"crossOrigin":false[,"topOrigin":…]}
```

CBOR maps are in CTAP2 canonical order. The response also has `publicKey` (DER SubjectPublicKeyInfo), `publicKeyAlgorithm`, `transports: ["internal"]`, `authenticatorAttachment: "platform"`, and `credProps: { rk: true }` when the RP asks for it. UP and UV are always set because the host only calls the authenticator after the user chose Octa Pass in an unlocked vault; BE and BS because passkeys sync. The signature counter stays 0, as for every synced passkey.

**Get.** Signs `authenticatorData ‖ SHA-256(clientDataJSON)` (or `‖ clientDataHash` as given): ASN.1 DER ECDSA for ES256 (deterministic, RFC 6979), raw 64 bytes for EdDSA. The passkey must be for the checked `rpId` and in `allowCredentials` when the list isn't empty (`passkey_not_found` otherwise).

**Storage.** A passkey is one entry of a login's `details.passkeys`, next to the display fields every client already shows:

| Field | Content |
|---|---|
| `rpId`, `userName`, `createdAt` | Display fields (`createdAt` is RFC 3339) |
| `credentialId`, `userHandle` | base64url |
| `userDisplayName` | Optional |
| `privateKey` | base64url of the unencrypted PKCS#8 DER key (Ed25519 as PKCS#8 v1) |
| `signCount` | 0 |

`Session::create_passkey` stores a new passkey in an existing login (replacing one for the same `rpId` and user handle) or a new login titled after the RP with the origin as its URL. It refuses (`passkey_excluded`) if the target or any of the `others` the host passes holds a credential in `excludeCredentials`. `Session::find_passkeys` lists the matching passkeys in the candidate items without their keys, and `Session::get_assertion` signs with one. All three take encrypted items and check the caller before decrypting anything, so the passkey flows never hand a private key to the caller. (`Session::decrypt_item` still returns whole details, private keys included, as it returns passwords; a vault UI that only shows passkeys doesn't need them.)

**CXF.** `PasskeyRecord::to_cxf` and `from_cxf` convert one passkey to and from the FIDO Credential Exchange Format's `passkey` credential (`credentialId`, `rpId`, `username`, `userDisplayName`, `userHandle`, `key` as base64url PKCS#8, `fido2Extensions`). Importing refuses keys other than ES256 and Ed25519 (`passkey_unsupported_algorithm`) and keeps `fido2Extensions` in the record so they export again. The rest of a CXF file is the importers' and exporters' job.

## Local mode

A local vault has no server account (plan 03, *Local mode keys*). Below the ASK the hierarchy is the account one, byte for byte (`privkeys`, `vaultkey:<id>`, `itemkey:…`, `item:…` contexts), so turning on sync re-wraps only the ASK.

```text
pw_key     = Argon2id v1.3(NFKD(password), local_salt (16 random bytes), m = 256 MiB or 64 MiB, t = 3, p = 1)
LUK        = HKDF-SHA256(ikm = pw_key ‖ hw_secret, salt = "", info = "octapass/v1/local-unlock")    (hw_secret: 32 bytes from the device chip, or nothing)
wrappedAsk = AEAD(LUK, ASK, context "local-ask")
body       = AEAD(ASK, body JSON, context "local-vault")
```

`LocalVault::to_bytes` is one JSON blob for the app to store:

| Field | Content |
|---|---|
| `format`, `version` | `"octapass-local-vault"`, `1` |
| `kdf`, `salt` | Argon2id parameters (checked like account ones: 64 MiB–1 GiB, t 3–16, p 1–4) and the local salt |
| `hardwareBound` | Whether the LUK needs the device chip's secret (`hardware_secret_required` without it) |
| `wrappedAsk` | ASK sealed by the LUK |
| `body` | The rest, sealed by the ASK: the key pairs (`publicEncKey`, `publicSignKey`, `wrappedPrivateKeys`), the personal vault `{ id, wrappedVaultKey }`, `items` (`{ id, encryptedItemKey, overview, details, createdAt, updatedAt, deletedAt? }`, Unix ms) and the backup settings |

- Without `hw_secret` the master password must score 4 with zxcvbn (`weak_master_password`), because a copied file is then only as strong as the password.
- A wrong password or chip secret is `login_failed`.
- `upgrade_to_account(email, password, kdf)` returns a `NewAccount` for `register/finish` with a new Secret Key, account salt and recovery code, `wrappedAsk` sealed by the new AUK, the vault's own key pairs and personal vault. `items()` are uploaded unchanged; nothing is decrypted.

### Backups

A `.octapass-backup` file opens on any device, so it's keyed by the master password alone. The backup key and its salt are derived when the vault is created (and again when its password changes) and kept in the encrypted body, so automatic backups don't need the password.

```text
backup_key   = Argon2id v1.3(NFKD(password), backup_salt (16 random bytes), m = 256 MiB, t = 4, p = 1)
recovery_key = HKDF-SHA256(ikm = backup recovery code (32 bytes), salt = "", info = "octapass/v1/backup-recovery")
```

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `OPBK` |
| 4 | 1 | version `0x01` |
| 5 | 12 | Argon2id memory (KiB), iterations, parallelism: three big-endian `u32` |
| 17 | 16 | backup salt |
| 33 | 89 | backup key sealed by the recovery key (envelope, context `backup-recovery`) |
| 122 | 24 | nonce |
| 146 | … | XChaCha20-Poly1305 ciphertext ‖ tag, with bytes 0–145 as associated data |

The plaintext is `{ ask, vault: body }`. Every header byte is authenticated, so lowering the parameters or swapping the salt makes the file fail rather than weaken it, and the parameters are checked before Argon2id runs. The **backup recovery code** has the account recovery code's format (32 bytes + checksum, 11 groups of 5) and opens every backup of the vault when the password is forgotten; restoring with it sets a new password. Wrong password: `login_failed`; wrong code: `invalid_recovery_code`; not a backup: `invalid_backup`.

Test vectors: `tests/vectors/local-vault.json` (a chip-bound vault with one item, its LUK, a backup and its backup key) and `tests/vectors/chip-secret.json` (a chip's secret sealed for the browser extension).

Clients whose items live in a store of their own keep `LocalVault::seed`, the same blob with no items, and rebuild the vault from it and a session (`LocalVault::from_seed`) for a backup, a password change or turning on sync. `local::unlock_session` opens a session from the bundle alone, for the phones' AutoFill extensions.

## Import

`import::import_file(source, bytes, options)` parses an export on the device and returns `{ items, totpUpdates, warnings, skipped }`. Files are UTF-8 (with or without a BOM) or UTF-16 with a BOM; anything else is refused rather than guessed.

| Source | Format | Notes |
|---|---|---|
| `chrome` | Chrome, Edge, Brave, Opera, Vivaldi, Arc CSV | `name,url,username,password[,note]` |
| `firefox` | Firefox CSV | `httpRealm` becomes a custom field, a different `formActionOrigin` a second URL; Firefox's own sync sign-in is skipped |
| `safari` | Safari / Apple Passwords CSV | including `OTPAuth` and notes |
| `bitwarden-json` | Bitwarden / Vaultwarden JSON | Unencrypted or password protected (PBKDF2-SHA256 or Argon2id, AES-256-CBC + HMAC, MAC checked first; `import_password_required`, `wrong_import_password`). Folders and collections become tags, URI match settings become `urlMatch`, password history and passkeys (all fields kept, not usable yet) carry over, SSH keys and unknown types become secure notes. Account-locked exports are `unsupported_import`. |
| `onepassword-1pux` | 1Password 1PUX (ZIP) | Logins, passwords, cards, identities, notes; other categories become logins (when they have credentials) or notes; vault names become tags when there are several; archived items get the tag `archived`; attachments aren't imported yet (warning) |
| `onepassword-csv` | 1Password CSV | |
| `lastpass-csv` | LastPass CSV | `http://sn` secure notes, with `NoteType:` credit cards → cards, addresses → identities, templates with a username or password → logins, others → notes |
| `generic-csv` | Any CSV with a header row | `,`, `;` or tab. Columns recognised by common names, or given by a `ColumnMapping`; `preview_csv` returns headers, the first rows and a suggested mapping |
| `otpauth` | `otpauth://` and `otpauth-migration://` links, one per line | Each code joins an `existing_logins` entry whose title or domain matches the issuer (and whose username matches the account when several do), returned in `totpUpdates`; otherwise it becomes a new login. HOTP setups are kept as hidden fields. |

Nothing is dropped: columns and fields the item model has no place for become custom fields on logins and `Label: value` lines in the notes of other types. TOTP values that aren't valid TOTP setups (Steam, typos) are kept as a hidden field instead of a code the app can't compute. A file in the wrong format is an `ImportError` with a stable code (`invalid_import_file` …) and a fixed sentence for the user. Warnings never contain secrets and are capped at 20.

## URL matching

`matching::match_items(page_url, candidates, options)` returns the items whose URLs match the page, one entry per item, best first.

- Hosts are parsed with the WHATWG URL parser (`https://` is assumed when the scheme is missing), IDNs compared as punycode, and the registrable domain comes from the embedded Public Suffix List (the `psl` crate, ICANN and private sections), so `paypal.com.evil.io` is `evil.io`, `alice.github.io` isn't `bob.github.io`, and IP addresses and single-label hosts match only themselves. Only `http` and `https` pages match.
- Match modes per URL (overview field `urlMatch: { [url]: mode }`, default from the options): `subdomains` (default since 2026-11-05: the page's own host, a domain above it or a host below it on one registrable domain, a leading `www.` ignored on both sides, ports ignored; another part of the domain such as `shop.example.com` on `login.example.com` doesn't match), `baseDomain` (any host on the registrable domain, the old default, now only when chosen; ports ignored), `host` (host and port), `startsWith` (same host and port, then a path-and-query prefix: never a raw string prefix, so `https://paypal.com` doesn't match `https://paypal.com.evil.io`), `regex` (the saved URL is a regular expression over the full page URL; invalid or oversized expressions match nothing), `never`.
- Ranking: `exact` (same host, or a `startsWith`/`regex` rule) > `domain` (a domain above the page's host, nearest first, then a host below it, then, under `baseDomain`, another part of the domain) > `equivalent` (`DEFAULT_EQUIVALENT_DOMAINS`, a short list of domains that share accounts such as google.com / youtube.com and apple.com / icloud.com, plus the user's own groups), then the longest saved path the page is under, then input order.
- `schemeMismatch` flags a saved `https` URL on an `http` page (and the reverse), so the caller can warn before filling.
- `matching::other_parts(page_url, candidates, options)` lists what `match_items` left out for being on another part of the page's registrable domain under `subdomains` (`{ id, url, host, site, schemeMismatch }`, sorted by host), for a "Logins for other parts of {site}" entry the user opens by hand. `matching::website_for_page(page_url)` is the origin to add to a login the user filled from there.

## Password rules

`rules::parse` reads Apple's [`passwordrules`](https://developer.apple.com/password-rules/) syntax: `minlength`, `maxlength`, `max-consecutive`, `required` and `allowed`, with the named classes `upper`, `lower`, `digit`, `special`, `ascii-printable`, `unicode` and custom classes such as `[-().&@]` (`-` first and `]` last are literals; `;` inside brackets doesn't end a property). Like Apple's parser it never fails; unknown parts are skipped. Repeated properties combine strictly, so rules from several places combine by joining their text.

`rules::rules_text_for_site(url)` looks up the embedded snapshot of Apple's `quirks/password-rules.json` (436 sites, MIT licence, see `src/rules/password-rules.LICENSE.md`), from the host up to its registrable domain. `rules::generate_for_rules(rules, options)` makes a random password that satisfies the rules, keeping the user's generator settings where the rules allow: the length is clamped into range, character sets the user turned off are used only when required, quotes, backslash, backtick and space are avoided unless a rule needs them, and `max-consecutive` is respected. Impossible rules are `invalid_password_rules`.

## Sharing

`sharing` implements the client side of plan 06. Account ids, vault ids and item ids are UUIDs in lower-case hyphenated form everywhere below.

### Sealed box

Carries a 32-byte key to another account's X25519 public key.

```text
shared   = X25519(ephemeral_secret, recipient_public)        fresh ephemeral key per seal; low-order keys refused
wrap_key = HKDF-SHA256(ikm = shared, salt = ephemeral_public ‖ recipient_public, info = "octapass/v1/seal")
sealed   = 0x01 ‖ ephemeral_public (32) ‖ nonce (24) ‖ XChaCha20-Poly1305(wrap_key, key, aad = "octapass/v1|" + context)
```

Version 2 is hybrid, and is what accounts with a key record get. **Not yet reviewed by an outside cryptographer.**

```text
ss_x       = X25519(ephemeral_secret, recipient_public)
ct_m, ss_m = ML-KEM-768.Encaps(recipient_pq_public)
transcript = SHA-256("octapass/v2/seal-transcript" ‖ 0x00 ‖ ephemeral_public ‖ recipient_public ‖ ct_m ‖ recipient_pq_public)
wrap_key   = HKDF-SHA256(ikm = ss_m ‖ ss_x, salt = transcript, info = "octapass/v2/seal")
sealed     = 0x02 ‖ ephemeral_public (32) ‖ ct_m (1088) ‖ nonce (24) ‖ XChaCha20-Poly1305(wrap_key, key, aad = "octapass/v1|" + context)
```

Version 1 is always 105 bytes and version 2 always 1,193. Both open with `open_key`. The ML-KEM private key is the 64-byte seed `d ‖ z`, in the bundle's `wrappedPqPrivateKey`, sealed by the ASK (context `pqprivkey`). Contexts: `vaultkey:<vaultId>:<recipientAccountId>` (a vault key in a grant), `emergency:<grantorId>:<contactId>:ask` and `emergency:<grantorId>:<contactId>:vault:<vaultId>` (emergency access).

### Grants

`SignedGrant { vaultId, recipientAccountId, role, wrappedVaultKey, grantedBy, grantedAt, signature }`: the vault key sealed to the member, signed by the granter's Ed25519 key. `role` is `read`, `write`, `manage` or `owner`; `grantedAt` is Unix milliseconds.

```text
message   = "octapass/v1/grant" ‖ 0x00 ‖ for each field: len (u32 BE) ‖ UTF-8
fields    = vaultId, recipientAccountId, role, wrappedVaultKey (base64url text), grantedBy, grantedAt (decimal)
signature = Ed25519(granter, message), checked with verify_strict
```

`Session::open_shared_vault` checks that the grant is for this account, verifies the signature against the granter's public signing key (`invalid_signature`), opens the sealed key and keeps the vault open. Clients open what sync returns with `open_synced_vault(&SyncedVault { id, personal, role, wrapped_vault_key, grant })`, the fields of a `VaultRecord`: personal vaults with the account key, shared and family vaults only through their verified grant (rebuilt with this account as recipient; `invalid_grant` without one). On failure it closes the vault, so a key opened before a rotation isn't used either; `close_vault` forgets a vault the account lost. `create_shared_vault` makes the id, key and the owner's own grant; `grant_vault` grants an open vault to a `Recipient { accountId, publicEncKey, role }`.

**Removing a member.** `rotate_vault_key` makes a new vault key, re-wraps every item key under it (context `itemkey:<vaultId>:<itemId>`, as always; item bodies don't change) and signs a grant for each remaining member. It returns `{ keyId, grants, items: [{ itemId, encryptedItemKey }] }` for `POST /v1/vaults/{id}/rotate`. The session keeps the old key until the new grant is opened. `keyId` is the vault key's key id, which the server compares with the key id in every `encryptedItemKey` it stores.

### Key log

**Not yet reviewed by an outside cryptographer.** Design and limits: plan 03, "Key transparency".

```text
record message = "octapass/v1/key-record" ‖ 0x00 ‖ for each field: len (u32 BE) ‖ UTF-8
fields         = logId, accountId, label, publicEncKey, publicSignKey, publicPqKey, createdAt (decimal ms)
record_hash    = SHA-256("octapass/v1/key-record-hash" ‖ 0x00 ‖ message ‖ signature text)
leaf           = label (32) ‖ record_hash (32)
tree           = RFC 9162: SHA-256(0x00 ‖ leaf), SHA-256(0x01 ‖ left ‖ right)
logId          = SHA-256("octapass/v1/key-log-id" ‖ 0x00 ‖ log_public_key ‖ oprf_public_key)
head message   = "octapass/v1/key-log-head" ‖ 0x00 ‖ logId ‖ size (u64 BE) ‖ timestamp ms (u64 BE) ‖ root
label          = SHA-256("octapass/v1/key-log-label" ‖ 0x00 ‖ VOPRF(oprf_key, normalised email))
```

The VOPRF is RFC 9497, ristretto255-SHA512. `transparency::client::LogState` is what a device pins: `accept_head`, `verify_account`, `check_own`, `scan_range` and `apply_page` do the checks and record alerts, so callers fetch, and store the state after failures too.

### Fingerprints

```text
digest = SHA-256("octapass/v1/fingerprint" ‖ 0x00 ‖ public_enc_key ‖ public_sign_key)
digits = for i in 0..6: (digest[5i..5i+5] as a 40-bit big-endian number) mod 10000, zero-padded, joined by spaces
emoji  = for i in 0..8: EMOJI[bits 6i..6i+5 of digest[0..6]]
```

`EMOJI` is the 64-emoji list Matrix uses for verification, each with a name to read aloud.

### Share links

```text
link_key    = 32 random bytes; the URL fragment is base64url(link_key)
pass_key    = Argon2id(NFKD(passphrase), salt (16 random bytes), 64 MiB, t = 3, p = 1)      optional
content_key = HKDF-SHA256(ikm = link_key [‖ pass_key], salt = "", info = "octapass/v1/share-link")
ciphertext  = header ‖ nonce (24) ‖ XChaCha20-Poly1305(content_key, item JSON, aad = "octapass/v1|share-link|" ‖ header)
header      = 0x01 ‖ 0x00                                                   no passphrase
            | 0x01 ‖ 0x01 ‖ salt ‖ memory_kib ‖ iterations ‖ parallelism (u32 BE each)
```

`share_link::open` refuses Argon2id parameters outside what `KdfParams::validate` accepts, and reports a missing or wrong passphrase as `wrong_passphrase`, a wrong link key as `invalid_share_link`.

### Emergency access

`Session::seal_for_emergency_contact` seals the ASK (scope `{ type: "account" }`) or one open vault's key (`{ type: "vault", vaultId }`) to the contact. After the server releases it, the contact calls `open_emergency_account(grantorBundle, sealed)`, which returns a `Session` for the grantor's account (the ASK must open the bundle's private keys), or `open_emergency_vault(grantorId, vaultId, sealed)`, which opens that vault in the contact's own session.

## Tools

- `tools::totp`: HOTP (RFC 4226) and TOTP (RFC 6238) with SHA-1/256/512 and 6–8 digits; `totp_code` takes an `otpauth://totp/…` URI or a bare base32 secret.
- `tools::otpauth`: `otpauth://` parsing and canonical URIs, and `parse_migration` for Google Authenticator's `otpauth-migration://offline?data=…` export (a hand-written reader for its small protobuf).
- `tools::generator`: random passwords (4–128 characters, chosen sets, optionally without look-alike characters, at least one character per set) and passphrases (3–20 words from the embedded [EFF large wordlist](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt), about 12.9 bits each). Every choice uses rejection sampling, so there's no modulo bias.
- `tools::age` (feature `age-files`): the age format through the `age` crate, streaming, with X25519 recipients and passphrases, and the account's two age keys: the exportable derived **file identity**, and the account's X25519 key, which is never exported. `tests/age_interop.rs` opens files made by the reference Go tool.
- `tools::strength`: zxcvbn score (0–4), `guessesLog10` and one hint.
- `tools::breach`: the SHA-1 prefix for the Pwned Passwords range API, and the local suffix match.

## Tests

```sh
cargo test -p octapass-core
```

- Unit tests next to the code, including RFC 4226/6238/5869 vectors and proptest round-trips (encodings, envelopes, key wrapping, Secret Key, recovery code, generator).
- `tests/flow.rs`: sign-up → OPAQUE registration → login on a new device → unlock → encrypt → decrypt → update → reauth → device unlock → wrong password → recovery, against the in-process OPAQUE server.
- `tests/passkey.rs`: passkeys checked by a relying-party verifier written from WebAuthn §7.1/§7.2 with independent parsers (`ciborium`, `coset`), origin and `rpId` refusals, and passkeys inside encrypted items.
- `tests/key_rotation_vectors.rs` and `tests/vectors/key-rotation.json`: a Secret Key rotation, a personal vault rotation, a queued change moved to a new key, the emergency takeover signature and a renewed emergency key, drawn from a fixed byte tape. Regenerate with `OCTAPASS_UPDATE_VECTORS=1 cargo test -p octapass-core --test key_rotation_vectors`.
- `tests/sharing_vectors.rs` and `tests/vectors/sharing.json`: both sealed boxes, the key log, a signed grant, fingerprints and share links (with and without a passphrase), drawn from a fixed byte tape so every random input is listed. Regenerate with `OCTAPASS_UPDATE_VECTORS=1 cargo test -p octapass-core --test sharing_vectors`.
- `tests/vectors.rs` and `tests/vectors/*.json`: deterministic test vectors for other implementations (`kdf`, `secret-key`, `recovery-code`, `envelope`, `attachment`, `opaque`, `account`, `device-unlock`, and `passkey` from `tests/passkey.rs`). They're regenerated from fixed inputs and fixed-seed randomness and compared with the committed files. After an intended format change, regenerate with `OCTAPASS_UPDATE_VECTORS=1 cargo test -p octapass-core --test vectors` (`--test passkey` for the passkey vectors) and say why in the commit.

- `tests/vectors.rs` and `tests/vectors/*.json`: deterministic test vectors for other implementations (`kdf`, `secret-key`, `recovery-code`, `envelope`, `opaque`, `account`, `device-unlock`, `local-vault`). They're regenerated from fixed inputs and fixed-seed randomness and compared with the committed files. After an intended format change, regenerate with `OCTAPASS_UPDATE_VECTORS=1 cargo test -p octapass-core --test vectors` and say why in the commit.

- `tests/import.rs` and `tests/import-fixtures/`: every importer against synthetic exports (Unicode, Arabic, multi-line notes, quotes, empty fields, a generated 10,000-row file, encrypted Bitwarden exports made independently with Node's crypto) and a property test that no input makes an importer panic.
- `fuzz/`: `cargo fuzz` targets for every importer, the CSV preview, URL matching, password rules, backup files, share links, sealed keys, passkey requests, otpauth links, and the Secret Key, recovery code and item formats (`cargo +nightly fuzz run import_chrome` from `crates/octapass-core/fuzz`; not run in CI). Last run 2026-10-23: all 18 targets for 3 minutes each, about 45 million inputs in all, no crashes.

Argon2id with the real parameters takes seconds per run in debug builds (the 256 MiB backup KDF the longest), so the local vault tests use the 64 MiB minimum where they can.

## Developer toolkit

`tools::toolkit` (the `toolkit` feature, plan 16) is one JSON entry point, `run(op, input, now_ms, rng)`, for every client. Published vectors live in `tests/toolkit_jose.rs` (RFC 7520, 7638 and 8037, in `tests/toolkit-fixtures/jose-rfc.json`). `tests/toolkit_interop.rs` checks our files against the real `openssl`, `ssh-keygen` and `gpg`, and skips a tool that isn't installed.
