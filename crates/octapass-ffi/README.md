# octapass-ffi

[UniFFI](https://mozilla.github.io/uniffi-rs/) bindings of [`octapass-core`](../octapass-core/) for the iOS and Android apps, and above all for their autofill extensions: the iOS AutoFill Credential Provider and the Android Autofill and Credential Manager services. These run in small native processes, so they need to unlock and fill without the full app (plan 14, workstream K).

Generated bindings live next to the native apps: the Swift package `OctaPassCore` in [`apps/ios/Packages/OctaPassCore`](../../apps/ios/Packages/OctaPassCore/) and the Kotlin package `app.octap.core` in [`apps/android/core`](../../apps/android/core/). The generated sources are committed; the XCFramework and the `.so` files are build outputs. Every error is `OctaPassError` (Swift) / `OctaPassException` (Kotlin) with typed cases; other core failures arrive as `Core { code, reason }` with the core's stable code. Messages never contain secrets.

## API

| Object | What it does |
|---|---|
| `HttpClient` | Implemented by the app (`URLSession`, OkHttp). `send(request)` returns every response the server gave, whatever the status, and throws `Network` only when there's none. |
| `OctaPassServer(baseUrl, http)` | `serverInfo`, `startSignup` → `Signup`, `logIn`, `logInTrusted` → `LogInResult`, `refresh`, `logOut`, `reauth`, `deleteAccount`, `sync`, `uploadPending`, and the two-step settings: `twoStepStatus`, `startTotpSetup`, `confirmTotpSetup`, `renewRecoveryCodes`, `disableTwoStep`, `removeSecurityKey`. `https` only (`http` for `localhost`). |
| `SecondFactorLogin` | A sign-in waiting for its second step: `methods`, `expiresIn`, `finishWithTotp(code)`, `finishWithRecoveryCode(code)` → `SignedIn`. |
| `Signup` | `secretKey`, `recoveryCode` (for the Recovery Kit), `devVerificationCode`, `finish(code, device)` → `SignedIn { session, tokens }`. A wrong code can be retried. |
| `LocalStore` | `create(path, serverUrl, session)`, `open(path)`, `reload`, `unlockWithPassword`, `unlockWithDevice`, `enableDeviceUnlock`, `disableDeviceUnlock`, `deviceUnlockStatus`, `hasPendingChanges`. |
| `Session` | `listItems`, `getItem`, `saveLogin`, `matchLogins`, `totpCode`, `credentialIdentities`, `createPasskey`, `findPasskeys`, `getPasskeyAssertion`, `lock`. |
| Functions | `generatePassword`, `estimateStrength`, `totpCode`, `normalizeSecretKey`, `passkeyCreationRequestFromJson`, `passkeyAssertionRequestFromJson`. |

Calls that touch the network or run Argon2id (`startSignup`, `logIn`, `unlockWithPassword`, `reauth`) block, so call them off the main thread. Tokens, the Secret Key and the device secret stay with the app, in the Keychain or Keystore-backed storage.

### Flows

```text
sign-up   server.startSignup(email, password) → show signup.secretKey / recoveryCode
          signup.finish(code, device) → { session, tokens }
          LocalStore.create(path, server.baseUrl, session); server.sync(token, store)
new device server.logInTrusted(email, password, secretKey, device, trustedDeviceToken)
          → .signedIn → LocalStore.create → sync, or .secondFactorRequired(login)
          login.finishWithTotp(code) / finishWithRecoveryCode(code) → { session, tokens }
unlock    store.unlockWithDevice(deviceSecret)   (Face ID / fingerprint or the device passcode)
          store.unlockWithPassword(password, secretKey)
fill      session.matchLogins(store, url) → session.getItem(store, id) / session.totpCode(store, id)
save      session.saveLogin(store, draft) → server.uploadPending(token, session, store)
passkeys  session.createPasskey / findPasskeys / getPasskeyAssertion(store, request, clientData)
lock      session.lock()
```

**Two-step sign-in.** Every sign-in returns `tokens.trustedDeviceToken`: keep it with the account and pass it to the next `logInTrusted` from this device, which then skips the second step. A `refresh` returns one only to a device that had none yet. Delete it on sign-out (the server forgets the device's trust at `logOut` too). A wrong code fails with `Server { problemType: "invalid-second-factor" }` and can be tried again; `LoginFailed` from `finishWith…` means the challenge expired or had too many wrong tries, so sign in again. Security keys only work where WebAuthn runs for the server's relying party (the web vault's host), so the apps offer the authenticator code and recovery codes only; `removeSecurityKey` still removes keys added in a browser. The settings calls that change something take a `TwoStep` reauth token (`confirmTotpSetup` doesn't). The old `logIn` fails with `Server { problemType: "second-factor-required" }` for these accounts, so new code calls `logInTrusted` (with `null` / `nil` when there's no token yet).

**Single sign-on.** `logInTrusted` can also return `SsoRequired`, when the account's organisation requires it. Open `sso.url()` in a browser, then call `sso.finish(code)` with the 6-digit code the last page shows; it returns another `LogInResult`, because two-step sign-in can follow. SSO decides only whether the sign-in may go on: the keys in `SsoLogin` come from the master password and Secret Key.

**Device unlock.** `enableDeviceUnlock(session, deviceSecret)` wraps the account key with a 32-byte secret that the app keeps behind the device's own lock. On iOS that's a Keychain item with `[.biometryCurrentSet, .or, .devicePasscode]`. On Android it's a Keystore key that needs `BIOMETRIC_STRONG or DEVICE_CREDENTIAL`, for example the HMAC of a fixed label. Only the wrapped key goes into the store; the core's device-unlock derivation is used unchanged. `unlockWithDevice` fails with `PasswordRequired` when device unlock is off, or 14 days after the last master password unlock (plan 03). Turn it off and delete the secret on sign-out, master password change and key rotation.

**Autofill matching.** Websites use the core's matcher (`octapass_core::matching`): the registrable domain from the Public Suffix List, each URL's own match mode (`urlMatch`) and equivalent domains, ranked exact host, then same domain, then equivalent. So `paypal.com.evil.io` never matches `paypal.com`. Android apps are `androidapp://<package>` and match only that package, which the core matcher doesn't cover. A match whose scheme differs from the page (`schemeMismatch`) needs a warning before filling an `http` page.

**Passkeys.** The private key never crosses the FFI. The new or changed login is saved to the store before the credential is returned, so a passkey the relying party accepted can't be lost. A passkey goes into the login that already has one for this user on the site, else into a login for the site with the same user name, else into a new login. `ClientData` says who built `clientDataJSON`:

| Case | Use for | What's signed |
|---|---|---|
| `Web { origin, topOrigin, frameAllowed }` | web views | The core checks the `rpId` against the origin and writes `clientDataJSON`. |
| `Json { clientDataJson }` | Android apps (origin `android:apk-key-hash:…`), after the provider checked Digital Asset Links | `SHA-256(clientDataJson)`; the JSON goes into `responseJson` |
| `Hash { clientDataHash }` | iOS `ASPasskeyCredentialRequest`; Android browsers that pass `clientDataHash` | The hash as given; `responseJson` has an empty `clientDataJSON` |

All three are the core's authenticator: `Web` is `octapass_core::passkey::ClientData::Web`, and `Json` and `Hash` are `ClientData::Hash` (the FFI only hashes the provider's JSON and puts it back into `responseJson`). For `Json` and `Hash` the platform has vouched for the caller, so the `rpId` must be given (`PasskeyInvalidRequest` otherwise) and `clientDataHash` must be 32 bytes. The core still refuses public suffixes (`PasskeyRpMismatch`), enforces `excludeCredentials` and `allowCredentials`, and uses the same authenticator data (flags `UP UV BE BS`, counter 0).

**Uploads and conflicts.** `saveLogin` and `createPasskey` save the encrypted item to the store as pending. `uploadPending` sends it with `If-Match` on the revision the change started from, or `If-None-Match: *` for a new item. If the item changed on the server meanwhile, the server's version is kept and this device's version is saved as "<title> (conflicting copy)", as the web vault does.

## The local store

One file per account, shared through the App Group (iOS) or app storage (Android). It holds exactly what the server holds (the account bundle, wrapped vault keys and encrypted items), plus this device's device-unlock record. Every secret in it is a core ciphertext envelope, and nothing is decrypted to disk. Writers lock `<file>.lock`, re-read the file, change it, write `<file>.tmp` and rename it over the file. The app and an extension writing at the same time therefore never lose each other's changes, and readers never see half a file. On iOS, hold a background task assertion while writing to a shared container.

Integers are little-endian. `str`/`bytes` are a `u32` length followed by UTF-8 or raw bytes. `opt` is a `u8` flag (0 = absent, 1 = present) followed by the value. Ids are 16 raw UUID bytes, and base64url values from the API are stored as their raw bytes.

```text
"OPLS" ‖ version u8 (1)
serverUrl str
account:  accountId opt str ‖ email str ‖ memoryKib u32 ‖ iterations u32 ‖ parallelism u32 (Argon2id)
          accountSalt ‖ wrappedAsk ‖ publicEncKey ‖ publicSignKey ‖ wrappedPrivateKeys ‖ recoveryWrappedAsk   (bytes each)
passwordUnlockedAt u64 (Unix ms)
deviceUnlock: u8 flag, then deviceSalt bytes ‖ wrappedAsk bytes
vaults:   count u32, then per vault: id (16) ‖ type u8 (0 personal, 1 shared, 2 family) ‖ role u8 (0 owner, 1 write, 2 read, 3 manage) ‖ revision u64 ‖ wrappedVaultKey bytes ‖ keyId opt-str ‖ grant opt-str (the signed grant as JSON)
items:    count u32, then per item: id (16) ‖ vaultId (16) ‖ sync u8 (0 synced, 1 changed here, 2 new here) ‖ revision u64
          ‖ encryptedItemKey bytes ‖ overview bytes ‖ details bytes ‖ updatedAt str ‖ deletedAt opt str
SHA-256 of everything above (32 bytes)
```

A file that is missing, damaged or from another version is `InvalidStore`: sign in again to rebuild it. Sync never moves an item or a vault cursor back to an older revision, in case another process synced in the meantime.

## Build

From the repository root, on a Mac with Xcode and the Rust targets `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`, `aarch64-linux-android` and `x86_64-linux-android` (`rustup target add …`):

```sh
crates/octapass-ffi/scripts/build-ios.sh       # apps/ios/Packages/OctaPassCore/OctaPassCoreFFI.xcframework + Swift source
crates/octapass-ffi/scripts/build-android.sh   # apps/android/core/jniLibs/{arm64-v8a,x86_64} + Kotlin source
```

The Android script uses the NDK in `$ANDROID_NDK_HOME`, or the newest one under `$ANDROID_HOME/ndk`, and targets API 28 (Android 9). Both scripts regenerate the committed bindings. Commit those whenever the exported API changes.

## Tests

```sh
cargo test -p octapass-ffi                     # unit tests + tests/flow.rs
crates/octapass-ffi/scripts/test-swift.sh      # swift test on this Mac
crates/octapass-ffi/scripts/test-kotlin.sh     # Gradle/JUnit on the JVM
```

All three run sign-up → login on a new device → encrypt → decrypt → TOTP → passkeys against `TestServer`. That's an in-process fake of the sync API built on the core's real OPAQUE server, behind the `test-server` feature, which app builds never enable. The tests' native `HttpClient` hands each request to `TestServer.handle`, so the foreign callback path is exercised as in the apps. `tests/flow.rs` also covers conflicting edits, device unlock from a second process's view of the file, reauth and account deletion. Passkey signatures are checked with an independent verifier: `p256` in Rust, CryptoKit in Swift, `java.security` in Kotlin.
