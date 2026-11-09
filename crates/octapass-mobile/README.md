# octapass-mobile

`OctaPassVault`, the [UniFFI](https://mozilla.github.io/uniffi-rs/) API the native iPhone/iPad (SwiftUI) and Android (Jetpack Compose) apps are built on ([plan 17](../../plans/17-native-mobile-apps.md)). It wraps the mobile vault ([`crates/octapass-mobile-vault`](../octapass-mobile-vault/)), which keeps the account in the encrypted store the autofill extensions share, and adds what the phone's web-view screens did in TypeScript: typed items for every type, list order, health and the recovery map, QR codes and Wi-Fi, masked email, sharing, families, share links, emergency access, devices, the security log, settings and exports. Swift and Kotlin only do UI and platform services (Keychain/Keystore, biometrics, camera, file pickers, the share sheet).

The autofill extensions keep using [`octapass-ffi`](../octapass-ffi/), which stays small for them. This crate is a separate library rather than more of `octapass-ffi` for that reason (plan 17 History).

| Generated bindings | Where | Built by |
|---|---|---|
| Swift package `OctaPassVault` (iOS 17+) | [`apps/ios/Packages/OctaPassVault`](../../apps/ios/Packages/OctaPassVault/), `Sources/OctaPassVault/OctaPassVault.swift` | `scripts/build-ios.sh` → `OctaPassVaultFFI.xcframework` (device arm64, simulator arm64 + x86_64) |
| Kotlin package `app.octap.vault` (Android 9+, API 28) | [`apps/android/vault`](../../apps/android/vault/), `src/main/kotlin/app/octapass/vault/octapass_mobile.kt` | `scripts/build-android.sh` → `jniLibs/{arm64-v8a,x86_64}/liboctapass_mobile.so` |

The generated sources are committed; the XCFramework and `.so` files are build outputs. Rebuild both after changing the exported API (the test scripts fail when the committed bindings are out of date).

## The API

One object, `OctaPassVault(config, platform, observer)`, per app. `config` names the App Group container (iOS) or `no_backup` folder (Android) shared with the extensions, the app's private temp folder, the device's name and platform. Every error is `VaultError.Failed(code, reason)` (Swift) / `VaultException.Failed` (Kotlin): `code` is the web vault's `VaultErrorCode` (plus `invalidInput`), so the apps show the catalog's `errors.<code>` message (`errorCodeName(code)` gives the key). `reason` is for logs and never holds a secret.

**What blocks.** Everything that touches the network, runs Argon2id, asks for Face ID / the fingerprint, or encrypts files is `async` (Swift) / `suspend` (Kotlin) and runs on a thread of its own: call it from anywhere, the main thread included. The rest returns at once: `snapshot`, `pendingTwoStep`, `cancelTwoStep`, `lock`, `closeAttachment`, `syncState`, `estimateStrength`, `settings`, `updateSettings`, `recordActivity`, `recordItemUse`, the lifecycle calls, and the free functions.

| Area | Calls |
|---|---|
| Account | `serverInfo`, `startSignup` → `finishSignup` (Recovery Kit), `signIn` (`signedIn` or `twoStepRequired`), `finishTwoStep`, `pendingTwoStep`, `cancelTwoStep`, `lock`, `unlock`, `unlockWithDevice`, `signOut`, `secretKey`, `accountSummary`, `deleteAccount` |
| Vaults on this device only | `localCapabilities`, `localVaults`, `createLocalVault`, `restoreLocalVault`, `switchLocalVault`, `leaveLocalVault`, `renameLocalVault`, `deleteLocalVault`, `localRecoveryCode`, `exportLocalBackup` → `localBackupSaved`, `setBackupFolder`, `startTurnOnSync` → `finishTurnOnSync` |
| Two-step sign-in | `twoStepStatus`, `startTotpSetup` → `confirmTotpSetup` (recovery codes the first time), `renewRecoveryCodes`, `disableTwoStep`, `removeSecurityKey`, `forgetTrustedDevices` |
| Device unlock | `unlockMethods`, `enableDeviceUnlock`, `disableDeviceUnlock`, `confirmUser` (before a secret is revealed, copied, exported or shown as a QR code; the app decides when to ask) |
| Items | `listVaults`, `listItems(filter)`, `arrangeItems(filter, sort, grouping)` (the web vault's sections), `getItem`, `saveItem(draft)`, `sameLogin(draft)` (a saved login for the same site and username, to ask before a copy), `setFavorite`, `setPinned`, `deleteItem` (to the trash), `restoreItem`, `moveItem`, `copyItem`; free: `newItemDraft`, `itemDraft`, `validateDraft`, `firstLetter` |
| Quick lists and uses | `smartList(list, query)` (Recently created, Frequently used, Recently used, Recently modified: 50 items in their own order), `recordItemUse(id)` (copied, filled or website opened; saved together 5 seconds later in the hidden `usageStats` item), `flushItemUses()` (on the way to the background); free: `smartListName` |
| SSH keys | `generateSshKey`, `readSshKey` (OpenSSH, PEM, PKCS#8; fails with `sshPassphraseRequired`), `exportSshKey` → a path for the share sheet; free: `sshKeyKinds`, `withSshKey`, `authorizedKeysLine`, `sshKeyTypeLabel`, `isUsableSshKey`, `sshKeyFileName` |
| Environments | free: `newEnvironmentVariable`, `mergeDotenv`, `environmentDotenv`, `environmentFileName`, `knownEnvironmentStage`, `isProductionStage`, `environmentChoices`, `missingEnvironmentKeys`; `writeShareFile` → a path for the share sheet; `ItemFilter.project` and `.stage`; `ListGrouping.project` |
| Attachments | `addAttachment(itemId, path, name, mediaType)` (from the app's picker), `openAttachment` → a path for Quick Look / another app, `closeAttachment(path)`, `removeAttachment`, `storageUsage`; files added offline wait in the outbox (`syncState().pendingFiles`) |
| Sync | `sync`, `syncState`; the observer hears about every change |
| Push | `setPushToken(platform, token, sandbox)` at every launch (sent to the server after the next sync, when it has a push relay), `clearPushToken`, `syncOnPush` when a push arrives: a full sync when unlocked, the changes as ciphertext into the store when locked |
| Tools | `estimateStrength`, `checkBreached`, `healthReport` (with the recovery map), `dismissHealthWarnings`, `restoreHealthWarnings`, `updatePassword`; opt-in, sending addresses: `setEmailBreachAlerts`, `emailBreachChecksAvailable`, `checkEmailBreaches`; free: `generatePassword`, `totpCode`, `normalizeSecretKey` |
| Watch | `watchPayload(atMs)`: the opaque text for a paired watch, codes or a clear (`Settings.showCodesOnWatch`, `src/watch.rs`) |
| QR codes and Wi-Fi | free: `qrChoices(item)`, `bankQrText(bank, amount, reference)`, `scannedDraft(text, vaultId)` (Wi-Fi, `otpauth://`, vCard), `wifiQrText`; `Item.wifi` describes a Wi-Fi network for Connect |
| Masked email | `maskedEmailConnections`, `connectMaskedEmail`, `disconnectMaskedEmail`, `createAlias`; free: `maskedEmailProviders` |
| Sharing | `myFingerprint`, `lookupAccount`, `markVerified`, `createVault`, `renameVault`, `listMembers`, `addMember`, `changeRole`, `removeMember` (rotates the key), `leaveVault` |
| Families | `getFamily`, `createFamily`, `inviteToFamily`, `acceptFamilyInvite`, `declineFamilyInvite`, `cancelFamilyInvite`, `removeFamilyMember`, `leaveFamily`, `deleteFamily` |
| Organisations (`src/organisations.rs`, the desktop app's engine) | `getOrganisation` (also refreshes the policies below), `createOrganisation`, `renameOrganisation`, `deleteOrganisation(password, confirmName)`, `acceptOrgInvite`, `declineOrgInvite`; `listOrgMembers`, `inviteOrgMember`, `cancelOrgInvite`, `setOrgMemberRole`, `removeOrgMember(accountId, orphanVaults)` and `leaveOrganisation(orphanVaults)` (`orgVaultOrphaned` until asked); `listOrgGroups`, `createOrgGroup`, `renameOrgGroup`, `deleteOrgGroup`, `addOrgGroupMember`, `removeOrgGroupMember`; `listOrgVaults`, `createOrgVault`, `deleteOrgVault(password, vaultId)`, `linkOrgVaultGroup`, `unlinkOrgVaultGroup`, `rotateOrgVault`; `orgAccess` (fingerprints computed here) and `applyOrgAccess(vaultId, confirmed)` (seals only to the people confirmed, checked again against the digits shown); `setOrgPolicies`, `orgSso`, `saveOrgSso`, `saveOrgSaml`, `removeOrgSso`, `testOrgSso`, `orgScim`, `createOrgScimToken`, `revokeOrgScimToken`, `orgEvents`; `clientPolicies()` (no network: the longest auto-lock, the shortest master password, exports without organisation vaults, as last seen, which the vault applies itself); free: `orgEventMessageKey` |
| Share links | `createShareLink` (returns the address to send), `listShareLinks`, `revokeShareLink`, `fetchShareLink` and `openShareLink` (work signed out); free: `parseShareLinkUrl` |
| Emergency access | `listEmergencyContacts`, `addEmergencyContact`, `removeEmergencyContact`, `request…`/`deny…`/`approveEmergencyAccess`, `openEmergencyAccess`, `openEmergencyAttachment` |
| Devices and log | `listDevices`, `renameDevice`, `signOutDevice`, `securityLog` |
| Import and export | `exportVault(format, password, masterPassword)` → a path for the share sheet (JSON, CSV, CXF, encrypted with files), `importFile(source, path, password, keyFilePath)` for every source the core reads |
| Settings and lifecycle | `settings`, `updateSettings` (theme, language, auto-lock, lock in the background, list order, the app-open gate `deviceAuthOnOpen`), `recordActivity`, `appDidEnterBackground`, `appWillEnterForeground` (auto-lock and a sync) |

**Items** are typed: `ItemDetails` has a case per type (`login`, `password`, `secureNote`, `card`, `identity`, `document`, `wifi`, `sshKey`, `environment`, `maskedEmailProvider`, `structured` for the types built from a field table, and `other` with the JSON of a type from a newer client). `fieldSpecs(itemType)` gives a `structured` type's fields, so the apps have one editor and one detail screen for bank accounts, API credentials, software licences, ID documents, crypto wallets, databases, custom items and custom templates; labels are the catalog's `itemFields.<key>` and `itemChoices.<key>.<choice>`. A save starts from the stored JSON and writes only the fields the apps edit, so fields from newer clients, passkeys, the password history and auto-type settings come back untouched. Saving cleans the draft as the web vault's editor does (trimmed values, secrets as typed, empty fields dropped, the list subtitle and card brand filled in) and refuses one `validateDraft` rejects. A stale `revision` saves a conflicting copy.

**Lists** filter, search and order as the web vault does (`packages/vault-client/src/items.ts` and `listOrder.ts`): search ignores case and accents and never looks at secrets; sorts are name A–Z and Z–A, newest, oldest and recently changed; sections are by type, first letter (accents dropped, `#` last), vault or none. Names compare like `Intl.Collator` with `numeric: true`, approximated without ICU (case and accents ignored, digit runs as numbers, scripts in code point order).

**Shared vaults** open in `octapass-ffi`'s `Session` (as in the Tauri app and the autofill extensions), once their grant verifies against the granter's signing key; a vault whose grant doesn't is `untrusted` and shows no items. A shared vault's name is an encrypted `vaultInfo` record in the vault, as on the web, and is never listed as an item. Device-local notes (fingerprints the user compared, which item each share link came from) are in `<tag>.notes.json` next to the store; the settings in `settings.json`. Neither holds a secret.

### What the app implements

```swift
final class Keychain: NativePlatform, @unchecked Sendable {
    func secret(name: String) throws -> String?                  // shared access group, no prompt
    func setSecret(name: String, value: String) throws
    func deleteSecret(name: String) throws
    func deviceLock() -> DeviceLock                             // LAContext: Face ID, Touch ID, passcode
    func storeDeviceSecret(name: String, secret: Data) throws   // [.biometryCurrentSet, .or, .devicePasscode]
    func deviceSecret(name: String, reason: String) throws -> Data  // prompts; throw .deviceUnlockCancelled
    func deleteDeviceSecret(name: String) throws
    func setCredentialIdentities(identities: [CredentialIdentity]) throws  // ASCredentialIdentityStore
    func chipAvailable() -> Bool                                // SecureEnclave.isAvailable
    func createChipKey(name: String) throws -> ChipKey?         // no prompt; nil without a chip
    func chipSecret(name: String, context: Data) throws -> Data
    func deleteChipKey(name: String) throws
    func lowMemory() -> Bool
    func backupFolderFiles(folder: String) throws -> [String]   // a security-scoped bookmark
    func writeBackupFile(folder: String, name: String, source: String) throws
    func deleteBackupFile(folder: String, name: String) throws
}

final class Model: VaultObserver, @unchecked Sendable {   // called on a vault thread: hop to the main actor
    func sessionChanged(snapshot: SessionSnapshot)
    func itemsChanged()
    func syncChanged(state: SyncState)
    func sharingChanged()
}

let vault = try OctaPassVault(config: VaultConfig(dataDir: group.path, tempDir: caches.path,
    deviceName: "Octa Pass for iPhone", platform: .ios), platform: Keychain(), observer: model)
switch try await vault.signIn(serverUrl: url, email: email, password: password, secretKey: nil) { … }
```

On Android the same names apply (`NativePlatform` over the Keystore and `BiometricPrompt`, with `BIOMETRIC_STRONG or DEVICE_CREDENTIAL`), and the app calls `app.octap.vault.PlatformVerifier.init(context)` once before the first call, so the HTTPS clients use Android's certificate verifier. The Keychain item names and `accounts.json` are the Tauri app's, so the existing AutoFill extension and Android services keep working on the same store.

## Build

From the repository root, on a Mac with Xcode, the Rust targets `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`, `aarch64-linux-android` and `x86_64-linux-android`, and for Android the NDK (`$ANDROID_NDK_HOME`, or the newest under `$ANDROID_HOME/ndk`):

```sh
crates/octapass-mobile/scripts/build-ios.sh       # XCFramework + Swift bindings
crates/octapass-mobile/scripts/build-android.sh   # .so for arm64-v8a and x86_64 + Kotlin bindings
```

The library also carries `octapass-ffi`'s C API (it's linked in), but only this crate's bindings are generated. An app that wants both in one binary generates `OctaPassCore` from this library too, instead of linking the second library.

## Tests

```sh
cargo test -p octapass-mobile                     # unit tests + tests/flow.rs, with the server in-process
crates/octapass-mobile/scripts/test-swift.sh      # swift test on this Mac
crates/octapass-mobile/scripts/test-kotlin.sh     # Gradle/JUnit on the JVM
```

`tests/flow.rs` runs the real sync server in-process and moves its clock: sign-up, two-step sign-in, device unlock, devices and the security log, items of every type, lists, the trash, attachments, health, every export and import, settings, sharing between two accounts with key rotation, families, share links, and emergency access after the waiting period. The Swift and Kotlin tests start the real server in development mode (`OCTAPASS_DEV_MODE=true`, or use the one at `OCTAPASS_TEST_SERVER`) and run the same flows through the generated bindings: sign-up, sign-in with two-step, items of each type with an attachment, a vault shared between two accounts, and export and import. Their platform callbacks are in-memory stand-ins for the Keychain and Keystore.
