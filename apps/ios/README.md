# Octa Pass for iPhone and iPad

The native app ([plan 17](../../plans/17-native-mobile-apps.md)): SwiftUI on iOS and iPadOS 17+, on `OctaPassVault`, the Rust API in [`crates/octapass-mobile`](../../crates/octapass-mobile/). Swift draws the screens and uses the phone's services (Keychain, Face ID, the camera, pickers, Quick Look, `NEHotspotConfiguration`, haptics); the vault's logic is all in Rust. The AutoFill Credential Provider extension lives here too and links the smaller [`octapass-ffi`](../../crates/octapass-ffi/).

## Layout

| Path | What it is |
|---|---|
| `project.yml` | The XcodeGen spec. `xcodegen generate` writes `OctaPass.xcodeproj` (committed). |
| `OctaPass/App` | The app: `AppModel` (the vault, its events, settings, lifecycle), theme, errors, the root view. |
| `OctaPass/Onboarding` | Sign in, two-step, sign up, the Recovery Kit, unlock and the device unlock offer. |
| `OctaPass/Vault` | Tabs on iPhone, the split view on iPad, the sidebar, item lists. |
| `OctaPass/Items` | Item view and editor for every type, files, Wi-Fi, QR codes, one-time codes and the import review. |
| `OctaPass/Tools`, `Settings`, `Sharing` | Generator, Health, masked email, Safes; Settings, two-step, devices, security log, import and export, account deletion; sharing, families, share links, emergency access. |
| `OctaPass/Platform` | The Keychain bridge (`NativePlatform`), file pickers, the QR camera, Wi-Fi, AutoFill settings, the Safes in Files (`SafeFiles`). |
| `AutoFill` | The AutoFill extension, moved from the Tauri app unchanged. |
| `SafeProvider` | The Files extension for Octa Pass Safe (below). |
| `Packages/OctaPassVault`, `OctaPassResources` | Generated: the vault's Swift bindings, and the strings (English and Arabic) and brand tokens. |
| `Watch` | The Apple Watch app: shows the one-time codes the phone sends (`docs/features/watch.md`). It holds no seed and links no vault. Its own scheme, `OctaPassWatch`, needs Xcode's watchOS platform; it isn't embedded in the iPhone app, so the app builds on a Mac without that platform. |
| `Packages/AutoFillKit`, `Keychain`, `Wifi`, `WatchCodes` | The extension's logic, the shared Keychain and App Group, Wi-Fi joining, what the watch does with a bundle of codes. |
| `OctaPassTests`, `OctaPassUITests` | Unit tests, and UI tests that drive the native screens against a development server. |
| `scripts` | `ui-tests.sh` (Simulator), `device.sh` (a connected iPhone), `test-packages.sh` (the packages' own tests). |

**The Mac app compiles these screens too** ([`apps/macos`](../macos/), plan 19): platform differences go behind `#if os(iOS)` / `#if os(macOS)`, and a change here should build there (`apps/macos/scripts/run.sh --build-only`).

## Build and test

From the repository root, on a Mac with Xcode, [XcodeGen](https://github.com/yonaskolb/XcodeGen) and the Rust iOS targets:

```sh
crates/octapass-mobile/scripts/build-ios.sh       # OctaPassVaultFFI.xcframework and the Swift bindings
crates/octapass-ffi/scripts/build-ios.sh          # OctaPassCoreFFI.xcframework, for the AutoFill extension
apps/ios/scripts/ui-tests.sh                      # unit and UI tests on the Simulator, screenshots in build/screenshots
DEVICE="iPad Pro 13-inch (M5)" apps/ios/scripts/ui-tests.sh build/screenshots-ipad
OCTAPASS_TEST_LANGUAGE=ar apps/ios/scripts/ui-tests.sh build/screenshots-ar
APPEARANCE=dark apps/ios/scripts/ui-tests.sh build/screenshots-dark
apps/ios/scripts/test-packages.sh                 # Keychain, Wifi and AutoFillKit
```

`ui-tests.sh` starts the sync server in development mode on a free port (the email code shows on screen), enrols a face on the Simulator and answers every Face ID prompt, and serves a sign-in page for the AutoFill test. The system's sheets can't be driven from a test, so debug builds take what they'd return at launch: `OCTAPASS_PICK_NAME` and `OCTAPASS_PICK_TEXT` stand in for the Files picker (attachments, imports), and `OCTAPASS_RECEIVE_CXF` for what another app sends through Credential Exchange. The app reads the server from `OCTAPASS_SERVER_URL` in development; release builds use the hosted service.

The scripts rebuild `OctaPassVaultFFI.xcframework` and `OctaPassCoreFFI.xcframework` whenever their Rust sources changed since the last build (the hash is in `target/sources-hash/`), since the committed Swift bindings change with them. When `xcodebuild` fails, they print its error lines and the full log's path in `build/`.

On the Simulator, `pnpm dev:ios` (`scripts/simulator.sh`) uses the booted Simulator and whichever of `pnpm dev:api` and `pnpm start` runs on the Mac, and asks only when it can't tell.

On a phone, run `pnpm dev:ios:device` (`scripts/device.sh`). It asks which team signs the app (from the accounts signed in to Xcode and the Apple Development certificates in the keychain), which connected iPhone or iPad to use, and which server to sign in to, then offers to save the answers in the gitignored `apps/ios/device.env` as `APPLE_DEVELOPMENT_TEAM`, `DEVICE` and `OCTAPASS_SERVER_URL`. A phone can't reach the Mac's localhost, so the server is `pnpm start`'s public address or one you type. `--setup` asks again. The team goes into the gitignored `Signing.local.xcconfig`; nothing about it is committed.

## Octa Pass Safe in Files

Safes open in the Files app through a File Provider extension (`SafeProvider`, `NSFileProviderReplicatedExtension`), one domain per Safe, while the vault is unlocked (plan 03 History, 2026-11-04). The extension can't unlock the vault, so the app (`OctaPass/Platform/SafeFiles.swift`) writes each Safe's key, id, name and a deadline to the shared Keychain group (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, never synced; `Packages/Keychain/.../SafeKeys.swift`). The deadline is the auto-lock time after the app was last used (4 hours, the longest choice, when auto-lock is off), moved forward by touches and on coming back. Every record goes, and every domain is removed with `.removeAll` (deleting Files' plaintext copies), when the vault locks, on sign-out and at launch. The extension refuses and deletes an expired record, answers `notAuthenticated` without one, and locks its drive when the record goes.

Both processes use the App Group's `safes` folder. **The app never browses or edits a Safe:** its Safes screen (Tools → Safes) lists, makes, syncs and deletes them, and files are opened and changed in Files. Syncing and deleting hold the Safe's `flock` (`SafeStoreLock`), which the extension also takes for every step (shared to read, exclusive to change), and a sync moves the record's generation so the extension opens the Safe again. The key records are tested in `Packages/Keychain` (`swift test`) and against the Simulator's Keychain (`OctaPassTests/SafeKeyRecordTests.swift`); the extension itself has only been built, since running it under Files needs a signed build on a device.

## App Store

`pnpm build:ios` (`scripts/build.sh`) archives the app with the same team as `pnpm dev:ios:device`, then exports it for App Store Connect: `build/AppStore/Octa Pass.ipa`, to upload with Transporter. `pnpm build:ios --upload` uploads it instead. The archive is signed for development, and App Store Connect refuses development signing (error 90161, "A distribution provisioning profile should be used"), so don't upload an `.ipa` exported for development or ad hoc. The export signs it again with automatic signing: Xcode makes the Apple Distribution certificate and the App Store profiles for `app.octap.ios`, `app.octap.ios.autofill` and `app.octap.ios.safes` (the Files extension; its App ID needs the App Group and the Keychain group, which automatic signing adds). That needs the team's Apple account in Xcode → Settings → Accounts with the Admin or App Manager role, and the app created in App Store Connect. Xcode also sets the build number above the ones already uploaded; `OCTAPASS_BUILD_NUMBER` sets it instead. Xcode's Organizer does the same with the archive (Distribute App → App Store Connect).

What App Store Connect checks, and where it is:

- **Permission prompts:** every one the app can show has its reason in `project.yml` (`Info.plist`), in English and in `ar.lproj/InfoPlist.strings`: the camera (QR codes and photos to attach), Face ID, location (only for the Wi-Fi network's name) and the local network (a self-hosted server on a LAN address). The extension asks only for Face ID (`AutoFill/Info.plist`). Picking photos and files needs no permission.
- **Privacy manifests:** `OctaPass/Resources/PrivacyInfo.xcprivacy`, `AutoFill/PrivacyInfo.xcprivacy` and `SafeProvider/PrivacyInfo.xcprivacy` declare the APIs with required reasons, from Swift and from the Rust core (user defaults, file metadata, elapsed time), and that the app collects only the account's email address, for the app to work. Add a reason when new code uses another such API, or the upload is refused (ITMS-91053).
- **Versions:** the extension takes its version and build number from the project, as the app does.
