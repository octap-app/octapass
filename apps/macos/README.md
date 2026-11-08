# Octa Pass for Mac (native)

The native Mac app ([plan 19](../../plans/19-native-desktop-apps.md)): SwiftUI on macOS 14+, on `OctaPassVault`, the same Rust API as the iPhone, iPad and Android apps ([`crates/octapass-mobile`](../../crates/octapass-mobile/)). Since 2026-11-06 it's Octa Pass on a Mac: the Tauri desktop app ([`apps/desktop`](../desktop/)) is for Windows and Linux only and no longer builds for macOS.

## How it shares the iPhone app's screens

The Mac target compiles [`apps/ios/OctaPass`](../ios/OctaPass/) directly. There are no copies:

- **Platform differences** are `#if os(iOS)` / `#if os(macOS)` in the shared files: the clipboard, printing, the share sheet (a save panel on the Mac), screen brightness, haptics.
- **Toolbar items and forms** get the Mac's look from stand-ins for SwiftUI's `ToolbarItem`, `ToolbarItemGroup` and `Form` in `OctaPassMac/MacControls.swift`, which the module's own declarations shadow.
- **iOS-only modifiers** with nothing to do on a Mac (the navigation bar's title size, the software keyboard) are no-ops in `OctaPassMac/IOSModifiers.swift`, so the shared files read the same on both.
- **iPhone-only services** (the camera scanner, joining Wi-Fi, the Apple Watch) have Mac stand-ins in `OctaPassMac/Platform/MacStandIns.swift` that say "not here", so the screens hide the action. Phase 2 replaces the ones the Mac gets. AutoFill settings and Credential Exchange are the iPhone's files, with the Mac's APIs behind `#if os(macOS)`.
- **Mac-only code** is in `OctaPassMac`: the window, the Settings window, menus and lifecycle (`OctaPassMacApp.swift`), the modal presenter and save panel (`Platform/MacModal.swift`).
- **Editing in the window:** the shared screens find a `DetailEditor` in their environment on the Mac only, and open the item editor in the window's detail column instead of a sheet (a sheet is a window of its own on the Mac). The menu commands read the list and item showing through `focusedSceneValue` (`NewItemCommand`, `ItemCommand` in `Vault/MainView.swift`).

| Command | Shortcut |
|---|---|
| New login, New item ▸ … | Cmd+N |
| Search | Cmd+F |
| Copy Username, Password, One-time code | Ctrl+Cmd+C, Shift+Cmd+C, Option+Cmd+C |
| Lock now | Ctrl+Cmd+L |
| Settings… | Cmd+, |

## Extensions

The first two are built from the iPhone's extension sources, so a fix reaches both; the Mac's differences are `#if os(macOS)` in those files. Each target's Info.plist and entitlements are generated from `project.yml` into `AutoFill/`, `SafeProvider/` and `SafeUnlock/`.

| Target | Sources | What it does |
|---|---|---|
| `OctaPassMacAutoFill` | [`apps/ios/AutoFill`](../ios/AutoFill/) | Passwords, passkeys and (macOS 15) one-time codes in Safari and other apps. It opens the store the app shares through the App Group with the small `octapass-ffi` (`OctaPassAutoFillKit` on `OctaPassCore`), as on the iPhone, so it works with the app closed. It unlocks with Touch ID or the Mac's password, the master password, or with no prompt while "Stay unlocked" is on. |
| `OctaPassMacSafeProvider` | [`apps/ios/SafeProvider`](../ios/SafeProvider/) | Safes in Finder, under Locations: a File Provider domain per Safe while the app runs, opened with the key the app leaves in the shared Keychain while the vault is unlocked. Locked, each Safe is still listed, empty, and asks for Octa Pass. |
| `OctaPassMacSafeUnlock` | `SafeUnlock` | Finder's Sign In on a locked Safe (a File Provider UI extension): opens Octa Pass and asks it to unlock (Touch ID at once). No key, no vault. |

**A Safe's files in the app:** a Safe's row in Safes opens its files in the detail column (`SafeBrowserView`, shared with the iPhone): Add files, New folder, Rename, Delete, Save a decrypted copy, Quick Look, and on the Mac Copy (Cmd+C), Paste (Cmd+V) and the Delete key. Drag files in from Finder, out to Finder, or between folders and Safes: within a Safe it moves (Option copies), between Safes it copies. Each step holds the Safe's store lock for that step only (`SafeFiles.withDrive`), so Finder's copy of the Safe isn't held up. Decrypted copies go in the app's temporary folder and are gone at the next lock.

On the Mac a path bar at the top of the column replaces the back button: the Safe, then each folder, with an earlier step to go back to it (Cmd+Up goes one up) or to drop files on. Choosing another Safe in the list opens it in place, without going back first; the open Safe's row is highlighted.

**How Finder names Safes:** with one Safe, Finder's sidebar shows "Octa Pass" (the app's name), not the Safe's: macOS ignores a lone domain's name there. With two or more it shows "Octa Pass - " and each Safe's name. The Safe's folder in `~/Library/CloudStorage` is `OctaPass-<Safe name>` either way.

Turn AutoFill on in Settings → AutoFill (macOS 15 asks in place), or in System Settings → General → AutoFill & Passwords. The extensions need the signed build: the App Group and the Keychain group are what they share with the app.

`OctaPassCore`'s XCFramework has macOS slices for the AutoFill extension (`crates/octapass-ffi/scripts/build-ios.sh` builds them with the iOS ones).

## Mac integration

- **`otpauth://` and `otpauth-migration://` links** open the app (`CFBundleURLTypes` in `project.yml`); `onOpenURL` keeps them until the vault is unlocked, then asks, as on the iPhone (`OpenedLinks`).
- **Credential Exchange** (macOS 26): another app's export opens the app with `ASCredentialExchangeActivity`; Settings → Other apps sends the vault to another app.
- **A window at launch:** the app always opens with its window (`NSQuitAlwaysKeepsWindows` off), since restoring a window closed at quit started it with none.
- **Open at login:** Settings → Running in the background, with `SMAppService` (`Platform/OpenAtLogin.swift`). Offered only to the app in an Applications folder.

## Desktop services

The browser extension's bridge, the `octapass` CLI's session and the SSH agent ([plan 19](../../plans/19-native-desktop-apps.md), phase 3) are Rust on the vault (`crates/octapass-mobile-vault/src/desktop`, exported in `crates/octapass-mobile/src/desktop.rs`); `Platform/DesktopServices.swift` starts them when the window first appears and stops them when the app quits. They work while the vault is locked: a request asks for Touch ID or the Mac's password (`VaultPlatform.verifyUser`), or brings the window forward when only the master password can unlock. Keys never reach Swift.

The app is sandboxed, so their sockets are in its App Group container, `~/Library/Group Containers/<team>.app.octap/`: `native-host.sock` (the bridge), `cli.sock` and `agent.sock`. `octapass-native-host` finds it by its own team (it's signed with the app's), the CLI by looking for the container with `cli.sock` in it; `OCTAPASS_DESKTOP_DATA_DIR` overrides both.

- **Browser extension:** Settings → Browser extension → Connect writes the native messaging manifest into each installed browser's `NativeMessagingHosts` folder (Chrome, Chromium, Edge, Brave, Firefox), the only folders outside the sandbox the app may write (for Firefox, all of `~/Library/Application Support/Mozilla`, which Firefox may not have made yet; Firefox counts as installed when that folder or its app in `/Applications` is there): `com.apple.security.temporary-exception.files.home-relative-path.read-write` in `project.yml`. The manifests point at `Contents/MacOS/octapass-native-host`, which `scripts/native-host.sh` (a build phase) builds with cargo for the architectures being built and signs with the app's identity, the hardened runtime and the App Group. The bridge answers only that binary, signed by the app's team, started by a known browser. A debug build of the app (and its debug host) also accepts the development extension (`oojckfebkmiogiahdggohbdnndbfcjnm`, `octa-pass@octap.app`); a release build only the store IDs, which are placeholders until the extension is published (`OCTAPASS_EXTRA_EXTENSION_IDS`, as in `apps/desktop`). To use a release build with the extension loaded unpacked from `apps/extension/dist/chrome` (or `dist/firefox`), build it with `OCTAPASS_EXTRA_EXTENSION_IDS=oojckfebkmiogiahdggohbdnndbfcjnm,octa-pass@octap.app pnpm build:macos`, then Connect again in Settings so the manifests list the ID. That build trusts any unpacked extension with the development key.
- **SSH agent:** Settings → SSH agent turns it on for this Mac (off by default) and shows the socket and the `IdentityAgent` lines for `~/.ssh/config`, to add by hand: the sandbox can't edit it. A Mac with no password and no Touch ID asks with an Allow / Deny window. The socket's folder is the App Group container, whose permissions the sandbox doesn't let the app change, so the agent leaves them alone when they're already 0700 (`apps/desktop/crates/ssh-agent/src/server.rs`).
- **CLI:** always on; the first command from a terminal asks, naming the program.

When you change an iPhone screen, build the Mac app too (`apps/macos/scripts/run.sh --build-only`).

## Layout

| Path | What it is |
|---|---|
| `project.yml` | The XcodeGen spec. `xcodegen generate` writes `OctaPassMac.xcodeproj` (committed). |
| `OctaPassMac` | Mac-only code, the app icon, Info.plist and entitlements. |
| `scripts/run.sh` | Builds the vault library if its Rust sources changed, builds the app and opens it. |
| `scripts/build.sh` | The release build, `pnpm build:macos`: `build/Release/Octa Pass.app` and `build/Octa Pass.dmg`. |
| `scripts/ui-tests.sh` | Starts the development server and runs `OctaPassMacUITests`: sign up, adding, editing and copying in the window and from the menus, Search, Settings, lock and unlock; two-step sign-in; and Safes (making two, a folder, the path bar, switching Safes). Screenshots of each step go to `build/screenshots`. |
| `OctaPassMacUITests` | The UI tests. The screens are the iPhone app's, so they use its accessibility identifiers. |

## UI tests

```sh
sudo DevToolsSecurity -enable   # once per Mac, or macOS asks for your password on every run
apps/macos/scripts/ui-tests.sh
```

The tests use a store of their own (a `UITests` folder in the app's container, emptied each run), so they don't touch the vault you use in the app. They drive the real app, so leave the keyboard and mouse alone while they run (about twelve minutes), and don't run the iPhone's UI tests at the same time: both want the front of the screen.

## Build and run

On a Mac with Xcode, [XcodeGen](https://github.com/yonaskolb/XcodeGen) and the Rust macOS targets (`rustup target add aarch64-apple-darwin x86_64-apple-darwin`):

```sh
OCTAPASS_DEV_MODE=true OCTAPASS_RATE_LIMITS=off OCTAPASS_DATA_DIR=/tmp/octapass-dev cargo run -p octapass-server   # another terminal
OCTAPASS_SERVER_URL=http://127.0.0.1:8080 apps/macos/scripts/run.sh
```

**Release build:** `pnpm build:macos` asks which server the app offers as "Octa Pass" (as the other app builds do), then writes `build/Release/Octa Pass.app` and `build/Octa Pass.dmg`. It's signed for development with the team below, so it opens on the Macs registered with that team. Developer ID signing and notarization aren't set up yet (plan 19, phase 4), and the release workflow has no Mac job until they are. `pnpm build:desktop` runs the same build on a Mac.

`crates/octapass-mobile/scripts/build-ios.sh` builds one `OctaPassVaultFFI.xcframework` for every Apple app: iOS, the Simulator and macOS (arm64 and x86_64). `crates/octapass-ffi/scripts/build-ios.sh` does the same for `OctaPassCoreFFI.xcframework`, which the AutoFill extensions link; `run.sh` and `build.sh` rebuild both when their Rust sources change.

**Signing:** the app is signed with the team in the iPhone app's gitignored `apps/ios/Signing.local.xcconfig` (`DEVELOPMENT_TEAM = …`), and Xcode makes its development profiles. The data-protection Keychain, the App Group and AutoFill need a signed build, so there's no unsigned fallback. Xcode has to be signed in to the team's Apple account (Xcode → Settings → Accounts) for the profiles: AutoFill's entitlement is only granted in a profile for an App ID with the capability.

**The iPhone app's identifiers:** the Mac app and its extensions use the iPhone app's App IDs (`app.octap.ios`, `.autofill`, `.safes`) and Keychain group (`<team>.app.octap.shared`), as one universal purchase, so the App IDs' capabilities serve both. The App Group is the Mac's own, team-prefixed (`<team>.app.octap`): macOS opens a `group.` container only to a target whose own profile lists it, and Xcode signs the Safes extension with the team's wildcard profile. A team-prefixed group needs no profile, and an App Group never leaves the device. They're apart from the earlier Tauri app's (`app.octap.desktop`), so this app has its own vault store and Keychain items, and nothing moves over from that app: sign in again here, and export and import a local vault.
