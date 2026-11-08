# Octa Pass desktop app

The Octa Pass desktop app for Windows and Linux, built with [Tauri 2](https://tauri.app). On a Mac, Octa Pass is the native app in [`apps/macos`](../macos/): the maintainer dropped this app's macOS support on 2026-11-06 ([plan 19](../../plans/19-native-desktop-apps.md)), and it no longer builds for macOS (`src-tauri/src/lib.rs` stops a macOS build with that reason). Native apps replace it on Windows and Linux too, in plan 19's phase 5. It shows the web vault's screens (`apps/web`), but the vault runs natively: the Rust side links `octapass-core`, talks to the sync server itself and keeps every key in its own process. The web view only receives what it renders. The design is in [`plans/13-milestone-3-extension-and-desktop.md`](../../plans/13-milestone-3-extension-and-desktop.md) (workstream J) and [`plans/03-security-model.md`](../../plans/03-security-model.md).

## Layout

`apps/desktop` is its own Cargo workspace, so Tauri and the system WebView libraries stay out of the root `cargo test --workspace`. The crates under `crates/` still build and test on macOS and keep their macOS code: the native Mac app uses `octapass-native-host` and `octapass-ssh-agent` from here, and may use the others.

| Path | What it is |
|---|---|
| `crates/device-unlock` | `octapass-device-unlock`: unlock with the device's own lock. macOS: Touch ID or the Mac login password (LocalAuthentication, plus a Keychain item behind `SecAccessControl` `[.biometryCurrentSet, .or, .devicePasscode]`). Windows: Windows Hello, face, fingerprint or PIN (`KeyCredentialManager`; DPAPI for Fill without unlocking). Linux: polkit, then the Secret Service. Each platform's logic is tested everywhere against a fake OS interface; only the FFI is behind `cfg`. |
| `crates/vault` | `octapass-desktop-vault`: the vault behind the app's commands. Local vaults are in `src/vault/local.rs`, the autofill gate in `src/vault/gates.rs`. It mirrors `VaultService`, handles OPAQUE sign-up and sign-in, keeps an encrypted local copy for offline unlock, syncs, saves conflict copies, does device unlock, computes health inputs, and wraps the account key for the browser extension. It also shares: shared vaults and their members and roles, families, one-time share links, emergency access, devices and the security log, with every key sealed and opened in Rust. |
| `crates/native-host` | `octapass-native-host`: the native messaging host for the browser extension, plus the manifests the app installs. |
| `crates/wifi` | `octapass-wifi`: the computer's Wi-Fi. The current network, networks in range and saved networks with their passwords where the system gives them, over a `WifiSystem` trait: macOS CoreWLAN, `networksetup` and the System keychain, Windows `wlanapi`, Linux NetworkManager over D-Bus. What the systems print is parsed by functions tested everywhere; `cargo run -p octapass-wifi --example networks` prints what this computer shows (never passwords). |
| `crates/autotype` | `octapass-autotype`: auto-type. The sequence language, which login a window belongs to, and the engine that checks and types, over a `Platform` trait: macOS `CGEvent` + Accessibility, Windows `SendInput`, X11 XTest, Wayland's RemoteDesktop portal. The logic is tested everywhere with a fake platform. |
| `crates/windows-passkey` | `octapass-windows-passkey`: the Windows 11 passkey provider. CTAP2 messages, the checks on Windows' signatures and the order of every operation are portable and tested everywhere, over `Host` and `PasskeyVault` traits; only the COM server and `webauthn.dll` calls are behind `cfg(windows)`. |
| `windows` | The MSIX package manifest; see [Passkeys on Windows](#passkeys-on-windows). |
| `crates/login-item` | `octapass-login-item`: opening the app at login with `--hidden`. A launch agent in `~/Library/LaunchAgents` on macOS, the `HKCU\…\Run` value (and Task Manager's `StartupApproved`) on Windows, an XDG autostart entry on Linux. The entries are written and read by functions tested everywhere; only the registry calls are behind `cfg(windows)`. |
| `src-tauri` | The Tauri app: commands, the quick-access window, auto-type, clipboard auto-clear, the native messaging socket, the menu, the tray icon and the background settings (`tray.rs`, `background.rs`). |
| `src` | `TauriVaultService` (`VaultService` over the commands), the entry that injects it into the web vault's `<App>`, and the quick-access UI. |

The web vault is used unchanged. `vite.config.ts` swaps `apps/web/src/app/service.ts` for `src/webService.ts`, so the web vault's WASM worker isn't bundled; the desktop app passes its own service to `<App>`.

## Develop

```sh
pnpm install
pnpm --filter @octapass/core build          # the web vault's sources import it for types

# A local sync server (another terminal)
OCTAPASS_DEV_MODE=true OCTAPASS_RATE_LIMITS=off OCTAPASS_DATA_DIR=/tmp/octapass-dev cargo run -p octapass-server

cd apps/desktop
VITE_SERVER_URL=http://localhost:8080 cargo tauri dev
```

`VITE_SERVER_URL` makes the "Octa Pass" server choice point at the local server; without it, it's the hosted service. `OCTAPASS_DESKTOP_DATA_DIR` moves the app's data folder (default: the OS app-data folder for `app.octap.desktop`), and the native host reads it too.

## Test

```sh
cd apps/desktop
cargo test --workspace                       # on Linux or Windows; vault integration tests run the real server in-process
cargo test --workspace --exclude octapass-desktop   # on a Mac: the crates only
cargo clippy --workspace --all-targets      # on Linux or Windows
cargo check -p octapass-desktop --target x86_64-unknown-linux-gnu   # the app's Linux code, from a Mac
cargo clippy -p octapass-device-unlock -p octapass-native-host -p octapass-autotype -p octapass-windows-passkey --all-targets --target x86_64-pc-windows-msvc
cargo clippy -p octapass-device-unlock -p octapass-native-host -p octapass-autotype --all-targets --target x86_64-unknown-linux-gnu
pnpm --filter @octapass/desktop test
pnpm --filter @octapass/desktop typecheck
```

`octapass-autotype`'s `types_into_a_real_window` opens a TextEdit window and types into it with real key events, then reads the text back. It runs only when the terminal has the Accessibility permission, the screen is unlocked and TextEdit isn't already open (it could have your documents); otherwise it prints why it skipped.

## Passkeys on Windows

Octa Pass can be a passkey provider on Windows 11 (24H2 build 26100.6725, 25H2 build 26200.6725 or newer), through Microsoft's [plugin authenticator API](https://github.com/microsoft/webauthn). Windows only activates a plugin from an installed package, so this needs the MSIX package; the NSIS installer keeps working and doesn't show the switch.

```powershell
cargo tauri build --no-bundle
apps/desktop/scripts/package-msix.ps1 -Publisher "CN=..." -Certificate octa-pass.pfx -Password $env:PFX_PASSWORD
```

`-Publisher` must be the certificate's subject. For a test machine, a self-signed certificate works once it's in *Trusted People*. Then turn on **Settings → Passkeys in Windows** in the app and enable Octa Pass under Windows Settings → Accounts → Passkeys → Advanced options. The design is in [plan 05](../../plans/05-clients-and-autofill.md) (History, 2026-11-02). None of this has run on real Windows yet.

## Build

From the repository root, `pnpm build:windows` and `pnpm build:linux` build the release bundles, and `pnpm build:desktop` picks the one for the system you're on (on a Mac, `pnpm build:macos`, the native app). They ask which server the app offers as "Octa Pass" (see [building the apps](../../docs/contributing/development-setup.md#build-the-apps)). By hand:

```sh
cd apps/desktop
cargo tauri build --debug --bundles deb      # target/debug/bundle/deb/ (on Linux)
```

`beforeBuildCommand` builds the frontend and `octapass-native-host`, which the `.deb` and `.rpm` put in `/usr/bin`, with the polkit policy from `src-tauri/linux/`. The Windows installer doesn't ship the host yet (Known limits). `scripts/build-windows.sh` cross-compiles the Windows installer on a Mac.

## Quick access

**Ctrl+Shift+Space** opens a search box over the other apps. Enter copies the password, Shift+Enter the username, Alt+Enter the one-time code. Copying happens in Rust, so the values never reach the web view, and the clipboard is cleared after 30 seconds unless something else was copied meanwhile. When the vault is locked, the window offers device unlock.

## Auto-type

**Ctrl+Enter** in quick access, or a row's keyboard button, types the login into the window quick access was opened over. `Ctrl+Shift+\` anywhere types the login that belongs to the focused window; with none or several, it opens quick access listing the matches, where Enter types. The values go from the vault to the key events in Rust (`src-tauri/src/autotype.rs`), never through the web view.

`octapass-autotype` refuses before typing anything when a permission is missing (only macOS has one, Accessibility; the crate keeps that code), the screen is locked, the target is Octa Pass's own window, the window doesn't belong to the login, or modifier keys stay down for 3 seconds. It waits 150 ms before the first key, 6 ms between characters and 80 ms after Tab and Enter, and checks focus and the screen lock again before each group of keys. The rules for which window belongs to which login, and the sequence language, are in `crates/autotype/src/window.rs` and `sequence.rs`, and in the docs (`docs/platforms/desktop.md#auto-type`). Refusals reach quick access as `{ code, … }`; the window comes back with the reason.

- **macOS** (the crate only; the Mac app doesn't auto-type yet): `AXIsProcessTrusted`, the focused window through Accessibility, and for browsers the page address from the web area's `AXURL` (Chromium builds its tree once `AXManualAccessibility` is set). The screen lock comes from `CGSessionCopyCurrentDictionary`.
- **Windows:** `GetForegroundWindow`, `SendInput` with `KEYEVENTF_UNICODE`; the screen is locked when the input desktop isn't `Default`.
- **X11:** `_NET_ACTIVE_WINDOW`, `_NET_WM_NAME`, `_NET_WM_PID`; each character is typed on a spare keycode mapped to its keysym (put back afterwards), so neither Shift nor the layout group changes it. The lock is logind's `LockedHint` or the screensaver's `GetActive`.
- **Wayland:** the RemoteDesktop portal with a keyboard-only session, closed after each run; its restore token stays in memory, so the desktop asks once per app run. Without the portal, auto-type copies the password with the usual auto-clear.

## Browser extension (native messaging)

**Browser → Connect browser extension** installs the manifest for `app.octap.desktop` for each browser on the machine. **Disconnect** removes it again. For installers, the same is available from the command line:

```sh
octapass-desktop --install-browser-integration      # "Octa Pass.exe" on Windows
octapass-desktop --uninstall-browser-integration
```

The manifests' macOS folders below are `octapass-native-host`'s, which the native Mac app is to use.

| Browser | macOS | Linux | Windows |
|---|---|---|---|
| Chrome | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts` | `~/.config/google-chrome/NativeMessagingHosts` | `HKCU\Software\Google\Chrome\NativeMessagingHosts` |
| Edge | `…/Microsoft Edge/NativeMessagingHosts` | `~/.config/microsoft-edge/NativeMessagingHosts` | `HKCU\Software\Microsoft\Edge\NativeMessagingHosts` |
| Brave, Chromium | their `NativeMessagingHosts` folders | the same | their `HKCU` keys |
| Firefox | `~/Library/Application Support/Mozilla/NativeMessagingHosts` | `~/.mozilla/native-messaging-hosts` | `HKCU\Software\Mozilla\NativeMessagingHosts` |

The manifests allow only the Octa Pass extension. Release builds allow the store IDs (`CHROME_WEB_STORE_ID`, `EDGE_ADD_ONS_ID` and `AMO_ID` in `crates/native-host/src/manifests.rs`: placeholders until the extension is published, so a release build accepts no extension until they're filled in). Debug builds also allow the development IDs: Chromium `oojckfebkmiogiahdggohbdnndbfcjnm` (the development key in plan 13's History) and Firefox `octa-pass@octap.app`. A self-distributed release (an extension loaded unpacked or signed as an unlisted add-on, which no store gave an ID) sets `OCTAPASS_EXTRA_EXTENSION_IDS=<id>,<id>` when it's built; those IDs are then allowed in debug and release alike. Any unpacked Chromium extension can claim an ID through its manifest `key`, so only do this for your own machines. The host checks the caller again before relaying anything to the app over a user-only Unix socket (a named pipe on Windows).

The extension's origin is only an argument the host was started with, so neither side takes it on trust (`crates/native-host/src/trust.rs`):

- **The host** relays only when its parent process is a known browser: Chrome (and Beta, Dev, Canary), Chromium, Edge, Brave, Firefox, Vivaldi, Opera or Arc. On Windows the `cmd.exe` Chromium starts hosts through is skipped. Release builds also require the browser's vendor signature (macOS: the running process meets `anchor apple generic` with the vendor's team ID; Windows: Authenticode with the vendor's name) or, on Linux, a root-owned system install. Otherwise every request gets `browserNotTrusted` with a message the extension can show.
- **The app** answers a connection only when the peer (macOS: `LOCAL_PEERTOKEN` audit token; Linux: `SO_PEERCRED`; Windows: `GetNamedPipeClientProcessId`) runs the `octapass-native-host` next to the app's own executable, and that host's parent passes the same browser check. On macOS (the crate's check, for the native Mac app) release builds also require the host's signature from the app's own team, checked on the exact process the audit token names. A browser that fails the check gets `browserNotTrusted`, as from the host; anything else gets `forbidden`. The app refuses before it reads the request, so the host puts the request's `id` on that reply. The unlock prompt names the browser ("unlock Octa Pass in Google Chrome").
- **Debug builds** check paths and names only and say so on stderr. Tests stand in for a browser with a copy of the `fake-browser` example at `Firefox.app/Contents/MacOS/firefox`, so `cargo test --workspace` (which builds the host and the example) is the way to run them.

Messages are length-prefixed JSON (native byte order):

| Request | Result |
|---|---|
| `{ "id": 1, "type": "unlock-status" }` | `{ appRunning, status: "signedOut" \| "locked" \| "unlocked", email?, serverUrl?, deviceUnlock, label, stayUnlocked }`. With the app closed: `{ appRunning: false }` |
| `{ "id": 2, "type": "unlock" }` | Asks for the device lock (Windows Hello, polkit; Touch ID in the Mac app), then returns the status |
| `{ "id": 3, "type": "get-session-key-wrap", "publicKey": "<base64url X25519>" }` | After the user confirms with the device lock (no prompt while the app stays unlocked, plan 18): `{ email, serverUrl, ephemeralPublicKey, deviceSalt, wrappedAsk }` |
| `{ "id": 4, "type": "local-chip-secret", "publicKey": "<base64url X25519>", "vaultId": "…", "context": "…" }` | The chip's secret for a local vault in the extension: `{ context, ephemeralPublicKey, sealedSecret }`, or `null` with no chip. No prompt: it opens nothing without the master password. Without `context`, makes a new chip key. Sealed under the same derivation with info `openpass/v1/native-messaging-chip`; the extension opens it with the WASM `openChipSecret(key, sealedSecret)` |

The extension derives `wrapKey = HKDF-SHA256(ikm = X25519(its secret, ephemeralPublicKey), salt = ephemeralPublicKey ‖ its public key, info = "openpass/v1/native-messaging")` and unlocks with the WASM `Session.unlockWithDeviceKey(wrapKey, deviceSalt, wrappedAsk, account)`. Errors are `{ "ok": false, "error": { "code", "message" } }` with the vault's codes (`locked`, `deviceUnlockCancelled`, …), `appNotRunning`, `browserNotTrusted`, `forbidden` or `invalidRequest`.

## Known limits

- **Stay unlocked** (plan 18): `store_unprotected` keeps its secret (Secret Service attribute `stay-unlocked`, DPAPI files in `%LOCALAPPDATA%\app.octap.desktop\stay-unlocked`). With it on, auto-type doesn't ask; with it off it follows the autofill gate. Quick access copy doesn't follow the gate yet. The screen-lock poll needs logind on Linux; without them only sleep resets "revealing asked once".
- **Windows:** the installer doesn't ship `octapass-native-host.exe` yet, and the Windows Hello prompt isn't attached to the app's window.
- **Sharing notifications:** there are no live notifications; someone else's sharing change shows after the app syncs.
- **Auto-type in browsers on Windows and Linux:** the page address can't be read there, so browser windows match only the login's auto-type windows.
