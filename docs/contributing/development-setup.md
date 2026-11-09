---
title: Development setup
description: Set up the Octa Pass monorepo locally with Node.js, pnpm and Rust, run the documentation website, and learn where each part of the project lives.
status: stable
sidebar:
  order: 2
---

The repository holds the plans, the docs, the website, the Rust crypto core and sync server, and every app: the web vault, the browser extension, the desktop and phone apps, the CLI and the IDE extensions.

## Requirements

| Tool | Version |
|---|---|
| Node.js | 22.13 or newer (24 recommended; the e2e suite uses `node:sqlite`) |
| pnpm | 11 |
| Rust | The version in `rust-toolchain.toml`, installed by rustup, with the `wasm32-unknown-unknown` target |
| wasm-pack | `cargo install wasm-pack --locked` |
| Google Chrome | For the end-to-end tests only |
| Git | Any recent version |

## Run the website

```bash
git clone https://github.com/octap-app/octapass.git
cd octapass
pnpm install
pnpm dev        # http://localhost:4321
```

Other root scripts:

```bash
pnpm build      # static build into apps/website/dist
pnpm preview    # serve the build locally
pnpm check      # type-check the website
```

## Run the web vault

The web vault runs on the real stack: the Rust crypto core compiled to WebAssembly, in a Web Worker, talking to `octapass-server`. One command starts both:

```bash
pnpm install
pnpm --filter @octapass/web dev:stack   # server on :8080, web vault on http://localhost:5174
```

It builds the server (`cargo build -p octapass-server`) and, whenever its Rust sources changed since the last build, the WASM core (`pnpm --filter @octapass/core build:if-stale`). `pnpm build:web`, `pnpm start` and the browser end-to-end tests check the core the same way, so a pull that changes the Rust crates never leaves them on an old build. The server runs in dev mode with a throwaway data directory that's deleted when you press Ctrl-C; set `OCTAPASS_DATA_DIR=./somewhere` to keep it. In dev mode the sign-up screen shows the email verification code, so no mail server is needed.

To run the two halves yourself:

```bash
OCTAPASS_DEV_MODE=true OCTAPASS_WEB_ORIGINS=http://localhost:5174 cargo run -p octapass-server
pnpm --filter @octapass/web dev         # talks to http://localhost:8080
```

`VITE_SERVER_URL` points the web vault at another server. `VITE_VAULT_BACKEND=mock` (or `pnpm --filter @octapass/web dev:mock`) runs it on the in-browser mock instead, with example items and no server, which is handy for UI work and demos.

### Tests

```bash
cargo test --workspace                              # crypto core, test vectors, server
pnpm --filter @octapass/core test                   # the WASM flows in Node (after its build)
pnpm --filter @octapass/vault-client test           # item model, tools, mock, HTTP client, worker bridge
pnpm --filter @octapass/vault-client test:server    # the real service against a real octapass-server
pnpm --filter @octapass/web test                    # UI tests, on the mock
pnpm --filter @octapass/web e2e                     # Chrome against a real server: see below
pnpm --filter @octapass/web build                   # type-check and production build
```

Each Rust crate's integration tests build as one binary, `tests/main.rs`, which declares every file in `tests/` as a module. That way cargo links the crate once rather than once per file. To run one file's tests, use `cargo test -p octapass-server --test integration sharing::`. A new test file needs a `mod` line in `tests/main.rs`; a test there fails if you forget it. The test-vector files in `octapass-core` stay as their own binaries, so `--test vectors` regenerates only its own files.

The e2e suite (`apps/web/e2e`) builds the server and the web vault, starts both on free ports with a fresh data directory, and drives the system Chrome with `playwright-core`. It signs up, checks that the server's database files hold no plaintext from the vault, locks and unlocks, signs in again with the Secret Key, unlocks with a virtual passkey (WebAuthn PRF), syncs an edit from a second browser, and deletes the account, checking that no table still mentions it. Set `HEADED=1` to watch, and `CHROME_PATH` if Chrome isn't in `/Applications`.

The native phone apps have UI tests that drive their real screens against a fresh development server on a free port (plan 17, phase 3; which flow each test covers is in plan 17a):

```bash
apps/ios/scripts/ui-tests.sh                                   # iPhone Simulator, screenshots in apps/ios/build/screenshots
DEVICE="iPad Pro 13-inch (M5)" apps/ios/scripts/ui-tests.sh    # iPad
apps/android/scripts/ui-tests.sh                               # the running emulator, screenshots in apps/android/build/screenshots
```

Each takes the screenshot folder first and passes the rest to `xcodebuild` or Gradle, so `-only-testing:OctaPassUITests/ScreenshotTests` (iOS) or `-Pandroid.testInstrumentationRunnerArguments.class=app.octap.android.ScreenshotsTest` (Android) runs one class. The iOS screenshots come in each language and appearance from `OCTAPASS_TEST_LANGUAGE=ar` and `APPEARANCE=dark`; Android's `ScreenshotsTest` takes all four itself. The Android script sets the screen-lock PIN `1111` the device-unlock tests type, unlocks an emulator that started locked, and installs the test app that `OtherAppsTest` fills. `OCTAPASS_DERIVED_DATA` gives an iOS run its own build folder, and `OCTAPASS_TEST_SERVER` uses a server that's already running.

## Serve it, or run the native apps

`pnpm start` builds the web vault and the server and serves both on one port, `127.0.0.1:8380`, for a tunnel or a proxy to publish. Dev mode stays off. The first run in a terminal asks two things:

- **Where people open it:** through a tunnel or proxy at an address you choose (for example `https://pass.example.com`), or only on this computer at `http://localhost:8380`.
- **Who can create an account:** only the emails you invite, anyone who can open the address, or no one new. Your git email is the suggested invite, and you can change it or add more.

It offers to save the answers in the gitignored `.env.local` at the repository root, and `pnpm start --setup` asks again. Without a terminal, or with `OCTAPASS_NO_PROMPT=1`, it uses the defaults and prints them. `pnpm serve` does the same without building.

The native apps' scripts work out the device and the server, and ask only when they can't tell:

| Command | Device | Server |
|---|---|---|
| `pnpm dev:ios` | The booted Simulator, else a choice | `pnpm dev:api` or `pnpm start` on this Mac, whichever is running |
| `pnpm dev:ios:device` | The connected iPhone or iPad, else a choice | `pnpm start`'s public address, or one you type, since a phone can't reach the Mac's localhost |
| `pnpm dev:android` | The only emulator or phone, else a choice | `pnpm dev:api` or `pnpm start` on this computer, through `adb reverse` |

`pnpm dev:ios:device` also asks which team signs the app. The choices come from the accounts signed in to Xcode and the Apple Development certificates in the keychain, and the answers can be saved in the gitignored `apps/ios/device.env`. Each command takes `--setup` to ask every question again. Environment variables skip the questions: `OCTAPASS_SERVER_URL`, `DEVICE`, `APPLE_DEVELOPMENT_TEAM` and `ANDROID_SERIAL`.

The iPhone and Android commands rebuild the app's Rust library whenever its sources changed since the last build, because the committed Swift and Kotlin bindings change with it. When an Xcode build fails, they print its error lines and the path of the full log in `apps/ios/build/`.

## Build the apps

Each app has a build command at the repository root:

| Command | What it builds | Where it runs |
|---|---|---|
| `pnpm build:extension` | Chrome and Firefox, unpacked in `apps/extension/dist` | Anywhere |
| `pnpm build:safari` | The Safari apps for macOS and the iOS Simulator | A Mac |
| `pnpm build:ios` | The iPhone and iPad app, signed for App Store Connect (`--upload` uploads it) | A Mac |
| `pnpm build:android` | The Android app, as an unsigned release APK | Anywhere with the Android SDK |
| `pnpm build:desktop` | The desktop app for the system you're on: `build:macos`, `build:windows` or `build:linux` | Anywhere |
| `pnpm build:macos` | The Mac app and disk image, in `apps/macos/build` | A Mac |
| `pnpm build:windows` | The Windows installer | Windows, or cross-compiled on a Mac |
| `pnpm build:linux` | `.deb`, `.rpm` and AppImage packages | Linux |
| `pnpm build:cli` | The `octapass` command and its Git and Docker helpers | Anywhere |
| `pnpm build:vscode` | The VS Code extension, as a `.vsix` | Anywhere |
| `pnpm build:jetbrains` | The JetBrains plugin, as a `.zip` | Anywhere with JDK 17 |

The extensions and the iPhone, Android and desktop apps offer one server as "Octa Pass" on their sign-in screen, and anyone can still type another under "Self-hosted". The first build in a terminal asks which server that is. It offers `pnpm start`'s public address and the hosted service, and can save the answer in `.env.local` as `OCTAPASS_BUILD_SERVER_URL`. Without a terminal the builds use the hosted service. `VITE_SERVER_URL`, which the release workflow sets, wins over both, and `--setup` asks again. The apps accept only `https://` addresses, or `http://localhost` on the same computer.

The builds are unsigned unless the app's own signing settings are set, as each app's README describes. The Windows and Linux builds need the Tauri CLI (`cargo install tauri-cli --locked --version 2.12.4`).

`pnpm build:macos` builds the Mac app (`apps/macos`), the native SwiftUI app that is Octa Pass on a Mac. The Tauri app (`apps/desktop`) is for Windows and Linux only and no longer builds for macOS. The Mac app needs XcodeGen and an Apple developer team, from `APPLE_DEVELOPMENT_TEAM` or the one `pnpm dev:ios:device` signs the iPhone app with: the app keeps its keys in the Mac's Keychain, which needs a signed app, so there's no unsigned build. It's signed for development, so it opens on the Macs registered with that team. Developer ID signing and notarisation, for downloads anyone can open, aren't set up yet.

## Where things live

| Path | Contents |
|---|---|
| `plans/` | Internal plans and decisions, numbered and read in order |
| `docs/` | These docs, served at `/docs/` |
| `changelog/` | One Markdown file per notable change, served at `/changelog/` |
| `skills/octapass-docs/` | The agent skill for querying these docs |
| `skills/octapass-cli/` | The agent skill for using the `octapass` CLI safely, tested against its `--help` |
| `apps/website/` | Astro + Starlight website |
| `apps/web/` | The web vault (Vite + React) |
| `packages/ui/` | Design tokens and React UI primitives |
| `packages/vault-client/` | Item model, `VaultService` interface, local tools, the real service (`src/remote`) and the mock |
| `packages/core/` | The WASM build of the crypto core (`@octapass/core`) |
| `crates/` | Rust: `octapass-core` (crypto, items, tools), `octapass-wasm` (bindings), `octapass-api` (API types) |
| `apps/server/` | The sync server (axum + SQLite) |
| `AGENTS.md` | Rules for AI coding agents |

The layout of every app and crate is in [architecture](/docs/developers/architecture/#repository-layout).

## Building the site for a real domain

The site URL and repository URL come from `apps/website/src/site.config.ts`. Override them at build time:

```bash
PUBLIC_SITE_URL=https://octap.app PUBLIC_REPO_URL=https://github.com/octap-app/octapass pnpm build
```
