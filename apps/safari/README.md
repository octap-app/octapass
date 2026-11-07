# Octa Pass for Safari

The macOS and iOS apps that carry the Octa Pass browser extension into Safari. The extension itself is `apps/extension`, built with `--target safari`; this folder is the native wrapper Safari requires, and a one-screen app that tells people where to turn the extension on.

| Path | What it is |
|---|---|
| `OctaPass.xcodeproj` | Four targets: *Octa Pass (macOS)* and *Octa Pass (iOS)* (`app.octap.safari`), each embedding *Octa Pass Extension* (`app.octap.safari.extension`) |
| `App/Shared` | The SwiftUI onboarding screen, brand colours and type, the extension's state, the asset catalog, and `Localizable.xcstrings` (Arabic; English is the source) |
| `App/iOS`, `App/macOS` | Each app's entry point |
| `Extension` | The `.appex`: its `Info.plist` and the native message handler |
| `Generated/` | Written by `scripts/build.sh`, not committed: the extension's files and the Mona Sans font |
| `scripts/build.sh` | Builds the extension, syncs it into `Generated/`, runs `xcodebuild` for macOS and the iOS Simulator, then `check-extension.swift` |
| `scripts/check-extension.swift` | Loads the extension into WebKit's extension runtime and checks that the background, the popup and a local vault work |
| `scripts/icons.swift` | Renders the app icons from `brand/logo-tile.svg` |
| `screenshots/` | The iOS app on the Simulator, in English and Arabic, light and dark |

## Build

```sh
apps/safari/scripts/build.sh                          # extension, macOS app, iOS Simulator app, WebKit check
apps/safari/scripts/build.sh --skip-extension         # reuse apps/extension/dist/safari
apps/safari/scripts/build.sh --platform ios           # one platform
apps/safari/scripts/build.sh --configuration Release
```

Products are in `build/DerivedData/Build/Products/<configuration>[-iphonesimulator]/Octa Pass.app`. The macOS app is signed ad hoc and the Simulator app is signed to run locally; nothing here needs an Apple developer account. Run `build.sh` once before opening the project in Xcode, because the project references `Generated/`.

The project's targets list the extension's top-level files one by one (each one is copied to the root of the `.appex`, where Safari looks for `manifest.json`). `build.sh` stops if `dist/safari` has a different set, so a new top-level file gets added to the project too.

## Try it

- **Mac:** Safari → Settings → Advanced → *Show features for web developers*, then Develop → Developer Settings → *Allow unsigned extensions*. Open the built `Octa Pass.app` once; it registers the extension. Then Safari → Settings → Extensions → Octa Pass.
- **iOS Simulator:** `xcrun simctl install booted "build/DerivedData/Build/Products/Debug-iphonesimulator/Octa Pass.app"`, then Settings → Apps → Safari → Extensions → Octa Pass.

## How Safari differs

The extension's Safari build (`apps/extension/src/manifest.ts`, `src/safari/`) differs from the Chrome build:

- **Manifest:** permissions are `storage` and `alarms` only. Safari has no `idle` and no side panel, and its native messaging reaches the containing app rather than the desktop app's host. `browser_specific_settings.safari.strict_min_version` is 18.0, the first Safari that runs `world: "MAIN"` content scripts (the passkey wrapper). The background is the same module service worker; `wasm-unsafe-eval` and `storage.session` work as in Chrome.
- **Entries** `src/safari/background.ts` and `src/safari/pages.ts` install `src/safari/compat.ts` before the shared code (a Vite HTML hook loads the pages one ahead of each page's script):
  - a `chrome.idle` whose event never fires ("Lock when the computer locks" does nothing in Safari; the inactivity timer still locks);
  - port delivery fixes for WebKit, which drops port messages that reach the worker before it listens, and delivers messages posted before a port finished connecting twice. In the worker, each port holds its messages until its first listener and drops an exact repeat from its first second;
  - WebKit also loses a message posted right after connecting when the connect had to start the worker. Pages hold what they post on the UI port until the worker's first message on it, the session state. Without these the popup stays blank when it starts the worker, and a passkey request would run twice.
- `xcrun safari-web-extension-converter` warns that `background.type` and `content_scripts[].world` aren't supported. Its table is out of date: WebKit loads the manifest without errors (`check-extension.swift`), and MDN lists both from Safari 16.4 and 18.

## What's verified, and what isn't

The app follows the system language: run it with `-AppleLanguages "(ar)"` to see Arabic, laid out right to left.

Checked on this machine (Xcode 26.5, macOS 26, iOS 26.5 Simulator):

- `xcodebuild` succeeds for macOS (ad hoc) and the iOS Simulator; the `.appex` is inside each `.app` with the extension at its resource root.
- `pluginkit -m -i app.octap.safari.extension` lists the macOS extension from the built app.
- The iOS app runs on the Simulator (`screenshots/`), and reports the extension's state through the iOS 26.2 API.
- `check-extension.swift` passes: the manifest, the background (WASM core, IndexedDB), the popup's first screen when the popup starts the worker, and a local vault (Argon2id at 256 MiB) in WebKit's extension runtime. It also runs without compiling: `swift scripts/check-extension.swift Generated/Extension`.

Rerun on 2026-10-23 after the frame-approval and popup-startup changes: the macOS and iOS Simulator builds and `check-extension.swift` pass (manifest, background, popup's first screen, local vault).

Not verified, because it needs Apple signing, a person at the Mac, or both:

- The extension running in Safari itself (Mac or iOS), so autofill, the save prompt and passkeys on real pages, the iOS popup sheet, and the per-site permission prompt.
- The macOS onboarding window on screen (the Mac was locked; its layout was rendered offscreen instead), and the buttons that open Safari's settings.
- Passkey device unlock (WebAuthn PRF) from a Safari extension page.
- A passkey request that has to start the worker: content script ports can't wait for the worker to speak first, so WebKit may lose the request.
- App Store builds: they need a team, provisioning profiles and an app group if the app and extension ever share data.
