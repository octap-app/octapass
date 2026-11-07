// Loads the Safari build of the extension into WebKit's own extension runtime (WKWebExtension, the
// engine Safari uses) and checks that it works there, without Safari or a signed app:
//
// 1. WebKit reads the manifest without errors.
// 2. The background service worker starts (the WASM core, IndexedDB).
// 3. The popup, opened before the worker has started, shows the first-launch screen.
// 4. A vault on this device only can be created over the popup's port (Argon2id in the worker).
//
// scripts/build.sh runs it after the macOS build:
//
//   swiftc -target "$(uname -m)-apple-macos15.4" scripts/check-extension.swift -o build/check-extension
//   build/check-extension Generated/Extension
//
// or without compiling: swift scripts/check-extension.swift Generated/Extension
//
// Needs macOS 15.4 or later. Runs with the screen locked: nothing has to be drawn.

import WebKit

@MainActor
func check(_ directory: URL) async throws {
    let fail = { (message: String) in throw NSError(domain: "check-extension", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }

    let webExtension = try await WKWebExtension(resourceBaseURL: directory)
    if !webExtension.errors.isEmpty { try fail("manifest: \(webExtension.errors.map(\.localizedDescription))") }
    print("ok   manifest (\(webExtension.displayName ?? "?") \(webExtension.version ?? "?"))")

    let controller = WKWebExtensionController(configuration: .nonPersistent())
    let context = WKWebExtensionContext(for: webExtension)
    for permission in webExtension.requestedPermissions { context.setPermissionStatus(.grantedExplicitly, for: permission) }
    for pattern in webExtension.requestedPermissionMatchPatterns { context.setPermissionStatus(.grantedExplicitly, for: pattern) }
    try controller.load(context)

    // Opened before the worker starts, as when the app tab loads after Safari stopped an idle worker.
    let popup = WKWebView(frame: CGRect(x: 0, y: 0, width: 400, height: 600), configuration: context.webViewConfiguration!)
    popup.load(URLRequest(url: context.baseURL.appending(path: "app.html")))

    let background: Error? = await withCheckedContinuation { done in context.loadBackgroundContent { done.resume(returning: $0) } }
    if let background { try fail("background: \(background)") }
    print("ok   background service worker")

    var heading = ""
    for _ in 0..<40 where heading.isEmpty {
        try await Task.sleep(for: .milliseconds(500))
        heading = (try? await popup.evaluateJavaScript("document.querySelector('#root h1')?.textContent ?? ''")) as? String ?? ""
    }
    if heading != "Welcome to Octa Pass" { try fail("popup: expected the first-launch screen, got \"\(heading)\"") }
    print("ok   popup: \(heading)")

    let result = try await popup.callAsyncJavaScript("""
        const port = chrome.runtime.connect({ name: 'octapass-ui' });
        const call = (id, method, args) => new Promise((resolve) => {
          port.onMessage.addListener(function reply(message) {
            if (message.id !== id) return;
            port.onMessage.removeListener(reply);
            resolve(message);
          });
          port.postMessage({ id, method, args });
        });
        const created = await call(1, 'createLocalVault', ['plum-orbit-canvas-violet-harbor-71']);
        const snapshot = await call(2, 'init', []);
        return JSON.stringify({ created, session: snapshot.value?.session?.status });
        """, contentWorld: .page) as? String ?? ""
    let reply = try JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any] ?? [:]
    let created = reply["created"] as? [String: Any] ?? [:]
    let code = created["value"] as? String ?? ""
    if created["ok"] as? Bool != true || code.wholeMatch(of: #/([A-Z0-9]{5}-){10}[A-Z0-9]{5}/#) == nil || reply["session"] as? String != "unlocked" {
        try fail("local vault: \(result)")
    }
    print("ok   vault on this device only: created and unlocked")
}

setvbuf(stdout, nil, _IOLBF, 0)
guard CommandLine.arguments.count == 2 else {
    print("usage: check-extension <extension directory>")
    exit(2)
}
// WebKit needs an absolute directory URL.
let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true).absoluteURL
let app = NSApplication.shared
Task { @MainActor in
    do {
        try await check(directory)
        exit(0)
    } catch {
        print("FAIL \(error.localizedDescription)")
        exit(1)
    }
}
app.run()
