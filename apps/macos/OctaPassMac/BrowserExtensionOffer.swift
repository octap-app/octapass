import AppKit
import OctaPassResources
import OctaPassVault
import SwiftUI

/// A browser the Octa Pass extension works in and connects to this app (the native messaging
/// manifests' browsers, `octapass_native_host::manifests::Browser`), found by its app: the app is
/// sandboxed, so it can't look in the browsers' profile folders.
struct MacBrowser: Identifiable, Equatable {
    /// The manifests' name, as `browserExtensionBrowsers` returns it.
    let name: String
    let bundleIds: [String]
    let store: URL

    var id: String { name }

    /// The app, when it's on this Mac.
    var app: URL? {
        bundleIds.lazy.compactMap { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) }.first
    }

    // PUBLISH: each store's listing once the extension is listed (the same table as
    // `apps/desktop/crates/native-host/src/stores.rs`). Until then, the website's page for it.
    static let extensionPage = URL(string: "https://octap.app/docs/platforms/browser-extension/")!
    static let safariPage = URL(string: "https://octap.app/docs/platforms/browser-extension/#safari")!

    static let supported: [MacBrowser] = [
        MacBrowser(name: "Chrome", bundleIds: ["com.google.Chrome", "com.google.Chrome.beta", "com.google.Chrome.canary"], store: extensionPage),
        MacBrowser(name: "Edge", bundleIds: ["com.microsoft.edgemac", "com.microsoft.edgemac.Beta"], store: extensionPage),
        MacBrowser(name: "Brave", bundleIds: ["com.brave.Browser"], store: extensionPage),
        MacBrowser(name: "Chromium", bundleIds: ["org.chromium.Chromium"], store: extensionPage),
        MacBrowser(name: "Firefox", bundleIds: ["org.mozilla.firefox", "org.mozilla.firefoxdeveloperedition", "org.mozilla.nightly"], store: extensionPage),
    ]

    /// Safari's extension comes in an Octa Pass app of its own (`apps/safari`) and can't reach
    /// this app, so it's never what the offer waits for. Settings links to it.
    static let safari = MacBrowser(name: "Safari", bundleIds: ["com.apple.Safari"], store: safariPage)
}

/// The browser extension on this Mac: which supported browsers it has, which are connected (have
/// the manifest), and which the extension has reached the app from. The bridge notes those in
/// `browser-extension.json` in the App Group container (`octapass_native_host::seen`); until one
/// has, the extension is most likely not installed, and the vault window offers it. This Mac's
/// own, never synced.
@MainActor @Observable
final class BrowserExtensionState {
    static let shared = BrowserExtensionState()

    enum Offer { case get, connect }

    private(set) var present: [MacBrowser] = []
    private(set) var connected: [String] = []
    private(set) var seen: [String] = []
    /// The vault window's card was closed with ×. Settings keeps the links.
    var dismissed = UserDefaults.standard.bool(forKey: MacPreferences.extensionOfferDismissed) {
        didSet { UserDefaults.standard.set(dismissed, forKey: MacPreferences.extensionOfferDismissed) }
    }

    @ObservationIgnored private var observer: NSObjectProtocol?

    /// The UI tests' store, where the services don't run either (`DesktopServices`): no card over
    /// the sidebar they click through.
    private static var uiTests: Bool {
        #if DEBUG
        ProcessInfo.processInfo.environment["OCTAPASS_RESET"] == "1"
        #else
        false
        #endif
    }

    private init() {
        // Back from the browser, the extension may have come: read it again.
        observer = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
        refresh()
    }

    /// The web vault's rule (`apps/web/src/lib/browserExtension.ts`): `get` while no extension
    /// has reached the app and this Mac has a browser it works in; `connect` when one has but no
    /// browser is connected now.
    var offer: Offer? {
        if Self.uiTests { return nil }
        if !seen.isEmpty { return connected.isEmpty ? .connect : nil }
        return present.isEmpty ? nil : .get
    }

    func refresh() {
        present = MacBrowser.supported.filter { $0.app != nil }
        guard let container = DesktopServices.container else { return }
        connected = browserExtensionBrowsers(dataDir: container.path)
        seen = Self.readSeen(container)
    }

    /// `{"browsers": [{"browser": "Google Chrome", "firstSeen": 1731100000}]}`.
    nonisolated static func readSeen(_ container: URL) -> [String] {
        struct Record: Decodable {
            struct Seen: Decodable { let browser: String }
            let browsers: [Seen]
        }
        guard let data = try? Data(contentsOf: container.appendingPathComponent("browser-extension.json")),
              let record = try? JSONDecoder().decode(Record.self, from: data) else { return [] }
        return record.browsers.map(\.browser)
    }

    /// Connects the browser extension (Settings → Browser extension → Connect). Nil when it worked,
    /// otherwise what to say.
    func connect() -> String? {
        guard let container = DesktopServices.container, let host = DesktopServices.hostPath else {
            return L10n.phone.mac.browserNone
        }
        defer { refresh() }
        do {
            let installed = try connectBrowserExtension(dataDir: container.path, hostPath: host, development: DesktopServices.development)
            return installed.isEmpty ? L10n.phone.mac.browserNone : nil
        } catch {
            return L10n.phone.mac.browserFailed(error: error.reason)
        }
    }

    /// Opens where `browser` gets the extension, in that browser when it's here.
    func get(_ browser: MacBrowser) {
        guard let app = browser.app else {
            NSWorkspace.shared.open(browser.store)
            return
        }
        NSWorkspace.shared.open([browser.store], withApplicationAt: app, configuration: NSWorkspace.OpenConfiguration())
    }
}

/// The card at the foot of the vault window's sidebar, as in the desktop app's web vault
/// (`ExtensionOffer.tsx`): get the extension for the browsers on this Mac, or connect it.
struct ExtensionOfferCard: View {
    @State private var state = BrowserExtensionState.shared
    @State private var note: String?

    /// No `onAppear` here: with nothing to show there's no view for it to run on. The state reads
    /// itself when it's made and each time the app comes to the front.
    var body: some View {
        if let offer = state.offer, !state.dismissed {
            card(offer)
        }
    }

    private func card(_ offer: BrowserExtensionState.Offer) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "puzzlepiece.extension")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 30, height: 30)
                .background(LinearGradient.brand, in: RoundedRectangle(cornerRadius: 8))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(offer == .get ? L10n.browserExtension.offerTitle : L10n.browserExtension.offerConnectTitle)
                    .font(.callout.weight(.semibold))
                Text(offer == .get
                     ? L10n.browserExtension.offerBody(browsers: BrowserExtensionSection.list(state.present.map(\.name)))
                     : L10n.browserExtension.offerConnectBody)
                    .font(.footnote)
                    .foregroundStyle(Color.mist)
                    .fixedSize(horizontal: false, vertical: true)
                if offer == .get {
                    ForEach(state.present) { browser in
                        Button {
                            state.get(browser)
                        } label: {
                            Label(L10n.browserExtension.getFor(browser: browser.name), systemImage: "arrow.up.forward.square")
                        }
                        .accessibilityIdentifier("extension-offer-get-\(browser.name)")
                    }
                }
                if offer == .connect || state.connected.isEmpty {
                    Button(offer == .connect ? L10n.browserExtension.connect : L10n.browserExtension.offerConnect) {
                        note = state.connect()
                    }
                    .accessibilityIdentifier("extension-offer-connect")
                }
                if let note {
                    Text(note).font(.footnote).foregroundStyle(Color.mist).fixedSize(horizontal: false, vertical: true)
                }
            }
            .font(.footnote.weight(.semibold))
            .foregroundStyle(Color.ink)
            Spacer(minLength: 0)
            Button {
                state.dismissed = true
            } label: {
                Image(systemName: "xmark").font(.caption.weight(.semibold)).foregroundStyle(Color.mist)
            }
            .accessibilityLabel(L10n.browserExtension.offerDismiss)
            .help(L10n.browserExtension.offerDismiss)
            .accessibilityIdentifier("extension-offer-dismiss")
        }
        .padding(12)
        .background(Color.surface, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.line))
        .padding(.horizontal, 10)
        .padding(.bottom, 10)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("extension-offer")
    }
}
