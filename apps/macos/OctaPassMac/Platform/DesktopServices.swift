import AppKit
import OctaPassKeychain
import OctaPassResources
import OctaPassVault

/// The desktop services (plan 19, phase 3): the browser extension's bridge, the `octapass` CLI's
/// session and the SSH agent. They're Rust on the vault (`crates/octapass-mobile/src/desktop.rs`);
/// this starts them when the app starts and stops them when it quits. They work while the vault
/// is locked: a request then asks for Touch ID or the Mac's password, or brings the window
/// forward when only the master password can unlock.
///
/// The app is sandboxed, so their sockets are in its App Group container
/// (`~/Library/Group Containers/<team>.app.octap`), where `octapass-native-host`, the CLI and
/// SSH clients find them.
@MainActor @Observable
final class DesktopServices {
    static let shared = DesktopServices()

    /// Why the browser bridge isn't listening, if it isn't.
    private(set) var bridgeError: String?
    /// Why the SSH agent isn't running, if it was asked to and isn't.
    private(set) var agentError: String?
    private(set) var agentRunning = false

    @ObservationIgnored private var vault: OctaPassVault?
    @ObservationIgnored private var bridge: DesktopService?
    @ObservationIgnored private var cli: DesktopService?
    @ObservationIgnored private var agent: SshAgentHandle?

    /// The App Group container: the sockets' folder.
    nonisolated static var container: URL? { SharedContainer.url() }

    /// `octapass-native-host`, next to the app's executable in `Contents/MacOS`, signed with the
    /// app's team (`scripts/native-host.sh`). The manifests point the browsers at it, and the
    /// bridge answers it only.
    nonisolated static var hostPath: String? {
        Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("octapass-native-host").path
    }

    /// Where SSH clients find the agent: `IdentityAgent` and `SSH_AUTH_SOCK`.
    nonisolated static var agentSocket: String? {
        container?.appendingPathComponent("agent.sock").path
    }

    /// A debug build also answers the development build of the extension (its fixed ID). The vault
    /// library is built for release in every build of the app, so the app says which it is.
    nonisolated static var development: Bool {
        #if DEBUG
        true
        #else
        false
        #endif
    }

    /// The UI tests run in a store of their own; they leave the sockets of the app in use alone.
    private static var disabled: Bool {
        #if DEBUG
        ProcessInfo.processInfo.environment["OCTAPASS_RESET"] == "1"
        #else
        false
        #endif
    }

    /// Settings → SSH agent → Run the SSH agent: this Mac's choice, off by default as in the Tauri
    /// app.
    var sshAgentOn = UserDefaults.standard.bool(forKey: MacPreferences.sshAgent) {
        didSet {
            UserDefaults.standard.set(sshAgentOn, forKey: MacPreferences.sshAgent)
            if sshAgentOn { startAgent() } else { stopAgent() }
        }
    }

    /// Starts the bridge and the CLI session, and the SSH agent if it's on. Once per launch.
    func start(vault: OctaPassVault) {
        guard self.vault == nil, !Self.disabled else { return }
        self.vault = vault
        guard let container = Self.container else {
            bridgeError = "no App Group container"
            return
        }
        do {
            guard let host = Self.hostPath else { throw CocoaError(.fileNoSuchFile) }
            bridge = try vault.startBrowserBridge(dataDir: container.path, hostPath: host, development: Self.development)
            bridgeError = nil
        } catch {
            bridgeError = error.reason
        }
        do {
            cli = try vault.startCliSession(dataDir: container.path)
        } catch {
            NSLog("Octa Pass: the CLI session didn't start: %@", error.reason)
        }
        if sshAgentOn { startAgent() }
    }

    /// When the app quits: the sockets go.
    func stop() {
        bridge?.stop()
        cli?.stop()
        agent?.stop()
        bridge = nil
        cli = nil
        agent = nil
        agentRunning = false
    }

    private func startAgent() {
        guard let vault, agent == nil else { return }
        do {
            agent = try vault.startSshAgent(prompts: SshPrompts(), endpoint: Self.agentSocket)
            agentError = nil
            agentRunning = true
            // The socket is made on the agent's own thread; a failure shows a moment later.
            Task { [weak self] in
                try? await Task.sleep(for: .milliseconds(300))
                self?.refreshAgent()
            }
        } catch {
            agentError = error.reason
            agentRunning = false
        }
    }

    private func stopAgent() {
        agent?.stop()
        agent = nil
        agentRunning = false
        agentError = nil
    }

    /// Reads the agent's state again, for Settings.
    func refreshAgent() {
        guard let agent else { return }
        if let error = agent.error() {
            agentError = error
            agentRunning = false
        }
    }
}

/// What the SSH agent asks of the UI. Called on the agent's threads.
final class SshPrompts: SshPromptsCallback, @unchecked Sendable {
    /// Allow / Deny, for a Mac with no Touch ID and no password to ask (every other Mac asks
    /// with the system's prompt). Waits for the answer.
    func approve(text: String) -> Bool {
        DispatchQueue.main.sync {
            MainActor.assumeIsolated {
                NSApp.activate(ignoringOtherApps: true)
                let alert = NSAlert()
                alert.messageText = L10n.phone.mac.sshRequest
                alert.informativeText = text.prefix(1).uppercased() + text.dropFirst()
                alert.alertStyle = .warning
                alert.addButton(withTitle: L10n.phone.mac.sshAllow)
                alert.addButton(withTitle: L10n.phone.mac.sshDeny)
                return alert.runModal() == .alertFirstButtonReturn
            }
        }
    }

    /// A request while locked that only the window can unlock: show it.
    func showUnlock() {
        DispatchQueue.main.async {
            MainActor.assumeIsolated { MacWindows.showVault() }
        }
    }

    func language() -> SshLanguage {
        L10n.language == "ar" ? .arabic : .english
    }
}
