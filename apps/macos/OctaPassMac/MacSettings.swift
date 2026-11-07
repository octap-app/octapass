import AppKit
import OctaPassResources
import OctaPassVault
import SwiftUI

/// Settings → Running in the background, on the Mac: what keeps working with the window closed.
/// These are this Mac's choices, kept in its own preferences, not the vault's settings.
struct BackgroundSection: View {
    @AppStorage(MacPreferences.showInMenuBar) private var showInMenuBar = true

    var body: some View {
        Section {
            Toggle(isOn: $showInMenuBar) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.background.menuBar)
                    Text(L10n.background.trayHelp).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            .accessibilityIdentifier("settings-menu-bar")
            // The system's login item (Platform/OpenAtLogin.swift).
            OpenAtLoginToggle()
        } header: {
            Text(L10n.background.title)
        } footer: {
            Text(L10n.background.help)
        }
    }
}

/// Settings → Browser extension, on the Mac: connecting writes the native messaging manifest that
/// lets each browser start the bundled `octapass-native-host` for the Octa Pass extension (the
/// Tauri app's Browser menu). Disconnecting removes them. This Mac's choice, not the vault's.
struct BrowserExtensionSection: View {
    @State private var browsers: [String] = []
    @State private var note: String?
    private let services = DesktopServices.shared

    var body: some View {
        Section {
            Text(browsers.isEmpty ? L10n.phone.mac.browserNotConnected : L10n.phone.mac.browserConnected(browsers: Self.list(browsers)))
                .accessibilityIdentifier("settings-browser-status")
            HStack {
                Button(L10n.phone.mac.browserConnect, action: connect)
                    .accessibilityIdentifier("settings-browser-connect")
                if !browsers.isEmpty {
                    Button(L10n.phone.mac.browserDisconnect, role: .destructive, action: disconnect)
                        .accessibilityIdentifier("settings-browser-disconnect")
                }
            }
            if let note {
                Text(note).font(.footnote).foregroundStyle(Color.mist)
            }
            if let error = services.bridgeError {
                Text(L10n.phone.mac.bridgeFailed(error: error)).font(.footnote).foregroundStyle(Color.red)
            }
        } header: {
            Text(L10n.phone.mac.browserTitle)
        } footer: {
            Text(L10n.phone.mac.browserHelp)
        }
        .onAppear(perform: refresh)
    }

    private func refresh() {
        guard let container = DesktopServices.container else { return }
        browsers = browserExtensionBrowsers(dataDir: container.path)
    }

    private func connect() {
        guard let container = DesktopServices.container, let host = DesktopServices.hostPath else { return }
        do {
            let installed = try connectBrowserExtension(dataDir: container.path, hostPath: host, development: DesktopServices.development)
            note = installed.isEmpty ? L10n.phone.mac.browserNone : nil
        } catch {
            note = L10n.phone.mac.browserFailed(error: error.reason)
        }
        refresh()
    }

    private func disconnect() {
        guard let container = DesktopServices.container else { return }
        do {
            _ = try disconnectBrowserExtension(dataDir: container.path)
            note = nil
        } catch {
            note = L10n.phone.mac.browserFailed(error: error.reason)
        }
        refresh()
    }

    /// "Chrome and Firefox", in the app's language.
    static func list(_ names: [String]) -> String {
        let formatter = ListFormatter()
        formatter.locale = Locale(identifier: L10n.language)
        return formatter.string(from: names) ?? names.joined(separator: ", ")
    }
}

/// Settings → SSH agent, on the Mac: on or off for this Mac, where SSH finds it, and the keys it
/// offers. The socket is in the app's App Group container (the app is sandboxed), so SSH is
/// pointed at it by hand: `IdentityAgent` in `~/.ssh/config`, or `SSH_AUTH_SOCK`.
struct SshAgentSection: View {
    @Environment(AppModel.self) private var model
    @Bindable private var services = DesktopServices.shared
    @State private var keys: [SshAgentKey]?

    var body: some View {
        Section {
            Toggle(isOn: $services.sshAgentOn) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.sshAgent.enable)
                    Text(L10n.sshAgent.enableHelp).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            .accessibilityIdentifier("settings-ssh-agent")
            if let error = services.agentError {
                Text(L10n.sshAgent.notRunning(error: error)).font(.footnote).foregroundStyle(Color.red)
            }
            if services.sshAgentOn, let socket = DesktopServices.agentSocket {
                LabeledContent(L10n.sshAgent.socket) {
                    copyable(socket, what: L10n.sshAgent.socket)
                }
                VStack(alignment: .leading, spacing: 6) {
                    Text(L10n.phone.mac.sshConfigHelp).font(.footnote)
                    copyable(Self.config(socket), what: "~/.ssh/config")
                    Text(L10n.sshAgent.envHelp(path: "\"\(socket)\"")).font(.footnote).foregroundStyle(Color.mist)
                        .textSelection(.enabled)
                }
                if let keys, !keys.isEmpty {
                    LabeledContent(L10n.sshAgent.keys(count: keys.count)) {
                        VStack(alignment: .trailing, spacing: 2) {
                            ForEach(keys, id: \.itemId) { key in
                                Text("\(key.title) (\(key.keyType))")
                            }
                        }
                    }
                } else if keys == nil {
                    Text(L10n.sshAgent.lockedKeys).font(.footnote).foregroundStyle(Color.mist)
                }
            }
        } header: {
            Text(L10n.sshAgent.title)
        } footer: {
            Text(L10n.sshAgent.help)
        }
        .task(id: services.sshAgentOn) {
            services.refreshAgent()
            keys = try? await model.vault.sshAgentKeys()
        }
    }

    /// The lines for `~/.ssh/config`. The path has a space ("Group Containers"), so it's quoted.
    static func config(_ socket: String) -> String {
        "Host *\n  IdentityAgent \"\(socket)\""
    }

    private func copyable(_ text: String, what: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(text)
                .font(.system(.footnote, design: .monospaced))
                .textSelection(.enabled)
                .environment(\.layoutDirection, .leftToRight)
            Spacer(minLength: 4)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
                model.confirm(L10n.copy.copied(what: what))
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .accessibilityLabel(L10n.copy.action(what: what))
        }
    }
}

/// The Mac's own preferences (`UserDefaults`), for what isn't the vault's.
enum MacPreferences {
    /// The menu bar icon, on by default as in the Tauri app.
    static let showInMenuBar = "showInMenuBar"
    /// The SSH agent, off by default as in the Tauri app (`DesktopServices.sshAgentOn`).
    static let sshAgent = "sshAgent"
}
