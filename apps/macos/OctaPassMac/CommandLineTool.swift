import AppKit
import OctaPassResources
import SwiftUI

/// The `octapass` CLI that ships inside the app (Contents/MacOS, built and signed by
/// scripts/cli.sh), and putting it on the PATH (plan 05, 2026-11-09). The CLI uses this app's
/// account and is unlocked whenever the app is, so after it's linked there's nothing to set up.
///
/// The app is sandboxed, so it can't write to /usr/local/bin itself: Settings gives the one
/// Terminal command that links the bundled CLI there (it asks for the Mac's password once), and
/// the link follows the app through updates.
enum CommandLineTool {
    /// Where Terminal finds it: `/usr/local/bin` is on every Mac's default PATH.
    static let linkPath = "/usr/local/bin/octapass"

    /// The bundled CLI, next to the app's executable.
    static var bundled: URL? {
        Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("octapass")
    }

    /// The Terminal command that links the bundled CLI into /usr/local/bin.
    static var installCommand: String? {
        guard let bundled, FileManager.default.isExecutableFile(atPath: bundled.path) else { return nil }
        return "sudo mkdir -p /usr/local/bin && sudo ln -sf \"\(bundled.path)\" \(linkPath)"
    }

    /// An `octapass` is already where Terminal looks. The sandbox may not let the app see it, in
    /// which case Settings still shows how to install it, which does no harm.
    static var installed: Bool {
        [linkPath, "/opt/homebrew/bin/octapass"].contains { FileManager.default.fileExists(atPath: $0) }
    }

    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

/// The command, in monospace, with a copy button.
private struct CommandRow: View {
    @Environment(AppModel.self) private var model
    let command: String

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(command)
                .font(.system(.footnote, design: .monospaced))
                .textSelection(.enabled)
                .environment(\.layoutDirection, .leftToRight)
            Spacer(minLength: 4)
            Button {
                CommandLineTool.copy(command)
                model.confirm(L10n.copy.copied(what: L10n.phone.mac.cliCommand))
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .accessibilityLabel(L10n.copy.action(what: L10n.phone.mac.cliCommand))
            .accessibilityIdentifier("settings-cli-copy")
        }
    }
}

/// Settings → Command-line tool, on the Mac.
struct CommandLineToolSection: View {
    @State private var installed = CommandLineTool.installed

    var body: some View {
        Section {
            if installed {
                Text(L10n.phone.mac.cliInstalled).accessibilityIdentifier("settings-cli-installed")
            }
            if let command = CommandLineTool.installCommand {
                VStack(alignment: .leading, spacing: 6) {
                    Text(installed ? L10n.phone.mac.cliRelink : L10n.phone.mac.cliInstall).font(.footnote)
                    CommandRow(command: command)
                }
            }
        } header: {
            Text(L10n.cliTool.title)
        } footer: {
            Text(L10n.cliTool.help)
        }
        .onAppear { installed = CommandLineTool.installed }
    }
}

/// Offers the CLI once, the first time the vault opens on this Mac (after signing in or creating
/// a vault), unless it's already installed. Settings has it after that.
struct CommandLineToolOffer: ViewModifier {
    @Environment(AppModel.self) private var model
    @AppStorage(MacPreferences.cliOffered) private var offered = false
    @State private var showing = false

    func body(content: Content) -> some View {
        content
            .task(id: model.isUnlocked) {
                // Not in the UI tests' own store: a sheet there would cover what they look for.
                guard model.isUnlocked, !offered, ProcessInfo.processInfo.environment["OCTAPASS_RESET"] != "1" else { return }
                offered = true
                if !CommandLineTool.installed, CommandLineTool.installCommand != nil { showing = true }
            }
            .sheet(isPresented: $showing) {
                CommandLineToolSheet { showing = false }
            }
    }
}

private struct CommandLineToolSheet: View {
    let done: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(L10n.phone.mac.cliOfferTitle, systemImage: "terminal")
                .font(.title3.weight(.semibold))
            Text(L10n.cliTool.help)
            if let command = CommandLineTool.installCommand {
                Text(L10n.phone.mac.cliInstall).font(.footnote)
                CommandRow(command: command)
            }
            Text(L10n.phone.mac.cliOfferLater).font(.footnote).foregroundStyle(Color.mist)
            HStack {
                Spacer()
                Button(L10n.phone.mac.cliOfferDismiss, action: done)
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("cli-offer-done")
            }
        }
        .padding(24)
        .frame(width: 460)
    }
}

extension View {
    /// The one-time CLI offer (`CommandLineToolOffer`).
    func commandLineToolOffer() -> some View {
        modifier(CommandLineToolOffer())
    }
}
