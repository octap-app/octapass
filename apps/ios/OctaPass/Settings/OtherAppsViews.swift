import AuthenticationServices
import OctaPassResources
import OctaPassVault
import SwiftUI

/// Settings → Other apps (iOS 26 Credential Exchange, the Tauri app's `OtherAppsSection`): send
/// the vault to another password manager through the system's sheet, after the master password
/// as for any export. Importing starts in the other app and lands in `ReceivedCredentialsReview`.
struct OtherAppsSection: View {
    @State private var exporting = false

    var body: some View {
        if CredentialExchange.isAvailable {
            Section {
                Button { exporting = true } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Label(L10n.phone.exportToApp, systemImage: "arrow.up.forward.app")
                        Text(L10n.phone.exportToAppHelp).font(.footnote).foregroundStyle(Color.mist)
                    }
                }
                .accessibilityIdentifier("settings-export-to-app")
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.phone.importFromApp)
                    Text(Self.importHelp).font(.footnote).foregroundStyle(Color.mist)
                }
            } header: {
                Text(L10n.phone.otherApps)
            } footer: {
                Text(Self.help)
            }
            .sheet(isPresented: $exporting) { ExportToAppSheet() }
        }
    }

    // "On this phone" and the iPhone's Settings → Apps → Passwords, or the Mac's.
    #if os(macOS)
    static var help: String { L10n.phone.otherAppsHelpMac }
    static var importHelp: String { L10n.phone.importFromAppHelpMac }
    #else
    static var help: String { L10n.phone.otherAppsHelp }
    static var importHelp: String { L10n.phone.importFromAppHelp }
    #endif
}

private struct ExportToAppSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField(L10n.phone.confirmPassword, text: $password)
                        .accessibilityIdentifier("export-to-app-password")
                    if let error { Text(error).font(.footnote).foregroundStyle(Color.dangerText) }
                    Button {
                        Task { await export() }
                    } label: {
                        HStack { Label(L10n.phone.exportToAppAction, systemImage: "arrow.up.forward.app"); if busy { Spacer(); ProgressView() } }
                    }
                    .disabled(busy || password.isEmpty)
                    .accessibilityIdentifier("export-to-app-action")
                } footer: {
                    Text(L10n.phone.exportToAppConfirm)
                }
            }
            .navigationTitle(L10n.phone.exportToApp)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() }.disabled(busy) } }
        }
    }

    private func export() async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            // The core's CXF export, read and deleted at once: only the system's sheet takes it.
            let path = try await model.vault.exportVault(format: .cxf, password: nil, masterPassword: password)
            let json = try Data(contentsOf: URL(fileURLWithPath: path))
            model.vault.closeAttachment(path: path)
            password = ""
            try await CredentialExchange.send(json)
            model.confirm(L10n.phone.exportToAppDone)
            dismiss()
        } catch let failure as ASAuthorizationError where failure.code == .canceled {
            // The user closed the system's sheet.
        } catch {
            self.error = error.message
        }
    }
}

/// What another app handed over, shown once the vault is unlocked: what it holds, then Import or
/// Cancel (the review Android's credential transfer shows). Nothing is saved before Import.
struct ReceivedCredentialsReview: ViewModifier {
    @Environment(AppModel.self) private var model
    @State private var preview: ReceivedPreview?
    @State private var opening = false

    /// The next handover, once nothing else is asked about.
    private var next: ReceivedCredentials? {
        guard preview == nil, !opening, model.openedLinks.isEmpty, model.offerDeviceUnlock == nil else { return nil }
        return model.received.first
    }

    func body(content: Content) -> some View {
        content
            .onChange(of: next, initial: true) { _, next in
                guard let next else { return }
                opening = true
                model.received.removeFirst()
                Task {
                    await open(next)
                    opening = false
                }
            }
            .sheet(item: Binding(get: { preview.map(ReceivedRoute.init) }, set: { if $0 == nil { preview = nil } })) { route in
                ReceivedSheet(received: route.preview) { preview = nil }
            }
    }

    private func open(_ next: ReceivedCredentials) async {
        do {
            let (json, from) = try await next.take()
            let received = try await model.vault.previewReceived(json: json, from: from)
            if received.items.isEmpty, received.codes == 0 {
                model.vault.discardReceived()
                model.toast = Toast(message: L10n.phone.receivedNothing(app: received.from), tone: .danger)
                Haptics.error()
            } else {
                preview = received
            }
        } catch {
            model.show(error)
        }
    }

    private struct ReceivedRoute: Identifiable {
        let preview: ReceivedPreview
        var id: String { preview.from }
    }
}

private struct ReceivedSheet: View {
    @Environment(AppModel.self) private var model
    let received: ReceivedPreview
    let onDone: () -> Void
    @State private var busy = false
    /// Shown here: a toast would be under the sheet.
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ForEach(ListScope.itemTypes.sorted { Self.order($0) < Self.order($1) }, id: \.self) { type in
                        if let count = received.items.first(where: { $0.itemType == type.name })?.count {
                            LabeledContent(type.categoryName, value: "\(count)")
                        }
                    }
                    if received.passkeys > 0 {
                        LabeledContent(L10n.categories.passkeys, value: "\(received.passkeys)")
                    }
                } footer: {
                    Text(L10n.phone.receivedBody)
                }
                let notes = [
                    received.updated + received.unchanged > 0 ? L10n.phone.receivedAgain(updated: "\(received.updated)", unchanged: "\(received.unchanged)") : nil,
                    received.codes > 0 ? L10n.phone.receivedCodes(count: Int(received.codes)) : nil,
                    received.skipped > 0 ? L10n.phone.receivedSkipped(count: Int(received.skipped)) : nil,
                ].compactMap { $0 } + received.warnings
                if !notes.isEmpty {
                    Section {
                        ForEach(notes, id: \.self) { Text($0).font(.footnote) }
                    }
                }
                if let error {
                    Section { Text(error).font(.footnote).foregroundStyle(Color.dangerText) }
                }
            }
            .navigationTitle(L10n.phone.receivedTitle(app: received.from))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.phone.receivedCancel) { model.vault.discardReceived(); onDone() }
                        .disabled(busy)
                        .accessibilityIdentifier("received-cancel")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.phone.receivedImport) { Task { await save() } }
                        .disabled(busy)
                        .accessibilityIdentifier("received-import")
                }
            }
            // Cancel or Import: nothing else forgets what was sent (locking does too).
            .interactiveDismissDisabled()
        }
    }

    /// In the order the item list shows them.
    static func order(_ type: ItemType) -> Int {
        [ItemType.login, .password, .wifi, .card, .identity, .secureNote, .sshKey, .document, .environment, .bankAccount, .idDocument, .cryptoWallet, .apiCredential, .database, .softwareLicense, .custom].firstIndex(of: type) ?? 99
    }

    private func save() async {
        busy = true
        do {
            let result = try await model.vault.importReceived()
            busy = false
            model.confirm(ImportView.summary(result))
            onDone()
        } catch {
            busy = false
            self.error = error.message
            Haptics.error()
        }
    }
}
