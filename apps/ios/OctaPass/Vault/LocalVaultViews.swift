import OctaPassResources
import OctaPassVault
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
import UniformTypeIdentifiers

extension AppModel {
    /// Makes another local vault current. Its lock screen comes next.
    func openLocalVault(_ tag: String) {
        Task {
            do { try await vault.switchLocalVault(tag: tag) } catch { show(error) }
        }
    }

    /// Back to the first screen. Nothing is deleted.
    func leaveLocalVault() {
        Task {
            do { try await vault.leaveLocalVault() } catch { show(error) }
        }
    }

    /// A backup file for the share sheet (`backupSheet`).
    func exportBackup() async throws -> BackupFile {
        BackupFile(path: try await vault.exportLocalBackup())
    }

    /// Automatic backups into a folder the picker returned, and the first one now.
    func useBackupFolder(_ url: URL) async throws {
        defer { reloadLocalVaults() }
        try await vault.setBackupFolder(folder: BackupFolder.reference(for: url), name: url.lastPathComponent)
    }

    /// A wrong master password. The catalog's `invalidCredentials` names an email and a Secret
    /// Key, which a local vault doesn't have.
    func passwordMessage(_ error: Error) -> String {
        isLocal && error.isVault(.invalidCredentials) ? L10n.identityGate.wrongPassword : error.message
    }
}

/// A backup the vault wrote to the app's own storage, on its way out through the share sheet.
struct BackupFile: Identifiable {
    let path: String
    var id: String { path }
}

extension View {
    /// The share sheet for a backup. `onShared` runs after the sheet has gone, and only when the
    /// file went somewhere; the file itself is deleted either way.
    func backupSheet(file: Binding<BackupFile?>, onShared: @escaping () -> Void) -> some View {
        modifier(BackupSheet(file: file, onShared: onShared))
    }

    /// The Files picker for the folder automatic backups go to.
    func backupFolderPicker(isPresented: Binding<Bool>, onPick: @escaping (URL) -> Void) -> some View {
        fileImporter(isPresented: isPresented, allowedContentTypes: [.folder]) { result in
            if case let .success(url) = result { onPick(url) }
        }
    }
}

private struct BackupSheet: ViewModifier {
    @Environment(AppModel.self) private var model
    @Binding var file: BackupFile?
    let onShared: () -> Void
    @State private var shared = false

    func body(content: Content) -> some View {
        content.sheet(item: $file, onDismiss: finish) { file in
            ShareSheet(url: URL(fileURLWithPath: file.path)) { completed in
                shared = completed
                self.file = nil
            }
            .presentationDetents([.medium, .large])
            .ignoresSafeArea()
            .onDisappear {
                model.vault.closeAttachment(path: file.path)
            }
        }
    }

    private func finish() {
        guard shared else { return }
        shared = false
        // Only now: a cancelled share is no backup.
        Task {
            try? await model.vault.localBackupSaved()
            model.reloadLocalVaults()
        }
        onShared()
    }
}

#if os(iOS)
/// The system's share sheet, which reports when it's done (`ShareLink` doesn't).
private struct ShareSheet: UIViewControllerRepresentable {
    let url: URL
    let onFinish: (Bool) -> Void

    func makeUIViewController(context: Context) -> UIActivityViewController {
        let controller = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        controller.completionWithItemsHandler = { activity, completed, _, _ in
            // Cancelling Save to Files leaves the share sheet up: it isn't over yet.
            if completed || activity == nil { onFinish(completed) }
        }
        return controller
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
#else
/// On the Mac a backup is saved where the user picks, with the save panel.
private struct ShareSheet: View {
    let url: URL
    let onFinish: (Bool) -> Void

    var body: some View {
        Color.clear
            .frame(width: 1, height: 1)
            .task { onFinish(await MacFiles.save(url)) }
    }
}
#endif

/// What only an account can do. A local vault shows `NeedsSyncView` in its place, never a dead end.
struct AccountOnly<Content: View>: View {
    @Environment(AppModel.self) private var model
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        if model.isLocal {
            NeedsSyncView().navigationTitle(title)
        } else {
            content()
        }
    }
}

struct NeedsSyncView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        EmptyStateView(icon: "arrow.triangle.2.circlepath", title: L10n.localVault.needsSync, message: L10n.localVault.needsSyncBody) {
            Button { model.turningOnSync = true } label: {
                Label(L10n.localVault.turnOnSync, systemImage: "arrow.triangle.2.circlepath")
            }
            .buttonStyle(.borderedProminent)
            .tint(.button)
            .accessibilityIdentifier("needs-sync-turn-on")
        }
    }
}

/// Every 30 days (plan 01), unless a folder takes care of it. It goes away with the next backup.
struct BackupReminder: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if model.isLocal, let vault = model.currentLocalVault, vault.backupDue {
            NavigationLink(value: Route.settings) {
                Notice(text: Self.text(vault), tone: .warn)
            }
            .listRowSeparator(.hidden)
            .accessibilityIdentifier("backup-reminder")
        }
    }

    private static func text(_ vault: LocalVaultInfo) -> String {
        guard let last = vault.lastBackupAt, let date = Dates.parse(last) else { return L10n.localVault.reminderNever }
        return L10n.localVault.reminder(count: Int(Date().timeIntervalSince(date) / 86_400))
    }
}
