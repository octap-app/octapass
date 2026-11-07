import OctaPassResources
import OctaPassVault
import SwiftUI

/// Settings for a vault on this phone only (the web vault's `LocalSection`): backups, its
/// recovery code, Turn on sync, the other vaults. Each row keeps its own sheet: a modifier on a
/// `Section` lands on every row in it.
struct ThisDeviceSection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let vault = model.currentLocalVault {
            Section {
                NameRow(name: vault.name)
                BackUpRow(vault: vault)
                FolderRow(vault: vault)
                RecoveryCodeRow()
                Label(vault.chipBound ? L10n.localVault.chipOn : L10n.localVault.chipOff, systemImage: vault.chipBound ? "cpu" : "lock.shield")
                    .font(.footnote)
                    .foregroundStyle(Color.mist)
                    .accessibilityIdentifier("local-chip")
                Button { model.turningOnSync = true } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Label(L10n.localVault.turnOnSync, systemImage: "arrow.triangle.2.circlepath")
                        Text(L10n.localVault.turnOnSyncHelp).font(.footnote).foregroundStyle(Color.mist)
                    }
                }
                .accessibilityIdentifier("local-turn-on-sync")
                OtherVaults()
                Button { model.leaveLocalVault() } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Label(L10n.localVault.addVault, systemImage: "plus")
                        Text(L10n.localVault.addVaultHelp).font(.footnote).foregroundStyle(Color.mist)
                    }
                }
                .accessibilityIdentifier("local-add-vault")
                DeleteRow(name: vault.name)
            } header: {
                Text(L10n.localVault.sectionTitle)
            } footer: {
                Text(L10n.localVault.sectionHelp)
            }
        }
    }
}

private extension View {
    /// `ConfirmItsYou` in a sheet. The action runs after the sheet has gone, since it may need to
    /// present one of its own.
    func confirmingUser(isPresented: Binding<Bool>, onConfirmed: @escaping () -> Void) -> some View {
        modifier(ConfirmGate(isPresented: isPresented, onConfirmed: onConfirmed))
    }
}

private struct ConfirmGate: ViewModifier {
    @Binding var isPresented: Bool
    let onConfirmed: () -> Void
    @State private var confirmed = false

    func body(content: Content) -> some View {
        content.sheet(isPresented: $isPresented, onDismiss: finish) {
            ScrollView {
                ConfirmItsYou {
                    confirmed = true
                    isPresented = false
                }
                .padding(20)
            }
            .presentationDetents([.medium, .large])
        }
    }

    private func finish() {
        guard confirmed else { return }
        confirmed = false
        onConfirmed()
    }
}

private struct NameRow: View {
    let name: String
    @State private var renaming = false

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(L10n.localVault.nameLabel)
                Text(name).font(.footnote).foregroundStyle(Color.mist)
            }
            .accessibilityElement(children: .combine)
            Spacer()
            Button(L10n.localVault.rename) { renaming = true }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("local-rename")
        }
        .sheet(isPresented: $renaming) { RenameSheet(name: name) }
    }
}

private struct RenameSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State var name: String
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                TextInput(label: L10n.localVault.nameLabel, text: $name, hint: L10n.localVault.nameHint, error: error, capitalization: .sentences)
                    .accessibilityIdentifier("local-rename-name")
            }
            .navigationTitle(L10n.localVault.renameTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.common.save) { Task { await save() } }
                        .disabled(busy)
                        .accessibilityIdentifier("local-rename-save")
                }
            }
        }
        .presentationDetents([.medium])
        .interactiveDismissDisabled(busy)
    }

    private func save() async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            try await model.vault.renameLocalVault(name: name)
            dismiss()
        } catch {
            self.error = error.message
            Haptics.error()
        }
    }
}

private struct BackUpRow: View {
    @Environment(AppModel.self) private var model
    let vault: LocalVaultInfo
    @State private var confirming = false
    @State private var file: BackupFile?
    @State private var busy = false

    var body: some View {
        Button { confirming = true } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Label(L10n.localVault.backUp, systemImage: "square.and.arrow.up")
                    Text(vault.lastBackupAt.map { L10n.localVault.lastBackup(date: Dates.long($0)) } ?? L10n.localVault.neverBackedUp)
                        .font(.footnote)
                        .foregroundStyle(Color.mist)
                    Text(L10n.localVault.backUpHelp).font(.footnote).foregroundStyle(Color.mist)
                }
                if busy { Spacer(); ProgressView() }
            }
        }
        .disabled(busy)
        .accessibilityIdentifier("local-back-up")
        .confirmingUser(isPresented: $confirming) { Task { await backUp() } }
        .backupSheet(file: $file) { model.confirm(L10n.localVault.backedUp) }
    }

    private func backUp() async {
        busy = true
        defer { busy = false }
        do {
            file = try await model.exportBackup()
        } catch {
            model.show(error)
        }
    }
}

private struct FolderRow: View {
    @Environment(AppModel.self) private var model
    let vault: LocalVaultInfo
    @State private var choosing = false
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(L10n.localVault.folder)
                Text(vault.backupFolderName.map { L10n.localVault.folderOn(folder: $0) } ?? L10n.localVault.folderOff)
                    .font(.footnote)
                    .foregroundStyle(Color.mist)
            }
            .accessibilityElement(children: .combine)
            HStack(spacing: 16) {
                Button(vault.backupFolderName == nil ? L10n.localVault.chooseFolder : L10n.localVault.changeFolder) { choosing = true }
                    .buttonStyle(.borderless)
                    .accessibilityIdentifier("local-folder-choose")
                if vault.backupFolderName != nil {
                    Button(L10n.localVault.stopFolder) { Task { await turnOff() } }
                        .buttonStyle(.borderless)
                        .accessibilityIdentifier("local-folder-off")
                }
                if busy { Spacer(); ProgressView() }
            }
        }
        .disabled(busy)
        .backupFolderPicker(isPresented: $choosing) { url in Task { await choose(url) } }
    }

    private func choose(_ url: URL) async {
        busy = true
        defer { busy = false }
        do {
            try await model.useBackupFolder(url)
            model.confirm(L10n.localVault.folderChosen)
        } catch {
            model.show(error)
        }
    }

    private func turnOff() async {
        busy = true
        defer { busy = false }
        do {
            try await model.vault.setBackupFolder(folder: nil, name: nil)
            model.reloadLocalVaults()
        } catch {
            model.show(error)
        }
    }
}

private struct RecoveryCodeRow: View {
    @Environment(AppModel.self) private var model
    @State private var confirming = false
    @State private var code: String?

    var body: some View {
        VStack(alignment: .leading) {
            if let code {
                HStack(alignment: .top) {
                    LocalRecoveryCode(code: code)
                    Button { self.code = nil } label: { Image(systemName: "eye.slash") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(L10n.common.hideWhat(what: L10n.localVault.recoveryCode))
                }
            } else {
                Button { confirming = true } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Label(L10n.localVault.showCode, systemImage: "eye")
                        Text(L10n.localVault.showCodeHelp).font(.footnote).foregroundStyle(Color.mist)
                    }
                }
                .accessibilityIdentifier("local-show-code")
            }
        }
        .confirmingUser(isPresented: $confirming) {
            Task {
                do { code = try await model.vault.localRecoveryCode() } catch { model.show(error) }
            }
        }
        .onDisappear { code = nil }
    }
}

private struct OtherVaults: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let others = model.localVaults.filter { !$0.current }
        if !others.isEmpty {
            VStack(alignment: .leading, spacing: 2) {
                Text(L10n.localVault.otherVaults)
                Text(L10n.localVault.otherVaultsHelp).font(.footnote).foregroundStyle(Color.mist)
            }
            .accessibilityElement(children: .combine)
            ForEach(others, id: \.tag) { LocalVaultRow(vault: $0) }
        }
    }
}

private struct DeleteRow: View {
    let name: String
    @State private var deleting = false

    var body: some View {
        Button(role: .destructive) { deleting = true } label: {
            VStack(alignment: .leading, spacing: 2) {
                Label(L10n.localVault.deleteVault, systemImage: "trash")
                Text(L10n.localVault.deleteVaultHelp).font(.footnote).foregroundStyle(Color.mist)
            }
        }
        .accessibilityIdentifier("local-delete")
        .sheet(isPresented: $deleting) { DeleteVaultSheet(name: name) }
    }
}

private struct DeleteVaultSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let name: String
    @State private var password = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section { Text(L10n.localVault.deleteBody) }
                Section {
                    PasswordInput(label: L10n.fields.masterPassword, text: $password, error: error, content: .oneTimeCode)
                        .accessibilityIdentifier("local-delete-password")
                }
                Section {
                    Button(role: .destructive) {
                        Task { await delete() }
                    } label: {
                        HStack {
                            Text(L10n.localVault.deleteAction)
                            if busy { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(busy || password.isEmpty)
                    .accessibilityIdentifier("local-delete-confirm")
                }
            }
            .navigationTitle(L10n.localVault.deleteTitle(name: name))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() }.disabled(busy) }
            }
        }
        .interactiveDismissDisabled(busy)
    }

    private func delete() async {
        busy = true
        error = nil
        do {
            try await model.vault.deleteLocalVault(password: password)
            model.confirm(L10n.localVault.deleted)
        } catch {
            self.error = model.passwordMessage(error)
            password = ""
            busy = false
            Haptics.error()
        }
    }
}
