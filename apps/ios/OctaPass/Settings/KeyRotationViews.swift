import OctaPassResources
import OctaPassVault
import SwiftUI

/// Settings → Replace Secret Key (`RotateSecretKey`): the master password, then the new Recovery
/// Kit, which `RootView` shows over everything until the user has saved it.
struct RotateSecretKeyView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var newRecoveryCode = false
    @State private var passwordError: String?
    @State private var formError: String?
    @State private var busy = false

    var body: some View {
        Form {
            Section {
                Text(L10n.rotateSecretKey.intro).foregroundStyle(Color.mist)
            }
            Section {
                PasswordInput(label: L10n.fields.masterPassword, text: $password, error: passwordError, content: .oneTimeCode)
                    .accessibilityIdentifier("rotate-password")
                Toggle(L10n.rotateSecretKey.newRecoveryCode, isOn: $newRecoveryCode)
                    .accessibilityIdentifier("rotate-recovery-code")
            }
            Section {
                Button {
                    Task { await submit() }
                } label: {
                    HStack {
                        Text(L10n.rotateSecretKey.submit)
                        if busy { Spacer(); ProgressView() }
                    }
                }
                .disabled(busy)
                .accessibilityIdentifier("rotate-submit")
            } footer: {
                Text(L10n.rotateSecretKey.signsOut)
            }
            if let formError {
                Section { Notice(text: formError) }
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
            }
        }
        .navigationTitle(L10n.rotateSecretKey.title)
        .navigationBarTitleDisplayMode(.inline)
    }

    private func submit() async {
        formError = nil
        passwordError = password.isEmpty ? L10n.validation.passwordRequired : nil
        guard passwordError == nil, !busy else {
            Haptics.error()
            return
        }
        busy = true
        defer {
            busy = false
            password = ""
        }
        do {
            let kit = try await model.vault.rotateSecretKey(password: password, newRecoveryCode: newRecoveryCode)
            model.newKit = PendingRecoveryKit(
                kit: kit, title: L10n.rotateSecretKey.kitTitle, message: L10n.rotateSecretKey.kitBody,
                done: L10n.rotateSecretKey.done)
            Haptics.success()
            dismiss()
        } catch {
            Haptics.error()
            if error.isVault(.invalidCredentials) {
                passwordError = L10n.changePassword.wrongCurrent
            } else {
                formError = error.message
            }
        }
    }
}

/// Settings → Vault keys (`VaultKeysRow`): a new key for a vault this account owns or manages.
struct VaultKeysView: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    @State private var confirming: Vault?
    @State private var rotating: String?

    private var vaults: [Vault] {
        directory.vaults.filter { ($0.role == .owner || $0.role == .manage) && !$0.untrusted }
    }

    var body: some View {
        List {
            Section { Text(L10n.vaultKeys.intro).font(.subheadline).foregroundStyle(Color.mist) }
            Section { Notice(text: L10n.vaultKeys.limits, tone: .info) }
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets())
            Section {
                ForEach(vaults, id: \.id) { vault in
                    HStack {
                        Label(vault.name, systemImage: vault.icon)
                        Spacer()
                        if rotating == vault.id {
                            ProgressView()
                        } else {
                            Button(L10n.vaultKeys.rotate) { confirming = vault }
                                .buttonStyle(.bordered)
                                .disabled(rotating != nil)
                                .accessibilityLabel("\(L10n.vaultKeys.rotate): \(vault.name)")
                                .accessibilityIdentifier("vault-key-rotate")
                        }
                    }
                }
            }
        }
        .navigationTitle(L10n.vaultKeys.title)
        .confirmationDialog(
            confirming.map { L10n.vaultKeys.confirmTitle(vault: $0.name) } ?? "",
            isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
            titleVisibility: .visible
        ) {
            Button(L10n.vaultKeys.rotate) {
                guard let vault = confirming else { return }
                Task { await rotate(vault) }
            }
        } message: {
            Text(L10n.vaultKeys.confirmBody)
        }
    }

    private func rotate(_ vault: Vault) async {
        // Key rotation asks every time, however the vault was unlocked (plan 18).
        guard await model.confirmIdentity() else { return }
        rotating = vault.id
        defer { rotating = nil }
        do {
            try await model.vault.rotateVaultKey(vaultId: vault.id)
            model.confirm(L10n.vaultKeys.done(vault: vault.name))
        } catch { model.show(error) }
    }
}
