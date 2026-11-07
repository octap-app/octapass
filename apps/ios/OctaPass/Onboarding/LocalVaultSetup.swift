import OctaPassResources
import OctaPassVault
import SwiftUI
import UniformTypeIdentifiers

/// On the first screen, next to signing in (`LocalChoices` in the web vault): the vaults here, a
/// new one, or a backup.
struct LocalChoices: View {
    @Environment(AppModel.self) private var model
    let onCreate: () -> Void
    let onRestore: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !model.localVaults.isEmpty {
                LocalVaultList(heading: L10n.localVault.onThisDevice, vaults: model.localVaults)
            }
            SecondaryButton(title: L10n.localVault.useOnThisDevice, systemImage: "lock", action: onCreate)
                .accessibilityIdentifier("local-use-device")
            Text(L10n.localVault.useOnThisDeviceHelp)
                .font(.footnote)
                .foregroundStyle(Color.mist)
            Button(L10n.localVault.restoreBackup, action: onRestore)
                .frame(maxWidth: .infinity)
                .accessibilityIdentifier("local-restore")
        }
    }
}

/// Under the lock screen of a local vault: the others here, and the way back to the first screen.
struct LocalLockChoices: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let others = model.localVaults.filter { !$0.current }
        VStack(spacing: 16) {
            if !others.isEmpty {
                LocalVaultList(heading: L10n.localVault.otherVaults, vaults: others)
            }
            Button(L10n.localVault.addVault) { model.leaveLocalVault() }
                .accessibilityIdentifier("local-add-vault")
        }
    }
}

/// Local vaults as a card, for the screens outside a `List`.
struct LocalVaultList: View {
    let heading: String
    let vaults: [LocalVaultInfo]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(heading)
                .font(.subheadline.weight(.medium))
                .foregroundStyle(Color.ink)
                .accessibilityAddTraits(.isHeader)
            VStack(spacing: 0) {
                ForEach(Array(vaults.enumerated()), id: \.element.tag) { index, vault in
                    if index > 0 { Divider() }
                    LocalVaultRow(vault: vault).padding(.horizontal, 14)
                }
            }
            .background(Color.surface, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Color.line))
        }
    }
}

/// A vault and Open, as one button: VoiceOver reads which vault it opens. It opens locked.
struct LocalVaultRow: View {
    @Environment(AppModel.self) private var model
    let vault: LocalVaultInfo

    var body: some View {
        Button { model.openLocalVault(vault.tag) } label: {
            HStack(spacing: 12) {
                Text(vault.name)
                    .foregroundStyle(Color.ink)
                    .multilineTextAlignment(.leading)
                Spacer(minLength: 0)
                Text(L10n.localVault.open)
                    .fontWeight(.medium)
                    .foregroundStyle(Color.trustText)
            }
            .frame(minHeight: 44)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("local-open-\(vault.name)")
    }
}

private let setupSteps = 3

/// "Use on this device only" (the web vault's `CreateLocal`): a name and a master password, the
/// recovery code, then a first backup. Creating unlocks the vault, so `model.signingUp` keeps
/// these steps up until the user opens it, as sign-up does for the Recovery Kit.
struct CreateLocalView: View {
    @Environment(AppModel.self) private var model
    @State private var code: String?
    @State private var kept = false
    let onBack: () -> Void

    var body: some View {
        Group {
            if kept {
                FirstBackupStep { model.signingUp = false }
            } else if let code {
                LocalKitStep(code: code) { kept = true }
            } else {
                LocalPasswordStep(onBack: onBack) { code = $0 }
            }
        }
    }
}

private struct LocalPasswordStep: View {
    @Environment(AppModel.self) private var model
    let onBack: () -> Void
    let onCreated: (String) -> Void
    @State private var name = L10n.localVault.defaultName
    @State private var password = ""
    @State private var confirm = ""
    @State private var errors: [Field: String] = [:]
    @State private var formError: String?
    @State private var busy = false

    enum Field { case name, password, confirm }

    private var capabilities: LocalCapabilities { model.vault.localCapabilities() }

    var body: some View {
        AuthLayout(
            title: L10n.localVault.createTitle, subtitle: L10n.localVault.createSubtitle,
            top: AnyView(SignUpProgress(step: 0, total: setupSteps))
        ) {
            VStack(alignment: .leading, spacing: 16) {
                if let formError { Notice(text: formError) }
                TextInput(
                    label: L10n.localVault.nameLabel, text: $name, hint: L10n.localVault.nameHint, error: errors[.name],
                    capitalization: .sentences)
                    .accessibilityIdentifier("local-name")
                // No content type: see sign-up. A master password is never stored anywhere else.
                PasswordInput(label: L10n.fields.masterPassword, text: $password, error: errors[.password], content: nil)
                    .accessibilityIdentifier("local-password")
                PasswordStrength(password: password)
                    .padding(.top, -8)
                PasswordInput(label: L10n.fields.confirmPassword, text: $confirm, error: errors[.confirm], content: nil, onSubmit: submit)
                    .accessibilityIdentifier("local-confirm")
                Notice(
                    text: capabilities.chip ? "\(L10n.localVault.guidance) \(L10n.localVault.guidanceChip)" : L10n.localVault.guidance,
                    tone: .info)
                PrimaryButton(title: busy ? L10n.localVault.creating : L10n.localVault.create, busy: busy, action: submit)
                    .accessibilityIdentifier("local-create")
            }
        } footer: {
            Button(L10n.common.back, action: onBack).disabled(busy)
        }
    }

    private func submit() {
        var next: [Field: String] = [:]
        if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { next[.name] = L10n.errors.invalidName }
        if model.vault.estimateStrength(password: password).score < capabilities.minScore {
            next[.password] = password.isEmpty ? L10n.validation.passwordRequired : L10n.localVault.weak
        }
        if confirm != password { next[.confirm] = L10n.validation.passwordsDontMatch }
        errors = next
        formError = nil
        guard next.isEmpty, !busy else { return Haptics.error() }
        busy = true
        let name = name, password = password
        Task {
            do {
                model.signingUp = true
                model.willSignIn()
                let created = try await model.vault.createLocalVault(name: name, password: password)
                model.unlockWasConfirmed()
                onCreated(created)
            } catch {
                model.signingUp = false
                busy = false
                formError = error.message
                Haptics.error()
            }
        }
    }
}

/// The backup recovery code. Digits and letters in groups read left to right in any language.
struct LocalRecoveryCode: View {
    let code: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(L10n.localVault.recoveryCode).font(.caption.weight(.medium)).foregroundStyle(Color.mist)
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text(code)
                    .font(.secret(.callout))
                    .foregroundStyle(Color.ink)
                    .textSelection(.enabled)
                    .environment(\.layoutDirection, .leftToRight)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityIdentifier("local-recovery-code")
                CopyButton(value: code, what: L10n.localVault.recoveryCode, secret: true)
            }
        }
    }
}

private struct LocalKitStep: View {
    let code: String
    let onDone: () -> Void
    @State private var saved = false

    var body: some View {
        AuthLayout(
            title: L10n.localVault.kitTitle, subtitle: L10n.localVault.kitSubtitle,
            top: AnyView(SignUpProgress(step: 1, total: setupSteps))
        ) {
            VStack(alignment: .leading, spacing: 16) {
                LocalRecoveryCode(code: code)
                    .padding(18)
                    .background(Color.surface, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Color.line))
                Toggle(L10n.localVault.kitConfirm, isOn: $saved)
                    .toggleStyle(CheckboxToggleStyle())
                    .accessibilityIdentifier("local-kit-saved")
                PrimaryButton(title: L10n.localVault.kitContinue, disabled: !saved, action: onDone)
                    .accessibilityIdentifier("local-kit-continue")
            }
        }
    }
}

/// Asked once, when the vault is new (plan 01): a file now, a folder for automatic backups, or later.
private struct FirstBackupStep: View {
    @Environment(AppModel.self) private var model
    let onDone: () -> Void
    @State private var file: BackupFile?
    @State private var choosing = false
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        AuthLayout(
            title: L10n.localVault.firstBackupTitle, subtitle: L10n.localVault.firstBackupSubtitle,
            top: AnyView(SignUpProgress(step: 2, total: setupSteps))
        ) {
            VStack(alignment: .leading, spacing: 16) {
                if let error { Notice(text: error) }
                PrimaryButton(title: L10n.localVault.backUp, systemImage: "square.and.arrow.up", busy: busy) {
                    Task { await backUp() }
                }
                .accessibilityIdentifier("local-first-backup")
                SecondaryButton(title: L10n.localVault.chooseFolder, systemImage: "folder", disabled: busy) { choosing = true }
                    .accessibilityIdentifier("local-first-folder")
                Button(L10n.localVault.firstBackupLater, action: onDone)
                    .disabled(busy)
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("local-first-backup-later")
            }
        }
        .backupSheet(file: $file) {
            model.confirm(L10n.localVault.backedUp)
            onDone()
        }
        .backupFolderPicker(isPresented: $choosing) { url in Task { await chooseFolder(url) } }
    }

    private func backUp() async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            file = try await model.exportBackup()
        } catch {
            self.error = error.message
            Haptics.error()
        }
    }

    private func chooseFolder(_ url: URL) async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            try await model.useBackupFolder(url)
            model.confirm(L10n.localVault.folderChosen)
            onDone()
        } catch {
            self.error = error.message
            Haptics.error()
        }
    }
}

/// Opens a `.octapass-backup` file as a new vault here (the web vault's `RestoreBackup`), with its
/// master password, or with the recovery code and a new one. The copy of the file stays while
/// the form does, so a mistyped password doesn't mean picking it again.
struct RestoreBackupView: View {
    @Environment(AppModel.self) private var model
    let onBack: () -> Void
    @State private var file: PickedFile?
    @State private var choosing = false
    @State private var secret = Secret.password
    @State private var password = ""
    @State private var code = ""
    @State private var newPassword = ""
    @State private var passwordError: String?
    @State private var formError: String?
    @State private var busy = false

    enum Secret { case password, code }

    var body: some View {
        AuthLayout(title: L10n.localVault.restoreTitle, subtitle: L10n.localVault.restoreSubtitle) {
            VStack(alignment: .leading, spacing: 16) {
                if let formError { Notice(text: formError) }
                SecondaryButton(title: file?.name ?? L10n.localVault.backupFile, systemImage: "doc", disabled: busy) { choosing = true }
                    .accessibilityIdentifier("restore-file")
                Picker(L10n.localVault.restoreTitle, selection: $secret) {
                    Text(L10n.localVault.withPassword).tag(Secret.password)
                    Text(L10n.localVault.withCode).tag(Secret.code)
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("restore-secret")
                if secret == .password {
                    PasswordInput(label: L10n.localVault.backupPassword, text: $password, error: passwordError, onSubmit: submit)
                        .accessibilityIdentifier("restore-password")
                } else {
                    TextInput(label: L10n.localVault.recoveryCode, text: $code, mono: true, capitalization: .characters)
                        .accessibilityIdentifier("restore-code")
                    PasswordInput(label: L10n.localVault.newPassword, text: $newPassword, error: passwordError, content: nil, onSubmit: submit)
                        .accessibilityIdentifier("restore-new-password")
                    PasswordStrength(password: newPassword)
                        .padding(.top, -8)
                }
                PrimaryButton(title: L10n.localVault.restore, busy: busy, action: submit)
                    .accessibilityIdentifier("restore-submit")
            }
        } footer: {
            Button(L10n.common.back, action: onBack).disabled(busy)
        }
        .filePicker(isPresented: $choosing, types: [.data]) { urls in
            if let url = urls.first { pick(url) }
        }
        .onChange(of: secret) { passwordError = nil }
        .onDisappear { if let file { PickedFiles.discard(file) } }
    }

    private func pick(_ url: URL) {
        if let file { PickedFiles.discard(file) }
        formError = nil
        do {
            file = try PickedFiles.copy(url)
        } catch {
            file = nil
            formError = error.message
        }
    }

    /// What opens the file, once it's all there.
    private func key() -> BackupKey? {
        switch secret {
        case .password:
            if password.isEmpty { passwordError = L10n.validation.passwordRequired }
            return password.isEmpty ? nil : BackupKey.password(password: password)
        case .code:
            let typed = code.trimmingCharacters(in: .whitespacesAndNewlines)
            if typed.isEmpty {
                formError = L10n.localVault.restoreFailed
                return nil
            }
            guard model.vault.estimateStrength(password: newPassword).score >= model.vault.localCapabilities().minScore else {
                passwordError = newPassword.isEmpty ? L10n.validation.passwordRequired : L10n.localVault.weak
                return nil
            }
            return BackupKey.recoveryCode(code: typed, newPassword: newPassword)
        }
    }

    private func submit() {
        passwordError = nil
        formError = nil
        guard !busy else { return }
        guard let file else {
            formError = L10n.localVault.restoreFailed
            return Haptics.error()
        }
        guard let key = key() else { return Haptics.error() }
        busy = true
        Task {
            do {
                model.willSignIn()
                try await model.vault.restoreLocalVault(path: file.url.path, key: key)
                model.unlockWasConfirmed()
            } catch {
                formError = error.message
                busy = false
                Haptics.error()
            }
        }
    }
}
