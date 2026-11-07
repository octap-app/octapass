import OctaPassResources
import OctaPassVault
import SwiftUI

/// "Forgot your master password?": the emailed code, the recovery code from the Recovery Kit, a
/// new master password, and the new kit (`Reset` in the web vault). Works signed out and locked.
struct PasswordResetView: View {
    @Environment(AppModel.self) private var model
    @State private var step = Step.email
    @State private var email = ""
    @State private var code = ""
    @State private var recoveryCode = ""
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var resetId: String?
    @State private var kit: RecoveryKit?
    @State private var fieldError: String?
    @State private var formError: String?
    @State private var busy = false

    private enum Step { case email, code, password, kit }

    var body: some View {
        NavigationStack {
            Form {
                if let formError {
                    Section { Notice(text: formError) }
                        .listRowBackground(Color.clear)
                        .listRowInsets(EdgeInsets())
                }
                switch step {
                case .email: emailStep
                case .code: codeStep
                case .password: passwordStep
                case .kit: kitStep
                }
            }
            .navigationTitle(L10n.reset.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if step != .kit {
                        Button(L10n.common.cancel) { close() }.disabled(busy)
                    }
                }
            }
        }
        .onAppear {
            if email.isEmpty {
                email = model.session.email ?? model.session.rememberedAccounts.first?.email ?? ""
            }
        }
    }

    private var emailStep: some View {
        Group {
            Section {
                Text(L10n.reset.subtitle).foregroundStyle(Color.mist)
                Text(L10n.reset.needs).font(.footnote).foregroundStyle(Color.mist)
            }
            Section {
                TextField(L10n.fields.email, text: $email)
                    .keyboardType(.emailAddress)
                    .textContentType(.username)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("reset-email")
            }
            Section {
                Button {
                    Task { await sendCode() }
                } label: {
                    HStack {
                        Text(L10n.reset.sendCode)
                        if busy { Spacer(); ProgressView() }
                    }
                }
                .disabled(busy)
                .accessibilityIdentifier("reset-send-code")
            } footer: {
                Button(L10n.reset.remembered) { close() }
                    .disabled(busy)
                    .accessibilityIdentifier("reset-back")
            }
        }
    }

    private var codeStep: some View {
        Group {
            Section {
                Text(L10n.reset.codeSent(email: email)).foregroundStyle(Color.mist)
                TextField(L10n.verify.codeLabel, text: $code)
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                    .accessibilityIdentifier("reset-code")
                if let fieldError { fieldErrorText(fieldError) }
            }
            Section {
                Button {
                    Task { await verify() }
                } label: {
                    HStack {
                        Text(L10n.reset.verify)
                        if busy { Spacer(); ProgressView() }
                    }
                }
                .disabled(busy)
                .accessibilityIdentifier("reset-verify")
            } footer: {
                Button(L10n.twoStep.startOver) { startOver() }
                    .disabled(busy)
                    .accessibilityIdentifier("reset-start-over")
            }
        }
    }

    private var passwordStep: some View {
        Group {
            Section {
                Text(L10n.reset.passwordSubtitle).foregroundStyle(Color.mist)
                TextField(L10n.twoStep.recoveryLabel, text: $recoveryCode, axis: .vertical)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .font(.secret(.body))
                    .accessibilityIdentifier("reset-recovery-code")
                Text(L10n.reset.recoveryCodeHint).font(.footnote).foregroundStyle(Color.mist)
                if let fieldError { fieldErrorText(fieldError) }
            }
            Section {
                PasswordInput(label: L10n.reset.newPassword, text: $password, content: .oneTimeCode)
                    .accessibilityIdentifier("reset-new-password")
                PasswordStrength(password: password)
                PasswordInput(label: L10n.fields.confirmPassword, text: $confirmPassword, content: .oneTimeCode)
                    .accessibilityIdentifier("reset-confirm-password")
            }
            Section {
                Button {
                    Task { await finish() }
                } label: {
                    HStack {
                        Text(L10n.reset.submit)
                        if busy { Spacer(); ProgressView() }
                    }
                }
                .disabled(busy)
                .accessibilityIdentifier("reset-submit")
            } footer: {
                Text(L10n.reset.signsOut)
            }
        }
    }

    @ViewBuilder
    private var kitStep: some View {
        if let kit {
            Section {
                Text(L10n.reset.kitTitle).font(.headline)
                Text(L10n.reset.kitSubtitle).font(.footnote).foregroundStyle(Color.mist)
                RecoveryKitCard(kit: kit)
                    .listRowInsets(EdgeInsets())
            }
            Section {
                RecoveryKitActions(kit: kit)
            }
            Section {
                Button { done() } label: {
                    Text(L10n.reset.kitConfirm).frame(maxWidth: .infinity)
                }
                .accessibilityIdentifier("reset-kit-confirm")
            }
        }
    }

    private func fieldErrorText(_ text: String) -> some View {
        Text(text).font(.footnote).foregroundStyle(Color.dangerText)
    }

    private func sendCode() async {
        formError = nil
        fieldError = nil
        let address = email.trimmingCharacters(in: .whitespaces)
        guard !address.isEmpty else {
            fieldError = L10n.validation.email
            return Haptics.error()
        }
        busy = true
        defer { busy = false }
        do {
            let normalized = normalizeEmail(email: address)
            let serverUrl = model.resetServerUrl
                ?? model.session.serverUrl
                ?? model.session.rememberedAccounts.first { $0.email == normalized }?.serverUrl
                ?? model.defaultServerUrl
            let started = try await model.vault.startPasswordReset(
                serverUrl: serverUrl, email: address)
            resetId = started.resetId
            email = address
            #if DEBUG
            if let dev = started.devVerificationCode { code = dev }
            #endif
            step = .code
            Haptics.success()
        } catch {
            Haptics.error()
            formError = error.message
        }
    }

    private func verify() async {
        guard let resetId else { return }
        formError = nil
        fieldError = nil
        let typed = code.filter(\.isNumber)
        guard typed.count == 6 else {
            fieldError = L10n.validation.code
            return Haptics.error()
        }
        busy = true
        defer { busy = false }
        do {
            try await model.vault.verifyPasswordReset(resetId: resetId, verificationCode: typed)
            step = .password
        } catch {
            Haptics.error()
            if error.isVault(.invalidVerificationCode) {
                fieldError = error.message
            } else if error.isVault(.resetExpired) {
                startOver()
                formError = error.message
            } else {
                formError = error.message
            }
        }
    }

    private func finish() async {
        guard let resetId else { return }
        formError = nil
        fieldError = nil
        if recoveryCode.trimmingCharacters(in: .whitespaces).isEmpty {
            fieldError = L10n.reset.recoveryCodeRequired
            return Haptics.error()
        }
        guard !password.isEmpty else {
            fieldError = L10n.validation.passwordRequired
            return Haptics.error()
        }
        guard model.vault.estimateStrength(password: password).score >= minimumScore else {
            fieldError = L10n.validation.passwordTooWeak
            return Haptics.error()
        }
        guard password == confirmPassword else {
            fieldError = L10n.validation.passwordsDontMatch
            return Haptics.error()
        }
        busy = true
        defer { busy = false }
        do {
            let result = try await model.vault.finishPasswordReset(
                resetId: resetId, recoveryCode: recoveryCode, password: password)
            kit = result.recoveryKit
            // Signed in with the new password, unless a second step is still to come.
            model.unlockWasConfirmed()
            // A second step is asked when signing in again, with the new password.
            if case .twoStepRequired? = result.signIn { model.vault.cancelTwoStep() }
            step = .kit
            Haptics.success()
        } catch {
            Haptics.error()
            if error.isVault(.invalidRecoveryCode) {
                fieldError = error.message
            } else if error.isVault(.resetExpired) {
                startOver()
                formError = error.message
            } else {
                formError = error.message
            }
        }
    }

    private func startOver() {
        if let resetId { model.vault.cancelPasswordReset(resetId: resetId) }
        resetId = nil
        code = ""
        recoveryCode = ""
        password = ""
        confirmPassword = ""
        fieldError = nil
        formError = nil
        step = .email
    }

    private func close() {
        model.resettingPassword = false
    }

    private func done() {
        kit = nil
        close()
    }
}
