import OctaPassResources
import OctaPassVault
import SwiftUI

/// Turn on sync (the web vault's `TurnOnSync`): sign-up's steps, but the vault keeps its keys and
/// items and moves into the new account. Shown over the vault by `RootView`, so the Recovery Kit
/// stays up while the session becomes the account's underneath.
struct TurnOnSyncView: View {
    @Environment(AppModel.self) private var model
    @State private var started: SignUpView.Started?
    @State private var kit: RecoveryKit?
    @State private var finishing = false

    /// Reading the email code in Mail can lock the vault. The lock screen shows through, and the
    /// steps are still here once it's unlocked.
    private var waitingForUnlock: Bool { kit == nil && !finishing && !model.isUnlocked }

    var body: some View {
        Group {
            if let kit {
                SyncKitStep(kit: kit) { model.turningOnSync = false }
            } else if let started {
                SyncCodeStep(started: started, finish: finish) { self.started = nil }
            } else {
                SyncAccountStep { started = $0 }
            }
        }
        .opacity(waitingForUnlock ? 0 : 1)
        .allowsHitTesting(!waitingForUnlock)
        .accessibilityHidden(waitingForUnlock)
        // Another vault opened from the lock screen, or Add a vault: this one's steps are over.
        .onChange(of: model.currentLocalVault?.tag) {
            if kit == nil, !finishing { model.turningOnSync = false }
        }
    }

    private func finish(_ code: String) async throws {
        guard let started else { return }
        finishing = true
        defer { finishing = false }
        kit = try await model.vault.finishTurnOnSync(signupId: started.id, verificationCode: code)
        // The same unlock, now an account's: the new master password was just typed.
        model.unlockWasConfirmed()
        // The local vault went without a session change of its own.
        model.reloadLocalVaults()
    }
}

private let syncSteps = 3

private struct SyncAccountStep: View {
    @Environment(AppModel.self) private var model
    let onDone: (SignUpView.Started) -> Void
    @State private var email = ""
    @State private var password = ""
    @State private var confirm = ""
    @State private var server = ServerChoice()
    @State private var errors: [Field: String] = [:]
    @State private var formError: String?
    @State private var busy = false

    enum Field { case email, password, confirm, server }

    var body: some View {
        AuthLayout(
            title: L10n.localVault.syncTitle, subtitle: L10n.localVault.syncSubtitle,
            top: AnyView(SignUpProgress(step: 0, total: syncSteps))
        ) {
            VStack(alignment: .leading, spacing: 16) {
                if let formError { Notice(text: formError) }
                TextInput(label: L10n.fields.email, text: $email, error: errors[.email], content: .emailAddress, keyboard: .emailAddress)
                    .accessibilityIdentifier("sync-email")
                // No content type: see sign-up. A master password is never stored anywhere else.
                PasswordInput(label: L10n.fields.masterPassword, text: $password, error: errors[.password], content: nil)
                    .accessibilityIdentifier("sync-password")
                PasswordStrength(password: password)
                    .padding(.top, -8)
                PasswordInput(label: L10n.fields.confirmPassword, text: $confirm, error: errors[.confirm], content: nil, onSubmit: submit)
                    .accessibilityIdentifier("sync-confirm")
                Notice(text: L10n.signUp.guidance, tone: .info)
                ServerPicker(choice: $server, error: errors[.server])
                PrimaryButton(title: L10n.signUp.continue, busy: busy, action: submit)
                    .accessibilityIdentifier("sync-continue")
            }
        } footer: {
            Button(L10n.common.cancel) { model.turningOnSync = false }
                .disabled(busy)
                .accessibilityIdentifier("sync-cancel")
        }
    }

    private func submit() {
        var next: [Field: String] = [:]
        if !isValidEmail(email: normalizeEmail(email: email)) { next[.email] = L10n.validation.email }
        if model.vault.estimateStrength(password: password).score < minimumScore {
            next[.password] = password.isEmpty ? L10n.validation.passwordRequired : L10n.validation.passwordTooWeak
        }
        if confirm != password { next[.confirm] = L10n.validation.passwordsDontMatch }
        errors = next
        formError = nil
        guard next.isEmpty, !busy else { return Haptics.error() }
        busy = true
        let url = server.serverUrl(hosted: model.defaultServerUrl)
        let email = email, password = password, selfHosted = server.selfHosted
        Task {
            defer { busy = false }
            do {
                let info = try await model.vault.serverInfo(serverUrl: url)
                if info.signups == .closed { throw VaultError.Failed(code: .signupsClosed, reason: "") }
                let started = try await model.vault.startTurnOnSync(serverUrl: url, email: email, password: password)
                onDone(.init(id: started.signupId, email: normalizeEmail(email: email), devCode: started.devVerificationCode))
            } catch {
                if selfHosted, error.isVault(.insecureServerUrl) || error.isVault(.serverUnreachable) {
                    errors[.server] = error.message
                } else {
                    formError = error.message
                }
                Haptics.error()
            }
        }
    }
}

private struct SyncCodeStep: View {
    let started: SignUpView.Started
    let finish: (String) async throws -> Void
    let onBack: () -> Void
    @State private var code = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        AuthLayout(
            title: L10n.verify.title, subtitle: L10n.verify.subtitle(email: started.email),
            top: AnyView(SignUpProgress(step: 1, total: syncSteps))
        ) {
            VStack(alignment: .leading, spacing: 16) {
                if let devCode = started.devCode {
                    Notice(text: "\(L10n.verify.devCode) \(devCode)", tone: .info)
                        .accessibilityIdentifier("dev-code")
                }
                TextInput(label: L10n.verify.codeLabel, text: $code, error: error, content: .oneTimeCode, keyboard: .numberPad, mono: true)
                    .accessibilityIdentifier("verification-code")
                    .onChange(of: code) { _, new in
                        let kept = String(new.filter { $0.isASCIIDigit || $0 == " " }.prefix(7))
                        if kept != new { code = kept }
                    }
                PrimaryButton(title: L10n.verify.submit, busy: busy, action: submit)
                    .accessibilityIdentifier("verify")
                Button(L10n.verify.changeEmail, action: onBack)
                    .disabled(busy)
                    .frame(maxWidth: .infinity)
            }
        }
    }

    private func submit() {
        let digits = code.filter { !$0.isWhitespace }
        guard digits.count == 6 else {
            error = L10n.validation.code
            return Haptics.error()
        }
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                try await finish(digits)
            } catch {
                self.error = error.message
                Haptics.error()
            }
        }
    }
}

private struct SyncKitStep: View {
    let kit: RecoveryKit
    let onDone: () -> Void
    @State private var saved = false

    var body: some View {
        AuthLayout(
            title: L10n.localVault.syncDoneTitle, subtitle: "\(L10n.localVault.syncDoneSubtitle) \(L10n.kit.subtitle)",
            top: AnyView(SignUpProgress(step: 2, total: syncSteps))
        ) {
            VStack(alignment: .leading, spacing: 16) {
                RecoveryKitCard(kit: kit)
                RecoveryKitActions(kit: kit)
                Toggle(L10n.kit.confirm, isOn: $saved)
                    .toggleStyle(CheckboxToggleStyle())
                    .accessibilityIdentifier("kit-saved")
                PrimaryButton(title: L10n.kit.continue, disabled: !saved, action: onDone)
                    .accessibilityIdentifier("kit-continue")
            }
        }
    }
}
