import OctaPassResources
import OctaPassVault
import SwiftUI

/// Create an account (the web vault's `SignUp`): the account, the email code, the Recovery Kit,
/// done. The vault is signed in after the code, but these screens stay until the user opens it.
struct SignUpView: View {
    @Environment(AppModel.self) private var model
    @State private var step = Step.account
    @State private var started: Started?
    @State private var kit: RecoveryKit?
    let onSignIn: () -> Void

    enum Step: Int { case account, verify, kit, done }

    struct Started {
        let id: String
        let email: String
        let devCode: String?
    }

    var body: some View {
        Group {
            switch step {
            case .account:
                AccountStep(onSignIn: onSignIn) { started in
                    self.started = started
                    step = .verify
                }
            case .verify:
                if let started {
                    VerifyStep(started: started, onBack: { step = .account }) { kit in
                        self.kit = kit
                        step = .kit
                    }
                }
            case .kit:
                if let kit {
                    KitStep(kit: kit) { step = .done }
                }
            case .done:
                DoneStep { model.signingUp = false }
            }
        }
        .animation(.default, value: step)
    }
}

private let totalSteps = 4
/// A master password must be at least "strong": the Secret Key protects the server's copy, this
/// protects the phone's.
let minimumScore: UInt8 = 3

private struct AccountStep: View {
    @Environment(AppModel.self) private var model
    let onSignIn: () -> Void
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
            title: L10n.signUp.title, subtitle: L10n.signUp.subtitle,
            top: AnyView(SignUpProgress(step: 0, total: totalSteps))
        ) {
            VStack(alignment: .leading, spacing: 16) {
                if let formError { Notice(text: formError) }
                TextInput(label: L10n.fields.email, text: $email, error: errors[.email], content: .emailAddress, keyboard: .emailAddress)
                    .accessibilityIdentifier("signup-email")
                // No content type: iOS would offer a random strong password or to save this one,
                // and a master password is one the user remembers, never stored anywhere else.
                PasswordInput(label: L10n.fields.masterPassword, text: $password, error: errors[.password], content: nil)
                    .accessibilityIdentifier("signup-password")
                PasswordStrength(password: password)
                    .padding(.top, -8)
                PasswordInput(label: L10n.fields.confirmPassword, text: $confirm, error: errors[.confirm], content: nil, onSubmit: submit)
                    .accessibilityIdentifier("confirm-password")
                Notice(text: L10n.signUp.guidance, tone: .info)
                ServerPicker(choice: $server, error: errors[.server])
                PrimaryButton(title: L10n.signUp.continue, busy: busy, action: submit)
                    .accessibilityIdentifier("continue")
            }
        } footer: {
            HStack(spacing: 4) {
                Text(L10n.signUp.haveAccount).foregroundStyle(Color.mist)
                Button(L10n.signUp.signIn, action: onSignIn)
            }
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
                let started = try await model.vault.startSignup(serverUrl: url, email: email, password: password)
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

private struct VerifyStep: View {
    @Environment(AppModel.self) private var model
    let started: SignUpView.Started
    let onBack: () -> Void
    let onDone: (RecoveryKit) -> Void
    @State private var code = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        AuthLayout(
            title: L10n.verify.title, subtitle: L10n.verify.subtitle(email: started.email),
            top: AnyView(SignUpProgress(step: 1, total: totalSteps))
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
            do {
                model.signingUp = true
                model.willSignIn()
                let kit = try await model.vault.finishSignup(signupId: started.id, verificationCode: digits)
                model.unlockWasConfirmed()
                onDone(kit)
            } catch {
                model.signingUp = false
                busy = false
                self.error = error.message
                Haptics.error()
            }
        }
    }
}

private struct KitStep: View {
    let kit: RecoveryKit
    let onDone: () -> Void
    @State private var saved = false

    var body: some View {
        AuthLayout(
            title: L10n.kit.title, subtitle: L10n.kit.subtitle,
            top: AnyView(SignUpProgress(step: 2, total: totalSteps))
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

private struct DoneStep: View {
    let onOpen: () -> Void

    var body: some View {
        AuthLayout(
            title: L10n.done.title, subtitle: L10n.done.subtitle,
            top: AnyView(SignUpProgress(step: 3, total: totalSteps))
        ) {
            VStack(alignment: .leading, spacing: 16) {
                fact("lock.fill", L10n.done.fact1)
                fact("key.fill", L10n.done.fact2)
                fact("checkmark.shield.fill", L10n.done.fact3)
                PrimaryButton(title: L10n.done.open, action: onOpen)
                    .accessibilityIdentifier("open-vault")
            }
        }
    }

    private func fact(_ icon: String, _ text: String) -> some View {
        Label {
            Text(text).foregroundStyle(Color.ink)
        } icon: {
            Image(systemName: icon).foregroundStyle(Color.free)
        }
    }
}

/// A checkbox, as the web vault's: a square that ticks, the label beside it.
struct CheckboxToggleStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button {
            configuration.isOn.toggle()
            Haptics.tap()
        } label: {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Image(systemName: configuration.isOn ? "checkmark.square.fill" : "square")
                    .foregroundStyle(configuration.isOn ? Color.trust : Color.mist)
                    .imageScale(.large)
                configuration.label.foregroundStyle(Color.ink)
                    .multilineTextAlignment(.leading)
            }
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isToggle)
        .accessibilityValue(configuration.isOn ? "1" : "0")
    }
}

/// The meter for a password being typed: the vault estimates it, in a view of its own so the
/// field above isn't rebuilt with every estimate.
struct PasswordStrength: View {
    @Environment(AppModel.self) private var model
    let password: String

    var body: some View {
        StrengthMeter(estimate: model.vault.estimateStrength(password: password), empty: password.isEmpty)
    }
}

/// The password meter: a bar in four steps, the score, and one tip from the estimator, as the
/// web vault's `StrengthHint`.
struct StrengthMeter: View {
    let estimate: StrengthEstimate
    var empty = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 4) {
                ForEach(0..<4, id: \.self) { index in
                    Capsule()
                        .fill(empty || Int(estimate.score) <= index ? Color.line : color)
                        .frame(height: 4)
                }
            }
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(empty ? L10n.strength.empty : Self.label(estimate.score))
                    .fontWeight(empty ? .regular : .semibold)
                if !empty, let hint { Text(hint).foregroundStyle(Color.mist) }
            }
            .font(.footnote)
        }
        .accessibilityElement(children: .combine)
    }

    static func label(_ score: UInt8) -> String {
        switch score {
        case 0: L10n.strength.score._0
        case 1: L10n.strength.score._1
        case 2: L10n.strength.score._2
        case 3: L10n.strength.score._3
        default: L10n.strength.score._4
        }
    }

    private var hint: String? {
        guard let feedback = estimate.feedback else { return estimate.score >= 4 ? L10n.strength.great : nil }
        switch feedback {
        case .tooShort: return L10n.strength.feedback.tooShort
        case .commonPassword: return L10n.strength.feedback.commonPassword
        case .dictionaryWord: return L10n.strength.feedback.dictionaryWord
        case .sequence: return L10n.strength.feedback.sequence
        case .repeat: return L10n.strength.feedback.repeat
        case .keyboardPattern: return L10n.strength.feedback.keyboardPattern
        case .date: return L10n.strength.feedback.date
        case .addMoreWords: return L10n.strength.feedback.addMoreWords
        case .addVariety: return L10n.strength.feedback.addVariety
        }
    }

    private var color: Color {
        switch estimate.score {
        case 0, 1: .danger
        case 2: .warn
        default: .free
        }
    }
}
