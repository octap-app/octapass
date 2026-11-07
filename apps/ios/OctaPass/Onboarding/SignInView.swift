import OctaPassResources
import OctaPassVault
import SwiftUI

/// Sign in, on this phone or a new one (the web vault's `SignIn`): email, master password, and
/// the Secret Key where this phone doesn't know the account yet. Then the second step, when the
/// account has two-step sign-in on.
struct SignInView: View {
    @Environment(AppModel.self) private var model
    @State private var email = ""
    @State private var password = ""
    @State private var secretKey = ""
    @State private var server = ServerChoice()
    @State private var showServer = false
    /// Replacing the key on another device leaves this phone remembering the old one.
    @State private var replaceSecretKey = false
    @State private var errors: [Field: String] = [:]
    @State private var formError: String?
    @State private var busy = false
    @State private var twoStep: [TwoStepMethod]?
    @State private var loaded = false
    let onCreateAccount: () -> Void
    let onCreateLocal: () -> Void
    let onRestore: () -> Void

    enum Field { case email, password, secretKey, server }

    var body: some View {
        Group {
            if let twoStep {
                TwoStepView(methods: twoStep) { error in
                    model.vault.cancelTwoStep()
                    self.twoStep = nil
                    formError = error
                }
            } else {
                form
            }
        }
        .onAppear(perform: load)
    }

    private var serverUrl: String { server.serverUrl(hosted: model.defaultServerUrl) }

    private var knownDevice: Bool {
        let normalized = normalizeEmail(email: email)
        return model.session.rememberedAccounts.contains { $0.email == normalized && $0.serverUrl == serverUrl }
    }

    /// The Secret Key lives on each signed-in device: asked where this account isn't known, or
    /// where the user says theirs changed.
    private var needsSecretKey: Bool { !knownDevice || replaceSecretKey }

    private var form: some View {
        AuthLayout(title: L10n.signIn.title, subtitle: L10n.signIn.subtitle) {
            VStack(alignment: .leading, spacing: 16) {
                if let formError { Notice(text: formError) }
                TextInput(
                    label: L10n.fields.email, text: $email, error: errors[.email],
                    content: .username, keyboard: .emailAddress)
                    .accessibilityIdentifier("email")
                PasswordInput(
                    label: L10n.fields.masterPassword, text: $password, error: errors[.password],
                    onSubmit: submit)
                    .accessibilityIdentifier("master-password")
                if knownDevice, !replaceSecretKey {
                    Button(L10n.signIn.newSecretKey) { replaceSecretKey = true }
                        .font(.callout)
                        .accessibilityIdentifier("new-secret-key")
                }
                if needsSecretKey {
                    TextInput(
                        label: L10n.fields.secretKey, text: $secretKey, hint: L10n.signIn.secretKeyHint,
                        error: errors[.secretKey], placeholder: "OP1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXX",
                        mono: true, capitalization: .characters)
                        .accessibilityIdentifier("secret-key")
                }
                if showServer {
                    ServerPicker(choice: $server, error: errors[.server])
                } else {
                    HStack(spacing: 4) {
                        Text(L10n.signIn.signingInTo(server: L10n.server.hosted)).foregroundStyle(Color.mist)
                        Button(L10n.signIn.changeServer) { showServer = true }
                    }
                    .font(.callout)
                }
                PrimaryButton(title: L10n.signIn.submit, busy: busy, action: submit)
                    .accessibilityIdentifier("sign-in")
                Button(L10n.signIn.forgotPassword) {
                    model.resetServerUrl = serverUrl
                    model.resettingPassword = true
                }
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("forgot-password")
            }
        } footer: {
            VStack(spacing: 24) {
                HStack(spacing: 4) {
                    Text(L10n.signIn.noAccount).foregroundStyle(Color.mist)
                    Button(L10n.signIn.createAccount, action: onCreateAccount)
                        .accessibilityIdentifier("create-account")
                }
                LocalChoices(onCreate: onCreateLocal, onRestore: onRestore)
            }
        }
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        if let account = model.session.rememberedAccounts.first {
            email = account.email
            if account.serverUrl != model.defaultServerUrl {
                server = ServerChoice(selfHosted: true, url: account.serverUrl)
                showServer = true
            }
        }
        // The app was closed while a code was being read: carry on with the second step.
        switch model.vault.pendingTwoStep() {
        case let .required(methods): twoStep = methods
        case .expired:
            formError = VaultError.Failed(code: .twoStepExpired, reason: "").message
            model.vault.cancelTwoStep()
        case nil: break
        }
    }

    private func validate() -> [Field: String] {
        var next: [Field: String] = [:]
        if !isValidEmail(email: normalizeEmail(email: email)) { next[.email] = L10n.validation.email }
        if password.isEmpty { next[.password] = L10n.validation.passwordRequired }
        if needsSecretKey, (try? normalizeSecretKey(text: secretKey)) == nil {
            next[.secretKey] = secretKey.trimmingCharacters(in: .whitespaces).isEmpty
                ? L10n.validation.secretKeyRequired : L10n.errors.invalidSecretKey
        }
        return next
    }

    private func submit() {
        errors = validate()
        formError = nil
        guard errors.isEmpty, !busy else { return Haptics.error() }
        busy = true
        let url = serverUrl, email = email, password = password
        let key = needsSecretKey ? secretKey : nil
        let selfHosted = server.selfHosted
        Task {
            defer { busy = false }
            do {
                if selfHosted { _ = try await model.vault.serverInfo(serverUrl: url) }
                model.willSignIn()
                switch try await model.vault.signIn(serverUrl: url, email: email, password: password, secretKey: key) {
                case .signedIn: model.unlockWasConfirmed()
                case let .twoStepRequired(methods):
                    self.password = ""
                    twoStep = methods
                case let .ssoRequired(_, orgName):
                    // No SSO step in the native apps yet (plan 17): say where it works.
                    formError = L10n.sso.notInThisApp(organisation: orgName)
                    Haptics.error()
                }
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

/// The second step on a new device (`TwoStepForm`): a code from the authenticator app, or a
/// recovery code. Security keys work only in the web vault.
struct TwoStepView: View {
    @Environment(AppModel.self) private var model
    let methods: [TwoStepMethod]
    let onStartOver: (String?) -> Void
    @State private var method: TwoStepMethod = .totp
    @State private var code = ""
    @State private var fieldError: String?
    @State private var formError: String?
    @State private var busy = false

    private var offered: [TwoStepMethod] { methods.filter { $0 != .securityKey } }

    var body: some View {
        AuthLayout(title: L10n.twoStep.title, subtitle: subtitle) {
            VStack(alignment: .leading, spacing: 16) {
                if let formError { Notice(text: formError) }
                if method == .totp {
                    TextInput(
                        label: L10n.twoStep.codeLabel, text: $code, error: fieldError,
                        content: .oneTimeCode, keyboard: .numberPad, mono: true)
                        .accessibilityIdentifier("two-step-code")
                } else {
                    TextInput(
                        label: L10n.twoStep.recoveryLabel, text: $code, error: fieldError,
                        placeholder: "XXXXX-XXXXX", mono: true, capitalization: .characters)
                        .accessibilityIdentifier("recovery-code")
                }
                PrimaryButton(title: L10n.twoStep.verify, busy: busy, action: submit)
                    .accessibilityIdentifier("verify")
                ForEach(offered.filter { $0 != method }, id: \.self) { other in
                    Button(other == .totp ? L10n.twoStep.useCode : L10n.twoStep.useRecovery) {
                        method = other
                        code = ""
                        fieldError = nil
                        formError = nil
                    }
                    .disabled(busy)
                    .frame(maxWidth: .infinity)
                }
            }
        } footer: {
            Button(L10n.twoStep.startOver) { onStartOver(nil) }.disabled(busy)
        }
        .onAppear {
            if !offered.contains(method), let first = offered.first { method = first }
        }
    }

    private var subtitle: String {
        method == .totp ? L10n.twoStep.totpSubtitle : L10n.twoStep.recoverySubtitle
    }

    private func submit() {
        let typed = method == .totp
            ? code.filter { !$0.isWhitespace }
            : code.trimmingCharacters(in: .whitespaces)
        if method == .totp, typed.count != 6 || !typed.allSatisfy(\.isASCIIDigit) {
            fieldError = L10n.twoStep.codeRequired
            return Haptics.error()
        }
        if method == .recoveryCode, typed.isEmpty {
            fieldError = L10n.twoStep.recoveryRequired
            return Haptics.error()
        }
        busy = true
        fieldError = nil
        formError = nil
        let proof: TwoStepProof = method == .totp ? .totp(code: typed) : .recoveryCode(code: typed)
        Task {
            do {
                model.willSignIn()
                try await model.vault.finishTwoStep(proof: proof)
                model.unlockWasConfirmed()
            } catch {
                busy = false
                Haptics.error()
                if error.isVault(.twoStepExpired) {
                    onStartOver(error.message)
                } else if error.isVault(.invalidTwoStepCode) {
                    fieldError = error.message
                    code = ""
                } else {
                    formError = error.message
                }
            }
        }
    }
}

extension Character {
    var isASCIIDigit: Bool { isASCII && isNumber }
}
