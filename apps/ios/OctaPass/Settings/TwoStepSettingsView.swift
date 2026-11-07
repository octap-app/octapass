import OctaPassResources
import OctaPassVault
import SwiftUI

/// Settings → Two-step sign-in (plan 03, "Account 2FA"): on with an authenticator app, recovery
/// codes, forget other devices, and off again. Every change asks for the master password.
/// Security keys are added in the web vault; they can be removed here.
struct TwoStepSettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var status: TwoStepStatus?
    @State private var loadError: String?
    @State private var flow: TwoStepFlow?
    @State private var forgetting = false

    var body: some View {
        List {
            Section { Text(L10n.settings.twoStepHelp).font(.subheadline).foregroundStyle(Color.mist) }
            if let status {
                if !status.enabled {
                    Section {
                        LabeledContent(L10n.twoStepSettings.status, value: L10n.twoStepSettings.off)
                        Button { flow = .enable } label: { Label(L10n.twoStepSettings.turnOn, systemImage: "lock.shield") }
                            .accessibilityIdentifier("two-step-turn-on")
                    }
                } else {
                    Section {
                        LabeledContent(L10n.twoStepSettings.authenticator, value: L10n.twoStepSettings.authenticatorOn)
                        Button(L10n.twoStepSettings.change) { flow = .change }
                    }
                    Section {
                        ForEach(status.securityKeys, id: \.id) { key in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(key.name)
                                    Text(L10n.twoStepSettings.keyAdded(date: Dates.long(key.createdAt))).font(.footnote).foregroundStyle(Color.mist)
                                    if let used = key.lastUsedAt {
                                        Text(L10n.twoStepSettings.keyUsed(date: Dates.long(used))).font(.footnote).foregroundStyle(Color.mist)
                                    }
                                }
                                Spacer()
                                Button(role: .destructive) { flow = .removeKey(key) } label: { Image(systemName: "trash") }
                                    .buttonStyle(.borderless)
                                    .accessibilityLabel(L10n.twoStepSettings.removeKey(name: key.name))
                            }
                        }
                    } header: {
                        Text(L10n.twoStepSettings.securityKeys)
                    } footer: {
                        Text(L10n.twoStepSettings.securityKeysUnsupported)
                    }
                    Section {
                        LabeledContent(L10n.twoStepSettings.recoveryCodes, value: L10n.twoStepSettings.recoveryCodesLeft(count: Int(status.recoveryCodesLeft)))
                        Button(L10n.twoStepSettings.newCodes) { flow = .renew }
                    }
                    Section {
                        Button {
                            Task { await forget() }
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(L10n.twoStepSettings.forgetDevices)
                                Text(L10n.twoStepSettings.otherDevicesHelp).font(.footnote).foregroundStyle(Color.mist)
                            }
                        }
                        .disabled(forgetting)
                        Button(role: .destructive) { flow = .disable } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(L10n.twoStepSettings.turnOff)
                                Text(L10n.twoStepSettings.turnOffHelp).font(.footnote).foregroundStyle(Color.mist)
                            }
                        }
                    }
                }
            } else if let loadError {
                Notice(text: loadError)
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.settings.twoStep)
        .task { await reload() }
        .sheet(item: $flow, onDismiss: { Task { await reload() } }) { TwoStepFlowSheet(flow: $0) }
    }

    private func reload() async {
        do {
            status = try await model.vault.twoStepStatus()
        } catch {
            loadError = error.message
        }
    }

    private func forget() async {
        forgetting = true
        defer { forgetting = false }
        do {
            try await model.vault.forgetTrustedDevices()
            model.confirm(L10n.twoStepSettings.devicesForgotten)
        } catch {
            model.show(error)
        }
    }
}

enum TwoStepFlow: Identifiable {
    case enable, change, renew, disable
    case removeKey(SecurityKeyInfo)

    var id: String {
        switch self {
        case .enable: "enable"
        case .change: "change"
        case .renew: "renew"
        case .disable: "disable"
        case let .removeKey(key): "removeKey-\(key.id)"
        }
    }

    var title: String {
        switch self {
        case .enable: L10n.twoStepSettings.titles.enable
        case .change: L10n.twoStepSettings.titles.change
        case .renew: L10n.twoStepSettings.titles.renew
        case .disable: L10n.twoStepSettings.titles.disable
        case .removeKey: L10n.twoStepSettings.titles.removeKey
        }
    }

    var intro: String {
        switch self {
        case .enable: L10n.twoStepSettings.passwordIntro.enable
        case .change: L10n.twoStepSettings.passwordIntro.change
        case .renew: L10n.twoStepSettings.passwordIntro.renew
        case .disable: L10n.twoStepSettings.passwordIntro.disable
        case let .removeKey(key): L10n.twoStepSettings.passwordIntro.removeKey(name: key.name)
        }
    }
}

/// One change: the master password, then (for the authenticator) the setup key and a code, and
/// the recovery codes, shown once.
private struct TwoStepFlowSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let flow: TwoStepFlow
    @State private var step = Step.password
    @State private var password = ""
    @State private var setup: TotpSetup?
    @State private var code = ""
    @State private var codes: [String] = []
    @State private var saved = false
    @State private var error: String?
    @State private var fieldError: String?
    @State private var busy = false

    enum Step { case password, scan, codes }

    var body: some View {
        NavigationStack {
            Form {
                if let error { Section { Notice(text: error) }.listRowBackground(Color.clear).listRowInsets(EdgeInsets()) }
                switch step {
                case .password: passwordStep
                case .scan: scanStep
                case .codes: codesStep
                }
            }
            .navigationTitle(flow.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if step != .codes { Button(L10n.common.cancel) { dismiss() }.disabled(busy) }
                }
            }
        }
        // Recovery codes are shown once: closing waits until they're saved.
        .interactiveDismissDisabled(busy || (step == .codes && !saved))
    }

    private var passwordStep: some View {
        Section {
            Text(flow.intro).foregroundStyle(Color.mist)
            SecureField(L10n.fields.masterPassword, text: $password)
                .accessibilityIdentifier("two-step-password")
            if let fieldError { Text(fieldError).font(.footnote).foregroundStyle(Color.dangerText) }
            Button {
                Task { await submitPassword() }
            } label: {
                HStack { Text(confirmLabel); if busy { Spacer(); ProgressView() } }
            }
            .disabled(busy)
            .accessibilityIdentifier("two-step-continue")
        }
    }

    private var confirmLabel: String {
        switch flow {
        case .enable, .change: L10n.twoStepSettings.continue
        case .renew: L10n.twoStepSettings.newCodes
        case .disable: L10n.twoStepSettings.turnOff
        case .removeKey: L10n.common.remove
        }
    }

    @ViewBuilder private var scanStep: some View {
        if let setup {
            Section {
                Text(L10n.twoStepSettings.scan).foregroundStyle(Color.mist)
                QRCodeImage(text: setup.otpauthUri)
                    .frame(width: 200, height: 200)
                    .frame(maxWidth: .infinity)
                    .accessibilityLabel(L10n.twoStepSettings.qrLabel)
                // Most authenticator apps are on this phone: the setup key goes there by copy and paste.
                LabeledContent(L10n.twoStepSettings.setupKey) {
                    Text(setup.secret).font(.secret(.footnote)).textSelection(.enabled)
                        .accessibilityIdentifier("two-step-setup-key")
                }
                CopyButton(value: setup.secret, what: L10n.twoStepSettings.setupKey, secret: true)
            }
            Section {
                TextField(L10n.twoStepSettings.confirmCode, text: $code)
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                    .font(.secret())
                    .accessibilityIdentifier("two-step-confirm-code")
                if let fieldError { Text(fieldError).font(.footnote).foregroundStyle(Color.dangerText) }
                Button {
                    Task { await confirm() }
                } label: {
                    HStack { Text(L10n.twoStepSettings.confirm); if busy { Spacer(); ProgressView() } }
                }
                .disabled(busy)
                .accessibilityIdentifier("two-step-confirm")
            }
        }
    }

    private var codesStep: some View {
        Section {
            Text(L10n.twoStepSettings.saveCodes).foregroundStyle(Color.mist)
            Text(codes.joined(separator: "\n"))
                .font(.secret())
                .textSelection(.enabled)
                .environment(\.layoutDirection, .leftToRight)
                .accessibilityLabel(L10n.twoStepSettings.codesLabel)
                .accessibilityIdentifier("two-step-recovery-codes")
            Button { model.copy(codes.joined(separator: "\n"), what: L10n.twoStepSettings.codesLabel) } label: {
                Label(L10n.twoStepSettings.copyCodes, systemImage: "doc.on.doc")
            }
            ShareLink(item: codes.joined(separator: "\n")) { Label(L10n.phone.native.kitShare, systemImage: "square.and.arrow.up") }
            Toggle(L10n.twoStepSettings.saved, isOn: $saved)
                .accessibilityIdentifier("two-step-saved")
            Button(L10n.twoStepSettings.done) {
                if case .enable = flow { model.confirm(L10n.twoStepSettings.turnedOn) }
                dismiss()
            }
            .disabled(!saved)
            .accessibilityIdentifier("two-step-done")
        }
    }

    private func submitPassword() async {
        guard !password.isEmpty else {
            fieldError = L10n.validation.passwordRequired
            return
        }
        busy = true
        error = nil
        fieldError = nil
        defer {
            password = ""
            busy = false
        }
        do {
            switch flow {
            case .enable, .change:
                setup = try await model.vault.startTotpSetup(password: password)
                step = .scan
            case .renew:
                codes = try await model.vault.renewRecoveryCodes(password: password)
                step = .codes
            case .disable:
                try await model.vault.disableTwoStep(password: password)
                model.confirm(L10n.twoStepSettings.turnedOff)
                dismiss()
            case let .removeKey(key):
                try await model.vault.removeSecurityKey(id: key.id, password: password)
                model.confirm(L10n.twoStepSettings.keyRemoved(name: key.name))
                dismiss()
            }
        } catch {
            self.error = error.message
        }
    }

    private func confirm() async {
        let typed = code.filter { !$0.isWhitespace }
        guard typed.count == 6, typed.allSatisfy(\.isASCIIDigit) else {
            fieldError = L10n.twoStep.codeRequired
            return
        }
        busy = true
        error = nil
        fieldError = nil
        defer { busy = false }
        do {
            if let recovery = try await model.vault.confirmTotpSetup(code: typed) {
                codes = recovery
                step = .codes
            } else {
                model.confirm(L10n.twoStepSettings.changed)
                dismiss()
            }
        } catch {
            if error.isVault(.invalidTwoStepCode) {
                fieldError = error.message
                code = ""
            } else if error.isVault(.twoStepExpired) {
                step = .password
                self.error = L10n.twoStepSettings.setupExpired
            } else {
                self.error = error.message
            }
        }
    }
}
