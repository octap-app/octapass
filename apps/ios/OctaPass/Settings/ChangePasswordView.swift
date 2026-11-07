import OctaPassResources
import OctaPassVault
import SwiftUI

/// Settings → Master password (`ChangePassword`): the current password, then a new one. The
/// account key stays, so nothing is re-encrypted; other devices are signed out and device unlock
/// starts again.
struct ChangePasswordView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var current = ""
    @State private var new = ""
    @State private var confirm = ""
    @State private var currentError: String?
    @State private var newError: String?
    @State private var confirmError: String?
    @State private var formError: String?
    @State private var busy = false

    var body: some View {
        Form {
            // These talk of the Secret Key and other devices; a local vault has neither.
            if !model.isLocal {
                Section {
                    Text(L10n.changePassword.intro).foregroundStyle(Color.mist)
                }
            }
            Section {
                PasswordInput(label: L10n.changePassword.current, text: $current, error: currentError, content: .oneTimeCode)
                    .accessibilityIdentifier("change-password-current")
                PasswordInput(label: L10n.fields.masterPassword, text: $new, error: newError, content: .oneTimeCode)
                    .accessibilityIdentifier("change-password-new")
                PasswordStrength(password: new)
                PasswordInput(label: L10n.fields.confirmPassword, text: $confirm, error: confirmError, content: .oneTimeCode)
                    .accessibilityIdentifier("change-password-confirm")
            }
            Section {
                Button {
                    Task { await submit() }
                } label: {
                    HStack {
                        Text(L10n.changePassword.submit)
                        if busy { Spacer(); ProgressView() }
                    }
                }
                .disabled(busy)
                .accessibilityIdentifier("change-password-submit")
            } footer: {
                if !model.isLocal { Text(L10n.changePassword.signsOut) }
            }
            if let formError {
                Section { Notice(text: formError) }
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
            }
        }
        .navigationTitle(L10n.changePassword.title)
        .navigationBarTitleDisplayMode(.inline)
    }

    private func validate() -> Bool {
        currentError = current.isEmpty ? L10n.validation.passwordRequired : nil
        if new.isEmpty {
            newError = L10n.changePassword.newRequired
        } else if model.vault.estimateStrength(password: new).score < minimumScore {
            newError = L10n.validation.passwordTooWeak
        } else if new == current {
            newError = L10n.changePassword.same
        } else {
            newError = nil
        }
        confirmError = confirm == new ? nil : L10n.validation.passwordsDontMatch
        return currentError == nil && newError == nil && confirmError == nil
    }

    private func submit() async {
        formError = nil
        guard validate(), !busy else {
            Haptics.error()
            return
        }
        busy = true
        defer { busy = false }
        do {
            try await model.vault.changeMasterPassword(currentPassword: current, newPassword: new)
            Haptics.success()
            model.confirm(L10n.changePassword.done)
            dismiss()
        } catch {
            Haptics.error()
            if error.isVault(.invalidCredentials) {
                currentError = L10n.changePassword.wrongCurrent
            } else {
                formError = error.message
            }
        }
    }
}
