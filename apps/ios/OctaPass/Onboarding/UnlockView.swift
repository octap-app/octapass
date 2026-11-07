import OctaPassResources
import OctaPassVault
import SwiftUI

/// What the device lock is called on screen. The vault names it in English; Face ID, Touch ID and
/// Optic ID are Apple's names in every language.
enum DeviceLockName {
    static func name(_ label: String) -> String {
        switch label {
        case "Face ID", "Touch ID", "Optic ID": label
        default: passcode
        }
    }

    /// A phone's passcode, or the Mac's login password on a Mac without Touch ID.
    private static var passcode: String {
        #if os(macOS)
        return L10n.unlockOffer.macPassword
        #else
        return L10n.phone.native.passcode
        #endif
    }

    /// "Use Face ID to unlock Octa Pass?", or "your passcode" (`offerMethodName`); "your Mac's
    /// password" on a Mac without Touch ID.
    static func offer(_ label: String) -> String {
        switch label {
        case "Face ID", "Touch ID", "Optic ID": label
        default: offerPasscode
        }
    }

    private static var offerPasscode: String {
        #if os(macOS)
        return L10n.unlockOffer.macPassword
        #else
        return L10n.unlockOffer.passcode
        #endif
    }

    static func icon(_ label: String) -> String {
        switch label {
        case "Face ID": "faceid"
        case "Touch ID": "touchid"
        case "Optic ID": "opticid"
        default: "lock.circle"
        }
    }
}

/// The locked vault (the web vault's `Lock`): Face ID / Touch ID or the passcode when device
/// unlock is on, started straight away; the master password is one tap away, and required every
/// 14 days.
struct UnlockView: View {
    @Environment(AppModel.self) private var model
    @State private var methods: UnlockMethods?
    @State private var mode = Mode.loading
    @State private var prompting = false
    @State private var deviceError: String?
    @State private var started = false

    enum Mode { case loading, device, password }

    var body: some View {
        AuthLayout(title: L10n.lock.title, subtitle: subtitle) {
            switch mode {
            case .loading:
                ProgressView().frame(maxWidth: .infinity, minHeight: 120)
            case .device:
                deviceView
            case .password:
                PasswordUnlock(
                    notice: methods?.passwordRequired == true ? L10n.lock.passwordRequired : deviceError,
                    methodName: methods.map { DeviceLockName.name($0.label) },
                    onUseDevice: canUseDevice ? { mode = .device } : nil,
                    // A local vault has no account to reset it from.
                    onForgot: model.isLocal ? nil : {
                        model.resetServerUrl = nil
                        model.resettingPassword = true
                    })
            }
        } footer: {
            if model.isLocal {
                LocalLockChoices()
            } else {
                Button(L10n.lock.signOut) {
                    Task {
                        do { try await model.vault.signOut() } catch { model.show(error) }
                    }
                }
                .accessibilityIdentifier("sign-out")
            }
        }
        .task { await load() }
        // Asked from outside the window (on the Mac, Finder's Sign In on a locked Safe): the device
        // prompt again, unless it's already up or the master password is due.
        .onChange(of: model.unlockRequests) { _, _ in
            if mode == .device, !prompting { Task { await unlockWithDevice() } }
        }
    }

    private var subtitle: String? {
        guard model.isLocal, let name = model.session.email else { return model.session.email }
        return "\(name) · \(L10n.localVault.lockedSubtitle)"
    }

    private var canUseDevice: Bool {
        guard let methods else { return false }
        return methods.deviceUnlockEnabled && !methods.passwordRequired
    }

    private var deviceView: some View {
        let label = methods?.label ?? ""
        let name = DeviceLockName.name(label)
        return VStack(spacing: 18) {
            Button {
                Task { await unlockWithDevice() }
            } label: {
                VStack(spacing: 12) {
                    Image(systemName: DeviceLockName.icon(label))
                        .font(.system(size: 44, weight: .light))
                        .foregroundStyle(Color.trust)
                        .symbolEffect(.pulse, isActive: prompting)
                        .frame(width: 88, height: 88)
                        .background(Color.trust.opacity(0.1), in: Circle())
                    Text(L10n.lock.unlockWith(method: name))
                        .font(.headline)
                        .foregroundStyle(Color.ink)
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.plain)
            .disabled(prompting)
            .accessibilityIdentifier("unlock-device")
            Text(prompting ? L10n.lock.waiting(method: name) : deviceError ?? " ")
                .font(.callout)
                .foregroundStyle(Color.mist)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
            SecondaryButton(title: L10n.lock.usePassword) { mode = .password }
                .accessibilityIdentifier("use-password")
        }
    }

    private func load() async {
        // Stay unlocked (plan 18) opens the vault with no prompt; this screen goes when it does.
        // Only when it can't (off, no passcode, "Lock now", the 14-day check) does anything ask.
        if !started, await model.openStayUnlocked() { return }
        do {
            let next = try await model.vault.unlockMethods()
            methods = next
            // The app-open gate is its own per-device switch: off means the master password here.
            // It doesn't apply while stay unlocked is on (plan 18).
            let gate = model.settings.deviceAuthOnOpen || model.staysUnlocked
            let useDevice = next.deviceUnlockEnabled && !next.passwordRequired && gate
            mode = useDevice ? .device : .password
            // The device prompt starts at once, once; the master password stays one tap away. Not
            // right after the person locked it themselves: they'd only have to cancel it.
            let byHand = model.lockedByHand
            model.lockedByHand = false
            if useDevice, !started {
                started = true
                if !byHand { await unlockWithDevice() }
            }
        } catch {
            mode = .password
        }
    }

    private func unlockWithDevice() async {
        prompting = true
        deviceError = nil
        do {
            try await model.vault.unlockWithDevice()
            model.unlockWasConfirmed()
            Haptics.success()
        } catch {
            prompting = false
            if error.isVault(.passwordRequired) {
                methods?.passwordRequired = true
                mode = .password
            } else if error.isVault(.deviceUnlockFailed) {
                methods?.deviceUnlockEnabled = false
                deviceError = error.message
                mode = .password
            } else if !error.isVault(.deviceUnlockCancelled) {
                deviceError = error.message
            }
        }
    }
}

private struct PasswordUnlock: View {
    @Environment(AppModel.self) private var model
    let notice: String?
    let methodName: String?
    let onUseDevice: (() -> Void)?
    let onForgot: (() -> Void)?
    @State private var password = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let notice { Notice(text: notice, tone: .info) }
            PasswordInput(label: L10n.fields.masterPassword, text: $password, error: error, onSubmit: submit)
                .accessibilityIdentifier("master-password")
            PrimaryButton(title: L10n.lock.unlock, systemImage: "lock.open", busy: busy, action: submit)
                .accessibilityIdentifier("unlock")
            if let onUseDevice, let methodName {
                Button(L10n.lock.unlockWith(method: methodName), action: onUseDevice)
                    .frame(maxWidth: .infinity)
            }
            if let onForgot {
                Button(L10n.signIn.forgotPassword, action: onForgot)
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("forgot-password")
            }
        }
    }

    private func submit() {
        guard !password.isEmpty else {
            error = L10n.validation.passwordRequired
            return Haptics.error()
        }
        busy = true
        error = nil
        let typed = password
        Task {
            do {
                try await model.vault.unlock(password: typed)
                model.unlockWasConfirmed()
                model.didUnlockWithPassword()
                Haptics.success()
            } catch {
                self.error = model.passwordMessage(error)
                password = ""
                busy = false
                Haptics.error()
            }
        }
    }
}

/// "Use Face ID to unlock Octa Pass?" right after sign-in or sign-up. Not now asks once more at a
/// later unlock, then never again; cancelling the system prompt is the same as Not now.
struct DeviceUnlockOffer: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let label: String
    @State private var busy = false

    var body: some View {
        let method = DeviceLockName.offer(label)
        VStack(alignment: .leading, spacing: 18) {
            Image(systemName: DeviceLockName.icon(label))
                .font(.system(size: 40, weight: .light))
                .foregroundStyle(Color.trust)
                .accessibilityHidden(true)
            Text(L10n.unlockOffer.title(method: method))
                .font(.title2.weight(.bold))
                .accessibilityAddTraits(.isHeader)
            Text(L10n.unlockOffer.body(method: method))
                .foregroundStyle(Color.mist)
            Spacer(minLength: 0)
            PrimaryButton(title: L10n.unlockOffer.turnOn, busy: busy) { Task { await turnOn(method) } }
                .accessibilityIdentifier("offer-turn-on")
            Button(L10n.unlockOffer.notNow, action: notNow)
                .frame(maxWidth: .infinity)
                .disabled(busy)
                .accessibilityIdentifier("offer-not-now")
        }
        .padding(24)
        .interactiveDismissDisabled(busy)
    }

    private func notNow() {
        if let email = model.session.email, DeviceUnlockOfferState.load(email) != .done {
            DeviceUnlockOfferState.save(.declined, for: email)
        }
        model.offerDeviceUnlock = nil
        dismiss()
    }

    private func turnOn(_ method: String) async {
        busy = true
        defer { busy = false }
        do {
            try await model.vault.enableDeviceUnlock()
            if let email = model.session.email { DeviceUnlockOfferState.save(.done, for: email) }
            model.offerDeviceUnlock = nil
            dismiss()
            model.confirm(L10n.unlockOffer.enabled(method: method))
        } catch {
            if error.isVault(.deviceUnlockCancelled) { return notNow() }
            model.show(error)
        }
    }
}
