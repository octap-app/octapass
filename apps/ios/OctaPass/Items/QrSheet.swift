import OctaPassResources
import OctaPassVault
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// Show as QR code (plan 01): generated on the phone, full screen at full brightness, hidden
/// after 60 seconds or when the vault locks. Secrets ask for the device lock or the master
/// password first, unless the user answered this unlock (`unlockCoversReveal`), and warn that
/// cameras can see the screen; Wi-Fi joins, contacts, websites and notes show straight away.
struct QrSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let item: Item
    @State private var choiceId: String?
    @State private var confirmed: Set<String> = []
    /// The unlock covers secrets (`unlockCoversReveal`); nil while it's being asked.
    @State private var unlockCovers: Bool?
    @State private var secondsLeft = 60
    @State private var savedBrightness: CGFloat?
    @State private var amount = ""
    @State private var reference = ""

    private var choices: [QrChoice] { qrChoices(item: item) }
    private var choice: QrChoice? { choices.first { $0.id == choiceId } ?? choices.first }

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if choices.count > 1 {
                    Picker(L10n.phone.qrChoice, selection: Binding(get: { choice?.id ?? "" }, set: { choiceId = $0 })) {
                        ForEach(choices, id: \.id) { Text(Self.label($0)).tag($0.id) }
                    }
                    .pickerStyle(.menu)
                    .accessibilityIdentifier("qr-choice")
                }
                if let choice {
                    if choice.confirm, !confirmed.contains(choice.id), unlockCovers != true {
                        if unlockCovers == nil {
                            ProgressView().frame(maxWidth: .infinity, minHeight: 120)
                        } else {
                            ConfirmItsYou {
                                confirmed.insert(choice.id)
                                // With stay unlocked on, the first reveal's answer covers the next (plan 18).
                                model.revealWasConfirmed()
                            }
                        }
                    } else {
                        if choice.warn { Notice(text: L10n.phone.qrWarning, tone: .warn) }
                        if choice.kind == "payment" {
                            TextField(L10n.typedItems.bankAmount, text: $amount).keyboardType(.decimalPad).textFieldStyle(.roundedBorder)
                            TextField(L10n.typedItems.bankReference, text: $reference).textFieldStyle(.roundedBorder)
                        }
                        if let text = text(of: choice) {
                            QRCodeImage(text: text)
                                .frame(maxWidth: 320, maxHeight: 320)
                                .accessibilityLabel(L10n.phone.qrLabel(title: item.title))
                                .accessibilityIdentifier("qr-code")
                        } else {
                            Notice(text: L10n.typedItems.bankQrInvalid)
                        }
                        Text(L10n.phone.qrHidesIn(count: secondsLeft))
                            .font(.footnote.monospacedDigit())
                            .foregroundStyle(Color.mist)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(20)
            .navigationTitle(L10n.phone.qrTitle)
            .navigationBarTitleDisplayMode(.inline)
            .task { unlockCovers = await model.unlockCoversReveal() }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.phone.close) { dismiss() }
                }
            }
        }
        .task {
            while secondsLeft > 0 {
                try? await Task.sleep(for: .seconds(1))
                if Task.isCancelled { return }
                secondsLeft -= 1
            }
            dismiss()
        }
        .onChange(of: model.session.status) { _, status in if status != .unlocked { dismiss() } }
        .onAppear {
            savedBrightness = ScreenBrightness.value
            ScreenBrightness.value = 1
        }
        .onDisappear {
            if let savedBrightness { ScreenBrightness.value = savedBrightness }
        }
    }

    /// A payment code takes the amount and reference typed above it; `nil` when they don't fit.
    private func text(of choice: QrChoice) -> String? {
        guard choice.kind == "payment", case let .structured(_, bank) = item.details else { return choice.text }
        return bankQrText(bank: bank, amount: amount, reference: reference)
    }

    static func label(_ choice: QrChoice) -> String {
        if choice.kind == "field" { return choice.label ?? L10n.phone.choices.field }
        if choice.kind == "address" { return choice.label ?? L10n.typedItems.address }
        switch choice.kind {
        case "wifi": return L10n.phone.choices.wifi
        case "password": return L10n.phone.choices.password
        case "both": return L10n.phone.choices.both
        case "totp": return L10n.phone.choices.totp
        case "website": return L10n.phone.choices.website
        case "contact": return L10n.phone.choices.contact
        case "payment": return L10n.phone.choices.payment
        case "iban": return L10n.phone.choices.iban
        default: return L10n.phone.choices.note
        }
    }
}

/// "Confirm it's you": the device lock, or the master password.
struct ConfirmItsYou: View {
    @Environment(AppModel.self) private var model
    /// False where the device lock has already been tried.
    var deviceButton = true
    var note: String?
    let onConfirmed: () -> Void
    @State private var methods: UnlockMethods?
    @State private var password = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(L10n.phone.confirmTitle).font(.title3.weight(.bold))
            Text(note ?? L10n.phone.confirmBody).foregroundStyle(Color.mist)
            if deviceButton, let methods, methods.deviceUnlockEnabled {
                SecondaryButton(title: L10n.phone.confirmDevice(method: DeviceLockName.name(methods.label)), systemImage: DeviceLockName.icon(methods.label)) {
                    confirm(nil)
                }
                .accessibilityIdentifier("confirm-device")
            }
            PasswordInput(label: L10n.phone.confirmPassword, text: $password, error: error) { confirm(password) }
                .accessibilityIdentifier("confirm-password")
            PrimaryButton(title: L10n.phone.confirm, busy: busy) { confirm(password) }
                .accessibilityIdentifier("confirm")
        }
        .task { methods = try? await model.vault.unlockMethods() }
    }

    private func confirm(_ password: String?) {
        if let password, password.isEmpty {
            error = L10n.validation.passwordRequired
            return
        }
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                try await model.vault.confirmUser(password: password)
                onConfirmed()
            } catch {
                if !error.isVault(.deviceUnlockCancelled) { self.error = model.passwordMessage(error) }
            }
        }
    }
}

/// The screen's brightness, raised to full while a code is shown so another phone's camera reads
/// it, and put back after. Macs keep theirs.
enum ScreenBrightness {
    @MainActor static var value: CGFloat {
        get {
            #if os(iOS)
            UIScreen.main.brightness
            #else
            1
            #endif
        }
        set {
            #if os(iOS)
            UIScreen.main.brightness = newValue
            #endif
        }
    }
}
