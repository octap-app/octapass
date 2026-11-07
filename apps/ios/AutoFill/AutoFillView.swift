import OctaPassAutoFillKit
import OctaPassCore
import SwiftUI
#if canImport(UIKit)
import UIKit
#else
import AppKit
#endif

/// The extension's one screen: unlock, then pick a login, passkey or code.
struct AutoFillView: View {
    @ObservedObject var model: AutoFillModel
    @State private var password = ""
    @FocusState private var passwordFocused: Bool

    var body: some View {
        #if os(macOS)
        // The Mac shows the extension in a sheet with no toolbar: the title and Cancel are its own.
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(model.title).font(.title2.weight(.bold))
                Spacer()
                Button("Cancel", action: model.cancel).keyboardShortcut(.cancelAction)
            }
            .padding([.horizontal, .top], 20)
            content
        }
        .frame(minWidth: 380, minHeight: 440, alignment: .topLeading)
        .tint(Color.trust)
        .onAppear(perform: model.start)
        #else
        NavigationStack {
            content
                .navigationTitle(model.title)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel", action: model.cancel)
                    }
                }
        }
        .tint(Color.trust)
        .onAppear(perform: model.start)
        #endif
    }

    @ViewBuilder
    private var content: some View {
        switch model.phase {
        case .locked, .unlocking:
            unlock
        case .list:
            list
        case .failed(let message):
            ContentUnavailableView("Can't fill", systemImage: "exclamationmark.triangle", description: Text(message))
        }
    }

    private var unlock: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield")
                .font(.system(size: 44, weight: .regular))
                .foregroundStyle(Color.trust)
                .padding(.top, 32)
            VStack(spacing: 4) {
                Text("Unlock Octa Pass").font(.title2.weight(.semibold))
                Text(model.email).foregroundStyle(Color.mist)
            }
            if let error = model.error {
                Text(error).foregroundStyle(.red).font(.callout).multilineTextAlignment(.center)
            }
            if model.canUseDevice {
                Button {
                    model.unlockWithDevice()
                } label: {
                    Label("Unlock with \(String(localized: String.LocalizationValue(model.deviceLabel)))", systemImage: model.deviceIcon)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .tint(Color.button)
            }
            SecureField("Master password", text: $password)
                .textContentType(.password)
                .focused($passwordFocused)
                .submitLabel(.go)
                .onSubmit(submitPassword)
                #if os(macOS)
                .textFieldStyle(.plain)
                #endif
                .padding(12)
                .background(RoundedRectangle(cornerRadius: 12).strokeBorder(.quaternary))
            Button("Unlock with master password", action: submitPassword)
                .buttonStyle(.bordered)
                .controlSize(.large)
                .disabled(password.isEmpty)
            if model.suggestDeviceUnlock {
                Text("Turn on \(String(localized: String.LocalizationValue(model.deviceLabel))) in Octa Pass → Settings → Security to fill without your master password.")
                    .font(.footnote)
                    .foregroundStyle(Color.mist)
                    .multilineTextAlignment(.center)
            }
            if model.phase == .unlocking { ProgressView() }
            Spacer()
        }
        .padding(.horizontal, 24)
        .disabled(model.phase == .unlocking)
    }

    private var list: some View {
        #if os(macOS)
        // No window toolbar for `.searchable` here: the field goes above the list.
        VStack(spacing: 8) {
            TextField("Search all logins", text: $model.query)
                .textFieldStyle(.roundedBorder)
                .padding(.horizontal, 20)
            logins
        }
        #else
        logins.searchable(text: $model.query, prompt: "Search all logins")
        #endif
    }

    private var logins: some View {
        List {
            if !model.passkeys.isEmpty {
                Section("Passkeys") {
                    ForEach(model.passkeys, id: \.credentialId) { passkey in
                        Button { model.choose(passkey) } label: {
                            Row(icon: "person.badge.key", title: passkey.userName, subtitle: passkey.rpId)
                        }
                    }
                }
            }
            if model.query.isEmpty {
                Section(LocalizedStringKey(model.suggestions.isEmpty ? "No logins for this site" : "Suggested")) {
                    ForEach(model.suggestions) { login in
                        Button { model.choose(login) } label: { LoginRow(login: login) }
                    }
                }
                ForEach(otherSites, id: \.self) { site in
                    Section("Logins for other parts of \(site)") {
                        ForEach(model.others.filter { $0.site == site }) { other in
                            Button { model.choose(other) } label: { LoginRow(login: other.login, host: other.host) }
                        }
                    }
                }
            } else {
                Section("All logins") {
                    ForEach(model.searchResults) { login in
                        Button { model.choose(login) } label: { LoginRow(login: login) }
                    }
                }
            }
            if let error = model.error {
                Text(error).foregroundStyle(.red)
            }
        }
        #if os(macOS)
        // Each row is a button: on the Mac, a row to click, not a push button.
        .buttonStyle(.plain)
        #endif
        .alert(
            "Add \(model.offer?.host ?? "") to this login?",
            isPresented: Binding(get: { model.offer != nil }, set: { _ in }),
            presenting: model.offer
        ) { offer in
            Button("Add") { model.finish(offer, add: true) }
            Button("Not now", role: .cancel) { model.finish(offer, add: false) }
        }
    }

    /// The domains of the other-parts logins, in the order they're listed.
    private var otherSites: [String] {
        var seen = Set<String>()
        return model.others.map(\.site).filter { seen.insert($0).inserted }
    }

    private func submitPassword() {
        guard !password.isEmpty else { return }
        model.unlock(password: password)
        password = ""
    }
}

private struct LoginRow: View {
    let login: Login
    /// For a login saved for another part of the domain: where it's saved, and a quieter row.
    var host: String?

    var body: some View {
        Row(
            icon: login.schemeMismatch ? "exclamationmark.shield" : "key",
            title: login.title,
            subtitle: [host, login.username, login.schemeMismatch ? String(localized: "Not a secure (https) page") : nil]
                .compactMap { $0 }.joined(separator: " · "),
            quiet: host != nil
        )
    }
}

private struct Row: View {
    let icon: String
    let title: String
    let subtitle: String
    var quiet = false

    /// Explicit colours, not `.primary` / `.secondary`: inside a `Button` in a `List` those are the
    /// levels of the button's tint, so the rows read as Trust blue (dark on the dark list).
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon).frame(width: 28).foregroundStyle(quiet ? Color.mist : Color.trust)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).foregroundStyle(Color.ink)
                if !subtitle.isEmpty { Text(subtitle).font(.footnote).foregroundStyle(Color.mist) }
            }
        }
        #if os(macOS)
        // The whole row is the click target, as on the iPhone.
        .padding(.vertical, 4)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        #endif
    }
}

/// The brand tokens the extension uses (`brand/README.md`, `packages/ui` tokens; the app gets the
/// same from `OctaPassResources`), following light and dark appearance.
extension Color {
    private static func token(light: UInt32, dark: UInt32) -> Color {
        #if os(macOS)
        func color(_ rgb: UInt32) -> NSColor {
            NSColor(
                srgbRed: CGFloat((rgb >> 16) & 0xFF) / 255, green: CGFloat((rgb >> 8) & 0xFF) / 255,
                blue: CGFloat(rgb & 0xFF) / 255, alpha: 1)
        }
        let light = color(light), dark = color(dark)
        return Color(nsColor: NSColor(name: nil) { $0.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light })
        #else
        func color(_ rgb: UInt32) -> UIColor {
            UIColor(
                red: CGFloat((rgb >> 16) & 0xFF) / 255, green: CGFloat((rgb >> 8) & 0xFF) / 255,
                blue: CGFloat(rgb & 0xFF) / 255, alpha: 1)
        }
        let light = color(light), dark = color(dark)
        return Color(uiColor: UIColor { $0.userInterfaceStyle == .dark ? dark : light })
        #endif
    }

    /// "Trust" blue: the tint (Cancel, the search field), icons.
    static let trust = token(light: 0x2456F0, dark: 0x5C86FF)
    /// Filled buttons: always the light Trust blue, with white text.
    static let button = token(light: 0x2456F0, dark: 0x2456F0)
    /// "Ink": text.
    static let ink = token(light: 0x0B1220, dark: 0xF5F6F8)
    /// "Mist": secondary text.
    static let mist = token(light: 0x5E6576, dark: 0x9BA3B4)
}
