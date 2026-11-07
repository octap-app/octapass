import OctaPassResources
import OctaPassVault
import SwiftUI
#if canImport(UIKit)
import UIKit
#else
import AppKit
#endif
import UniformTypeIdentifiers

/// Copying, as the web vault does it: secrets leave the clipboard after 30 seconds and never go to
/// other devices through Universal Clipboard.
enum Clipboard {
    static let clearAfter: TimeInterval = 30

    static func copy(_ value: String, secret: Bool = true) {
        #if os(iOS)
        var options: [UIPasteboard.OptionsKey: Any] = [:]
        if secret {
            options[.expirationDate] = Date().addingTimeInterval(clearAfter)
            options[.localOnly] = true
        }
        UIPasteboard.general.setItems([[UTType.plainText.identifier: value]], options: options)
        #else
        // The Mac's pasteboard has no expiry: a secret is cleared after 30 seconds unless something
        // else was copied meanwhile, and marked concealed and transient so clipboard managers and
        // Universal Clipboard leave it alone (the nspasteboard.org convention).
        let board = NSPasteboard.general
        board.clearContents()
        let item = NSPasteboardItem()
        item.setString(value, forType: .string)
        if secret {
            for marker in ["org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType"] {
                item.setString("", forType: NSPasteboard.PasteboardType(marker))
            }
        }
        board.writeObjects([item])
        guard secret else { return }
        let copied = board.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + clearAfter) {
            if NSPasteboard.general.changeCount == copied { NSPasteboard.general.clearContents() }
        }
        #endif
    }
}

extension AppModel {
    /// Copies and says so: "Password copied. Clears in 30 seconds." Copying from an item (`item`)
    /// counts as using it, for Frequently used and Recently used.
    func copy(_ value: String, what: String, secret: Bool = true, item: String? = nil) {
        Clipboard.copy(value, secret: secret)
        confirm(secret ? L10n.copy.copiedSecret(what: what) : L10n.copy.copied(what: what))
        if let item { vault.recordItemUse(id: item) }
    }
}

/// The item a screen shows (`ItemDetailView` sets it), so its copy buttons count a use of it.
private struct UsedItemKey: EnvironmentKey {
    static let defaultValue: String? = nil
}

extension EnvironmentValues {
    var usedItemId: String? {
        get { self[UsedItemKey.self] }
        set { self[UsedItemKey.self] = newValue }
    }
}

/// One field of an item: label above, value below, Copy at the end. Long values wrap.
struct FieldRow: View {
    @Environment(AppModel.self) private var model
    let label: String
    let value: String
    var what: String?
    var copyable = true
    var ltr = false
    var mono = false

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(label).font(.caption.weight(.medium)).foregroundStyle(Color.mist)
                Text(value)
                    .font(mono ? .secret() : .body)
                    .foregroundStyle(Color.ink)
                    .textSelection(.enabled)
                    .environment(\.layoutDirection, ltr ? .leftToRight : model.layoutDirection)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            if copyable {
                CopyButton(value: value, what: what ?? label, secret: false)
            }
        }
        .accessibilityElement(children: .contain)
    }
}

/// A secret: dots until Reveal, Copy without revealing, both after confirming it's the owner
/// (plan 03). Hidden again when the screen goes.
struct SecretFieldRow: View {
    @Environment(AppModel.self) private var model
    let label: String
    let value: String
    var what: String?
    var format: (String) -> String = { $0 }
    var multiline = false
    @State private var shown = false

    var body: some View {
        HStack(alignment: multiline ? .top : .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(label).font(.caption.weight(.medium)).foregroundStyle(Color.mist)
                Group {
                    if shown {
                        Text(format(value))
                            .font(multiline ? .body : .secret())
                            .textSelection(.enabled)
                    } else {
                        Text(String(repeating: "•", count: min(max(value.count, 8), 16)))
                            .font(.secret())
                            .accessibilityLabel(L10n.phone.native.hidden)
                    }
                }
                .foregroundStyle(Color.ink)
                .environment(\.layoutDirection, multiline ? model.layoutDirection : .leftToRight)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Button {
                Task {
                    if !shown {
                        guard await model.confirmReveal() else { return }
                    }
                    shown.toggle()
                    Haptics.tap()
                }
            } label: {
                Image(systemName: shown ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(shown ? L10n.common.hideWhat(what: what ?? label) : L10n.common.revealWhat(what: what ?? label))
            .accessibilityIdentifier("reveal-\(label)")
            CopyButton(value: value, what: what ?? label, secret: true, gate: .reveal)
        }
        .accessibilityElement(children: .contain)
        .onDisappear { shown = false }
    }
}

/// What a copy asks first: nothing, "Confirm it's you" unless this unlock covers it
/// (`confirmReveal`), or every time (`confirmIdentity`, for the Secret Key).
enum CopyGate { case none, reveal, always }

struct CopyButton: View {
    @Environment(AppModel.self) private var model
    @Environment(\.usedItemId) private var usedItemId
    let value: String
    let what: String
    let secret: Bool
    var gate = CopyGate.none

    var body: some View {
        Button {
            Task {
                switch gate {
                case .none: break
                case .reveal: guard await model.confirmReveal() else { return }
                case .always: guard await model.confirmIdentity() else { return }
                }
                model.copy(value, what: what, secret: secret, item: usedItemId)
            }
        } label: {
            Image(systemName: "doc.on.doc")
        }
        .buttonStyle(.borderless)
        .accessibilityLabel(L10n.copy.action(what: what))
        .accessibilityIdentifier("copy-\(what)")
    }
}

/// The current one-time code with its countdown; tapping copies it. Opened from the item, as the
/// web vault's `LiveCode`, and computed by the vault every second. A counter-based code has no
/// current code: a list row gets Next code instead, unless its vault can't be written.
struct LiveCode: View {
    @Environment(AppModel.self) private var model
    @Environment(\.usedItemId) private var usedItemId
    var itemId: String?
    var secret: String?
    var large = false
    var title = ""
    /// Opens the item again when it changes, so an edit from one kind of code to the other shows.
    var updatedAt: String?
    var canAdvance = true
    @State private var loaded: String?
    @State private var code: TotpCode?
    @State private var invalid = false
    @State private var counterBased = false

    var body: some View {
        Group {
            if counterBased {
                if let itemId, canAdvance { NextCodeButton(itemId: itemId, title: title) }
            } else {
                timeCode
            }
        }
        .task(id: "\(itemId ?? secret ?? "") \(updatedAt ?? "")") { await run() }
    }

    private var timeCode: some View {
        Button {
            if let code { model.copy(code.code, what: L10n.fields.totp, item: itemId ?? usedItemId) }
        } label: {
            HStack(spacing: 8) {
                if invalid {
                    Text(L10n.list.codeInvalid).font(.footnote).foregroundStyle(Color.dangerText)
                } else {
                    Text(code.map { Self.format($0.code) } ?? "––– –––")
                        .font(.secret(large ? .title2 : .body).weight(.semibold))
                        .foregroundStyle(Color.ink)
                        .contentTransition(.numericText())
                        .environment(\.layoutDirection, .leftToRight)
                    if let code {
                        CountdownRing(fraction: Double(code.remaining) / Double(max(code.period, 1)), warn: code.remaining <= 5)
                            .frame(width: large ? 22 : 18, height: large ? 22 : 18)
                    }
                }
            }
        }
        .buttonStyle(.borderless)
        .disabled(code == nil)
        .accessibilityLabel(code.map { "\(L10n.fields.totp) \($0.code.map(String.init).joined(separator: " "))" } ?? L10n.fields.totp)
        .accessibilityHint(L10n.copy.action(what: L10n.fields.totpShort))
    }

    static func format(_ code: String) -> String {
        // "123 456", "1234 5678".
        let half = (code.count + 1) / 2
        return "\(code.prefix(half)) \(code.suffix(code.count - half))"
    }

    private func run() async {
        var totp = secret
        if totp == nil, let itemId {
            let item = try? await model.vault.getItem(id: itemId)
            if case let .login(login)? = item?.details { totp = login.totp }
            if case let .password(login)? = item?.details { totp = login.totp }
        }
        guard let totp, !totp.isEmpty else { return }
        counterBased = isHotp(totp: totp)
        guard !counterBased else { return }
        while !Task.isCancelled {
            do {
                let next = try totpCode(totp: totp, atMs: nil)
                withAnimation { code = next }
                invalid = false
            } catch {
                invalid = true
                return
            }
            try? await Task.sleep(for: .seconds(1))
        }
    }
}

/// A list row's counter-based code: each press uses one up and copies it.
private struct NextCodeButton: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    let title: String
    @State private var busy = false

    var body: some View {
        Button {
            Task { await next() }
        } label: {
            if busy { ProgressView() } else { Text(L10n.detail.hotpNext).font(.footnote.weight(.medium)) }
        }
        .buttonStyle(.borderless)
        .disabled(busy)
        .accessibilityLabel(L10n.list.nextCode(title: title.isEmpty ? L10n.detail.untitled : title))
        .accessibilityIdentifier("next-code")
    }

    private func next() async {
        busy = true
        defer { busy = false }
        do {
            let next = try await model.vault.nextHotpCode(id: itemId)
            model.copy(next.code, what: L10n.fields.totp, item: itemId)
        } catch {
            model.show(error)
        }
    }
}

/// A counter-based code on the item (the web vault's `HotpField`). Each code exists once: asking
/// saves the moved counter first, then shows it, and only until the item is left. `itemId`: the
/// item it belongs to; left out where nothing can be saved (an old version, a shared copy, a vault
/// that can't be written), which shows only the counter.
struct HotpField: View {
    @Environment(AppModel.self) private var model
    var itemId: String?
    let secret: String
    @State private var code: HotpCode?
    @State private var busy = false
    /// What's typed under Change counter; nil while that's closed.
    @State private var counter: String?

    /// The typed number, in Western or Arabic digits, as long as the web vault takes it.
    private var entered: UInt64? {
        guard let counter, (1...15).contains(counter.count) else { return nil }
        let digits = counter.compactMap(\.wholeNumberValue)
        guard digits.count == counter.count, digits.allSatisfy({ $0 < 10 }) else { return nil }
        return digits.reduce(UInt64(0)) { $0 * 10 + UInt64($1) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(L10n.fields.totp).font(.caption.weight(.medium)).foregroundStyle(Color.mist)
                    Text(code.map { LiveCode.format($0.code) } ?? "––– –––")
                        .font(.secret(.title2).weight(.semibold))
                        .foregroundStyle(Color.ink)
                        .environment(\.layoutDirection, .leftToRight)
                        .accessibilityLabel(code.map { $0.code.map(String.init).joined(separator: " ") } ?? L10n.fields.totp)
                        .accessibilityIdentifier("hotp-code")
                }
                Spacer()
                if let code { CopyButton(value: code.code, what: L10n.fields.totpShort, secret: true) }
            }
            if let itemId {
                Button {
                    run { code = try await model.vault.nextHotpCode(id: itemId) }
                } label: {
                    HStack(spacing: 8) {
                        Text(L10n.detail.hotpNext)
                        if busy { ProgressView() }
                    }
                }
                .buttonStyle(.bordered)
                .disabled(busy)
                .accessibilityIdentifier("hotp-next")
            }
            if let next = hotpCounter(totp: secret) {
                Text(L10n.detail.hotpCounter(counter: String(next)))
                    .font(.footnote)
                    .foregroundStyle(Color.mist)
                    .accessibilityIdentifier("hotp-counter")
            }
            if let itemId { resync(itemId) }
        }
    }

    @ViewBuilder
    private func resync(_ itemId: String) -> some View {
        if counter == nil {
            Button(L10n.detail.hotpResync) { counter = hotpCounter(totp: secret).map { String($0) } ?? "" }
                .buttonStyle(.borderless)
                .font(.footnote)
                .accessibilityIdentifier("hotp-resync")
        } else {
            EditorField(label: L10n.detail.hotpCounterField, text: Binding(get: { counter ?? "" }, set: { counter = $0 }),
                        error: entered == nil ? L10n.detail.hotpCounterInvalid : nil, hint: L10n.detail.hotpCounterHint,
                        keyboard: .numberPad, mono: true, ltr: true)
                .accessibilityIdentifier("hotp-counter-field")
            HStack(spacing: 16) {
                Button(L10n.common.save) {
                    guard let entered else { return }
                    run {
                        _ = try await model.vault.setHotpCounter(id: itemId, counter: entered)
                        code = nil
                        counter = nil
                    }
                }
                .buttonStyle(.bordered)
                .disabled(entered == nil || busy)
                .accessibilityIdentifier("hotp-counter-save")
                Button(L10n.common.cancel) { counter = nil }
                    .buttonStyle(.borderless)
            }
        }
    }

    private func run(_ action: @escaping () async throws -> Void) {
        busy = true
        Task {
            defer { busy = false }
            do { try await action() } catch { model.show(error) }
        }
    }
}

/// The time left for a code, as a ring that empties.
struct CountdownRing: View {
    let fraction: Double
    let warn: Bool

    var body: some View {
        ZStack {
            Circle().stroke(Color.line, lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(warn ? Color.warn : Color.free, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: fraction)
        }
        .accessibilityHidden(true)
    }
}

/// Long-press on a list row: copy its username or password without opening it.
struct ItemCopyMenu: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    @State private var login: LoginDetails?

    var body: some View {
        Group {
            if let username = login?.username, !username.isEmpty {
                Button { model.copy(username, what: L10n.fields.username, secret: false, item: itemId) } label: {
                    Label(L10n.copy.action(what: L10n.fields.username), systemImage: "person")
                }
            }
            if let password = login?.password, !password.isEmpty {
                Button {
                    Task {
                        guard await model.confirmReveal() else { return }
                        model.copy(password, what: L10n.fields.password, item: itemId)
                    }
                } label: {
                    Label(L10n.copy.action(what: L10n.fields.password), systemImage: "key")
                }
            }
        }
        .task {
            let item = try? await model.vault.getItem(id: itemId)
            switch item?.details {
            case let .login(details)?, let .password(details)?: login = details
            default: login = nil
            }
        }
    }
}
