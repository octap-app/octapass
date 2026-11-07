import AppKit
import Carbon.HIToolbox
import OctaPassResources
import OctaPassVault
import SwiftUI

// Quick access and the menu bar (plan 19 phase 2), as the Tauri app's (`quick.rs`, `tray.rs`): a
// small search panel on Cmd+Shift+Space or from the menu bar, to copy a login's username, password
// or one-time code without opening the vault window.

/// The menu bar's menu: show the vault window, quick access, lock, quit. Lock only while unlocked.
struct MenuBarMenu: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button(L10n.phone.mac.show) { MacWindows.showVault(openWindow) }
        Button(L10n.phone.mac.quickAccess) { QuickAccess.shared.show() }
            .keyboardShortcut(.space, modifiers: [.command, .shift])
        Divider()
        Button(L10n.nav.lockNow) { model.lockNow() }
            .disabled(!model.isUnlocked)
        Divider()
        Button(L10n.phone.mac.quit) { NSApp.terminate(nil) }
    }
}

/// The vault window, shown again from the menu bar or quick access, opened if it was closed.
@MainActor
enum MacWindows {
    /// SwiftUI's action to open a scene's window, kept from a view that has it, for AppKit callers.
    static var openWindow: OpenWindowAction?

    static func showVault(_ action: OpenWindowAction? = nil) {
        NSApp.activate(ignoringOtherApps: true)
        if let window = NSApp.windows.first(where: { $0.identifier?.rawValue == "vault" }) {
            window.makeKeyAndOrderFront(nil)
        } else {
            (action ?? openWindow)?(id: "vault")
        }
    }
}

/// Keeps the scene's `openWindow` for `MacWindows`.
struct OpenWindowKeeper: View {
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Color.clear.onAppear { MacWindows.openWindow = openWindow }
    }
}

/// The quick-access panel: floats above other apps, takes the keyboard, and hides when it loses
/// focus, like Spotlight. Cmd+Shift+Space shows and hides it from anywhere (a Carbon hot key, which
/// works in the sandbox and asks for no permission).
@MainActor
final class QuickAccess: NSObject, NSWindowDelegate {
    static let shared = QuickAccess()
    /// Posted when the panel shows: the search starts over.
    static let opened = Notification.Name("app.octap.quickAccess.opened")

    private var model: AppModel?
    private var panel: NSPanel?
    private var hotKey: EventHotKeyRef?

    func install(model: AppModel) {
        guard self.model == nil else { return }
        self.model = model
        registerHotKey()
    }

    func toggle() {
        if panel?.isVisible == true { hide() } else { show() }
    }

    func show() {
        guard let model else { return }
        let panel = panel ?? makePanel(model: model)
        self.panel = panel
        NSApp.activate(ignoringOtherApps: true)
        panel.center()
        panel.makeKeyAndOrderFront(nil)
        NotificationCenter.default.post(name: Self.opened, object: nil)
    }

    func hide() {
        panel?.orderOut(nil)
    }

    /// Set while the panel asks for Touch ID: the system's prompt takes focus, and the panel stays.
    var asking = false

    func windowDidResignKey(_ notification: Notification) {
        // A "Confirm it's you" sheet on the panel, or the Touch ID prompt, keeps it; anything else
        // hides it.
        if panel?.attachedSheet == nil, !asking { hide() }
    }

    /// Back to the front after the Touch ID prompt.
    func refocus() {
        guard let panel, panel.isVisible else { return }
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }

    private func makePanel(model: AppModel) -> NSPanel {
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 380),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered, defer: true)
        panel.titlebarAppearsTransparent = true
        panel.titleVisibility = .hidden
        panel.isMovableByWindowBackground = true
        panel.level = .floating
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = true
        panel.identifier = NSUserInterfaceItemIdentifier("quick")
        panel.title = L10n.phone.mac.quickAccess
        panel.delegate = self
        panel.contentView = NSHostingView(rootView:
            QuickAccessView(onClose: { [weak self] in self?.hide() })
                .background(ActivityTracker { model.recordActivity() })
                .modifier(SceneRoot(model: model)))
        return panel
    }

    private func registerHotKey() {
        var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        InstallEventHandler(GetApplicationEventTarget(), { _, _, _ in
            DispatchQueue.main.async { MainActor.assumeIsolated { QuickAccess.shared.toggle() } }
            return noErr
        }, 1, &spec, nil, nil)
        let id = EventHotKeyID(signature: OSType(0x4F50_5141), id: 1) // "OPQA"
        RegisterEventHotKey(UInt32(kVK_Space), UInt32(cmdKey | shiftKey), id, GetApplicationEventTarget(), 0, &hotKey)
    }
}

/// Search logins, copy from the one picked: Return copies its password, the row's buttons each
/// field. Esc closes. Locked, it says so and opens the vault window to unlock.
struct QuickAccessView: View {
    @Environment(AppModel.self) private var model
    let onClose: () -> Void
    @State private var query = ""
    @State private var logins: [ItemSummary] = []
    @State private var loaded = false
    @State private var selected: String?
    @FocusState private var searching: Bool

    private var trimmed: String { query.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        Group {
            if model.isUnlocked {
                VStack(spacing: 0) {
                    HStack(spacing: 10) {
                        Image(systemName: "magnifyingglass").foregroundStyle(Color.mist)
                        TextField(L10n.phone.mac.search, text: $query)
                            .textFieldStyle(.plain)
                            .font(.title3)
                            .focused($searching)
                            .onSubmit { copy(.password) }
                            .accessibilityIdentifier("quick-search")
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 30)
                    .padding(.bottom, 12)
                    Divider()
                    results
                }
            } else {
                QuickUnlock(onClose: onClose)
            }
        }
        .frame(width: 560, height: 380)
        .background(Color.paper)
        .task(id: "\(trimmed)|\(model.itemsVersion)|\(model.isUnlocked)") { await load() }
        .onReceive(NotificationCenter.default.publisher(for: QuickAccess.opened)) { _ in
            query = ""
            searching = true
        }
        .onExitCommand(perform: onClose)
        .onKeyPress(.downArrow) { move(1); return .handled }
        .onKeyPress(.upArrow) { move(-1); return .handled }
    }

    @ViewBuilder private var results: some View {
        if loaded, logins.isEmpty {
            Text(trimmed.isEmpty ? L10n.phone.mac.empty : L10n.phone.mac.noMatch(query: trimmed))
                .foregroundStyle(Color.mist)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollViewReader { scroller in
                List(logins, id: \.id, selection: $selected) { login in
                    QuickRow(login: login) { field in copy(field, login.id) }
                        .id(login.id)
                        .tag(login.id)
                }
                .listStyle(.plain)
                .onChange(of: selected) { _, id in if let id { scroller.scrollTo(id) } }
            }
        }
    }

    private func load() async {
        guard model.isUnlocked else { return }
        var filter = ListScope.type(.login).filter
        filter.query = trimmed.isEmpty ? nil : trimmed
        logins = (try? await model.vault.listItems(filter: filter)) ?? []
        loaded = true
        if selected == nil || !logins.contains(where: { $0.id == selected }) { selected = logins.first?.id }
    }

    private func move(_ step: Int) {
        guard !logins.isEmpty else { return }
        let index = logins.firstIndex { $0.id == selected } ?? -step
        selected = logins[max(0, min(logins.count - 1, index + step))].id
    }

    private func copy(_ field: QuickCopy.Field, _ id: String? = nil) {
        guard let id = id ?? selected else { return }
        Task { await QuickCopy.copy(field, itemId: id, model: model) }
    }
}

private struct QuickRow: View {
    let login: ItemSummary
    let onCopy: (QuickCopy.Field) -> Void

    var body: some View {
        HStack(spacing: 12) {
            Avatar(name: login.title, iconDomain: login.iconDomain, size: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(login.title.isEmpty ? L10n.detail.untitled : login.title).foregroundStyle(Color.ink)
                if let subtitle = login.subtitle, !subtitle.isEmpty {
                    Text(subtitle).font(.caption).foregroundStyle(Color.mist)
                }
            }
            Spacer()
            button(.username, "person", L10n.fields.username)
            button(.password, "key", L10n.fields.password)
            if login.hasTotp { button(.code, "clock", L10n.fields.totp) }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("quick-\(login.title)")
    }

    private func button(_ field: QuickCopy.Field, _ icon: String, _ what: String) -> some View {
        Button { onCopy(field) } label: { Image(systemName: icon) }
            .help(L10n.copy.action(what: what))
            .accessibilityLabel(L10n.copy.action(what: what))
    }
}

/// Quick access while the vault is locked: device unlock right here, asked at once when the panel
/// opens (it was opened to get at a login), or the vault window for the master password.
private struct QuickUnlock: View {
    @Environment(AppModel.self) private var model
    let onClose: () -> Void
    @State private var methods: UnlockMethods?
    @State private var busy = false
    @State private var failed = false

    private var canUseDevice: Bool {
        guard let methods else { return false }
        return methods.deviceUnlockEnabled && !methods.passwordRequired
    }

    var body: some View {
        EmptyStateView(icon: "lock", title: L10n.phone.mac.locked, message: failed ? L10n.phone.mac.unlockFailed : nil) {
            VStack(spacing: 10) {
                if let methods, canUseDevice {
                    Button {
                        Task { await unlock() }
                    } label: {
                        Label(L10n.lock.unlockWith(method: DeviceLockName.name(methods.label)), systemImage: DeviceLockName.icon(methods.label))
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(busy)
                    .accessibilityIdentifier("quick-unlock-device")
                }
                Button(L10n.phone.mac.openApp) {
                    onClose()
                    MacWindows.showVault()
                }
                .accessibilityIdentifier("quick-open-app")
            }
        }
        // Asked when the panel opens, not when the vault locks with the panel open.
        .task { methods = try? await model.vault.unlockMethods() }
        .onReceive(NotificationCenter.default.publisher(for: QuickAccess.opened)) { _ in
            failed = false
            Task {
                methods = try? await model.vault.unlockMethods()
                if canUseDevice, !busy { await unlock() }
            }
        }
    }

    private func unlock() async {
        busy = true
        QuickAccess.shared.asking = true
        defer {
            busy = false
            QuickAccess.shared.asking = false
            QuickAccess.shared.refocus()
        }
        do {
            try await model.vault.unlockWithDevice()
            model.unlockWasConfirmed()
            failed = false
        } catch {
            if !error.isVault(.deviceUnlockCancelled) { failed = true }
        }
    }
}

/// Copying one field of a login by its id, as the item's own buttons do: the password asks
/// "Confirm it's you" unless this unlock covers it, every copy counts as using the item.
enum QuickCopy {
    enum Field { case username, password, code }

    @MainActor
    static func copy(_ field: Field, itemId: String, model: AppModel) async {
        guard let item = try? await model.vault.getItem(id: itemId) else { return }
        let login: LoginDetails?
        switch item.details {
        case let .login(details), let .password(details): login = details
        default: login = nil
        }
        switch field {
        case .username:
            guard let value = login?.username, !value.isEmpty else { return }
            model.copy(value, what: L10n.fields.username, secret: false, item: itemId)
        case .password:
            guard let value = login?.password, !value.isEmpty else { return }
            guard await model.confirmReveal() else { return }
            model.copy(value, what: L10n.fields.password, item: itemId)
        case .code:
            guard let secret = login?.totp, !secret.isEmpty else { return }
            if let code = try? totpCode(totp: secret, atMs: nil) {
                model.copy(code.code, what: L10n.fields.totp, item: itemId)
            } else {
                model.toast = Toast(message: L10n.copy.failed, tone: .danger)
            }
        }
    }
}
