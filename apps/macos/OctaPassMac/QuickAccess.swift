import AppKit
import Carbon.HIToolbox
import OctaPassResources
import OctaPassVault
import SwiftUI

// Quick access and the menu bar (plan 19 phase 2), as the Tauri app's (`quick.rs`, `tray.rs`): a
// small search panel on Cmd+Shift+Space or from the menu bar, to copy a field of any item (a
// login's password, a card's number, a Wi-Fi password, an SSH public key…) without opening the
// vault window, or to open the item there.

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
            contentRect: NSRect(x: 0, y: 0, width: QuickAccessView.width, height: QuickAccessView.height),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered, defer: true)
        // Spotlight's look: no title bar or window buttons (Esc closes), the system's rounded
        // corners and shadow, and the view's own material showing through.
        panel.titlebarAppearsTransparent = true
        panel.titleVisibility = .hidden
        for button in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] {
            panel.standardWindowButton(button)?.isHidden = true
        }
        panel.isOpaque = false
        panel.backgroundColor = .clear
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

/// Search every item, grouped by type as the vault window groups them (Logins, Cards, Wi-Fi, SSH
/// keys…), and act on the one picked: Return runs its first action (a login's password, a card's
/// number), Cmd+1 to Cmd+9 the others, Cmd+K lists them all, Cmd+O opens the item in the vault
/// window. Up and Down move, Esc closes. Locked, it says so and unlocks (`QuickUnlock`).
struct QuickAccessView: View {
    static let width: CGFloat = 640
    static let height: CGFloat = 440

    @Environment(AppModel.self) private var model
    let onClose: () -> Void
    @State private var query = ""
    @State private var sections: [ListSection] = []
    @State private var loaded = false
    @State private var selected: String?
    /// The selected item, opened for its actions. Memory only, like the vault window's item.
    @State private var item: Item?
    @State private var actions: [QuickAction] = []
    /// The Cmd+K list, and the action highlighted in it.
    @State private var menuShown = false
    @State private var menuIndex = 0
    @FocusState private var searching: Bool

    private var trimmed: String { query.trimmingCharacters(in: .whitespaces) }
    private var rows: [ItemSummary] { sections.flatMap(\.items) }
    /// The selected item's actions, once it's open: never another item's while the next one opens.
    private var current: [QuickAction] { item?.id == selected ? actions : [] }

    var body: some View {
        Group {
            if model.isUnlocked {
                VStack(spacing: 0) {
                    searchField
                    Divider()
                    results
                    Divider()
                    footer
                }
                .overlay(alignment: .bottomTrailing) {
                    if menuShown, let item, !current.isEmpty {
                        QuickActionMenu(title: item.title, actions: current, index: menuIndex) { run($0) }
                            .padding(.trailing, 10)
                            .padding(.bottom, 46)
                            .transition(.opacity.combined(with: .scale(scale: 0.97, anchor: .bottomTrailing)))
                    }
                }
                .background { shortcuts }
            } else {
                QuickUnlock(onClose: onClose)
            }
        }
        .frame(width: Self.width, height: Self.height)
        .background(.regularMaterial)
        .task(id: "\(trimmed)|\(model.itemsVersion)|\(model.isUnlocked)") { await load() }
        .task(id: "\(selected ?? "")|\(model.itemsVersion)|\(model.isUnlocked)") { await open() }
        .onReceive(NotificationCenter.default.publisher(for: QuickAccess.opened)) { _ in
            query = ""
            menuShown = false
            searching = true
        }
        .onChange(of: query) { menuShown = false }
        .onChange(of: selected) { menuShown = false }
        .onExitCommand {
            if menuShown { menuShown = false } else { onClose() }
        }
        .onKeyPress(.downArrow) { move(1); return .handled }
        .onKeyPress(.upArrow) { move(-1); return .handled }
    }

    private var searchField: some View {
        HStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .font(.title3)
                .foregroundStyle(Color.mist)
            TextField(L10n.phone.mac.search, text: $query)
                .textFieldStyle(.plain)
                .font(.title2)
                .focused($searching)
                .onSubmit(submit)
                // The first time, and after an unlock in the panel, the field appears after
                // `QuickAccess.opened` was posted: it takes the keyboard itself.
                .onAppear { searching = true }
                .accessibilityIdentifier("quick-search")
        }
        .padding(.horizontal, 18)
        .padding(.top, 18)
        .padding(.bottom, 14)
    }

    @ViewBuilder private var results: some View {
        if loaded, rows.isEmpty {
            Text(trimmed.isEmpty ? L10n.phone.mac.empty : L10n.phone.mac.noMatch(query: trimmed))
                .foregroundStyle(Color.mist)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollViewReader { scroller in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        ForEach(sections, id: \.key) { section in
                            Section {
                                ForEach(section.items, id: \.id) { summary in
                                    row(summary)
                                }
                            } header: {
                                Text(Self.sectionTitle(section.key))
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(Color.mist)
                                    .padding(.horizontal, 10)
                                    .padding(.top, 10)
                                    .padding(.bottom, 3)
                                    .accessibilityAddTraits(.isHeader)
                            }
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.bottom, 8)
                }
                .onChange(of: selected) { _, id in
                    if let id { scroller.scrollTo(id) }
                }
            }
        }
    }

    private func row(_ summary: ItemSummary) -> some View {
        let isSelected = summary.id == selected
        return QuickRow(item: summary, selected: isSelected,
                        actions: isSelected ? Array(current.filter { $0.id != QuickActions.openId }.prefix(3)) : []) { run($0) }
            .id(summary.id)
            .onTapGesture(count: 2) { runPrimary() }
            .simultaneousGesture(TapGesture().onEnded { selected = summary.id })
    }

    /// The selected item's first action with Return, the action list with Cmd+K.
    private var footer: some View {
        HStack(spacing: 14) {
            Image("LogoTile")
                .resizable()
                .frame(width: 18, height: 18)
                .accessibilityHidden(true)
            Text(L10n.phone.mac.quickAccess)
                .font(.callout)
                .foregroundStyle(Color.mist)
            Spacer(minLength: 8)
            if let primary = current.first {
                Button { run(primary) } label: {
                    HStack(spacing: 6) {
                        Text(primary.title).foregroundStyle(Color.ink)
                        KeyCap(keys: "↩")
                    }
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("quick-primary")
                Divider().frame(height: 16)
            }
            Button { toggleMenu() } label: {
                HStack(spacing: 6) {
                    Text(L10n.phone.mac.actions).foregroundStyle(current.isEmpty ? Color.mist : Color.ink)
                    KeyCap(keys: "⌘K")
                }
            }
            .buttonStyle(.plain)
            .keyboardShortcut("k", modifiers: .command)
            .disabled(current.isEmpty)
            .accessibilityIdentifier("quick-actions")
        }
        .font(.callout)
        .lineLimit(1)
        .padding(.horizontal, 14)
        .frame(height: 40)
    }

    /// Cmd+1 to Cmd+9 for the actions in their order, Cmd+O for Open, and the vault window's own
    /// shortcuts for a login's username, password and one-time code (Ctrl+Cmd+C, Shift+Cmd+C,
    /// Option+Cmd+C). Invisible: the footer and the Cmd+K list show them.
    private var shortcuts: some View {
        let copies = current.filter { $0.id != QuickActions.openId }
        return ZStack {
            ForEach(Array(copies.prefix(9).enumerated()), id: \.element.id) { index, action in
                Button("") { run(action) }
                    .keyboardShortcut(KeyEquivalent(Character(String(index + 1))), modifiers: .command)
            }
            if let open = current.first(where: { $0.id == QuickActions.openId }) {
                Button("") { run(open) }.keyboardShortcut("o", modifiers: .command)
            }
            ForEach(QuickActions.windowShortcuts, id: \.id) { shortcut in
                if let action = copies.first(where: { $0.id == shortcut.id }) {
                    Button("") { run(action) }.keyboardShortcut("c", modifiers: shortcut.modifiers)
                }
            }
        }
        .opacity(0)
        .frame(width: 0, height: 0)
        .accessibilityHidden(true)
    }

    static func sectionTitle(_ key: String) -> String {
        let type = ItemType.from(name: key)
        return ListScope.itemTypes.contains(type) ? type.categoryName : L10n.list.otherType
    }

    private func load() async {
        guard model.isUnlocked else {
            sections = []
            item = nil
            actions = []
            loaded = false
            return
        }
        var filter = ListScope.all.filter
        filter.query = trimmed.isEmpty ? nil : trimmed
        sections = (try? await model.vault.arrangeItems(filter: filter, sort: .name, grouping: .type)) ?? []
        loaded = true
        if selected == nil || !rows.contains(where: { $0.id == selected }) { selected = rows.first?.id }
    }

    /// Opens the selected item for its actions; the panel shows only what the vault already has.
    private func open() async {
        guard model.isUnlocked, let id = selected else {
            item = nil
            actions = []
            return
        }
        guard let opened = try? await model.vault.getItem(id: id), opened.id == selected else { return }
        item = opened
        actions = QuickActions.of(opened)
        menuIndex = 0
    }

    private func move(_ step: Int) {
        if menuShown {
            guard !current.isEmpty else { return }
            menuIndex = max(0, min(current.count - 1, menuIndex + step))
            return
        }
        let list = rows
        guard !list.isEmpty else { return }
        let index = list.firstIndex { $0.id == selected } ?? -step
        selected = list[max(0, min(list.count - 1, index + step))].id
    }

    private func submit() {
        if menuShown, current.indices.contains(menuIndex) {
            run(current[menuIndex])
        } else {
            runPrimary()
        }
        // Return leaves the search field; it stays where typing goes.
        searching = true
    }

    private func runPrimary() {
        if let primary = current.first { run(primary) }
    }

    private func toggleMenu() {
        guard !current.isEmpty else { return }
        menuIndex = 0
        withAnimation(.snappy(duration: 0.15)) { menuShown.toggle() }
    }

    private func run(_ action: QuickAction) {
        menuShown = false
        Task { await action.run(model) }
    }
}

/// A result: the website's icon or the item's initial for logins and items with a website, the
/// type's symbol otherwise, the title and subtitle. The selected row shows its first actions as
/// buttons (a login's password, username and one-time code); the others mark passkeys and codes.
private struct QuickRow: View {
    let item: ItemSummary
    let selected: Bool
    let actions: [QuickAction]
    let onRun: (QuickAction) -> Void

    var body: some View {
        HStack(spacing: 10) {
            QuickIcon(item: item)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title.isEmpty ? L10n.detail.untitled : item.title)
                    .foregroundStyle(Color.ink)
                    .lineLimit(1)
                if let subtitle = item.subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.callout)
                        .foregroundStyle(Color.mist)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            if selected {
                ForEach(actions) { action in
                    Button { onRun(action) } label: {
                        Image(systemName: action.icon)
                            .frame(width: 26, height: 22)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(Color.ink)
                    .help(action.title)
                    .accessibilityLabel(action.title)
                    .accessibilityIdentifier("quick-row-\(action.id)")
                }
            } else {
                HStack(spacing: 6) {
                    if item.hasPasskey { Image(systemName: "person.badge.key").accessibilityLabel(L10n.list.hasPasskey) }
                    if item.hasTotp { Image(systemName: "clock").accessibilityLabel(L10n.list.hasTotp) }
                }
                .font(.footnote)
                .foregroundStyle(Color.mist)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .frame(minHeight: 44)
        .background {
            if selected {
                RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.trust.opacity(0.18))
            }
        }
        .contentShape(Rectangle())
        .accessibilityElement(children: .contain)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("quick-\(item.title)")
    }
}

private struct QuickIcon: View {
    let item: ItemSummary

    var body: some View {
        if item.itemType == .login || item.iconDomain != nil {
            Avatar(name: item.title, iconDomain: item.iconDomain, size: 28)
        } else {
            Image(systemName: item.itemType.icon)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Color.trustText)
                .frame(width: 28, height: 28)
                .background(Color.trust.opacity(0.13), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .accessibilityHidden(true)
        }
    }
}

/// Cmd+K: every action of the selected item with its shortcut. Up and Down move, Return runs, Esc
/// closes, as the panel's own keys do.
private struct QuickActionMenu: View {
    let title: String
    let actions: [QuickAction]
    let index: Int
    let onRun: (QuickAction) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title.isEmpty ? L10n.detail.untitled : title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(Color.mist)
                .lineLimit(1)
                .padding(.horizontal, 10)
                .padding(.vertical, 4)
            ForEach(Array(actions.enumerated()), id: \.element.id) { offset, action in
                Button { onRun(action) } label: {
                    HStack(spacing: 10) {
                        Image(systemName: action.icon)
                            .frame(width: 18)
                            .foregroundStyle(Color.mist)
                        Text(action.title)
                            .foregroundStyle(Color.ink)
                            .lineLimit(1)
                        Spacer(minLength: 12)
                        if let keys = shortcut(offset, action) { KeyCap(keys: keys) }
                    }
                    .padding(.horizontal, 10)
                    .frame(height: 28)
                    .background {
                        if offset == index {
                            RoundedRectangle(cornerRadius: 6, style: .continuous).fill(Color.trust.opacity(0.18))
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("quick-action-\(action.id)")
            }
        }
        .padding(6)
        .frame(width: 300)
        .background(.thickMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Color.line))
        .shadow(color: .black.opacity(0.18), radius: 16, y: 6)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(L10n.phone.mac.actions)
    }

    private func shortcut(_ offset: Int, _ action: QuickAction) -> String? {
        if offset == 0 { return "↩" }
        if action.id == QuickActions.openId { return "⌘O" }
        return offset < 9 ? "⌘\(offset + 1)" : nil
    }
}

/// A key or shortcut, as menus show them: left to right in every language.
private struct KeyCap: View {
    let keys: String

    var body: some View {
        Text(keys)
            .font(.caption.weight(.medium))
            .foregroundStyle(Color.mist)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(Color.mist.opacity(0.14), in: RoundedRectangle(cornerRadius: 4, style: .continuous))
            .environment(\.layoutDirection, .leftToRight)
            .accessibilityHidden(true)
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


/// One thing quick access can do with an item: copy one of its fields, or open it in the vault
/// window. An item's first action is Return's.
struct QuickAction: Identifiable {
    let id: String
    let title: String
    let icon: String
    let run: @MainActor (AppModel) async -> Void
}

/// Each type's actions, first the one people reach for (a login's password, a card's number, a
/// Wi-Fi password, an SSH public key, a note's text), then its other fields in the item's own
/// order, and Open in Octa Pass last. They copy as the item's own buttons do: secrets clear from
/// the clipboard after 30 seconds and go through `confirmReveal`, which doesn't ask while the
/// vault is unlocked (plan 03); every copy counts as using the item.
@MainActor
enum QuickActions {
    static let openId = "open"

    /// The vault window's copy shortcuts (Copy Username, Password, One-time code), for the actions
    /// of the same name.
    static let windowShortcuts = [
        WindowShortcut(id: "username", modifiers: [.command, .control]),
        WindowShortcut(id: "password", modifiers: [.command, .shift]),
        WindowShortcut(id: "code", modifiers: [.command, .option]),
    ]

    struct WindowShortcut {
        let id: String
        let modifiers: SwiftUI.EventModifiers
    }

    /// The field a table type's Return copies, before the rest in table order.
    private static let firstKeys: [String: [String]] = [
        "bankAccount": ["iban", "accountNumber"],
        "apiCredential": ["key", "secret"],
        "softwareLicense": ["licenseKey"],
        "idDocument": ["number"],
        "database": ["password", "connectionString"],
    ]

    static func of(_ item: Item) -> [QuickAction] {
        var list = Builder(itemId: item.id)
        switch item.details {
        case let .login(login), let .password(login):
            list.copy("password", L10n.fields.password, "key", login.password)
            list.copy("username", L10n.fields.username, "person", login.username, secret: false)
            list.code("code", login.totp)
            list.copy("website", L10n.fields.website, "globe", item.urls.first, secret: false)
            list.custom(login.customFields)
            list.notes(login.notes)
        case let .card(card):
            list.copy("number", L10n.fields.cardNumber, "creditcard", card.number)
            list.copy("expiry", L10n.fields.expiry, "calendar", card.expiry, secret: false)
            list.copy("cvv", L10n.fields.cvv, "lock", card.cvv)
            list.copy("cardholder", L10n.fields.cardholder, "person", card.cardholder, secret: false)
            list.copy("pin", L10n.fields.pin, "lock", card.pin)
            list.notes(card.notes)
        case let .identity(identity):
            let name = [identity.firstName, identity.lastName].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " ")
            list.copy("name", L10n.fields.fullName, "person", name, secret: false)
            list.copy("email", L10n.fields.email, "envelope", identity.email, secret: false)
            list.copy("phone", L10n.fields.phone, "phone", identity.phone, secret: false)
            list.copy("address", L10n.fields.address, "house", identity.address.map(addressLines), secret: false)
            list.copy("birthDate", L10n.fields.birthDate, "calendar", identity.birthDate.map(DateText.long), secret: false)
            list.notes(identity.notes)
        case let .secureNote(note):
            list.copy("note", L10n.fields.note, "note.text", note.notes)
        case let .document(document):
            list.notes(document.notes)
        case let .wifi(wifi):
            list.copy("password", L10n.fields.password, "key", wifi.password)
            list.copy("ssid", L10n.wifi.ssid, "wifi", wifi.ssid, secret: false)
            list.copy("username", L10n.fields.username, "person", wifi.username, secret: false)
        case let .sshKey(key):
            list.copy("publicKey", L10n.sshKey.publicKey, "key.horizontal", authorizedKeysLine(details: key), secret: false)
            list.copy("fingerprint", L10n.sshKey.fingerprint, "number", key.fingerprint, secret: false)
            list.copy("privateKey", L10n.sshKey.privateKey, "lock", key.privateKey)
            list.copy("passphrase", L10n.sshKey.passphrase, "lock", key.passphrase)
            list.custom(key.customFields)
            list.notes(key.notes)
        case let .environment(environment):
            if !environment.variables.isEmpty {
                let itemId = item.id
                list.add("dotenv", L10n.env.copyDotenv, "doc.text") { model in
                    guard await model.confirmReveal() else { return }
                    guard let text = try? environmentDotenv(details: environment) else {
                        model.toast = Toast(message: L10n.copy.failed, tone: .danger)
                        return
                    }
                    model.copy(text, what: L10n.env.copyDotenvWhat, item: itemId)
                }
            }
            for (index, variable) in environment.variables.enumerated() {
                list.copy("variable-\(index)", variable.key, "chevron.left.forwardslash.chevron.right", variable.value, secret: variable.concealed)
            }
            list.notes(environment.notes)
        case let .structured(type, details):
            structured(type, details, into: &list)
        case .maskedEmailProvider, .other:
            break
        }
        let id = item.id
        list.add(openId, L10n.phone.mac.openItem, "arrow.up.forward.app") { model in
            model.itemToShow = id
            QuickAccess.shared.hide()
            MacWindows.showVault()
        }
        return list.actions
    }

    /// Bank accounts, API credentials, licences, ID documents, crypto wallets, databases and custom
    /// items, from the vault's table (`fieldSpecs`), as their detail screen shows them.
    private static func structured(_ type: ItemType, _ details: StructuredDetails, into list: inout Builder) {
        if type == .cryptoWallet {
            for (index, entry) in details.addresses.enumerated() {
                let what = entry.label.flatMap { $0.isEmpty ? nil : $0 } ?? entry.network
                list.copy("address-\(index)", what.isEmpty ? L10n.typedItems.address : what, "qrcode", entry.address, secret: false)
            }
        }
        let first = firstKeys[type.name] ?? []
        let specs = fieldSpecs(itemType: type).filter { $0.style != .choice }
        let ordered = first.compactMap { key in specs.first { $0.key == key } } + specs.filter { !first.contains($0.key) }
        for spec in ordered {
            let value = details.value(spec.key)
            guard !value.isEmpty else { continue }
            let secret = spec.style == .secret || spec.style == .secretLong
            list.copy("field-\(spec.key)", StructuredNames.label(spec.key), secret ? "lock" : icon(spec.style),
                      StructuredNames.shown(spec, value), secret: secret)
        }
        if type == .custom {
            for (index, field) in details.fields.enumerated() where !field.value.isEmpty {
                if field.kind == "totp" {
                    list.code("typed-\(index)", field.value, what: field.label.isEmpty ? L10n.fields.totp : field.label)
                } else {
                    let plain = customKindIsPlain(kind: field.kind)
                    list.copy("typed-\(index)", field.label, plain ? "doc.on.doc" : "lock",
                              field.kind == "date" ? DateText.long(field.value) : field.value, secret: !plain)
                }
            }
        }
        list.custom(details.customFields)
        list.notes(details.notes)
    }

    private static func icon(_ style: FieldStyle) -> String {
        switch style {
        case .code, .port: "number"
        case .date: "calendar"
        case .email: "envelope"
        default: "doc.on.doc"
        }
    }

    /// An identity's address on lines, as its detail screen shows it.
    private static func addressLines(_ address: Address) -> String {
        let city = [address.city, address.region].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: ", ")
        return [address.line1, address.line2, city, address.postalCode, address.country]
            .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: "\n")
    }

    private struct Builder {
        let itemId: String
        var actions: [QuickAction] = []

        mutating func add(_ id: String, _ title: String, _ icon: String, _ run: @escaping @MainActor (AppModel) async -> Void) {
            actions.append(QuickAction(id: id, title: title, icon: icon, run: run))
        }

        /// Copies `value`, when there is one. A secret goes through `confirmReveal` first.
        mutating func copy(_ id: String, _ what: String, _ icon: String, _ value: String?, secret: Bool = true) {
            guard let value, !value.isEmpty else { return }
            let itemId = itemId
            add(id, L10n.copy.action(what: what), icon) { model in
                if secret {
                    guard await model.confirmReveal() else { return }
                }
                model.copy(value, what: what, secret: secret, item: itemId)
            }
        }

        /// The current one-time code, worked out when it's copied.
        mutating func code(_ id: String, _ secret: String?, what: String = L10n.fields.totp) {
            guard let secret, !secret.isEmpty else { return }
            let itemId = itemId
            add(id, L10n.copy.action(what: what), "clock") { model in
                if let code = try? totpCode(totp: secret, atMs: nil) {
                    model.copy(code.code, what: what, item: itemId)
                } else {
                    model.toast = Toast(message: L10n.copy.failed, tone: .danger)
                }
            }
        }

        mutating func custom(_ fields: [CustomField]) {
            for (index, field) in fields.enumerated() {
                copy("custom-\(index)", field.label, field.hidden ? "lock" : "doc.on.doc", field.value, secret: field.hidden)
            }
        }

        mutating func notes(_ notes: String?) {
            copy("notes", L10n.fields.notes, "note.text", notes)
        }
    }
}
