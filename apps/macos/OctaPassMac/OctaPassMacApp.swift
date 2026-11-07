import AppKit
import OctaPassResources
import OctaPassVault
import SwiftUI

/// The Mac app (plan 19): the iPhone and iPad app's screens in a Mac window, on the same vault.
/// `RootView` and everything under it are shared; this file is the Mac's window, menus and
/// lifecycle.
@main
struct OctaPassMacApp: App {
    @NSApplicationDelegateAdaptor(MacAppDelegate.self) private var delegate
    @State private var model = AppModel.live()
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage(MacPreferences.showInMenuBar) private var showInMenuBar = true

    var body: some Scene {
        Window("Octa Pass", id: "vault") {
            RootView()
                .modifier(SceneRoot(model: model))
                .background(ActivityTracker { model.recordActivity() })
                .background(OpenWindowKeeper())
                .onAppear {
                    QuickAccess.shared.install(model: model)
                    // The browser extension's bridge, the CLI session and the SSH agent (plan 19).
                    DesktopServices.shared.start(vault: model.vault)
                }
                .frame(minWidth: 860, minHeight: 540)
                .onOpenURL { url in
                    if OpenedLinks.accepts(url) { model.openedLinks.append(url.absoluteString) }
                }
                // Credential Exchange (macOS 26): another app's export, as on the iPhone.
                .onContinueUserActivity(CredentialExchange.activityType) { activity in
                    if let token = CredentialExchange.token(activity) { model.received.append(.token(token)) }
                }
        }
        .defaultSize(width: 1180, height: 760)
        .onChange(of: scenePhase) { _, phase in model.scenePhaseChanged(phase) }
        .commands { VaultCommands(model: model) }

        // Octa Pass ▸ Settings… (Cmd+,): the iPhone's Settings screen in a window of its own.
        Settings {
            MacSettings()
                .modifier(SceneRoot(model: model))
        }

        // The menu bar: show the vault, quick access, lock, quit (Settings → Running in the background).
        MenuBarExtra(isInserted: $showInMenuBar) {
            MenuBarMenu()
                .environment(model)
        } label: {
            Image("MenuBarIcon")
                .accessibilityLabel("Octa Pass")
        }
    }
}

/// The app keeps running with its window closed (quick access, the menu bar, the browser
/// extension, the CLI and the SSH agent), and the Dock icon opens the window again.
final class MacAppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        // The app keeps running with its window closed, so a quit usually finds no window open,
        // and restoring that would start the app with none: no window to unlock in, nothing on
        // screen but the menu bar icon. Opened by hand, the app always shows its window (at login
        // it's closed again below). Set in the app's own domain so it wins over the system-wide
        // "Close windows when quitting an application".
        UserDefaults.standard.set(false, forKey: "NSQuitAlwaysKeepsWindows")
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Opened at login (Settings → Running in the background): in the background, without the
        // vault window. SwiftUI opens the window as the app starts, so it's closed right after.
        guard MainActor.assumeIsolated({ OpenAtLogin.launchedAtLogin }) else { return }
        DispatchQueue.main.async {
            for window in NSApp.windows where window.identifier?.rawValue == "vault" { window.close() }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { DesktopServices.shared.stop() }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !hasVisibleWindows { MainActor.assumeIsolated { MacWindows.showVault() } }
        return true
    }
}

/// What every window of the app gets: the model, the language and its direction, the theme, the
/// toast, and the iPhone's control defaults.
struct SceneRoot: ViewModifier {
    @Bindable var model: AppModel

    func body(content: Content) -> some View {
        content
            .environment(model)
            // Every screen reads its strings again when the language changes.
            .id(model.languageVersion)
            .environment(\.layoutDirection, model.layoutDirection)
            .environment(\.locale, model.locale)
            .modifier(ThemeModifier(scheme: model.colorScheme))
            // The iPhone's default: text buttons without a bezel, red when destructive
            // (`MacTextButtonStyle`). Explicit styles still win. Fields
            // keep the Mac's box, except in the shared components that draw their own
            // (`LabeledField`).
            .buttonStyle(MacTextButtonStyle())
            .modifier(ToastOverlay(toast: $model.toast))
    }
}

/// The Settings window. Settings are the vault's, so they show while it's unlocked; locked, the
/// window says to unlock first.
struct MacSettings: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if model.isUnlocked {
                NavigationStack {
                    SettingsView()
                        .navigationDestination(for: Route.self) { RouteView(route: $0) }
                }
                .environment(VaultDirectory.shared)
            } else {
                EmptyStateView(icon: "lock", title: L10n.lock.title, message: L10n.phone.native.settingsUnlockFirst) {}
            }
        }
        .frame(minWidth: 560, idealWidth: 620, minHeight: 520, idealHeight: 680)
    }
}

/// The menu bar's vault commands, with the shortcuts a Mac user expects. Each works only when it
/// makes sense: Lock while unlocked, New item on a list that can take one, the copy commands on an
/// open login.
struct VaultCommands: Commands {
    let model: AppModel
    @FocusedValue(\.newItemCommand) private var newItem
    @FocusedValue(\.itemCommand) private var item

    var body: some Commands {
        CommandGroup(after: .appInfo) {
            Button(L10n.nav.lockNow) { model.lockNow() }
                .keyboardShortcut("l", modifiers: [.command, .control])
                .disabled(!model.isUnlocked)
        }
        // A password manager has one vault window, so File ▸ New is for items.
        CommandGroup(replacing: .newItem) {
            Button(Self.newTitle(.login)) { newItem?.add(.login) }
                .keyboardShortcut("n")
                .disabled(!(newItem?.types.contains(.login) ?? false))
            Menu(L10n.list.newItem) {
                ForEach(newItem?.types ?? [], id: \.self) { type in
                    Button(Self.newTitle(type)) { newItem?.add(type) }
                }
            }
            .disabled(newItem == nil)
        }
        CommandGroup(after: .pasteboard) {
            Divider()
            // SwiftUI's search field has no Find command of its own on the Mac.
            Button(L10n.list.search) { MacSearch.focus() }
                .keyboardShortcut("f")
                .disabled(!model.isUnlocked)
            Divider()
            Button(L10n.copy.action(what: L10n.fields.username)) { item?.copyUsername?() }
                .keyboardShortcut("c", modifiers: [.command, .control])
                .disabled(item?.copyUsername == nil)
            Button(L10n.copy.action(what: L10n.fields.password)) { item?.copyPassword?() }
                .keyboardShortcut("c", modifiers: [.command, .shift])
                .disabled(item?.copyPassword == nil)
            Button(L10n.copy.action(what: L10n.fields.totp)) { item?.copyCode?() }
                .keyboardShortcut("c", modifiers: [.command, .option])
                .disabled(item?.copyCode == nil)
        }
    }

    /// "New login", as the editor's title says it.
    static func newTitle(_ type: ItemType) -> String {
        L10n.text(forKey: "editor.new.\(type.name)") ?? type.typeName
    }
}

/// Edit ▸ Search (Cmd+F): into the window's search field. The list's `.searchable` field is a
/// search item in the window's toolbar; a field elsewhere in the window is the fallback.
enum MacSearch {
    @MainActor static func focus() {
        guard let window = NSApp.keyWindow ?? NSApp.mainWindow else { return }
        if let item = window.toolbar?.items.lazy.compactMap({ $0 as? NSSearchToolbarItem }).first {
            item.beginSearchInteraction()
        } else if let field = window.contentView.flatMap(searchField) {
            window.makeFirstResponder(field)
        }
    }

    private static func searchField(in view: NSView) -> NSSearchField? {
        if let field = view as? NSSearchField { return field }
        for child in view.subviews {
            if let field = searchField(in: child) { return field }
        }
        return nil
    }
}

/// Every key press, click and scroll in the app's windows counts as activity, so auto-lock waits for
/// the user to stop (plan 03). A local event monitor sees events without taking them.
struct ActivityTracker: View {
    let onActivity: () -> Void
    @State private var monitor: Any?

    var body: some View {
        Color.clear
            .onAppear {
                guard monitor == nil else { return }
                let handler = onActivity
                monitor = NSEvent.addLocalMonitorForEvents(
                    matching: [.keyDown, .leftMouseDown, .rightMouseDown, .scrollWheel]
                ) { event in
                    handler()
                    return event
                }
            }
            .onDisappear {
                if let monitor { NSEvent.removeMonitor(monitor) }
                monitor = nil
            }
    }
}

/// The Mac's screen locking or the Mac going to sleep: while staying unlocked, reveal and copy ask
/// again (plan 18), as the phone locking does.
enum MacDeviceLock {
    static func observe(_ locked: @escaping @MainActor () -> Void) -> NSObjectProtocol {
        let workspace = NSWorkspace.shared.notificationCenter
        let sleep = workspace.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { locked() }
        }
        // Posted by the login window; not public API, but stable since 10.x and what other apps use.
        DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main
        ) { _ in
            MainActor.assumeIsolated { locked() }
        }
        return sleep
    }
}
