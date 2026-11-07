import AppKit
import OctaPassResources
import ServiceManagement
import SwiftUI

/// Settings → Running in the background → Open when I sign in (plan 19): the app as a login item,
/// with `SMAppService`. Whether it's on is read from the system each time, so turning it off in
/// System Settings → General → Login Items shows here too. As in the Tauri app, it's offered only
/// to an app in an Applications folder: a login item pointing into a download or a build folder
/// breaks when that copy moves.
enum OpenAtLogin {
    static var isOn: Bool {
        switch SMAppService.mainApp.status {
        case .enabled, .requiresApproval: true
        default: false
        }
    }

    /// In /Applications or ~/Applications.
    static var isInstalled: Bool {
        let folder = Bundle.main.bundleURL.deletingLastPathComponent().standardizedFileURL.path
        let home = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications").path
        return folder == "/Applications" || folder == home
    }

    /// Throws what the system said when it couldn't. When macOS wants the person's approval first
    /// (an administrator's policy), it opens Login Items in System Settings.
    static func set(_ on: Bool) throws {
        if on {
            try SMAppService.mainApp.register()
            if SMAppService.mainApp.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
        } else {
            try SMAppService.mainApp.unregister()
        }
    }

    /// The system opened the app at login (the open-application event says so), so it starts in
    /// the background without its window. Read it while the app finishes launching.
    @MainActor static var launchedAtLogin: Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent else { return false }
        return event.eventID == AEEventID(kAEOpenApplication)
            && event.paramDescriptor(forKeyword: AEKeyword(keyAEPropData))?.enumCodeValue == OSType(keyAELaunchedAsLogInItem)
    }
}

/// The toggle, in `BackgroundSection`.
struct OpenAtLoginToggle: View {
    @Environment(\.scenePhase) private var scenePhase
    @State private var on = OpenAtLogin.isOn
    @State private var failure: String?

    var body: some View {
        Toggle(isOn: Binding(get: { on }, set: change)) {
            VStack(alignment: .leading, spacing: 2) {
                Text(L10n.background.openAtLogin)
                Text(help).font(.footnote).foregroundStyle(failure == nil ? Color.mist : Color.red)
            }
        }
        // Off and not in Applications: nothing it could do. On anyway (moved since): it can still go off.
        .disabled(!OpenAtLogin.isInstalled && !on)
        .accessibilityIdentifier("settings-open-at-login")
        .onChange(of: scenePhase) { _, _ in on = OpenAtLogin.isOn }
    }

    private var help: String {
        if let failure { return failure }
        return OpenAtLogin.isInstalled || on ? L10n.background.openAtLoginHelp : L10n.background.notInstalled
    }

    private func change(_ wanted: Bool) {
        do {
            try OpenAtLogin.set(wanted)
            failure = nil
        } catch {
            failure = L10n.background.failed(error: error.localizedDescription)
        }
        on = OpenAtLogin.isOn
    }
}
