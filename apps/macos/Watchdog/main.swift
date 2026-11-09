import AppKit

// Octa Pass Watchdog (plan 19): a faceless app inside Octa Pass (Contents/Library/LoginItems) that
// starts Octa Pass again, in the background, when it's force quit or crashes, so its menu bar icon
// comes back. Octa Pass starts it every time it starts (OctaPassMac/Platform/Watchdog.swift). It
// ends when Octa Pass quits in order, which removes the marker naming its process
// (WatchdogMarker), and at logout. It has no vault, no key and no network: it only watches which
// apps end and opens one.

@MainActor
final class WatchdogDelegate: NSObject, NSApplicationDelegate {
    /// Octa Pass.app: this bundle is its Contents/Library/LoginItems/Octa Pass Watchdog.app.
    private let appURL = Bundle.main.bundleURL
        .deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
    /// When it was started again lately: a crash at every start isn't tried for ever.
    private var restarts: [Date] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        // One watchdog, and only while Octa Pass runs (not when macOS reopens it at login on its own).
        let me = ProcessInfo.processInfo.processIdentifier
        let others = NSRunningApplication.runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? "")
            .filter { $0.processIdentifier != me }
        guard others.isEmpty, !runningApps.isEmpty else { exit(0) }

        let workspace = NSWorkspace.shared.notificationCenter
        workspace.addObserver(forName: NSWorkspace.didTerminateApplicationNotification, object: nil, queue: .main) { note in
            let ended = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication
            MainActor.assumeIsolated { self.ended(ended) }
        }
        // Logging out or shutting down ends Octa Pass too: nothing to start again.
        workspace.addObserver(forName: NSWorkspace.willPowerOffNotification, object: nil, queue: .main) { _ in
            exit(0)
        }
    }

    /// The copies of Octa Pass running from the bundle this watchdog is in. Its bundle ID comes from
    /// this one's Info.plist: the sandbox may not let the watchdog read the app's.
    private var runningApps: [NSRunningApplication] {
        guard let id = Bundle.main.object(forInfoDictionaryKey: "OctaPassAppBundleIdentifier") as? String else { return [] }
        return NSRunningApplication.runningApplications(withBundleIdentifier: id).filter(isOurs)
    }

    /// From this bundle, not another copy of Octa Pass (a build folder's, say).
    private func isOurs(_ app: NSRunningApplication) -> Bool {
        app.bundleURL.map(Self.place) == Self.place(appURL)
    }

    /// A bundle's path to compare, worked out from the path alone: the sandbox may not let the
    /// watchdog look at the folders to resolve links. The system's own links (/tmp, /var, /etc
    /// are in /private) are the ones a path is given both ways.
    private static func place(_ url: URL) -> String {
        var path = url.standardizedFileURL.path
        while path.count > 1, path.hasSuffix("/") { path.removeLast() }
        for link in ["/tmp/", "/var/", "/etc/"] where path.hasPrefix("/private" + link) {
            path.removeFirst("/private".count)
        }
        return path
    }

    private func ended(_ app: NSRunningApplication?) {
        guard let app, isOurs(app) else { return }
        guard WatchdogMarker.read() == app.processIdentifier else {
            // Quit in order: the marker is gone, and the watchdog stops too. Unless it was opened
            // again already: then that one is watched.
            if runningApps.isEmpty { exit(0) }
            return
        }
        // A moment for the system to finish with the old process, then once more.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.restart() }
    }

    private func restart() {
        // Opened again meanwhile (by hand): it's watched as it is.
        guard runningApps.isEmpty else { return }
        let now = Date()
        restarts = restarts.filter { now.timeIntervalSince($0) < 120 }
        // Ended three times in two minutes: something's wrong, and starting it again won't help.
        guard restarts.count < 3 else { exit(0) }
        restarts.append(now)

        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = false
        configuration.addsToRecentItems = false
        configuration.promptsUserIfNeeded = false
        configuration.arguments = [WatchdogMarker.backgroundArgument]
        // This copy, even while another copy of Octa Pass runs (a build folder's): otherwise
        // LaunchServices hands back that one and starts nothing. This one isn't running (above).
        configuration.createsNewApplicationInstance = true
        WatchdogMarker.requestBackground()
        NSWorkspace.shared.openApplication(at: appURL, configuration: configuration) { _, error in
            // Gone or moved: nothing more to watch.
            if let error {
                NSLog("Octa Pass Watchdog: couldn't start Octa Pass: %@", error.localizedDescription)
                // So the next start, by hand, shows the window.
                _ = WatchdogMarker.takeBackgroundRequest()
                exit(0)
            }
        }
    }
}

let application = NSApplication.shared
let delegate = MainActor.assumeIsolated { WatchdogDelegate() }
application.delegate = delegate
application.run()
