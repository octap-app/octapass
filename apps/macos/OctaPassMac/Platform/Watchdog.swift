import AppKit

/// Keeps Octa Pass in the menu bar until it's quit on purpose (plan 19): if it's force quit or
/// crashes, its watchdog starts it again in the background, with the menu bar icon and no window.
///
/// The watchdog is a small faceless app inside this one (`Contents/Library/LoginItems`, source in
/// `Watchdog/`), which the app starts every time it starts, however it was opened. It isn't a login
/// item: opening at login stays `SMAppService.mainApp` (`OpenAtLogin`), and the watchdog only runs
/// while the app does. Quitting in order stops both (`WatchdogMarker`).
@MainActor
enum Watchdog {
    /// Started again by the watchdog, or by the system at login: stay in the background. Read once,
    /// as the app finishes launching: the watchdog's note is used up.
    static var launchedInBackground: Bool {
        let byWatchdog = WatchdogMarker.takeBackgroundRequest()
        return byWatchdog || CommandLine.arguments.contains(WatchdogMarker.backgroundArgument) || OpenAtLogin.launchedAtLogin
    }

    /// Watches the watchdog. NSWorkspace says nothing when a background-only app ends, so it's the
    /// running app's `isTerminated`.
    private static var helperWatch: NSKeyValueObservation?
    /// Held while it's watched: an observed object going away first crashes the app.
    private static var helper: NSRunningApplication?
    private static var lastHelperStart = Date.distantPast
    private static var quitting = false

    /// As the app finishes launching.
    static func start() {
        guard isWanted else { return }
        WatchdogMarker.write(ProcessInfo.processInfo.processIdentifier)
        startHelper()
    }

    /// The watchdog gone while the app runs (it was force quit too): start it again, once in a
    /// while at most, so one that can't start isn't tried in a loop.
    private static func watch(_ running: NSRunningApplication) {
        helperWatch?.invalidate()
        helperWatch = nil
        helper = running
        helperWatch = running.observe(\.isTerminated, options: [.initial, .new]) { running, _ in
            guard running.isTerminated else { return }
            DispatchQueue.main.async { helperEnded() }
        }
    }

    private static func helperEnded() {
        guard !quitting, Date().timeIntervalSince(lastHelperStart) > 30 else { return }
        startHelper()
    }

    /// As the app quits in order: the watchdog sees the marker gone and stops too.
    static func stop() {
        quitting = true
        WatchdogMarker.remove()
    }

    private static var helperURL: URL { Bundle.main.bundleURL.appending(path: WatchdogMarker.helperPath) }

    private static func startHelper() {
        lastHelperStart = Date()
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = false
        configuration.addsToRecentItems = false
        configuration.promptsUserIfNeeded = false
        NSWorkspace.shared.openApplication(at: helperURL, configuration: configuration) { helper, error in
            if let error { NSLog("Octa Pass: the watchdog didn't start: %@", error.localizedDescription) }
            guard let helper else { return }
            DispatchQueue.main.async { watch(helper) }
        }
    }

    /// Not under the UI tests, which end the app themselves, nor under a debugger, whose Stop
    /// would only bring the app back.
    private static var isWanted: Bool {
        if ProcessInfo.processInfo.environment["OCTAPASS_RESET"] == "1" { return false }
        if isDebugged { return false }
        return FileManager.default.fileExists(atPath: helperURL.path)
    }

    private static var isDebugged: Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&name, u_int(name.count), &info, &size, nil, 0) == 0 else { return false }
        return info.kp_proc.p_flag & P_TRACED != 0
    }
}
