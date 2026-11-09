import Foundation

/// What the app and its watchdog (`Watchdog/main.swift`, plan 19) share, compiled into both.
///
/// While the app runs, a file in the App Group container holds its process ID. The app removes it
/// whenever it quits in order (Quit Octa Pass in the menu bar, Cmd+Q, Quit in the Dock, logging
/// out), which it can't do when it's force quit or crashes. So when the app ends with the file
/// still naming it, it didn't mean to, and the watchdog starts it again in the background.
enum WatchdogMarker {
    /// The watchdog starts the app with this: in the background, with no window. A sandboxed app's
    /// arguments don't reach the app it opens, so the watchdog leaves a note as well
    /// (`requestBackground`).
    static let backgroundArgument = "--background"
    /// The watchdog's bundle, inside the app's.
    static let helperPath = "Contents/Library/LoginItems/Octa Pass Watchdog.app"

    private static var url: URL? { file("app-running.pid") }

    private static func file(_ name: String) -> URL? {
        guard let group = (Bundle.main.object(forInfoDictionaryKey: "OctaPassAppGroup") as? String), !group.isEmpty
        else { return nil }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)?.appending(path: name)
    }

    /// The watchdog, just before it opens the app: start in the background.
    static func requestBackground() {
        guard let note = file("background-start") else { return }
        try? Data(String(Date().timeIntervalSince1970).utf8).write(to: note, options: .atomic)
    }

    /// The app, as it starts: whether the watchdog just asked for that. The note is used up, and
    /// one older than a minute (the watchdog's start that never happened) doesn't count.
    static func takeBackgroundRequest() -> Bool {
        guard let note = file("background-start"), let data = try? Data(contentsOf: note) else { return false }
        try? FileManager.default.removeItem(at: note)
        guard let time = TimeInterval(String(decoding: data, as: UTF8.self)) else { return false }
        return abs(Date().timeIntervalSince1970 - time) < 60
    }

    /// The running app's process ID, written as it starts.
    static func write(_ pid: pid_t) {
        guard let url else { return }
        try? Data(String(pid).utf8).write(to: url, options: .atomic)
    }

    /// Removed as the app quits in order.
    static func remove() {
        guard let url else { return }
        try? FileManager.default.removeItem(at: url)
    }

    /// The process ID in the file, if there is one.
    static func read() -> pid_t? {
        guard let url, let data = try? Data(contentsOf: url) else { return nil }
        return pid_t(String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
    }
}
