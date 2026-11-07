import Foundation

/// The keys of the dictionaries the phone and the watch exchange over Watch Connectivity.
public enum WatchLink {
    /// The phone's payload: the string `OctaPassVault.watchPayload` returned, passed on unread.
    public static let payload = "payload"
    /// The watch asking for a fresh payload.
    public static let refresh = "refresh"
}

/// A format this build doesn't know is ignored, never guessed at.
private let knownFormat = 1
/// The most a bundle may last, whatever it says: `WATCH_BUNDLE_TTL_MS` in the Rust core.
private let longestLifetimeMs: UInt64 = 15 * 60 * 1000

/// One item's codes, as the core made them.
public struct WatchEntry: Decodable, Equatable, Identifiable, Sendable {
    public let id: String
    public let title: String
    public let favorite: Bool
    /// Seconds per code.
    public let period: UInt64
    /// Characters per code.
    public let digits: UInt32
    /// When `codes[0]` started. `codes[n]` starts `n` periods later.
    public let startMs: UInt64
    public let codes: [String]

    /// The code for this moment, or nil before the first one or after the last.
    public func code(atMs now: UInt64) -> WatchCode? {
        guard now >= startMs else { return nil }
        let periodMs = period * 1000
        let index = (now - startMs) / periodMs
        guard index < UInt64(codes.count) else { return nil }
        let elapsedMs = (now - startMs) % periodMs
        return WatchCode(text: codes[Int(index)], remainingMs: periodMs - elapsedMs, periodMs: periodMs)
    }

    fileprivate var isUsable: Bool { period > 0 && period <= UInt64.max / 1000 && !codes.isEmpty }
}

/// The code to show now, with what the countdown ring needs.
public struct WatchCode: Equatable, Sendable {
    public let text: String
    public let remainingMs: UInt64
    public let periodMs: UInt64

    /// How much of the code's time is left, from 1 down to 0.
    public var fraction: Double { Double(remainingMs) / Double(periodMs) }
    /// Whole seconds left, rounded up, so it reaches 1 and never shows 0.
    public var remainingSeconds: Int { Int((remainingMs + 999) / 1000) }
    /// `123 456`, `1234 5678`. A Steam-style five-character code stays in one piece.
    public var display: String {
        guard text.count >= 6 else { return text }
        let half = text.count / 2
        return "\(text.prefix(half)) \(text.dropFirst(half))"
    }
}

public struct WatchBundle: Decodable, Equatable, Sendable {
    public let issuedAtMs: UInt64
    public let expiresAtMs: UInt64
    public let entries: [WatchEntry]

    public func isExpired(atMs now: UInt64) -> Bool {
        now >= min(expiresAtMs, issuedAtMs + longestLifetimeMs)
    }
}

/// What the phone sent.
public enum WatchPayload: Equatable, Sendable {
    case bundle(WatchBundle)
    case clear(issuedAtMs: UInt64)

    var issuedAtMs: UInt64 {
        switch self {
        case let .bundle(bundle): bundle.issuedAtMs
        case let .clear(issuedAtMs): issuedAtMs
        }
    }

    private struct Envelope: Decodable {
        let v: Int
        let clear: Bool?
        let issuedAtMs: UInt64
    }

    /// Nil for anything that isn't a payload of a known version. An entry that makes no sense is
    /// left out; the rest still show.
    public static func decode(_ text: String) -> WatchPayload? {
        let data = Data(text.utf8)
        let decoder = JSONDecoder()
        guard let envelope = try? decoder.decode(Envelope.self, from: data), envelope.v == knownFormat else {
            return nil
        }
        if envelope.clear == true { return .clear(issuedAtMs: envelope.issuedAtMs) }
        guard let bundle = try? decoder.decode(WatchBundle.self, from: data) else { return nil }
        return .bundle(WatchBundle(
            issuedAtMs: bundle.issuedAtMs, expiresAtMs: bundle.expiresAtMs,
            entries: bundle.entries.filter(\.isUsable)))
    }
}

/// What the watch has: the newest payload's codes, only until they expire.
public struct WatchCodes: Equatable, Sendable {
    private var bundle: WatchBundle?
    private var newestIssuedAtMs: UInt64 = 0

    public init() {}

    /// Payloads can arrive out of order: an older one never replaces a newer one, so a late
    /// bundle can't bring back what a clear removed.
    public mutating func apply(_ payload: WatchPayload) {
        guard payload.issuedAtMs >= newestIssuedAtMs else { return }
        newestIssuedAtMs = payload.issuedAtMs
        switch payload {
        case let .bundle(bundle): self.bundle = bundle
        case .clear: bundle = nil
        }
    }

    /// Drops the codes once they've expired, so they don't stay in memory.
    public mutating func forgetExpired(atMs now: UInt64) {
        if let bundle, bundle.isExpired(atMs: now) { self.bundle = nil }
    }

    /// The rows to show now, in the phone's order (favourites first). Empty when there's nothing
    /// valid: expired, cleared, or a clock too far from the phone's.
    public func rows(atMs now: UInt64) -> [(entry: WatchEntry, code: WatchCode)] {
        guard let bundle, !bundle.isExpired(atMs: now) else { return [] }
        return bundle.entries.compactMap { entry in entry.code(atMs: now).map { (entry, $0) } }
    }

    /// The phone has answered, with a live bundle, and the vault has no codes.
    public func isEmptyVault(atMs now: UInt64) -> Bool {
        bundle.map { !$0.isExpired(atMs: now) && $0.entries.isEmpty } ?? false
    }
}
