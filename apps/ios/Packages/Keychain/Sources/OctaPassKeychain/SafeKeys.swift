import Foundation
import Security

// Octa Pass Safe in the Files app (plan 03 History, 2026-11-04). The File Provider extension runs
// in its own process and can't show UI, so it can't unlock the vault. While the vault is unlocked,
// the app hands it each Safe's key through the shared Keychain, with a deadline; the app deletes
// every record when the vault locks, on sign-out and at launch, and the extension refuses an
// expired one. Both sides use what's in this file, so they agree on the format.

/// One Safe's key for the Files extension, as the app writes it.
public struct SafeKeyRecord: Codable, Equatable, Sendable {
    /// The Safe's item in the vault; also the File Provider domain's identifier.
    public let itemId: String
    /// Names the Safe's folder in the shared container's `safes` folder.
    public let safeId: String
    public let name: String
    /// The Safe's 256-bit key.
    public let key: Data
    /// After this, the record is no good: the extension deletes it and locks its drive.
    public var deadline: Date
    /// Goes up when the app changed the Safe's store itself (a sync), so the extension reads it
    /// again instead of trusting the tree it has in memory.
    public var generation: Int

    public init(itemId: String, safeId: String, name: String, key: Data, deadline: Date, generation: Int = 0) {
        self.itemId = itemId
        self.safeId = safeId
        self.name = name
        self.key = key
        self.deadline = deadline
        self.generation = generation
    }

    public func isExpired(at now: Date) -> Bool { now >= deadline }
}

/// Where the records are kept. The Keychain on a phone; memory in tests.
public protocol SafeKeyStorage: Sendable {
    func read(_ account: String) throws -> Data?
    /// Adds the record, or replaces the one there in place (never a delete first: the extension
    /// would see no key in between and close the Safe).
    func write(_ data: Data, for account: String) throws
    func delete(_ account: String) throws
    func accounts() throws -> [String]
    func deleteAll() throws
}

/// The shared Keychain: the access group the AutoFill extension also uses, readable only while the
/// phone is unlocked, never synced to iCloud or put in a backup (`…ThisDeviceOnly`).
public struct KeychainSafeKeyStorage: SafeKeyStorage {
    public static let service = "app.octap.safeKey"
    public let accessGroup: String?

    public init(accessGroup: String? = SharedContainer.keychainGroup) {
        self.accessGroup = accessGroup
    }

    func query(_ account: String?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
        ]
        if let account { query[kSecAttrAccount as String] = account }
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }

    /// What every record is written with.
    var attributes: [String: Any] {
        [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
    }

    public func read(_ account: String) throws -> Data? {
        var query = query(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw KeychainError.failed(status) }
        return data
    }

    public func write(_ data: Data, for account: String) throws {
        var changes = attributes
        changes[kSecValueData as String] = data
        let status = SecItemUpdate(query(account) as CFDictionary, changes as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw KeychainError.failed(status) }
        let item = query(account).merging(changes) { _, new in new }
        let added = SecItemAdd(item as CFDictionary, nil)
        guard added == errSecSuccess else { throw KeychainError.failed(added) }
    }

    public func delete(_ account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.failed(status) }
    }

    public func accounts() throws -> [String] {
        var query = query(nil)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = result as? [[String: Any]] else { throw KeychainError.failed(status) }
        return items.compactMap { $0[kSecAttrAccount as String] as? String }
    }

    public func deleteAll() throws {
        let status = SecItemDelete(query(nil) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.failed(status) }
    }
}

/// The records, as the app writes them and the extension reads them.
public struct SafeKeyRecords: Sendable {
    /// How long Files keeps a Safe open after the app was last used when auto-lock is off (0): the
    /// longest auto-lock choice. Nothing may stay valid for ever, since a killed app can't lock.
    public static let longestLifetime: TimeInterval = 240 * 60

    let storage: SafeKeyStorage
    let now: @Sendable () -> Date

    public init(storage: SafeKeyStorage = KeychainSafeKeyStorage(), now: @escaping @Sendable () -> Date = Date.init) {
        self.storage = storage
        self.now = now
    }

    /// How long a record stays good after the app was last used: the vault's auto-lock time.
    public static func lifetime(autoLockMinutes: UInt32) -> TimeInterval {
        autoLockMinutes == 0 ? longestLifetime : min(TimeInterval(autoLockMinutes) * 60, longestLifetime)
    }

    /// Writes (or rewrites) a Safe's record, good for `lifetime` from now. A rewrite keeps the
    /// generation, so an extension with the Safe open doesn't read it again for nothing.
    public func publish(itemId: String, safeId: String, name: String, key: Data, lifetime: TimeInterval) throws {
        let generation = (try? stored(itemId))?.generation ?? 0
        let record = SafeKeyRecord(
            itemId: itemId, safeId: safeId, name: name, key: key,
            deadline: now().addingTimeInterval(lifetime), generation: generation)
        try save(record)
    }

    /// The app is in use: every record is good for `lifetime` from now. One that already ran out
    /// isn't brought back (the extension may have closed its Safe on it); it's deleted, and the
    /// app publishes again if the vault is still unlocked.
    public func extend(lifetime: TimeInterval) throws {
        let now = now()
        for account in try storage.accounts() {
            guard var record = try stored(account) else { continue }
            if record.isExpired(at: now) {
                try storage.delete(account)
                continue
            }
            record.deadline = now.addingTimeInterval(lifetime)
            try save(record)
        }
    }

    /// The app changed the Safe's store: the extension reads it again before its next step.
    public func bumpGeneration(_ itemId: String) throws {
        guard var record = try stored(itemId) else { return }
        record.generation += 1
        try save(record)
    }

    /// The record the extension may use: nil when there's none or it ran out, which it deletes.
    public func valid(_ itemId: String) throws -> SafeKeyRecord? {
        guard let record = try stored(itemId) else { return nil }
        if record.isExpired(at: now()) {
            try storage.delete(itemId)
            return nil
        }
        return record
    }

    /// Every item id with a record, valid or not.
    public func itemIds() throws -> [String] {
        try storage.accounts()
    }

    public func remove(_ itemId: String) throws {
        try storage.delete(itemId)
    }

    /// The vault locked, someone signed out, or the app just started: no Safe stays open in Files.
    public func removeAll() throws {
        try storage.deleteAll()
    }

    func stored(_ itemId: String) throws -> SafeKeyRecord? {
        guard let data = try storage.read(itemId) else { return nil }
        guard let record = try? JSONDecoder().decode(SafeKeyRecord.self, from: data), record.itemId == itemId else {
            // Not something this version wrote: no good to anyone.
            try storage.delete(itemId)
            return nil
        }
        return record
    }

    func save(_ record: SafeKeyRecord) throws {
        try storage.write(try JSONEncoder().encode(record), for: record.itemId)
    }
}

/// What the app does with the records as the vault's session changes: the Safes it has keys for
/// while unlocked, the deadline moved forward while it's used, and nothing once it locks.
public final class SafeKeyCustody: @unchecked Sendable {
    /// A Safe whose key the unlocked vault gave out.
    public struct Grant: Equatable, Sendable {
        public let itemId: String
        public let safeId: String
        public let name: String
        public let key: Data

        public init(itemId: String, safeId: String, name: String, key: Data) {
            self.itemId = itemId
            self.safeId = safeId
            self.name = name
            self.key = key
        }
    }

    let records: SafeKeyRecords
    let now: @Sendable () -> Date
    private let mutex = NSLock()
    private var extended: Date?

    public init(records: SafeKeyRecords = SafeKeyRecords(), now: @escaping @Sendable () -> Date = Date.init) {
        self.records = records
        self.now = now
    }

    /// The vault is unlocked and these are its Safes: each gets a record good for `lifetime`, and
    /// a record for any other Safe (deleted, or from another account) goes.
    public func publish(_ grants: [Grant], lifetime: TimeInterval) throws {
        for grant in grants {
            try records.publish(itemId: grant.itemId, safeId: grant.safeId, name: grant.name, key: grant.key, lifetime: lifetime)
        }
        let wanted = Set(grants.map(\.itemId))
        for itemId in try records.itemIds() where !wanted.contains(itemId) {
            try records.remove(itemId)
        }
        mutex.withLock { extended = now() }
    }

    /// The app was used: the deadline moves to `lifetime` from now. Touches come with every tap,
    /// so the Keychain is written at most every `lifetime / 10` (and at least every minute).
    @discardableResult
    public func touch(lifetime: TimeInterval) throws -> Bool {
        let now = now()
        let due = mutex.withLock {
            guard let extended, now.timeIntervalSince(extended) < min(60, lifetime / 10) else {
                self.extended = now
                return true
            }
            return false
        }
        if due { try records.extend(lifetime: lifetime) }
        return due
    }

    /// The vault locked, someone signed out, or the app just started.
    public func end() throws {
        mutex.withLock { extended = nil }
        try records.removeAll()
    }
}

/// Where Safes live on the phone: one folder per Safe under the shared container's `safes`, so the
/// app (`openSafe`, `syncSafe`, `deleteSafe`) and the Files extension (`SafeDrive.openWithKey`)
/// see one store.
public enum SafeStore {
    public static func folder(in container: URL? = SharedContainer.url()) -> URL? {
        container?.appendingPathComponent("safes", isDirectory: true)
    }

    /// A Safe id the vault would accept as a folder name (the Rust side checks it too).
    public static func isPlainId(_ safeId: String) -> Bool {
        !safeId.isEmpty && safeId.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-") }
    }

    /// `name`, or `name (2).txt` as the engine numbers names, when `taken` holds it: the engine's
    /// rename replaces whatever has the name already, which Files and the app never mean. As
    /// Android's `SafeDocuments.uniqueName`.
    public static func uniqueName(_ name: String, taken: Set<String>) -> String {
        guard taken.contains(name) else { return name }
        let dot = name.lastIndex(of: ".").flatMap { $0 > name.startIndex ? $0 : nil }
        let stem = dot.map { String(name[..<$0]) } ?? name
        let suffix = dot.map { String(name[$0...]) } ?? ""
        var number = 2
        while taken.contains("\(stem) (\(number))\(suffix)") { number += 1 }
        return "\(stem) (\(number))\(suffix)"
    }

    /// The Darwin notification Finder's "Sign in" on a locked Safe posts on the Mac (the Safe unlock
    /// extension), asking the running app to unlock. Prefixed with the App Group: the only names
    /// the sandbox lets the app and its extensions share. It carries nothing, and only asks.
    public static var unlockRequest: String { "\(SharedContainer.appGroup).safes.unlock" }

    /// The Darwin notification the Files extension posts after it changes a Safe, so the app
    /// syncs a synced one soon (`SafeFiles.syncSoon`). It carries nothing, not even which Safe.
    public static var changed: String { "\(SharedContainer.appGroup).safes.changed" }

    /// The lock file both processes take before touching a Safe's folder: next to it, not inside,
    /// so deleting the Safe doesn't take the lock away from whoever holds it.
    public static func lockFile(_ safeId: String, in folder: URL) -> URL? {
        isPlainId(safeId) ? folder.appendingPathComponent(".\(safeId).lock") : nil
    }
}

/// An advisory `flock` on a Safe's lock file, so the app and the Files extension never change one
/// Safe's folder at the same time: opening a Safe clears its temporary files, and each process
/// holds its own tree in memory. Taking it blocks, so never on the main thread or in Swift's
/// cooperative pool; `acquire` runs it on a dispatch queue. Held only for one step: iOS ends an
/// app suspended while it holds a lock in a shared container.
public final class SafeStoreLock: @unchecked Sendable {
    private var descriptor: Int32
    private let mutex = NSLock()

    /// Blocks until the lock is free.
    public init(safeId: String, in folder: URL, exclusive: Bool = true) throws {
        guard let file = SafeStore.lockFile(safeId, in: folder) else { throw CocoaError(.fileNoSuchFile) }
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let descriptor = open(file.path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        while flock(descriptor, exclusive ? LOCK_EX : LOCK_SH) != 0 {
            guard errno == EINTR else {
                let code = errno
                close(descriptor)
                throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
            }
        }
        self.descriptor = descriptor
    }

    /// Waits for the lock on a dispatch thread.
    public static func acquire(safeId: String, in folder: URL, exclusive: Bool = true) async throws -> SafeStoreLock {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result { try SafeStoreLock(safeId: safeId, in: folder, exclusive: exclusive) })
            }
        }
    }

    public func release() {
        mutex.lock()
        defer { mutex.unlock() }
        guard descriptor >= 0 else { return }
        flock(descriptor, LOCK_UN)
        close(descriptor)
        descriptor = -1
    }

    deinit { release() }
}
