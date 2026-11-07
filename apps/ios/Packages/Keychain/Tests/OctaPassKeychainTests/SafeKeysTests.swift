import Foundation
import Security
import XCTest
@testable import OctaPassKeychain

/// The Keychain as a dictionary: the record logic is the same, and `swift test` on a Mac has no
/// shared access group to write to.
final class MemoryStorage: SafeKeyStorage, @unchecked Sendable {
    private let mutex = NSLock()
    private var items: [String: Data] = [:]
    private(set) var writes = 0

    func read(_ account: String) throws -> Data? { mutex.withLock { items[account] } }
    func write(_ data: Data, for account: String) throws {
        mutex.withLock {
            items[account] = data
            writes += 1
        }
    }
    func delete(_ account: String) throws { _ = mutex.withLock { items.removeValue(forKey: account) } }
    func accounts() throws -> [String] { mutex.withLock { Array(items.keys) } }
    func deleteAll() throws { mutex.withLock { items = [:] } }
}

/// A clock the test moves.
final class Clock: @unchecked Sendable {
    private let mutex = NSLock()
    private var time = Date(timeIntervalSince1970: 1_800_000_000)
    var now: Date { mutex.withLock { time } }
    func advance(_ seconds: TimeInterval) { mutex.withLock { time += seconds } }
}

final class SafeKeysTests: XCTestCase {
    let key = Data(repeating: 7, count: 32)
    var storage: MemoryStorage!
    var clock: Clock!
    var records: SafeKeyRecords!

    override func setUp() {
        storage = MemoryStorage()
        clock = Clock()
        let clock = clock!
        records = SafeKeyRecords(storage: storage, now: { clock.now })
    }

    func testAPublishedKeyIsGoodUntilItsDeadline() throws {
        try records.publish(itemId: "item-a", safeId: "safe-a", name: "Scans", key: key, lifetime: 15 * 60)
        let record = try XCTUnwrap(records.valid("item-a"))
        XCTAssertEqual(record.safeId, "safe-a")
        XCTAssertEqual(record.name, "Scans")
        XCTAssertEqual(record.key, key)
        XCTAssertEqual(record.deadline, clock.now.addingTimeInterval(15 * 60))

        clock.advance(15 * 60 - 1)
        XCTAssertNotNil(try records.valid("item-a"))
        clock.advance(1)
        // Expired: refused and deleted, so nothing can use it later either.
        XCTAssertNil(try records.valid("item-a"))
        XCTAssertNil(try storage.read("item-a"))
    }

    func testUsingTheAppMovesTheDeadline() throws {
        try records.publish(itemId: "item-a", safeId: "safe-a", name: "A", key: key, lifetime: 60)
        clock.advance(50)
        try records.extend(lifetime: 60)
        clock.advance(50)
        XCTAssertNotNil(try records.valid("item-a"))
        clock.advance(10)
        XCTAssertNil(try records.valid("item-a"))

        // Once run out, a touch doesn't bring it back: the app publishes again instead.
        try records.publish(itemId: "item-a", safeId: "safe-a", name: "A", key: key, lifetime: 60)
        clock.advance(61)
        try records.extend(lifetime: 60)
        XCTAssertNil(try records.valid("item-a"))
        XCTAssertEqual(try storage.accounts(), [])
    }

    func testAutoLockTimeIsTheLifetime() {
        XCTAssertEqual(SafeKeyRecords.lifetime(autoLockMinutes: 5), 300)
        XCTAssertEqual(SafeKeyRecords.lifetime(autoLockMinutes: 240), 240 * 60)
        // "Only when the app is closed" still runs out: a killed app can't lock.
        XCTAssertEqual(SafeKeyRecords.lifetime(autoLockMinutes: 0), SafeKeyRecords.longestLifetime)
    }

    func testGenerationGoesUpAndSurvivesARepublish() throws {
        try records.publish(itemId: "item-a", safeId: "safe-a", name: "A", key: key, lifetime: 60)
        try records.bumpGeneration("item-a")
        XCTAssertEqual(try records.valid("item-a")?.generation, 1)
        try records.publish(itemId: "item-a", safeId: "safe-a", name: "Renamed", key: key, lifetime: 60)
        XCTAssertEqual(try records.valid("item-a")?.generation, 1)
        XCTAssertEqual(try records.valid("item-a")?.name, "Renamed")
    }

    func testSomethingElseUnderTheNameIsDeleted() throws {
        try storage.write(Data("not a record".utf8), for: "item-a")
        XCTAssertNil(try records.valid("item-a"))
        XCTAssertEqual(try storage.accounts(), [])
        // A record filed under another Safe's name isn't that Safe's.
        let other = SafeKeyRecord(itemId: "item-b", safeId: "safe-b", name: "B", key: key, deadline: .distantFuture)
        try storage.write(try JSONEncoder().encode(other), for: "item-a")
        XCTAssertNil(try records.valid("item-a"))
    }

    func testCustodyPublishesOnUnlockAndDeletesEverythingOnLock() throws {
        let clock = clock!
        let custody = SafeKeyCustody(records: records, now: { clock.now })
        // Left from another session: gone at the first publish.
        try records.publish(itemId: "old", safeId: "safe-old", name: "Old", key: key, lifetime: 600)
        try custody.publish([
            .init(itemId: "item-a", safeId: "safe-a", name: "A", key: key),
            .init(itemId: "item-b", safeId: "safe-b", name: "B", key: key),
        ], lifetime: 600)
        XCTAssertEqual(Set(try records.itemIds()), ["item-a", "item-b"])

        // A Safe deleted elsewhere loses its record at the next publish.
        try custody.publish([.init(itemId: "item-a", safeId: "safe-a", name: "A", key: key)], lifetime: 600)
        XCTAssertEqual(try records.itemIds(), ["item-a"])

        // Locking (and signing out, and launching) leaves nothing for the extension.
        try custody.end()
        XCTAssertEqual(try records.itemIds(), [])
        XCTAssertNil(try records.valid("item-a"))
    }

    func testTouchesWriteTheKeychainOnlyNowAndThen() throws {
        let clock = clock!
        let custody = SafeKeyCustody(records: records, now: { clock.now })
        try custody.publish([.init(itemId: "item-a", safeId: "safe-a", name: "A", key: key)], lifetime: 600)
        let writes = storage.writes
        XCTAssertFalse(try custody.touch(lifetime: 600))
        clock.advance(59)
        XCTAssertFalse(try custody.touch(lifetime: 600))
        XCTAssertEqual(storage.writes, writes)
        clock.advance(1)
        XCTAssertTrue(try custody.touch(lifetime: 600))
        XCTAssertEqual(try records.valid("item-a")?.deadline, clock.now.addingTimeInterval(600))
        // A short auto-lock moves it more often: a tenth of the time.
        clock.advance(6)
        XCTAssertTrue(try custody.touch(lifetime: 60))
    }

    func testRecordsStayOnThisDeviceAndNeedItUnlocked() {
        let storage = KeychainSafeKeyStorage(accessGroup: "TEAM.app.octap.shared")
        let query = storage.query("item-a")
        XCTAssertEqual(query[kSecAttrAccessGroup as String] as? String, "TEAM.app.octap.shared")
        XCTAssertEqual(query[kSecAttrService as String] as? String, "app.octap.safeKey")
        XCTAssertEqual(query[kSecAttrSynchronizable as String] as? Bool, false)
        XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, true)
        XCTAssertEqual(storage.attributes[kSecAttrAccessible as String] as? String,
                       kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }

    func testLockFilesStayInTheSafesFolder() {
        let folder = URL(fileURLWithPath: "/tmp/safes")
        XCTAssertEqual(SafeStore.lockFile("1111-aaaa", in: folder)?.path, "/tmp/safes/.1111-aaaa.lock")
        for bad in ["", "..", "../x", "a/b", "é"] {
            XCTAssertNil(SafeStore.lockFile(bad, in: folder), bad)
        }
    }

    func testTheStoreLockKeepsTwoHoldersApart() async throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: folder) }
        let first = try await SafeStoreLock.acquire(safeId: "safe-a", in: folder)
        let started = Date()
        let second = Task { try await SafeStoreLock.acquire(safeId: "safe-a", in: folder) }
        try await Task.sleep(nanoseconds: 200_000_000)
        first.release()
        let lock = try await second.value
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(started), 0.2)
        lock.release()
        // Readers share it.
        let a = try await SafeStoreLock.acquire(safeId: "safe-a", in: folder, exclusive: false)
        let b = try await SafeStoreLock.acquire(safeId: "safe-a", in: folder, exclusive: false)
        a.release()
        b.release()
    }

    func testUniqueNamesNumberAsTheEngineDoes() {
        XCTAssertEqual(SafeStore.uniqueName("notes.txt", taken: []), "notes.txt")
        XCTAssertEqual(SafeStore.uniqueName("notes.txt", taken: ["notes.txt"]), "notes (2).txt")
        XCTAssertEqual(SafeStore.uniqueName("notes.txt", taken: ["notes.txt", "notes (2).txt"]), "notes (3).txt")
        XCTAssertEqual(SafeStore.uniqueName("Photos", taken: ["Photos"]), "Photos (2)")
        // A leading dot is a name, not an extension.
        XCTAssertEqual(SafeStore.uniqueName(".env", taken: [".env"]), ".env (2)")
    }
}
