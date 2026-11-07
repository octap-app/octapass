import OctaPassKeychain
import OctaPassResources
import OctaPassVault
import XCTest
@testable import OctaPass

/// The Safe key records in the real Keychain, in the shared group the Files extension reads
/// (`OctaPassKeychain`'s own tests cover the same logic in memory).
final class SafeKeyRecordTests: XCTestCase {
    /// The app's own storage: the test host is a fresh app with a locked vault, so it has none.
    let storage = KeychainSafeKeyStorage()

    override func setUp() async throws {
        try storage.deleteAll()
    }

    override func tearDown() async throws {
        try storage.deleteAll()
    }

    func testRecordsGoInTheSharedKeychainAndComeOutOnLock() throws {
        let start = Date()
        let clock = { @Sendable in start }
        let records = SafeKeyRecords(storage: storage, now: clock)
        let custody = SafeKeyCustody(records: records, now: clock)
        let key = Data(repeating: 9, count: 32)
        try custody.publish([.init(itemId: "item-a", safeId: "safe-a", name: "Scans", key: key)], lifetime: 300)

        // What the extension reads, through its own instance.
        let record = try XCTUnwrap(SafeKeyRecords(storage: KeychainSafeKeyStorage(), now: clock).valid("item-a"))
        XCTAssertEqual(record.key, key)
        XCTAssertEqual(record.deadline, start.addingTimeInterval(300))

        // A sync moves the generation; a later write keeps it, in place.
        try records.bumpGeneration("item-a")
        try records.extend(lifetime: 600)
        XCTAssertEqual(try records.valid("item-a")?.generation, 1)
        XCTAssertEqual(try records.valid("item-a")?.deadline, start.addingTimeInterval(600))

        // Past the deadline the extension gets nothing, and the record is gone.
        let later = SafeKeyRecords(storage: storage, now: { start.addingTimeInterval(601) })
        XCTAssertNil(try later.valid("item-a"))
        XCTAssertEqual(try storage.accounts(), [])

        // Locking deletes every record.
        try custody.publish([
            .init(itemId: "item-a", safeId: "safe-a", name: "A", key: key),
            .init(itemId: "item-b", safeId: "safe-b", name: "B", key: key),
        ], lifetime: 300)
        XCTAssertEqual(Set(try storage.accounts()), ["item-a", "item-b"])
        try custody.end()
        XCTAssertEqual(try storage.accounts(), [])
    }

    func testTheSafesFolderIsInTheSharedContainer() throws {
        let group = try XCTUnwrap(SharedContainer.url())
        XCTAssertEqual(SafeStore.folder()?.deletingLastPathComponent().standardizedFileURL, group.standardizedFileURL)
    }
}
