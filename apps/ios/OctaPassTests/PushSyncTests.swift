import UIKit
import XCTest
@testable import OctaPass

/// The parts of push sync that don't need Apple: the token's form, which pushes are ours, and what
/// iOS is told after the sync (the relay's payloads, plan 04 "Push relay").
final class PushSyncTests: XCTestCase {
    let syncPush: [AnyHashable: Any] = ["aps": ["content-available": 1], "octapass": "sync"]
    let alertPush: [AnyHashable: Any] = [
        "aps": [
            "alert": ["title-loc-key": "phone.native.pushAlertTitle", "loc-key": "phone.native.pushAlertBody"],
            "sound": "default", "content-available": 1,
        ],
        "octapass": "alert",
    ]

    func testTokenIsLowercaseHex() {
        XCTAssertEqual(PushSync.hex(Data([0x00, 0x0f, 0xab, 0xff, 0x10])), "000fabff10")
        XCTAssertEqual(PushSync.hex(Data()), "")
        let token = Data((0..<32).map { UInt8($0 * 7 & 0xff) })
        let hex = PushSync.hex(token)
        XCTAssertEqual(hex.count, 64)
        XCTAssertEqual(hex, hex.lowercased())
    }

    func testKinds() {
        XCTAssertEqual(PushSync.kind(syncPush), .sync)
        XCTAssertEqual(PushSync.kind(alertPush), .alert)
        XCTAssertNil(PushSync.kind(["aps": ["content-available": 1]]))
        XCTAssertNil(PushSync.kind(["octapass": "something-newer"]))
    }

    func testOurPushSyncs() async {
        let calls = Counter()
        let result = await PushSync.handle(syncPush) { calls.add() }
        XCTAssertEqual(result, .newData)
        XCTAssertEqual(calls.value, 1)
        let alert = await PushSync.handle(alertPush) { calls.add() }
        XCTAssertEqual(alert, .newData)
        XCTAssertEqual(calls.value, 2)
    }

    func testOtherPushesDoNothing() async {
        let calls = Counter()
        let result = await PushSync.handle(["aps": ["content-available": 1]]) { calls.add() }
        XCTAssertEqual(result, .noData)
        XCTAssertEqual(calls.value, 0)
    }

    func testFailedSyncFails() async {
        struct Offline: Error {}
        let result = await PushSync.handle(syncPush) { throw Offline() }
        XCTAssertEqual(result, .failed)
    }

    func testSlowSyncAnswersAtTheDeadline() async {
        let started = Date()
        let result = await PushSync.handle(syncPush, deadline: .milliseconds(100)) {
            try await Task.sleep(for: .seconds(5))
        }
        XCTAssertEqual(result, .failed)
        XCTAssertLessThan(Date().timeIntervalSince(started), 2)
    }
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.withLock { count } }
    func add() { lock.withLock { count += 1 } }
}
