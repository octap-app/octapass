import Foundation
import XCTest
@testable import OctaPassWatchCodes

final class WatchCodesTests: XCTestCase {
    /// The bundle the Rust tests pin (`crates/octapass-mobile/tests/fixtures/watch-bundle.json`):
    /// issued at `now`, with a 30-second and a 60-second item.
    private let now: UInt64 = 1_700_000_012_345

    private func fixture() throws -> String {
        let repo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try String(contentsOf: repo.appending(path: "crates/octapass-mobile/tests/fixtures/watch-bundle.json"), encoding: .utf8)
    }

    private func bundle() throws -> WatchBundle {
        let payload = WatchPayload.decode(try fixture())
        guard case let .bundle(bundle) = payload else {
            throw NSError(domain: "the fixture isn't a bundle", code: 1)
        }
        return bundle
    }

    private func entry(period: UInt64 = 30, startMs: UInt64 = 30_000, codes: [String] = ["111111", "222222"]) -> String {
        let list = codes.map { "\"\($0)\"" }.joined(separator: ",")
        return #"{"id":"a","title":"T","favorite":false,"period":\#(period),"digits":6,"startMs":\#(startMs),"codes":[\#(list)]}"#
    }

    private func payload(issued: UInt64 = 30_000, expires: UInt64 = 60_000, entries: [String]) -> WatchPayload {
        WatchPayload.decode(#"{"v":1,"issuedAtMs":\#(issued),"expiresAtMs":\#(expires),"entries":[\#(entries.joined(separator: ","))]}"#)!
    }

    func testReadsWhatTheCoreWrites() throws {
        let bundle = try bundle()
        XCTAssertEqual(bundle.issuedAtMs, now)
        XCTAssertEqual(bundle.expiresAtMs, now + 900_000)
        XCTAssertEqual(bundle.entries.map(\.title), ["GitHub", "بنك الأمل"])
        XCTAssertEqual(bundle.entries.map(\.period), [30, 60])
        XCTAssertEqual(bundle.entries.map(\.digits), [6, 8])
        XCTAssertTrue(bundle.entries[0].favorite)
        XCTAssertEqual(bundle.entries[0].id.count, 32)
    }

    func testPicksTheCodeForTheMoment() throws {
        let entry = try bundle().entries[0]
        XCTAssertEqual(entry.code(atMs: entry.startMs)?.text, entry.codes[0])
        XCTAssertEqual(entry.code(atMs: entry.startMs + 29_999)?.text, entry.codes[0])
        XCTAssertEqual(entry.code(atMs: entry.startMs + 30_000)?.text, entry.codes[1])
        let last = entry.startMs + 30_000 * UInt64(entry.codes.count - 1)
        XCTAssertEqual(entry.code(atMs: last)?.text, entry.codes.last)
        XCTAssertNil(entry.code(atMs: last + 30_000), "past the last code")
        XCTAssertNil(entry.code(atMs: entry.startMs - 1), "before the first code")
    }

    func testCountdown() throws {
        let entry = try bundle().entries[0]
        let start = try XCTUnwrap(entry.code(atMs: entry.startMs))
        XCTAssertEqual(start.remainingSeconds, 30)
        XCTAssertEqual(start.fraction, 1)
        let end = try XCTUnwrap(entry.code(atMs: entry.startMs + 29_999))
        XCTAssertEqual(end.remainingSeconds, 1)
        XCTAssertLessThan(end.fraction, 0.01)
    }

    func testDisplay() {
        func display(_ text: String) -> String { WatchCode(text: text, remainingMs: 1, periodMs: 1).display }
        XCTAssertEqual(display("123456"), "123 456")
        XCTAssertEqual(display("12345678"), "1234 5678")
        XCTAssertEqual(display("1234567"), "123 4567")
        XCTAssertEqual(display("2BCDF"), "2BCDF")
    }

    func testExpiresAtItsEndAndNeverLaterThanFifteenMinutes() throws {
        let bundle = try bundle()
        var codes = WatchCodes()
        codes.apply(.bundle(bundle))
        XCTAssertEqual(codes.rows(atMs: bundle.expiresAtMs - 1).count, 2)
        XCTAssertTrue(codes.rows(atMs: bundle.expiresAtMs).isEmpty)

        let long = WatchBundle(issuedAtMs: 0, expiresAtMs: 3_600_000, entries: bundle.entries)
        XCTAssertFalse(long.isExpired(atMs: 899_999))
        XCTAssertTrue(long.isExpired(atMs: 900_000))
    }

    func testForgettingExpiredCodes() {
        var codes = WatchCodes()
        codes.apply(payload(entries: [entry()]))
        codes.forgetExpired(atMs: 59_999)
        XCTAssertEqual(codes.rows(atMs: 59_999).count, 1)
        codes.forgetExpired(atMs: 60_000)
        XCTAssertEqual(codes, {
            var empty = WatchCodes()
            empty.apply(.clear(issuedAtMs: 30_000))
            return empty
        }())
        XCTAssertTrue(codes.rows(atMs: 30_000).isEmpty, "gone, even if the clock is set back")
    }

    func testAClearWins() {
        var codes = WatchCodes()
        codes.apply(payload(issued: 30_000, entries: [entry()]))
        XCTAssertEqual(WatchPayload.decode(#"{"v":1,"clear":true,"issuedAtMs":40000}"#), .clear(issuedAtMs: 40_000))
        codes.apply(.clear(issuedAtMs: 40_000))
        XCTAssertTrue(codes.rows(atMs: 45_000).isEmpty)
        codes.apply(payload(issued: 35_000, entries: [entry()]))
        XCTAssertTrue(codes.rows(atMs: 45_000).isEmpty, "a late bundle stays cleared")
        codes.apply(payload(issued: 50_000, expires: 80_000, entries: [entry(startMs: 30_000)]))
        XCTAssertEqual(codes.rows(atMs: 55_000).count, 1, "a newer one is shown")
    }

    func testBadPayloadsAreRefused() {
        XCTAssertNil(WatchPayload.decode(""))
        XCTAssertNil(WatchPayload.decode("not json"))
        XCTAssertNil(WatchPayload.decode(#"{"v":2,"issuedAtMs":1,"expiresAtMs":2,"entries":[]}"#))
        XCTAssertNil(WatchPayload.decode(#"{"v":1,"issuedAtMs":1}"#))
        guard case let .bundle(bundle) = payload(entries: [entry(period: 0), entry(codes: []), entry()]) else {
            return XCTFail("a bundle")
        }
        XCTAssertEqual(bundle.entries.count, 1, "entries that make no sense are left out")
    }

    func testAnEmptyVaultIsToldApartFromNoAnswer() {
        var codes = WatchCodes()
        XCTAssertFalse(codes.isEmptyVault(atMs: 30_000))
        codes.apply(payload(entries: []))
        XCTAssertTrue(codes.isEmptyVault(atMs: 30_000))
        XCTAssertFalse(codes.isEmptyVault(atMs: 60_000))
    }
}
