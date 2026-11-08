import LocalAuthentication
import XCTest
@testable import OctaPassKeychain

final class SharedContainerTests: XCTestCase {
    func testReadsTheCurrentAccountTheAppWrote() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        XCTAssertNil(SharedContainer.currentAccount(in: directory))

        // The shape `octapass-mobile-vault` writes.
        let json = """
        {
          "accounts": [
            { "tag": "aa", "email": "a@example.com", "serverUrl": "https://a.example/" },
            { "tag": "bb", "email": "b@example.com", "serverUrl": "http://localhost:8080/" }
          ],
          "current": "bb"
        }
        """
        try Data(json.utf8).write(to: directory.appendingPathComponent("accounts.json"))
        let account = try XCTUnwrap(SharedContainer.currentAccount(in: directory))
        XCTAssertEqual(account.email, "b@example.com")
        XCTAssertEqual(account.storeFile, "bb.opstore")
        XCTAssertEqual(account.deviceSecretName, "deviceSecret.bb")
        XCTAssertEqual(account.secretKeyName, "secretKey.bb")
        XCTAssertEqual(account.stayUnlockedName, "stayUnlocked.bb", "the name the vault gives it (Account::stay_unlocked_name)")
        XCTAssertEqual(account.fillKeyName, "unlockedFill.bb", "the name the vault gives it (Account::fill_key_name)")
    }

    func testNamesTheDeviceLock() {
        XCTAssertEqual(DeviceLock.label(.faceID), "Face ID")
        XCTAssertEqual(DeviceLock.label(.touchID), "Touch ID")
        XCTAssertEqual(DeviceLock.label(.none), "Passcode")
    }

    func testQueriesStayInTheSharedGroupAndTheDataProtectionKeychain() {
        let keychain = Keychain(accessGroup: "TEAM.app.octap.shared")
        let query = keychain.base("secretKey.aa", service: keychain.deviceService)
        XCTAssertEqual(query[kSecAttrAccessGroup as String] as? String, "TEAM.app.octap.shared")
        XCTAssertEqual(query[kSecAttrService as String] as? String, "app.octap.device")
        XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, true)
        XCTAssertNil(Keychain(accessGroup: nil).base("x", service: "s")[kSecAttrAccessGroup as String])
        // Its own service, so it never meets the device-unlock secret or a plain secret of that name.
        XCTAssertEqual(keychain.stayUnlockedService, "app.octap.stayUnlocked")
    }
}
