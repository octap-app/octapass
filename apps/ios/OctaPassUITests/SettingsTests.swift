import CryptoKit
import XCTest

/// The tools and Settings on a new account: the generator, Health, two-step sign-in turned on
/// and used to sign in again, and Arabic with the layout mirrored.
final class SettingsTests: UITestCase {
    func testTwoStepSignInAndArabic() throws {
        launchFresh()
        let email = "ios-\(UUID().uuidString.prefix(8).lowercased())@example.com"
        let secretKey = signUpAndOpenVault(email: email)

        // The generator is in the vault's lists, one step back from All items; Safes has its tab.
        tab(0)
        waitFor(element("new-item"))
        tap("BackButton")
        scrollAndTap("sidebar-generator")
        let generated = waitFor(element("generated-password"))
        let first = generated.value as? String
        tap("regenerate")
        XCTAssertNotEqual(element("generated-password").value as? String, first)
        snap("40-generator")

        tab(2)
        waitFor(textContaining("of 100"), timeout: 60)
        reveal("recovery-map")
        snap("41-health")

        // Two-step sign-in with an authenticator app: the test is the authenticator.
        tab(3)
        scrollAndTap("settings-two-step")
        tap("two-step-turn-on")
        type(Self.password, into: "two-step-password")
        tap("two-step-continue")
        // "Setup key, ABCD…": the row's label, then the key.
        let key = waitFor(element("two-step-setup-key"), timeout: 30).label.components(separatedBy: ", ").last ?? ""
        // A code lasts 30 seconds; on a busy Mac typing it can take longer, so a rejected one is
        // typed again, fresh.
        for _ in 0..<3 {
            type(try Self.totp(key), into: "two-step-confirm-code")
            tap("two-step-confirm")
            if element("two-step-recovery-codes").waitForExistence(timeout: 30) { break }
        }
        waitFor(element("two-step-recovery-codes"), timeout: 5)
        snap("42-recovery-codes")
        // A Form toggle flips from its switch, not its label.
        reveal("two-step-saved").coordinate(withNormalizedOffset: CGVector(dx: 0.92, dy: 0.5)).tap()
        tap("two-step-done")
        gone(element("two-step-done"))

        // Signing in again asks for a code.
        tap("BackButton")
        scrollAndTap("settings-sign-out")
        type(email, into: "email")
        type(Self.password, into: "master-password")
        type(secretKey, into: "secret-key")
        tap("sign-in")
        waitFor(element("two-step-code"), timeout: 60)
        snap("43-two-step")
        // A fresh code again if the first one ran out while it was typed.
        for _ in 0..<3 {
            type(try Self.totp(key), into: "two-step-code")
            tap("verify")
            if app.tabBars.buttons.firstMatch.waitForExistence(timeout: 60) { break }
        }
        waitForVault(timeout: 10)

        // Arabic: the strings and the layout follow at once.
        tab(3)
        scrollAndTap("settings-language")
        waitFor(app.buttons["العربية"].firstMatch).tap()
        waitFor(app.tabBars.buttons["الإعدادات"].firstMatch, timeout: 10, "Arabic tab names")
        snap("44-settings-arabic")
        tab(0)
        snap("45-list-arabic")
    }

    /// Devices, the security log, an encrypted export and deleting the account (groups 5 and 6),
    /// ending on the goodbye screen. The system's share sheet for the export isn't opened.
    func testDevicesLogExportAndDeleteAccount() {
        launchFresh()
        let email = "ios-\(UUID().uuidString.prefix(8).lowercased())@example.com"
        signUp(email: email)
        scrollAndTap("kit-saved")
        tap("kit-continue")
        tap("open-vault")
        // Without device unlock, "Confirm it's you" is the master password sheet a test can see.
        tap("offer-not-now", timeout: 30)
        waitForVault()

        tab(3)
        scrollAndTap("settings-devices")
        waitFor(text("This device"), timeout: 30, "this phone in the device list")
        snap("47-devices")
        tap("BackButton")
        scrollAndTap("settings-security-log")
        waitFor(app.navigationBars["Security log"], timeout: 20)
        // Signing up and signing in are logged.
        XCTAssertTrue(app.cells.firstMatch.waitForExistence(timeout: 30) || app.staticTexts.count > 2, "entries in the log")
        snap("48-security-log")
        tap("BackButton")

        // The encrypted export: a password for the file, then "Confirm it's you", then the file.
        scrollAndTap("settings-export")
        type("export-file-pass-77", into: "field-Password for the file")
        type("export-file-pass-77", into: "field-Confirm the password")
        tap("export-action")
        type(Self.password, into: "confirm-password")
        tap("confirm")
        waitFor(element("export-share"), timeout: 60, "the exported file, ready to share")
        snap("49-export-ready")
        app.buttons["Done"].firstMatch.tap()
        gone(element("export-share"))

        // Delete the account: the summary, then the email and master password.
        scrollAndTap("settings-delete-account")
        tap("delete-continue", timeout: 30)
        type(email, into: "delete-email")
        type(Self.password, into: "delete-password")
        snap("4a-delete-account")
        tap("delete-confirm")
        waitFor(text("Your account has been deleted"), timeout: 60, "the goodbye screen")
        snap("4b-account-deleted")
        waitFor(app.buttons["Back to the start"].firstMatch).tap()
        waitFor(element("sign-in"), timeout: 30)
    }

    func tab(_ index: Int) {
        app.tabBars.buttons.element(boundBy: index).tap()
    }

    /// The authenticator code for a base32 setup key now (RFC 6238: SHA-1, 6 digits, 30 s).
    static func totp(_ key: String, at date: Date = Date()) throws -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0, value = 0
        var secret = [UInt8]()
        for character in key.uppercased() where character != " " && character != "=" {
            guard let index = alphabet.firstIndex(of: character) else { continue }
            value = (value << 5) | index
            bits += 5
            if bits >= 8 {
                secret.append(UInt8((value >> (bits - 8)) & 0xFF))
                bits -= 8
            }
        }
        var counter = UInt64(date.timeIntervalSince1970 / 30).bigEndian
        let message = Data(bytes: &counter, count: 8)
        let mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: secret)))
        let offset = Int(mac[19] & 0x0F)
        let number = (UInt32(mac[offset] & 0x7F) << 24) | (UInt32(mac[offset + 1]) << 16) | (UInt32(mac[offset + 2]) << 8) | UInt32(mac[offset + 3])
        return String(format: "%06d", number % 1_000_000)
    }
}
