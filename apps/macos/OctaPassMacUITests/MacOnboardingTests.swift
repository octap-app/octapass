import AppKit
import CryptoKit
import XCTest

/// Plan 19 phase 1, end to end on the real development server (`scripts/ui-tests.sh` starts it):
/// sign up and the Recovery Kit; adding, editing and copying in the vault window and its menus;
/// Search, Settings, Lock and unlocking with the master password; two-step sign-in. The screens are
/// the iPhone app's, so the identifiers are too.
final class MacOnboardingTests: XCTestCase {
    let app = XCUIApplication()
    static let password = "correct horse battery staple 42"

    override func setUp() {
        continueAfterFailure = false
        let server = ProcessInfo.processInfo.environment["OCTAPASS_TEST_SERVER"] ?? "http://127.0.0.1:8080"
        app.launchEnvironment["OCTAPASS_SERVER_URL"] = server
        app.launchEnvironment["OCTAPASS_PWNED_URL"] = server
        app.launchEnvironment["OCTAPASS_RESET"] = "1"
    }

    func testSignUpAddLoginLockAndUnlock() {
        signUp(shots: true)
        snap("03-vault")

        // Add is a pull-down menu on the Mac; Login is its menu item. The editor opens in the
        // window's detail column, not a sheet (a window of its own on the Mac).
        click("new-item")
        click("new-login", timeout: 10)
        waitFor("editor-title")
        XCTAssertEqual(app.sheets.count, 0, "the editor is in the window, not a sheet")
        type("GitHub", into: "editor-title")
        type("octocat", into: "editor-username")
        click("editor-save")
        XCTAssertTrue(element("item-GitHub").waitForExistence(timeout: 20), app.debugDescription)
        // The saved login opens in the detail column.
        waitFor("edit-item")
        snap("04-item")

        // Edit ▸ Copy Username (Ctrl+Cmd+C) copies from the open login.
        NSPasteboard.general.clearContents()
        app.typeKey("c", modifierFlags: [.command, .control])
        let copied = expectation(for: NSPredicate { _, _ in NSPasteboard.general.string(forType: .string) == "octocat" }, evaluatedWith: nil)
        wait(for: [copied], timeout: 10)

        // File ▸ New Login (Cmd+N), in the detail column too.
        app.typeKey("n", modifierFlags: .command)
        waitFor("editor-title")
        XCTAssertEqual(app.sheets.count, 0)
        type("GitLab", into: "editor-title")
        snap("05-editor")
        click("editor-save")
        waitFor("item-GitLab")

        // Edit inline; leaving with unsaved changes asks first.
        click("item-GitHub")
        click("edit-item")
        type("GitHub (work)", into: "editor-title")
        click("item-GitLab")
        // In the window: the alert's buttons are on the Touch Bar too.
        let discard = app.windows.buttons["Discard changes"].firstMatch
        XCTAssertTrue(discard.waitForExistence(timeout: 10), "asks before discarding\n\(app.debugDescription)")
        discard.click()
        XCTAssertFalse(element("item-GitHub (work)").exists, "the change wasn't saved")

        // Edit ▸ Find (Cmd+F) goes to the search field.
        app.typeKey("f", modifierFlags: .command)
        app.typeText("Lab")
        waitFor("item-GitLab")
        let hidden = expectation(for: NSPredicate(format: "exists == false"), evaluatedWith: element("item-GitHub"))
        wait(for: [hidden], timeout: 10)

        // An otpauth:// link: the review sheet shows the code and its Save button in full.
        // Opened with the copy under test: macOS would hand the link to an installed Octa Pass.
        let link = URL(string: "otpauth://totp/Test:me?secret=JBSWY3DPEHPK3PXP&issuer=Test")!
        let underTest = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("Octa Pass.app")
        if FileManager.default.fileExists(atPath: underTest.path) {
            let opened = expectation(description: "link opened")
            NSWorkspace.shared.open([link], withApplicationAt: underTest, configuration: NSWorkspace.OpenConfiguration()) { _, _ in
                opened.fulfill()
            }
            wait(for: [opened], timeout: 20)
        } else {
            app.open(link)
        }
        waitFor("review-save", timeout: 20)
        snap("06-link-review")
        app.typeKey(.escape, modifierFlags: [])

        // Octa Pass ▸ Settings… (Cmd+,): a window of its own.
        app.typeKey(",", modifierFlags: .command)
        waitFor("settings-export")
        snap("06-settings")
        app.typeKey("w", modifierFlags: .command)

        // The menu bar's Lock.
        app.typeKey("l", modifierFlags: [.command, .control])
        waitFor("master-password", timeout: 20)
        snap("07-locked")
        type(Self.password, into: "master-password")
        click("unlock")
        waitFor("lock-now", timeout: 60)
        XCTAssertTrue(element("item-GitHub").waitForExistence(timeout: 20), "the login is still there")
    }

    /// Two-step sign-in turned on in the Settings window, the test being the authenticator, then
    /// signing out and back in with the Secret Key and a code.
    func testTwoStepSignIn() throws {
        let (email, secretKey) = signUp(shots: false)

        app.typeKey(",", modifierFlags: .command)
        click("settings-two-step")
        click("two-step-turn-on")
        type(Self.password, into: "two-step-password")
        click("two-step-continue")
        // "Setup key, ABCD…": the row's words, then the key.
        let key = text(waitFor("two-step-setup-key", timeout: 30)).components(separatedBy: ", ").last ?? ""
        type(try Self.totp(key), into: "two-step-confirm-code")
        click("two-step-confirm")
        waitFor("two-step-recovery-codes", timeout: 30)
        snap("10-recovery-codes")
        click("two-step-saved")
        click("two-step-done")

        // Back to Settings, and signing out there: the vault window goes to sign-in.
        // The Settings window's title follows its page; its identifier stays.
        let back = app.windows.matching(identifier: "com_apple_SwiftUI_Settings_window").buttons["Back"].firstMatch
        XCTAssertTrue(back.waitForExistence(timeout: 10), app.debugDescription)
        back.click()
        click("settings-sign-out")
        waitFor("sign-in", timeout: 30)
        app.typeKey("w", modifierFlags: .command)
        type(email, into: "email")
        type(Self.password, into: "master-password")
        type(secretKey, into: "secret-key")
        click("sign-in")
        waitFor("two-step-code", timeout: 60)
        snap("11-two-step")
        type(try Self.totp(key), into: "two-step-code")
        click("verify")
        waitFor("lock-now", timeout: 60)
    }

    /// Settings → Master password in the Settings window: the fields take typing, the change
    /// goes through, and the vault unlocks with the new password only.
    func testChangeMasterPassword() {
        signUp(shots: false)
        let newPassword = "a brand new master password 7"

        app.typeKey(",", modifierFlags: .command)
        click("settings-change-password")
        waitFor("change-password-current")
        snap("12-change-password", window: settingsWindow)
        // Clicked where a person would, near the start of the box, not at the field's own centre.
        for (field, text) in [("change-password-current", Self.password), ("change-password-new", newPassword), ("change-password-confirm", newPassword)] {
            waitFor(field).coordinate(withNormalizedOffset: CGVector(dx: 0.1, dy: 0.75)).click()
            app.typeText(text)
            let input = waitFor(field).secureTextFields.firstMatch
            XCTAssertEqual((input.value as? String ?? "").count, text.count, "\(field) has what was typed\n\(app.debugDescription)")
            // Its text starts at the start of the box, as on the iPhone.
            XCTAssertLessThan(input.frame.minX - waitFor(field).frame.minX, 40, "\(field) fills its box\n\(app.debugDescription)")
        }
        snap("13-change-password-filled", window: settingsWindow)
        click("change-password-submit")
        // Done: back on the Settings page.
        waitFor("settings-export", timeout: 60)
        app.typeKey("w", modifierFlags: .command)

        app.typeKey("l", modifierFlags: [.command, .control])
        type(Self.password, into: "master-password")
        click("unlock")
        XCTAssertFalse(element("lock-now").waitForExistence(timeout: 10), "the old password doesn't unlock")
        type(newPassword, into: "master-password")
        click("unlock")
        waitFor("lock-now", timeout: 60)
    }

    var settingsWindow: XCUIElement {
        app.windows.matching(identifier: "com_apple_SwiftUI_Settings_window").firstMatch
    }

    /// Safes in the vault window: new ones from the list, one opened in the detail column with a
    /// path bar instead of a back button, a folder in it, and another Safe chosen straight from the
    /// list in its place.
    func testSafes() {
        signUp(shots: false)
        click("sidebar-safes")
        click("safes-new-empty", timeout: 30)
        type("Taxes", into: "safes-name")
        click("safes-create")
        waitFor("safes-open-Taxes", timeout: 30)
        // Then the + at the top of the list.
        click("safes-new")
        type("Photos", into: "safes-name")
        click("safes-create")
        waitFor("safes-open-Photos", timeout: 30)

        click("safes-open-Taxes")
        XCTAssertTrue(text(waitFor("safe-path-current")).contains("Taxes"), app.debugDescription)
        XCTAssertFalse(app.toolbars.buttons["Back"].exists, "the path bar goes up, not a back button")
        snap("20-safe")

        // A folder, opened: the path bar shows the way back up.
        click("safe-new-folder")
        // An alert's field loses its identifier on the Mac.
        let name = app.sheets.textFields.firstMatch
        XCTAssertTrue(name.waitForExistence(timeout: 10), app.debugDescription)
        name.click()
        name.typeText("Receipts")
        app.sheets.buttons["Make folder"].firstMatch.click()
        waitFor("safe-entry-Receipts", timeout: 30).doubleClick()
        XCTAssertTrue(text(waitFor("safe-path-current")).contains("Receipts"), app.debugDescription)
        waitFor("safe-path-0")
        snap("21-safe-folder")

        // Another Safe, straight from the list, from inside a folder.
        click("safes-open-Photos")
        let switched = expectation(for: NSPredicate { _, _ in self.text(self.element("safe-path-current")).contains("Photos") }, evaluatedWith: nil)
        wait(for: [switched], timeout: 20)
        XCTAssertFalse(element("safe-entry-Receipts").exists, "Photos' files, not Taxes'")
        snap("22-safe-switched")

        // And back up from Taxes' folder by its path bar.
        click("safes-open-Taxes")
        waitFor("safe-entry-Receipts", timeout: 20).doubleClick()
        click("safe-path-0")
        let up = expectation(for: NSPredicate { _, _ in self.text(self.element("safe-path-current")).contains("Taxes") }, evaluatedWith: nil)
        wait(for: [up], timeout: 20)
    }

    // MARK: Helpers

    /// A new account through sign-up, the Recovery Kit and the device unlock offer (Not now), to the
    /// open vault. Its email and Secret Key.
    @discardableResult
    func signUp(shots: Bool) -> (email: String, secretKey: String) {
        app.launch()
        waitFor("sign-in", timeout: 60)
        if shots { snap("01-sign-in") }

        let email = "mac-\(UUID().uuidString.prefix(8).lowercased())@example.com"
        click("create-account")
        type(email, into: "signup-email")
        type(Self.password, into: "signup-password")
        type(Self.password, into: "confirm-password")
        click("continue")
        let notice = waitFor("dev-code", timeout: 60)
        type(String(text(notice).filter(\.isNumber).suffix(6)), into: "verification-code")
        click("verify")
        let secretKey = secretKey(in: waitFor("kit-secret-key", timeout: 60))
        XCTAssertTrue(secretKey.hasPrefix("OP1-"), "the kit shows the Secret Key: \(secretKey)")
        // The step slides in; the screenshot waits until it's in place.
        let saved = waitFor("kit-saved")
        _ = XCTWaiter().wait(for: [expectation(for: NSPredicate(format: "hittable == true"), evaluatedWith: saved)], timeout: 10)
        if shots { snap("02-recovery-kit") }
        click("kit-saved")
        click("kit-continue")
        click("open-vault")

        // Right after sign-up: the device unlock offer. Not now keeps the master password.
        click("offer-not-now", timeout: 30)
        waitFor("lock-now", timeout: 30)
        return (email, secretKey)
    }

    /// "Secret Key, OP1-…": the Secret Key from the kit's row.
    func secretKey(in row: XCUIElement) -> String {
        let words = ([text(row)] + row.staticTexts.allElementsBoundByIndex.map(text)).joined(separator: " ")
        return words.range(of: "OP1(-[A-Z0-9]+)+", options: .regularExpression).map { String(words[$0]) } ?? ""
    }

    /// An element's words: on macOS a static text's are its value, not its label as on iOS.
    func text(_ element: XCUIElement) -> String {
        element.label.isEmpty ? (element.value as? String ?? "") : element.label
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

    func element(_ identifier: String) -> XCUIElement {
        app.descendants(matching: .any).matching(identifier: identifier).firstMatch
    }

    @discardableResult
    func waitFor(_ identifier: String, timeout: TimeInterval = 20) -> XCUIElement {
        let found = element(identifier)
        XCTAssertTrue(found.waitForExistence(timeout: timeout), "no \(identifier)\n\(app.debugDescription)")
        return found
    }

    func click(_ identifier: String, timeout: TimeInterval = 20) {
        let target = waitFor(identifier, timeout: timeout)
        _ = XCTWaiter().wait(for: [expectation(for: NSPredicate(format: "hittable == true"), evaluatedWith: target)], timeout: 10)
        target.click()
    }

    /// Clicks into the field (the identifier may be on its container) and types, replacing what's there.
    func type(_ text: String, into identifier: String) {
        let field = waitFor(identifier)
        let input = [field.textFields.firstMatch, field.secureTextFields.firstMatch].first { $0.exists } ?? field
        input.click()
        input.typeKey("a", modifierFlags: .command)
        input.typeText(text)
    }

    func snap(_ name: String, window: XCUIElement? = nil) {
        let shot = (window ?? app.windows.firstMatch).screenshot()
        let attachment = XCTAttachment(screenshot: shot)
        attachment.name = name
        attachment.lifetime = .keepAlways
        // scripts/ui-tests.sh exports it from the result bundle to build/screenshots/<name>.png.
        add(attachment)
    }
}
