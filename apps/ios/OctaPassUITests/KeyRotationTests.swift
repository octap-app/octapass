import XCTest

/// Replaces the Secret Key in Settings: the new Recovery Kit covers the app until it's saved, and
/// the new key is the one that signs in. Then gives the personal vault a new key.
final class KeyRotationTests: UITestCase {
    func testReplaceSecretKeyThenSignInWithTheNewOne() throws {
        launchFresh()
        let email = "ios-\(UUID().uuidString.prefix(8).lowercased())@example.com"
        let oldKey = openVault(email: email)

        // Settings → Replace Secret Key, keeping the recovery code.
        tab(3)
        scrollAndTap("settings-rotate-secret-key")
        type(Self.password, into: "rotate-password")
        scrollAndTap("rotate-submit")

        // The kit says the recovery code stayed, and can't be left until it's saved.
        let key = waitFor(element("kit-secret-key"), timeout: 60, "the new Recovery Kit")
        let label = key.label
        let newKey = try XCTUnwrap(label.range(of: "OP").map { String(label[$0.lowerBound...]) })
        XCTAssertNotEqual(newKey, oldKey)
        reveal("kit-recovery-kept")
        XCTAssertTrue(element("kit-recovery-kept").exists, "the kept recovery code")
        XCTAssertFalse(element("kit-recovery-code").exists, "no new recovery code")
        snap("49-new-secret-key-kit")
        reveal("new-kit-continue")
        XCTAssertFalse(element("new-kit-continue").isEnabled, "not until it's saved")
        scrollAndTap("new-kit-saved")
        scrollAndTap("new-kit-continue")
        gone(element("new-kit-continue"), timeout: 10)

        // Signing out forgets the account here, so the Secret Key is asked for: the new one works.
        scrollAndTap("settings-sign-out")
        type(email, into: "email")
        type(Self.password, into: "master-password")
        type(newKey, into: "secret-key")
        tap("sign-in")
        waitForVault(timeout: 60)
    }

    func testRotateAVaultKey() {
        launchFresh()
        openVault(email: "ios-\(UUID().uuidString.prefix(8).lowercased())@example.com")

        tab(3)
        scrollAndTap("settings-vault-keys")
        tap("vault-key-rotate")
        waitFor(app.buttons["Rotate key"].firstMatch, timeout: 10, "the confirmation").tap()
        // Then "Confirm it's you", every time: the master password, with no device unlock.
        type(Self.password, into: "confirm-password")
        tap("confirm")
        snap("50-vault-keys")
        waitFor(textContaining("has a new key"), timeout: 60, "the new key's toast")
    }

    /// A new account to the open vault; returns its Secret Key.
    @discardableResult
    private func openVault(email: String) -> String {
        let key = signUp(email: email)
        tap("kit-saved")
        tap("kit-continue")
        tap("open-vault")
        tap("offer-not-now", timeout: 30)
        waitForVault()
        return key
    }

    private func tab(_ index: Int) {
        gone(app.keyboards.firstMatch)
        let button = app.tabBars.buttons.element(boundBy: index)
        waitFor(button)
        let hittable = expectation(for: NSPredicate(format: "hittable == true"), evaluatedWith: button)
        XCTAssertEqual(XCTWaiter().wait(for: [hittable], timeout: 10), .completed, "tab \(index)")
        button.tap()
    }
}
