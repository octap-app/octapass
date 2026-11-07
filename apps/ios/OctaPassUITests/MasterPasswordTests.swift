import XCTest

/// Changes the master password in Settings, then resets it from "Forgot your master password?"
/// with the recovery code from the kit: both end at a vault the new password opens.
final class MasterPasswordTests: UITestCase {
    func testChangeThenReset() throws {
        launchFresh()
        let email = "ios-\(UUID().uuidString.prefix(8).lowercased())@example.com"
        signUp(email: email)
        let recoveryCode = lastRecoveryCode
        tap("kit-saved")
        tap("kit-continue")
        tap("open-vault")
        tap("offer-not-now", timeout: 30)
        waitForVault()
        XCTAssertFalse(recoveryCode.isEmpty, "the kit's recovery code")

        // Settings → Master password.
        tab(3)
        scrollAndTap("settings-change-password")
        type(Self.password, into: "change-password-current")
        type(Self.changePassword, into: "change-password-new")
        type(Self.changePassword, into: "change-password-confirm")
        tap("change-password-submit")
        waitFor(element("settings-change-password"), timeout: 20, "back in Settings")
        snap("46-password-changed")

        // The new password opens the vault; changing it turned device unlock off.
        tab(0)
        lockNow()
        if element("use-password").waitForExistence(timeout: 5) { tap("use-password") }
        type(Self.changePassword, into: "master-password")
        tap("unlock")
        waitForVault(timeout: 60)
        dismissUnlockOffer()

        // Sign out, then reset with the recovery code and a second new password.
        tab(3)
        scrollAndTap("settings-sign-out")
        tap("forgot-password")
        type(email, into: "reset-email")
        scrollAndTap("reset-send-code")
        waitFor(element("reset-verify"), timeout: 60, "the reset code")
        scrollAndTap("reset-verify")
        waitFor(element("reset-recovery-code"), timeout: 20, "the recovery code step")
        snap("47-reset-password")
        type(recoveryCode, into: "reset-recovery-code")
        type(Self.resetPassword, into: "reset-new-password")
        type(Self.resetPassword, into: "reset-confirm-password")
        scrollAndTap("reset-submit")
        reveal("reset-kit-confirm")
        XCTAssertTrue(element("reset-kit-confirm").exists, "the new Recovery Kit")
        snap("48-new-kit")
        scrollAndTap("reset-kit-confirm")
        gone(element("reset-kit-confirm"), timeout: 30)
        waitForVault(timeout: 60)

        // And the second new password opens it.
        tab(0)
        lockNow()
        if element("use-password").waitForExistence(timeout: 5) { tap("use-password") }
        type(Self.resetPassword, into: "master-password")
        tap("unlock")
        waitForVault(timeout: 60)
        dismissUnlockOffer()
    }

    /// The Face ID offer comes back once after "Not now"; the sheet would cover the tab bar.
    private func dismissUnlockOffer() {
        if element("offer-not-now").waitForExistence(timeout: 10) {
            tap("offer-not-now")
            gone(element("offer-not-now"))
        }
    }

    static let changePassword = "another correct horse battery staple 43"
    static let resetPassword = "reset correct horse battery staple 44"

    private func tab(_ index: Int) {
        gone(app.keyboards.firstMatch)
        let button = app.tabBars.buttons.element(boundBy: index)
        waitFor(button)
        let hittable = expectation(for: NSPredicate(format: "hittable == true"), evaluatedWith: button)
        XCTAssertEqual(XCTWaiter().wait(for: [hittable], timeout: 10), .completed, "tab \(index)")
        button.tap()
    }
}
