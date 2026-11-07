import XCTest

/// Sign up, the Recovery Kit, device unlock right after, locking and unlocking both ways, then
/// signing out and back in with the Secret Key, all on the real development server. The script
/// enrols a face on the Simulator and matches every Face ID prompt.
final class OnboardingTests: UITestCase {
    func testSignUpUnlockAndSignInAgain() throws {
        launchFresh()
        waitFor(element("sign-in"), timeout: 60)
        snap("01-sign-in")

        let email = "ios-\(UUID().uuidString.prefix(8).lowercased())@example.com"
        let secretKey = signUp(email: email)
        XCTAssertTrue(secretKey.hasPrefix("OP"), "the kit shows the Secret Key: \(secretKey)")
        snap("03-recovery-kit")
        // Continue waits until the kit is saved.
        XCTAssertFalse(element("kit-continue").isEnabled)
        XCTAssertTrue(element("kit-save").exists && element("kit-print").exists)
        // Below the kit's actions on a smaller screen.
        scrollAndTap("kit-saved")
        tap("kit-continue")
        tap("open-vault")

        // Right after sign-up: "Use Face ID to unlock Octa Pass?" Not now asks once more later.
        tap("offer-not-now", timeout: 30)
        waitForVault()
        snap("05-vault")

        // Without device unlock, locking asks for the master password.
        lockNow()
        snap("06-unlock-password")
        type("wrong password", into: "master-password")
        tap("unlock")
        waitFor(textContaining("password"), timeout: 30)
        type(Self.password, into: "master-password")
        tap("unlock")

        // The reminder comes after that unlock; this time Face ID goes on.
        tap("offer-turn-on", timeout: 60)
        gone(element("offer-turn-on"))
        waitForVault()

        // Locked by hand, it waits for Unlock with Face ID (matched by the script) instead of
        // asking at once.
        lockNow()
        tap("unlock-device")
        waitForVault()

        // Signed out, the phone forgets the account: signing in needs the Secret Key again.
        app.tabBars.buttons.element(boundBy: 3).tap()
        scrollAndTap("settings-sign-out")
        waitFor(element("sign-in"), timeout: 30)
        type(email, into: "email")
        type(Self.password, into: "master-password")
        type(secretKey, into: "secret-key")
        snap("07-sign-in-new-device")
        tap("sign-in")
        // Face ID was settled for this account on this phone, so it isn't offered again.
        waitForVault(timeout: 60)
        XCTAssertFalse(element("offer-turn-on").exists)
    }

    func testSignInErrors() {
        launchFresh()
        tap("sign-in", timeout: 60)
        // Nothing typed: every field says what's missing, nothing is sent.
        waitFor(textContaining("email"))
        type("nobody@example.com", into: "email")
        type("whatever it is", into: "master-password")
        type("OP1-AAAAAA-AAAAAA-AAAAA-AAAAA-AAAA", into: "secret-key")
        tap("sign-in")
        // The server doesn't know the account; the form says so and stays.
        waitFor(element("sign-in"), timeout: 30)
        snap("02-sign-in-error")
    }
}
