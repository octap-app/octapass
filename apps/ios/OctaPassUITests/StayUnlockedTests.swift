import notify
import XCTest

/// Stay unlocked while logged in to this phone (plan 18), on the Simulator: the next start opens
/// with no prompt, reveal and copy never ask while the vault is open (maintainer decision, plan 03
/// History 2026-11-06), not even after the phone locked, export asks every time, and turning it off brings the unlock screen back. Device unlock is
/// left off ("Not now"), so "Confirm it's you" is the master password sheet a test can see (the
/// Simulator answers Face ID by itself).
final class StayUnlockedTests: UITestCase {
    func testOpensWithNoPromptAndRevealNeverAsks() {
        launchFresh()
        openVaultWithoutDeviceUnlock()
        addLogin(title: "Stay", username: "ada", password: "stay-Passw0rd-71", website: "example.com")

        // The next start opens straight into the vault, with no unlock screen.
        relaunch()
        waitForVault()
        XCTAssertFalse(element("master-password").exists, "the unlock screen showed")
        snap("60-stay-unlocked-start")

        // It opened by itself, and still reveal and copy don't ask.
        tap("item-Stay")
        waitFor(element("password-field"))
        tap("reveal-Password")
        waitFor(text("stay-Passw0rd-71"), timeout: 20, "the password without a prompt")
        XCTAssertFalse(element("confirm-password").exists, "the reveal asked")
        snap("61-stay-unlocked-first-reveal")
        tap("copy-Password")
        Thread.sleep(forTimeInterval: 2)
        XCTAssertFalse(element("confirm-password").exists, "copy asked")

        // The phone locks and comes back: the vault is still open, so nothing asks.
        tap("reveal-Password")
        gone(text("stay-Passw0rd-71"))
        notify_post("app.octap.test.deviceLocked")
        Thread.sleep(forTimeInterval: 1)
        tap("reveal-Password")
        waitFor(text("stay-Passw0rd-71"), timeout: 20, "the password after the phone locked")
        XCTAssertFalse(element("confirm-password").exists, "the reveal after the phone locked asked")

        // Export still asks, every time.
        let back = app.navigationBars.buttons["BackButton"]
        if back.exists { back.tap() }
        tab(3)
        scrollAndTap("settings-export")
        tap("export-format")
        waitFor(app.buttons["JSON"].firstMatch).tap()
        tap("export-action")
        waitFor(element("confirm-password"), timeout: 20, "export asks")
        tap("confirm-cancel")
        gone(element("confirm-password"))
    }

    /// Off: the gates come back, and the next start shows the unlock screen.
    func testTurnedOffTheUnlockScreenComesBack() {
        launchFresh()
        openVaultWithoutDeviceUnlock()
        tab(3)
        let stay = waitFor(reveal("settings-stay-unlocked"), timeout: 20, "the switch").switches.firstMatch
        XCTAssertEqual(stay.value as? String, "1", "on by default")
        // While on, the app-open gate is shown greyed out, with the note saying when it applies,
        // and the auto-lock time doesn't apply.
        XCTAssertTrue(reveal("settings-stay-unlocked-on").exists)
        XCTAssertFalse(reveal("settings-device-auth-open").switches.firstMatch.isEnabled, "the gate is greyed out")
        XCTAssertTrue(reveal("settings-stay-unlocked-gates").exists)
        XCTAssertFalse(reveal("settings-auto-lock").isEnabled, "auto-lock is greyed out")
        snap("62-stay-unlocked-settings")

        // Off: the note goes and auto-lock is back. (The gate itself stays greyed out here for
        // its own reason: device unlock is off.)
        reveal("settings-stay-unlocked").switches.firstMatch.tap()
        gone(element("settings-stay-unlocked-gates"), timeout: 10)
        let enabled = NSPredicate(format: "isEnabled == true")
        wait(for: [expectation(for: enabled, evaluatedWith: reveal("settings-auto-lock"))], timeout: 10)

        relaunch()
        waitFor(element("master-password"), timeout: 30, "the unlock screen")
        snap("63-stay-unlocked-off")
        type(Self.password, into: "master-password")
        tap("unlock")
        waitForVault()
    }

    /// The autofill gate (plan 03, "Ask on every fill"): greyed out under stay unlocked; with it off
    /// and Face ID on, the switch works and turning it off shows the warning.
    func testTheAutofillGateAndItsWarning() {
        launchFresh()
        signUp(email: "ios-\(UUID().uuidString.prefix(8).lowercased())@example.com")
        waitFor(element("kit-saved"), timeout: 30)
        scrollAndTap("kit-saved")
        tap("kit-continue")
        tap("open-vault")
        // Face ID on (the Simulator answers it), so the gate has something to ask with.
        tap("offer-turn-on", timeout: 30)
        gone(element("offer-turn-on"))
        waitForVault()
        tab(3)
        let gate = waitFor(reveal("settings-device-auth-autofill"), timeout: 20, "the autofill switch").switches.firstMatch
        XCTAssertFalse(gate.isEnabled, "greyed out while staying unlocked")
        XCTAssertFalse(element("settings-device-auth-autofill-off").exists)

        reveal("settings-stay-unlocked").switches.firstMatch.tap()
        gone(element("settings-stay-unlocked-gates"), timeout: 10)
        let enabled = NSPredicate(format: "isEnabled == true")
        wait(for: [expectation(for: enabled, evaluatedWith: gate)], timeout: 10)
        XCTAssertEqual(gate.value as? String, "1", "on by default: every fill asks")

        gate.tap()
        waitFor(reveal("settings-device-auth-autofill-off"), timeout: 10, "the warning")
        snap("64-autofill-gate-off")
        reveal("settings-device-auth-autofill").switches.firstMatch.tap()
        gone(element("settings-device-auth-autofill-off"), timeout: 10)
    }

    /// "Lock now" holds until the user unlocks, even with stay unlocked on.
    func testLockNowHoldsUntilTheUserUnlocks() {
        launchFresh()
        openVaultWithoutDeviceUnlock()
        lockNow()
        waitFor(element("master-password"), timeout: 30, "the unlock screen after Lock now")
        // Coming back doesn't open it either.
        XCUIDevice.shared.press(.home)
        app.activate()
        waitFor(element("master-password"), timeout: 10, "still locked after coming back")
        type(Self.password, into: "master-password")
        tap("unlock")
        waitForVault()
    }

    private func openVaultWithoutDeviceUnlock() {
        signUp(email: "ios-\(UUID().uuidString.prefix(8).lowercased())@example.com")
        // The kit's switch can be laid out but not yet hittable while the screen settles.
        waitFor(element("kit-saved"), timeout: 30)
        scrollAndTap("kit-saved")
        tap("kit-continue")
        tap("open-vault")
        tap("offer-not-now", timeout: 30)
        waitForVault()
        // The key is kept on a vault thread just after the unlock.
        Thread.sleep(forTimeInterval: 2)
    }

    private func relaunch() {
        app.terminate()
        app.launch()
    }

    private func tab(_ index: Int) {
        app.tabBars.buttons.element(boundBy: index).tap()
    }
}
