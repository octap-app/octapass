import XCTest

/// A vault on this phone only, with no server involved: create one, add a login, lock and unlock,
/// then a second vault and switching between the two. The Simulator has no Secure Enclave, so a
/// new vault needs the estimator's top score.
final class LocalVaultTests: UITestCase {
    func testCreateLockAndSwitch() throws {
        launchFresh()
        waitFor(element("sign-in"), timeout: 60)

        scrollAndTap("local-use-device")
        waitFor(element("local-name"))
        snap("60-local-create")
        typeNewPassword("short")
        scrollAndTap("local-create")
        waitFor(textContaining("stronger"))

        createVault(name: "Personal")
        addLogin(title: "GitHub", username: "me@example.com", password: "s3cret-Pass-word", website: "github.com")
        waitFor(element("item-GitHub"))
        snap("63-local-vault")

        // Locked: no account to sign out of or reset, and the vault's name shows.
        lockNow()
        waitFor(element("local-add-vault"))
        waitFor(textContaining("Personal"))
        XCTAssertFalse(element("sign-out").exists)
        XCTAssertFalse(element("forgot-password").exists)
        snap("64-local-locked")
        type("wrong password", into: "master-password")
        tap("unlock")
        waitFor(textContaining("wrong"), timeout: 60)
        unlock()
        waitFor(element("item-GitHub"))

        // A second vault, from the first screen, which now lists the first one.
        lockNow()
        tap("local-add-vault")
        waitFor(element("sign-in"), timeout: 30)
        XCTAssertTrue(reveal("local-open-Personal").exists)
        snap("65-local-first-screen")
        scrollAndTap("local-use-device")
        createVault(name: "Work")
        XCTAssertFalse(element("item-GitHub").exists)

        // Back to the first from Settings: it opens locked.
        openSettings()
        scrollAndTap("local-open-Personal")
        waitFor(element("local-open-Work"), timeout: 30)
        waitFor(textContaining("Personal"))

        // And across, on the lock screen: the screen follows the vault.
        tap("local-open-Work")
        waitFor(element("local-open-Personal"), timeout: 30)
        waitFor(textContaining("Work"))
        tap("local-open-Personal")
        waitFor(element("local-open-Work"), timeout: 30)
        unlock()
        waitFor(element("item-GitHub"))
        snap("66-local-switched")
    }

    /// The name and master password, the recovery code, and no first backup, to the open vault.
    private func createVault(name: String) {
        type(name, into: "local-name")
        typeNewPassword(Self.password)
        scrollAndTap("local-create")
        waitFor(element("local-recovery-code"), timeout: 60, "the recovery code")
        snap("61-local-code")
        // Continue waits until the code is written down.
        XCTAssertFalse(element("local-kit-continue").isEnabled)
        tap("local-kit-saved")
        tap("local-kit-continue")
        waitFor(element("local-first-folder"))
        snap("62-local-first-backup")
        tap("local-first-backup-later")
        waitForVault()
        dismissUnlockOffer()
    }

    /// iOS treats a form with two secure fields as account creation, and under XCUITest its
    /// strong-password handling drops what's typed into the first one: type each twice.
    private func typeNewPassword(_ password: String) {
        for _ in 0..<2 {
            for field in ["local-password", "local-confirm"] {
                let input = reveal(field).secureTextFields.firstMatch
                focus(input, field)
                Thread.sleep(forTimeInterval: 1)
                if let value = input.value as? String, !value.isEmpty {
                    input.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: value.count))
                }
                input.typeText(password)
            }
        }
    }

    private func unlock() {
        type(Self.password, into: "master-password")
        tap("unlock")
        waitForVault(timeout: 60)
        dismissUnlockOffer()
    }

    /// Offered after creating a vault and once more after a password unlock, where the phone has
    /// a device lock.
    private func dismissUnlockOffer() {
        guard element("offer-not-now").waitForExistence(timeout: 8) else { return }
        tap("offer-not-now")
        gone(element("offer-not-now"))
    }

    private func openSettings() {
        if isPad {
            tap("sidebar-settings")
        } else {
            app.tabBars.buttons.element(boundBy: 3).tap()
        }
    }
}
