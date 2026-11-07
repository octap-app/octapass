import XCTest

/// Sharing between two accounts on one server, both through the app: B signs up; A signs up,
/// makes a shared vault, adds B after comparing B's fingerprint, and saves a login in it; B signs
/// in again and opens the vault.
final class SharingTests: UITestCase {
    func testSharedVaultBetweenTwoAccounts() {
        launchFresh()
        let other = "ios-b-\(UUID().uuidString.prefix(6).lowercased())@example.com"
        let otherKey = signUpAndOpenVault(email: other)
        signOut()

        signUpAndOpenVault()
        openTool("sharing")
        tap("sharing-new-vault")
        type("Household", into: "new-vault-name")
        tap("new-vault-create")
        let vault = waitFor(app.staticTexts["Household"].firstMatch, timeout: 30)
        vault.tap()
        tap("members-invite")
        type(other, into: "person-email")
        tap("person-find")
        // B's fingerprint, to compare before adding them.
        waitFor(app.switches.firstMatch, timeout: 30).coordinate(withNormalizedOffset: CGVector(dx: 0.92, dy: 0.5)).tap()
        snap("60-add-member")
        scrollAndTap("person-add")
        waitFor(textContaining(other), timeout: 30)
        snap("61-members")
        signOut()

        // B on this phone again: the Secret Key is asked for, the shared vault shows.
        type(other, into: "email")
        type(Self.password, into: "master-password")
        type(otherKey, into: "secret-key")
        tap("sign-in")
        waitForVault(timeout: 60)
        openTool("sharing")
        waitFor(app.staticTexts["Household"].firstMatch, timeout: 60)
        snap("62-shared-vault")
    }

    /// A tool from the vault's lists (one step back from a list on iPhone).
    func openTool(_ name: String) {
        app.tabBars.buttons.firstMatch.tap()
        let back = app.navigationBars.buttons["BackButton"]
        if back.exists { back.tap() }
        scrollAndTap("sidebar-\(name)")
    }

    func signOut() {
        app.tabBars.buttons.element(boundBy: 3).tap()
        scrollAndTap("settings-sign-out")
        waitFor(element("sign-in"), timeout: 30)
    }
}
