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

    /// Share links, families and emergency access (group 5): a link for an item, listed in
    /// Sharing and revoked there; a family; another account added as a trusted contact.
    func testShareLinkFamilyAndEmergencyContact() {
        launchFresh()
        let other = "ios-c-\(UUID().uuidString.prefix(6).lowercased())@example.com"
        signUpAndOpenVault(email: other)
        signOut()

        signUpAndOpenVault()
        addLogin(title: "Door", username: "ada", password: "door-Passw0rd-71", website: "door.example")
        tap("item-Door")
        tap("item-more")
        waitFor(app.buttons["Share a copy"].firstMatch).tap()
        tap("share-link-create")
        let url = waitFor(element("share-link-url"), timeout: 30, "the new link")
        XCTAssertTrue(url.label.contains("#") || (url.value as? String ?? "").contains("#"), "the key is in the link's fragment")
        snap("63-share-link")
        app.buttons["Done"].firstMatch.tap()
        gone(element("share-link-url"))

        // Sharing lists it; a swipe revokes it.
        openTool("sharing")
        let link = app.buttons.matching(NSPredicate(format: "label CONTAINS 'Door'")).firstMatch
        let row = link.exists ? link : textContaining("Door")
        waitFor(row, timeout: 30, "the link in Sharing")
        snap("64-sharing")
        row.swipeLeft()
        waitFor(app.buttons["Revoke"].firstMatch).tap()
        waitFor(textContaining("Link revoked"), timeout: 30)

        // A family of one.
        scrollAndTap("sharing-family")
        tap("family-create", timeout: 30)
        waitFor(app.buttons.matching(NSPredicate(format: "label CONTAINS 'Invite'")).firstMatch, timeout: 30, "the new family")
        snap("65-family")

        // A trusted contact for emergency access, after comparing their fingerprint.
        openTool("emergency")
        tap("emergency-add", timeout: 30)
        type(other, into: "person-email")
        tap("person-find")
        confirmFingerprint(of: other)
        snap("66-emergency-add")
        scrollAndTap("person-add")
        waitFor(textContaining(other), timeout: 30, "the trusted contact")
        snap("67-emergency")
    }

    /// Turns on "It matches what <email> sees". Found by its label: the screen under the sheet can
    /// have switches of its own. A Form toggle flips from its switch, not its label, and the form
    /// grows as the account is found, so let it settle and check the switch took the tap.
    func confirmFingerprint(of email: String) {
        let toggle = waitFor(app.switches.matching(NSPredicate(format: "label CONTAINS %@", email)).firstMatch, timeout: 30)
        for _ in 0..<3 where (toggle.value as? String) != "1" {
            Thread.sleep(forTimeInterval: 2)
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.92, dy: 0.5)).tap()
            _ = XCTWaiter().wait(for: [expectation(for: NSPredicate(format: "value == '1'"), evaluatedWith: toggle)], timeout: 5)
        }
        XCTAssertEqual(toggle.value as? String, "1", "the fingerprint confirmed\n\(app.debugDescription)")
    }

    /// A tool from the vault's lists (one step back from a list on iPhone).
    func openTool(_ name: String) {
        app.tabBars.buttons.firstMatch.tap()
        // Back until the lists show: a tool's own screens (a family, a vault's members) are
        // further in.
        let back = app.navigationBars.buttons["BackButton"]
        for _ in 0..<4 where !visible(element("sidebar-\(name)")) {
            guard back.waitForExistence(timeout: 2) else { break }
            back.tap()
        }
        scrollAndTap("sidebar-\(name)")
    }

    func signOut() {
        app.tabBars.buttons.element(boundBy: 3).tap()
        scrollAndTap("settings-sign-out")
        waitFor(element("sign-in"), timeout: 30)
    }
}
