import XCTest

/// An organisation between two accounts on one server, both through the app, on one phone: the
/// owner creates it, invites the member, makes a vault with a login in it and links a group; the
/// member joins; the owner adds them to the group and gives access after checking their
/// fingerprint; the member signs in again and sees the login.
final class OrganisationTests: UITestCase {
    func testOrganisationSharesAVaultWithASecondAccount() {
        launchFresh()
        let member = "ios-m-\(UUID().uuidString.prefix(6).lowercased())@example.com"
        let owner = "ios-o-\(UUID().uuidString.prefix(6).lowercased())@example.com"
        let memberKey = signUpAndOpenVault(email: member)
        signOut()

        // The owner: the organisation, an invitation, a vault with a login, a group linked to it.
        let ownerKey = signUpAndOpenVault(email: owner)
        openTool("organisation")
        tap("org-create-start", timeout: 30)
        type("Acme", into: "org-name")
        tap("org-create")
        waitFor(element("org-role"), timeout: 30, "the new organisation")
        snap("80-organisation")
        scrollAndTap("org-members")
        type(member, into: "org-invite-email")
        scrollAndTap("org-invite-send")
        waitFor(textContaining(member), timeout: 30, "the pending invitation")
        snap("81-org-members")
        back()
        scrollAndTap("org-vaults")
        type("Deploy", into: "org-vault-name")
        scrollAndTap("org-vault-create")
        tap("org-vault", timeout: 30)
        tap("org-vault-open", timeout: 30)
        addLogin(title: "Deploy key", username: "deploy", password: "deploy-Passw0rd-93", website: "deploy.example")
        waitFor(element("item-Deploy key"), timeout: 30)
        back()
        back()
        back()
        scrollAndTap("org-groups")
        type("Team", into: "org-group-name")
        scrollAndTap("org-group-create")
        waitFor(app.staticTexts["TEAM"].exists ? app.staticTexts["TEAM"] : textContaining("Team"), timeout: 30, "the new group")
        back()
        scrollAndTap("org-vaults")
        tap("org-vault", timeout: 30)
        choose("Team", in: "org-link-group")
        scrollAndTap("org-link")
        waitFor(app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Unlink'")).firstMatch, timeout: 30, "the linked group")
        snap("82-org-vault")
        signOut()

        // The member joins.
        signIn(member, memberKey)
        openTool("organisation")
        tap("org-accept", timeout: 30)
        waitFor(element("org-role"), timeout: 30, "the joined organisation")
        snap("83-org-joined")
        signOut()

        // The owner puts them in the group and gives access, after seeing their fingerprint.
        signIn(owner, ownerKey)
        openTool("organisation")
        scrollAndTap("org-groups")
        waitFor(element("org-group-add"), timeout: 30)
        choose(member, in: "org-group-add")
        waitFor(app.buttons.matching(NSPredicate(format: "label CONTAINS %@", member)).firstMatch, timeout: 60, "the member in the group")
        back()
        tap("org-review", timeout: 60)
        let confirm = waitFor(app.switches["org-review-confirm"].firstMatch, timeout: 30, "the person to confirm")
        snap("84-org-review")
        confirm.coordinate(withNormalizedOffset: CGVector(dx: 0.92, dy: 0.5)).tap()
        scrollAndTap("org-review-apply")
        waitFor(textContaining("Access given"), timeout: 60)
        signOut()

        // The member sees the vault and the login in it.
        signIn(member, memberKey)
        app.tabBars.buttons.firstMatch.tap()
        let back = app.navigationBars.buttons["BackButton"]
        if back.exists { back.tap() }
        waitFor(app.staticTexts["Deploy"].firstMatch, timeout: 60, "the organisation vault").tap()
        waitFor(element("item-Deploy key"), timeout: 60, "the shared login")
        snap("85-org-shared-item")
    }

    /// A tool from the vault's lists (one step back from a list on iPhone).
    private func openTool(_ name: String) {
        app.tabBars.buttons.firstMatch.tap()
        let back = app.navigationBars.buttons["BackButton"]
        if back.exists { back.tap() }
        scrollAndTap("sidebar-\(name)")
    }

    private func back() {
        let button = app.navigationBars.buttons.element(boundBy: 0)
        waitFor(button, timeout: 10, "a back button").tap()
    }

    /// Picks `option` from the menu picker with this identifier.
    private func choose(_ option: String, in identifier: String) {
        reveal(identifier).tap()
        waitFor(app.buttons[option].firstMatch, timeout: 30, "\(option) in \(identifier)").tap()
    }

    private func signOut() {
        app.tabBars.buttons.element(boundBy: 3).tap()
        scrollAndTap("settings-sign-out")
        waitFor(element("sign-in"), timeout: 30)
    }

    private func signIn(_ email: String, _ secretKey: String) {
        type(email, into: "email")
        type(Self.password, into: "master-password")
        if element("secret-key").exists { type(secretKey, into: "secret-key") }
        tap("sign-in")
        waitForVault(timeout: 60)
    }
}
