import XCTest

/// The vault's lists on a new account: logins added in the editor, two for one website shown as
/// one row that opens in place, search, Sort and group, favourites, the trash.
final class VaultTests: UITestCase {
    func testListsSearchFavouritesAndTrash() {
        launchFresh()
        signUpAndOpenVault()
        addLogin(title: "GitHub Work", username: "octo", password: "hunter2-hunter2", website: "https://github.com")
        addLogin(title: "GitHub Personal", username: "me", password: "hunter3-hunter3", website: "github.com/login")
        addLogin(title: "Bank", username: "ada", password: "hunter4-hunter4", website: "bank.example")

        // Two logins for one site share a row, which opens in place.
        let site = waitFor(element("site-github.com"))
        XCTAssertFalse(element("item-GitHub Work").exists)
        site.tap()
        waitFor(element("item-GitHub Work"))
        snap("10-list-site-row")

        // Search finds by name, website or username's subtitle.
        let search = app.searchFields.firstMatch
        search.tap()
        search.typeText("bank")
        waitFor(element("item-Bank"))
        XCTAssertFalse(element("site-github.com").exists)
        snap("11-search")
        // iOS 26's search bar closes with Close (Cancel before).
        let close = [app.buttons["Close"], app.buttons["Cancel"]].first { $0.firstMatch.exists }
        close?.firstMatch.tap()
        waitFor(element("site-github.com"))

        // Sort and group: by first letter.
        tap("sort-menu")
        waitFor(app.buttons["First letter"].firstMatch).tap()
        waitFor(app.staticTexts["B"].firstMatch)
        snap("12-by-letter")

        // A favourite, from a swipe.
        element("item-Bank").swipeRight()
        waitFor(app.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'favo'")).firstMatch).tap()
        openList("favorites")
        waitFor(element("item-Bank"))

        // To the trash and back.
        element("item-Bank").swipeLeft()
        waitFor(app.buttons["Move to Trash"].firstMatch).tap()
        gone(element("item-Bank"))
        openList("trash")
        waitFor(element("item-Bank"))
        snap("13-trash")
        element("item-Bank").swipeLeft()
        waitFor(app.buttons["Restore"].firstMatch).tap()
        gone(element("item-Bank"))
    }

    /// A website's "Fill on" rule starts at "This site and its subdomains", which the item doesn't
    /// name; the two domain-wide rules say under the picker what they fill.
    func testFillOnDefaultsToThisSiteAndItsSubdomains() {
        launchFresh()
        signUpAndOpenVault()
        addLogin(title: "Shop", username: "ada", password: "shop-Passw0rd-71", website: "login.example.com")
        tap("item-Shop")
        waitFor(element("password-field"))
        XCTAssertFalse(textContaining("This site and its subdomains").exists, "the default isn't named")

        tap("edit-item")
        waitFor(textContaining("Not on other parts"))
        tap("editor-match-0")
        waitFor(app.buttons["Every part of this domain"].firstMatch).tap()
        waitFor(textContaining("including other parts"))
        tap("editor-save")
        gone(element("editor-save"))
        waitFor(textContaining("Every part of this domain"))
    }

    /// One of the vault's lists, from the lists one step back.
    func openList(_ name: String) {
        let back = app.navigationBars.buttons["BackButton"]
        if back.exists { back.tap() }
        scrollAndTap("sidebar-\(name)")
    }
}
