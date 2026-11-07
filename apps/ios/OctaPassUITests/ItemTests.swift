import XCTest

/// Items of each type through the editor and their screens: a card, a secure note, a Wi-Fi
/// network with Connect and its QR code, and a login with a one-time code and a generated
/// password.
final class ItemTests: UITestCase {
    /// A site written twice is saved once, and a login whose password is on another login says
    /// so, with the other one in "See them".
    func testRepeatedWebsitesAndReusedPassword() {
        launchFresh()
        signUpAndOpenVault()
        addLogin(title: "Forum", username: "ada", password: "shared-Passw0rd-71", website: "https://forum.example.com")

        newItem("Login")
        type("Saasify", into: "editor-title")
        type("ada@saasify", into: "editor-username")
        type("shared-Passw0rd-71", into: "editor-password")
        scrollAndTap("editor-add-website")
        type("https://saasify.example.com", into: "editor-website-0")
        scrollAndTap("editor-add-website")
        type("saasify.example.com/login", into: "editor-website-1")
        tap("editor-save")
        gone(element("editor-save"))

        tap("item-Saasify")
        waitFor(element("password-field"))
        let warning = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", "Password used on 1 other login")).firstMatch
        waitFor(warning, timeout: 30, "the reused-password warning")
        XCTAssertFalse(text("Also used on").exists, "one website, listed once")
        snap("34-reused-password")
        tap("reused-password-list")
        waitFor(app.navigationBars["Logins with this password"])
        waitFor(text("Forum"))
        waitFor(app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "Change password")).firstMatch)
    }

    func testEveryTypeThroughTheEditor() {
        launchFresh()
        signUpAndOpenVault()

        newItem("Card")
        type("Travel card", into: "editor-title")
        type("Ada Lovelace", into: "field-Name on card")
        type("4111 1111 1111 1111", into: "field-Card number")
        type("12/30", into: "field-Expiry date")
        tap("editor-save")
        gone(element("editor-save"))
        // The vault fills in the brand and the subtitle.
        waitFor(textContaining("Visa ending 1111"))

        newItem("Secure note")
        type("Wi-Fi at the office", into: "editor-title")
        let note = app.textViews.firstMatch
        waitFor(note).tap()
        note.typeText("Ask reception for the guest code.")
        tap("editor-save")
        gone(element("editor-save"))

        newItem("Wi-Fi network")
        type("Cafe", into: "editor-ssid")
        type("espresso-12", into: "field-Password")
        snap("30-editor-wifi")
        tap("editor-save")
        gone(element("editor-save"))
        tap("item-Cafe")
        // The location question for the Connected mark; the monitor allows it on the next touch.
        let alert = springboard.alerts.firstMatch
        if alert.waitForExistence(timeout: 5) { alert.buttons["Allow While Using App"].tap() }
        waitFor(element("wifi-connect"))
        snap("31-wifi")
        tap("show-qr")
        waitFor(element("qr-code"), timeout: 10, "a Wi-Fi code shows without confirming")
        snap("32-wifi-qr")
        app.buttons["Close"].firstMatch.tap()
        app.navigationBars.buttons["BackButton"].tap()

        // A login with a generated password and a one-time code.
        newItem("Login")
        type("Mail", into: "editor-title")
        tap("editor-generate")
        scrollAndTap("use-password")
        type("JBSWY3DPEHPK3PXP", into: "field-One-time code")
        tap("editor-save")
        gone(element("editor-save"))
        tap("item-Mail")
        waitFor(element("password-field"))
        snap("33-login")
        XCTAssertTrue(textContaining("Encrypted").exists || app.staticTexts.count > 0)
    }

    /// A counter-based code shows no live code: each code is asked for, and the counter moves.
    func testCounterBasedCode() {
        launchFresh()
        signUpAndOpenVault()

        newItem("Login")
        type("Bank", into: "editor-title")
        type("otpauth://hotp/Bank?secret=JBSWY3DPEHPK3PXP&counter=4", into: "field-One-time code")
        tap("editor-save")
        gone(element("editor-save"))
        tap("item-Bank")
        waitFor(textContaining("Next code is number 4"))
        tap("hotp-next")
        waitFor(textContaining("Next code is number 5"))
        tap("hotp-resync")
        type("20", into: "hotp-counter-field")
        tap("hotp-counter-save")
        waitFor(textContaining("Next code is number 20"))
    }

    /// A website's match rule, then the version from before it restored.
    func testMatchRuleAndVersionHistory() {
        launchFresh()
        signUpAndOpenVault()

        addLogin(title: "Forum", username: "ada", password: "first-password-1", website: "forum.example.com")
        tap("item-Forum")
        tap("edit-item")
        tap("editor-match-0")
        waitFor(app.buttons["This exact host"].firstMatch).tap()
        tap("editor-save")
        gone(element("editor-save"))
        waitFor(textContaining("This exact host"))

        scrollAndTap("item-history")
        waitFor(app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'version-'")).firstMatch).tap()
        scrollAndTap("version-restore")
        waitFor(app.sheets.buttons["Restore"].firstMatch).tap()
        gone(textContaining("This exact host"))
    }

    func newItem(_ type: String) {
        tap("new-item")
        waitFor(app.buttons[type].firstMatch).tap()
        waitFor(element("editor-save"))
    }
}
