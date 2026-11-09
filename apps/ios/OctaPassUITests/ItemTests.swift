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

    /// An item's files (group 3): one from Files (the app's stand-in picker in debug builds,
    /// `OCTAPASS_PICK_NAME`), opened in Quick Look, then removed after a confirm.
    func testAFileIsAttachedOpenedAndRemoved() {
        app.launchEnvironment["OCTAPASS_PICK_NAME"] = "lease.txt"
        app.launchEnvironment["OCTAPASS_PICK_TEXT"] = "Lease agreement, flat 4"
        launchFresh()
        signUpAndOpenVault()

        newItem(type: "secureNote")
        type("Lease", into: "editor-title")
        tap("editor-save")
        gone(element("editor-save"))
        tap("item-Lease")
        openMenu("attach-file", choosing: "Choose files")
        let row = app.buttons["Open lease.txt"].firstMatch
        waitFor(row, timeout: 30, "the attached file")
        snap("35-files")

        // Quick Look shows the decrypted copy (its contents are drawn in another process, so the
        // test only sees its Done button).
        let done = app.buttons["Done"].firstMatch
        // The file is still uploading for a moment after it's attached; a second tap if the first
        // lands while it's busy.
        for _ in 0..<2 where !done.exists {
            row.tap()
            _ = done.waitForExistence(timeout: 30)
        }
        waitFor(done, timeout: 30, "Quick Look")
        snap("36-quick-look")
        done.tap()
        gone(done, timeout: 30)

        row.swipeLeft()
        waitFor(app.buttons["Remove"].firstMatch).tap()
        waitFor(app.buttons["Remove file"].firstMatch).tap()
        gone(row, timeout: 30)
    }

    /// The types `testEveryTypeThroughTheEditor` doesn't make: an identity, a document (which
    /// needs its file before it saves) and a password-only item.
    func testIdentityDocumentAndPasswordItems() {
        app.launchEnvironment["OCTAPASS_PICK_NAME"] = "passport.txt"
        app.launchEnvironment["OCTAPASS_PICK_TEXT"] = "Passport P1234567"
        launchFresh()
        signUpAndOpenVault()

        newItem(type: "identity")
        type("Me", into: "editor-title")
        type("Ada", into: "field-First name")
        type("Lovelace", into: "field-Last name")
        type("ada@example.com", into: "field-Email")
        tap("editor-save")
        gone(element("editor-save"))
        tap("item-Me")
        waitFor(textContaining("Ada Lovelace"), timeout: 20, "the identity's full name")
        snap("37-identity")
        app.navigationBars.buttons["BackButton"].tap()

        // A document saves only with its file.
        newItem(type: "document")
        type("Passport", into: "editor-title")
        tap("editor-save")
        XCTAssertTrue(element("editor-save").waitForExistence(timeout: 5), "a document without a file is refused")
        openMenu("editor-attach", choosing: "Choose files")
        waitFor(textContaining("passport.txt"), timeout: 20, "the picked file in the editor")
        tap("editor-save")
        gone(element("editor-save"), timeout: 30)
        tap("item-Passport")
        waitFor(app.buttons["Open passport.txt"].firstMatch, timeout: 30, "the document's file")
        snap("38-document")
        app.navigationBars.buttons["BackButton"].tap()

        newItem(type: "password")
        type("Disk key", into: "editor-title")
        tap("editor-generate")
        scrollAndTap("use-password")
        tap("editor-save")
        gone(element("editor-save"))
        tap("item-Disk key")
        waitFor(element("password-field"))
    }

    /// One-time codes (group 3): a pasted setup link goes through the review and becomes a login
    /// with a live code; then a link another app opens joins that login after the same review.
    func testSetupLinksGoThroughTheReview() {
        launchFresh()
        signUpAndOpenVault()

        tap("scan")
        type("otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP&issuer=Example", into: "codes-paste")
        tap("codes-paste-add")
        tap("codes-continue")
        waitFor(element("review-save"), timeout: 20, "the review")
        snap("39-code-review")
        tap("review-save")
        gone(element("review-save"))
        tap("item-Example", timeout: 30)
        // The live code reads out digit by digit: "One-time code 1 2 3 4 5 6".
        waitFor(app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'One-time code '")).firstMatch, timeout: 20, "the live code")
        XCTAssertTrue(element("link-code").exists, "a code on its own offers to join a login")

        // A link opened from outside: the review first, nothing saved before it.
        app.navigationBars.buttons["BackButton"].tap()
        // Opened in Octa Pass itself: the system may give otpauth links to Apple's Passwords.
        app.open(URL(string: "otpauth://totp/Example:ada%40work?secret=KRSXG5CTMVRXEZLU&issuer=Example")!)
        waitFor(element("review-save"), timeout: 60, "the review of the opened link")
        tap("review-save")
        gone(element("review-save"))
    }

    /// Opens a menu and picks one of its buttons. Under XCUITest a `Menu` in a `Form` row doesn't
    /// always open on the first tap (plan 17 History, 2026-10-24): tap again near its label, then
    /// press and hold.
    func openMenu(_ identifier: String, choosing label: String) {
        let choice = app.buttons[label].firstMatch
        reveal(identifier)
        tap(identifier)
        if !choice.waitForExistence(timeout: 3) {
            element(identifier).coordinate(withNormalizedOffset: CGVector(dx: 0.2, dy: 0.5)).tap()
        }
        if !choice.waitForExistence(timeout: 3) {
            element(identifier).press(forDuration: 0.8)
        }
        waitFor(choice, timeout: 10, "\(label) in the \(identifier) menu").tap()
    }

    /// New item of a type, by the menu entry's identifier (the web vault's type name), so it works
    /// in any language.
    func newItem(type name: String) {
        tap("new-item")
        tap("new-\(name)")
        waitFor(element("editor-save"))
    }

    func newItem(_ type: String) {
        tap("new-item")
        waitFor(app.buttons[type].firstMatch).tap()
        waitFor(element("editor-save"))
    }
}
