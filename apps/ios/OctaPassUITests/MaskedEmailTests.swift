import XCTest

/// Masked email with a file imported without the system's picker: in debug builds the app takes
/// the file a test names at launch (`OCTAPASS_PICK_NAME`, `OCTAPASS_PICK_TEXT`) instead.
final class MaskedEmailTests: UITestCase {
    /// An Octa Pass export with a login on a masked email alias: the import, then Masked email
    /// lists the alias with the login that uses it (the web vault's Aliases in use).
    func testImportedAliasShowsInMaskedEmail() {
        app.launchEnvironment["OCTAPASS_PICK_NAME"] = "octapass-export.json"
        app.launchEnvironment["OCTAPASS_PICK_TEXT"] = Self.export
        launchFresh()
        signUpAndOpenVault()

        app.tabBars.buttons.element(boundBy: 3).tap()
        scrollAndTap("settings-import")
        tap("import-source")
        waitFor(app.buttons["Octa Pass"].firstMatch).tap()
        tap("import-choose-file")
        waitFor(textContaining("octapass-export.json"))
        tap("import-action")
        waitFor(textContaining("Imported 1"), timeout: 30, "the import summary")

        // The vault's lists, one step back from All items.
        app.tabBars.buttons.element(boundBy: 0).tap()
        waitFor(element("new-item"))
        tap("BackButton")
        scrollAndTap("sidebar-masked-email")
        waitFor(textContaining("shop.x7k2@simplelogin.com"), timeout: 30, "the alias")
        XCTAssertTrue(textContaining("SimpleLogin · Used by 1 login").exists)
        XCTAssertTrue(app.buttons.matching(NSPredicate(format: "label CONTAINS 'Shop'")).firstMatch.exists)
        snap("51-masked-email-aliases")
    }

    static let export = """
    {"format":"octapass-export","version":1,"exportedAt":"2026-10-24T08:00:00.000Z",
     "vaults":[{"id":"v1","name":"Personal","type":"personal"}],
     "items":[{"id":"7d3f8f5e-9a43-4f6e-9a40-3c1f8d2a0b11","vaultId":"v1","createdAt":"2026-10-24T08:00:00.000Z","updatedAt":"2026-10-24T08:00:00.000Z",
       "overview":{"schemaVersion":1,"type":"login","title":"Shop","urls":["https://shop.example"]},
       "details":{"schemaVersion":1,"username":"shop.x7k2@simplelogin.com","password":"pw-shop-1",
         "recovery":{"email":"shop.x7k2@simplelogin.com","emailSource":{"kind":"alias","provider":"simplelogin","aliasId":"42"}}}}]}
    """
}
