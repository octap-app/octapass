import XCTest

/// Credential Exchange (iOS 26): what another app hands over waits for the unlocked vault, shows
/// what it holds, and is saved only on Import. The system's import sheet can't be driven from a
/// test, so the app is handed the CXF at launch (`OCTAPASS_RECEIVE_CXF`, debug builds only), as
/// Apple's encoder writes it.
final class OtherAppsTests: UITestCase {
    func testReceivedCredentialsAreReviewedThenImported() throws {
        let fixture = URL(fileURLWithPath: #filePath)
            .appending(path: "../../../../crates/octapass-core/tests/import-fixtures/cxf-apple-passwords.json")
        app.launchEnvironment["OCTAPASS_RECEIVE_CXF"] = try String(contentsOf: fixture.standardized, encoding: .utf8)
        app.launchEnvironment["OCTAPASS_RECEIVE_FROM"] = "Passwords"
        launchFresh()
        signUpAndOpenVault()

        waitFor(element("received-import"), timeout: 30, "the review of what Passwords sent")
        XCTAssertTrue(app.navigationBars.staticTexts.element(boundBy: 0).label.contains("Passwords"))
        snap("60-received-review")
        tap("received-import")
        gone(element("received-import"))
        waitFor(textContaining("GitHub"), timeout: 30, "the imported login in the list")

        // Settings lists the export to another app (the system's sheet isn't opened here).
        app.tabBars.buttons.element(boundBy: 3).tap()
        reveal("settings-export-to-app")
        snap("61-other-apps")
    }
}
