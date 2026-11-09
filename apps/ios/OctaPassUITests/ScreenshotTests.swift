import XCTest

/// The main screens, for the screenshot runs in both languages and appearances (plan 17, phase 3).
/// It finds everything by accessibility identifier, never by its words, so it runs in any
/// language; the other tests match some English labels and run in English only. On iPhone and
/// iPad:
///
///     scripts/ui-tests.sh build/screenshots/en-light -only-testing:OctaPassUITests/ScreenshotTests
///     APPEARANCE=dark scripts/ui-tests.sh build/screenshots/en-dark -only-testing:OctaPassUITests/ScreenshotTests
///     OCTAPASS_TEST_LANGUAGE=ar scripts/ui-tests.sh build/screenshots/ar-light -only-testing:OctaPassUITests/ScreenshotTests
///     OCTAPASS_TEST_LANGUAGE=ar APPEARANCE=dark scripts/ui-tests.sh build/screenshots/ar-dark -only-testing:OctaPassUITests/ScreenshotTests
///     DEVICE="iPad Pro 13-inch (M5)" scripts/ui-tests.sh build/screenshots/ipad-en-light -only-testing:OctaPassUITests/ScreenshotTests
final class ScreenshotTests: UITestCase {
    func testMainScreens() {
        launchFresh()
        waitFor(element("sign-in"), timeout: 60)
        snap("s01-sign-in")
        signUp(email: "ios-shots-\(UUID().uuidString.prefix(6).lowercased())@example.com")
        snap("s02-recovery-kit")
        scrollAndTap("kit-saved")
        tap("kit-continue")
        tap("open-vault")
        waitFor(element("offer-turn-on"), timeout: 30)
        snap("s03-device-unlock-offer")
        tap("offer-not-now")
        gone(element("offer-not-now"))
        waitForVault()

        addLogin(title: "GitHub", username: "octo@example.com", password: "c0rrect-Horse-battery", website: "https://github.com")
        addLogin(title: "GitHub work", username: "octo@work.example", password: "an0ther-Horse-battery", website: "github.com/login")
        addLogin(title: "Bank", username: "ada", password: "hunter2-hunter2", website: "bank.example")
        snap("s04-list")
        tap("site-github.com")
        waitFor(element("item-GitHub work"))
        snap("s05-site-row")
        tap("item-Bank")
        waitFor(element("password-field"))
        snap("s06-item")
        tap("edit-item")
        waitFor(element("editor-save"))
        snap("s07-editor")
        tap("editor-save")
        gone(element("editor-save"))

        show("generator")
        waitFor(element("generated-password"))
        snap("s08-generator")
        show("health")
        waitFor(element("health-weak"), timeout: 60)
        snap("s09-health")
        show("sharing")
        waitFor(element("sharing-new-vault"), timeout: 30)
        snap("s10-sharing")
        show("settings")
        waitFor(element("settings-language"), timeout: 30)
        snap("s11-settings")

        // The lock screen, then back in with the master password.
        if !isPad { app.tabBars.buttons.element(boundBy: 0).tap() }
        lockNow()
        waitFor(element("master-password"), timeout: 30)
        snap("s12-locked")
        type(Self.password, into: "master-password")
        tap("unlock")
        if element("offer-not-now").waitForExistence(timeout: 20) { tap("offer-not-now") }
        waitForVault(timeout: 60)
    }

    /// One of the vault's screens: a tab on iPhone (Health, Settings), a row in the vault's lists
    /// one step back from All items (the others), the sidebar on iPad.
    func show(_ route: String) {
        if isPad {
            revealInSidebar("sidebar-\(route)").tap()
            return
        }
        switch route {
        case "health": app.tabBars.buttons.element(boundBy: 2).tap()
        case "settings": app.tabBars.buttons.element(boundBy: 3).tap()
        default:
            app.tabBars.buttons.element(boundBy: 0).tap()
            let back = app.navigationBars.buttons["BackButton"]
            for _ in 0..<4 where !visible(element("sidebar-\(route)")) {
                guard back.waitForExistence(timeout: 2) else { break }
                back.tap()
            }
            scrollAndTap("sidebar-\(route)")
        }
    }

    /// Scrolls the iPad's sidebar until the row shows (`reveal` drags the list in the middle). The
    /// sidebar is on the right in Arabic.
    func revealInSidebar(_ identifier: String) -> XCUIElement {
        let window = app.windows.firstMatch
        let x = ProcessInfo.processInfo.environment["OCTAPASS_TEST_LANGUAGE"] == "ar" ? 0.86 : 0.14
        for (from, to) in [(0.7, 0.3), (0.3, 0.7)] {
            for _ in 0..<10 where !visible(element(identifier)) {
                window.coordinate(withNormalizedOffset: CGVector(dx: x, dy: from))
                    .press(forDuration: 0.05, thenDragTo: window.coordinate(withNormalizedOffset: CGVector(dx: x, dy: to)))
            }
        }
        return element(identifier)
    }
}
