import XCTest

/// The AutoFill extension, moved from the Tauri app: with Octa Pass turned on in Settings, Safari
/// offers it on a sign-in page; it unlocks with Face ID and fills the login the native app saved.
/// The script serves the page (`OCTAPASS_TEST_PAGE`) and matches every Face ID prompt.
final class AutoFillTests: UITestCase {
    let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
    let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")

    func testSafariFillsFromTheExtension() throws {
        let page = try XCTUnwrap(ProcessInfo.processInfo.environment["OCTAPASS_TEST_PAGE"], "the script serves the page")
        launchFresh()
        signUpAndOpenVault()
        addLogin(title: "Example", username: "ada", password: "hunter2-hunter2", website: page)
        snap("20-login-saved")

        try enableOctaPass()
        // Back in the foreground the app syncs and registers its logins with the system.
        app.activate()
        _ = element("lock-now").waitForExistence(timeout: 10)

        safari.launch()
        let address = safari.textFields["Address"].firstMatch
        if !address.waitForExistence(timeout: 10) { safari.buttons["Address"].firstMatch.tap() }
        address.tap()
        address.typeText("\(page)/login.html\n")
        let password = safari.webViews.secureTextFields.firstMatch
        XCTAssertTrue(password.waitForExistence(timeout: 30))
        password.tap()
        // With the Simulator's hardware keyboard the software keyboard (and its Passwords button)
        // stays below the screen until something is typed.
        password.typeText("x" + XCUIKeyboardKey.delete.rawValue)
        let picker = [safari.buttons["Passwords"], safari.buttons["Octa Pass"]].first { $0.waitForExistence(timeout: 5) }
        try XCTUnwrap(picker, "no AutoFill entry in\n\(safari.debugDescription)").tap()
        let octaPass = safari.buttons["Octa Pass"].firstMatch
        if octaPass.waitForExistence(timeout: 5) { octaPass.tap() }

        let login = shown("Example", in: [safari, springboard])
        snap("21-autofill-extension")
        try XCTUnwrap(login, "the extension unlocked and suggested the login").tap()
        let filled = expectation(for: NSPredicate(format: "value != nil AND value != ''"), evaluatedWith: password)
        wait(for: [filled], timeout: 20)
        snap("22-safari-filled")
    }

    func enableOctaPass() throws {
        settings.launch()
        settings.staticTexts["General"].firstMatch.tap()
        let autofill = settings.staticTexts["AutoFill & Passwords"].firstMatch
        XCTAssertTrue(autofill.waitForExistence(timeout: 10), settings.debugDescription)
        autofill.tap()
        // The row is a switch that contains the switch itself; tapping the row does nothing.
        let row = settings.switches.matching(NSPredicate(format: "label BEGINSWITH 'Octa Pass'")).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 10), settings.debugDescription)
        let toggle = row.switches.firstMatch.exists ? row.switches.firstMatch : row
        if (toggle.value as? String) != "1" { toggle.tap() }
        wait(for: [expectation(for: NSPredicate(format: "value == '1'"), evaluatedWith: toggle)], timeout: 10)
    }

    /// The extension's screen is a remote view: look for it in Safari and in SpringBoard.
    func shown(_ label: String, in apps: [XCUIApplication], timeout: TimeInterval = 30) -> XCUIElement? {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            for app in apps {
                let match = app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@", label)).firstMatch
                if match.exists { return match }
            }
            sleep(1)
        } while Date() < deadline
        return nil
    }
}
