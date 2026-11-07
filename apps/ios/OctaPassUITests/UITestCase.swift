import XCTest

/// What every UI test shares: the app pointed at the development server the script started
/// (`scripts/ui-tests.sh`), screenshots, and small waits. The app's screens are native, so the
/// tests find elements by accessibility identifier or label and tap them.
class UITestCase: XCTestCase {
    let app = XCUIApplication()
    let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    /// The recovery code shown in the Recovery Kit of the last `signUp(email:)`.
    private(set) var lastRecoveryCode = ""

    static var server: String {
        ProcessInfo.processInfo.environment["OCTAPASS_TEST_SERVER"] ?? "http://localhost:8080"
    }

    static let password = "correct horse battery staple 42"

    override func setUp() {
        continueAfterFailure = false
        app.launchEnvironment["OCTAPASS_SERVER_URL"] = Self.server
        app.launchEnvironment["OCTAPASS_PWNED_URL"] = Self.server
        // System alerts (location for the Wi-Fi marks): allow, so the screens behind carry on.
        addUIInterruptionMonitor(withDescription: "system alerts") { alert in
            for label in ["Allow While Using App", "Allow", "OK"] where alert.buttons[label].exists {
                alert.buttons[label].tap()
                return true
            }
            return false
        }
        if let language = ProcessInfo.processInfo.environment["OCTAPASS_TEST_LANGUAGE"] {
            app.launchArguments += ["-AppleLanguages", "(\(language))"]
        }
    }

    /// Starts with nothing on the phone: no account, no settings.
    func launchFresh() {
        app.launchEnvironment["OCTAPASS_RESET"] = "1"
        app.launch()
        app.launchEnvironment["OCTAPASS_RESET"] = nil
    }

    /// The element on screen with this identifier: screens further back in a navigation stack
    /// keep theirs.
    func element(_ identifier: String) -> XCUIElement {
        let matches = app.descendants(matching: .any).matching(identifier: identifier)
        guard matches.count > 1 else { return matches.firstMatch }
        let screen = app.windows.firstMatch.frame
        return matches.allElementsBoundByIndex.first { $0.exists && screen.intersects($0.frame) } ?? matches.firstMatch
    }

    func text(_ label: String) -> XCUIElement {
        app.staticTexts.matching(NSPredicate(format: "label == %@", label)).firstMatch
    }

    func textContaining(_ part: String) -> XCUIElement {
        app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", part)).firstMatch
    }

    @discardableResult
    func waitFor(_ element: XCUIElement, timeout: TimeInterval = 20, _ message: String = "") -> XCUIElement {
        XCTAssertTrue(element.waitForExistence(timeout: timeout), "\(message)\n\(app.debugDescription)")
        return element
    }

    /// Whether the element is on screen and not under the keyboard.
    func visible(_ element: XCUIElement) -> Bool {
        guard element.exists, !element.frame.isEmpty else { return false }
        var area = app.windows.firstMatch.frame
        let keyboard = app.keyboards.firstMatch
        if keyboard.exists { area.size.height = min(area.height, keyboard.frame.minY) }
        return area.contains(CGPoint(x: element.frame.midX, y: element.frame.midY))
    }

    /// Scrolls a little at a time, down and then back up, until the element shows.
    @discardableResult
    func reveal(_ identifier: String) -> XCUIElement {
        let window = app.windows.firstMatch
        for (from, to, times) in [(0.62, 0.42, 14), (0.38, 0.62, 28)] {
            for _ in 0..<times {
                if visible(element(identifier)) { return element(identifier) }
                window.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: from))
                    .press(forDuration: 0.05, thenDragTo: window.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: to)))
            }
        }
        return element(identifier)
    }

    /// Scrolls until the element shows, then taps it.
    func scrollAndTap(_ identifier: String) {
        reveal(identifier).tap()
    }

    /// Taps once the element is there and can take the tap (a sheet may still be closing).
    func tap(_ identifier: String, timeout: TimeInterval = 20) {
        waitFor(element(identifier), timeout: timeout, "no \(identifier)")
        let target = element(identifier)
        // Mid-animation an element has no frame, and asking if it's hittable then fails the test.
        let laidOut = NSPredicate { _, _ in !target.frame.isEmpty }
        _ = XCTWaiter().wait(for: [XCTNSPredicateExpectation(predicate: laidOut, object: nil)], timeout: 10)
        _ = XCTWaiter().wait(for: [expectation(for: NSPredicate(format: "hittable == true"), evaluatedWith: target)], timeout: 10)
        target.tap()
    }

    /// Types into a field, replacing what's there, and checks it took the text.
    func type(_ text: String, into identifier: String) {
        waitFor(element(identifier), timeout: 20, "no \(identifier)")
        let field = reveal(identifier)
        let input = [field.textFields.firstMatch, field.secureTextFields.firstMatch].first { $0.exists } ?? field
        let secure = input.elementType == .secureTextField
        for _ in 0..<3 {
            focus(input, identifier)
            // Keys typed while the keyboard switches to or from a secure field get lost: wait.
            if secure { Thread.sleep(forTimeInterval: 1) }
            if let value = input.value as? String, !value.isEmpty, value != input.placeholderValue {
                input.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: value.count))
            }
            input.typeText(text)
            let value = input.value as? String ?? ""
            // A secure field shows one dot per character.
            if value == text || (secure && value.count == text.count) { return }
        }
        XCTFail("couldn't type into \(identifier): \(input.value ?? "")")
    }

    /// A tap during a screen's push animation lands nowhere: tap until the field has focus.
    func focus(_ input: XCUIElement, _ identifier: String) {
        let focused = NSPredicate(format: "hasKeyboardFocus == true")
        for _ in 0..<5 {
            if (input.value(forKey: "hasKeyboardFocus") as? Bool) == true { return }
            input.tap()
            if XCTWaiter().wait(for: [expectation(for: focused, evaluatedWith: input)], timeout: 2) == .completed { return }
        }
        snap("focus-\(identifier)")
        XCTFail("\(identifier) never got keyboard focus\n\(app.debugDescription)")
    }

    /// The vault is open: its tab bar shows on iPhone, its sidebar (with Lock now) on iPad.
    @discardableResult
    func waitForVault(timeout: TimeInterval = 30) -> XCUIElement {
        let open = NSPredicate { _, _ in self.app.tabBars.buttons.firstMatch.exists || self.element("lock-now").exists }
        XCTAssertEqual(XCTWaiter().wait(for: [XCTNSPredicateExpectation(predicate: open, object: nil)], timeout: timeout), .completed,
                       "the open vault\n\(app.debugDescription)")
        return app.tabBars.buttons.firstMatch.exists ? app.tabBars.buttons.firstMatch : element("lock-now")
    }

    var isPad: Bool { UIDevice.current.userInterfaceIdiom == .pad }

    /// Lock now, from the vault's lists (one step back from a list on iPhone).
    func lockNow() {
        let lock = element("lock-now")
        if !visible(lock) {
            let back = app.navigationBars.buttons["BackButton"]
            if back.exists { back.tap() }
        }
        tap("lock-now")
    }

    /// A new account, through sign-up to the open vault (Face ID turned on when offered).
    @discardableResult
    func signUpAndOpenVault(email: String = "ios-\(UUID().uuidString.prefix(8).lowercased())@example.com") -> String {
        let secretKey = signUp(email: email)
        // Below the kit's actions on a smaller screen.
        waitFor(element("kit-saved"), timeout: 30)
        scrollAndTap("kit-saved")
        tap("kit-continue")
        tap("open-vault")
        tap("offer-turn-on", timeout: 30)
        gone(element("offer-turn-on"))
        waitForVault()
        return secretKey
    }

    /// A login through the editor, from the list's New item menu.
    func addLogin(title: String, username: String, password: String, website: String) {
        tap("new-item")
        waitFor(app.buttons["Login"].firstMatch).tap()
        type(title, into: "editor-title")
        type(username, into: "editor-username")
        type(password, into: "editor-password")
        scrollAndTap("editor-add-website")
        type(website, into: "editor-website-0")
        tap("editor-save")
        gone(element("editor-save"))
    }

    func gone(_ element: XCUIElement, timeout: TimeInterval = 20) {
        let predicate = NSPredicate(format: "exists == false")
        wait(for: [expectation(for: predicate, evaluatedWith: element)], timeout: timeout)
    }

    func snap(_ name: String) {
        let shot = XCUIScreen.main.screenshot()
        let attachment = XCTAttachment(screenshot: shot)
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
        if let dir = ProcessInfo.processInfo.environment["SCREENSHOTS_DIR"] {
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try? shot.pngRepresentation.write(to: URL(fileURLWithPath: dir).appendingPathComponent("\(name).png"))
        }
    }

    /// A new account on the development server, through the sign-up screens; returns its
    /// Secret Key. Leaves the vault open.
    @discardableResult
    func signUp(email: String) -> String {
        tap("create-account")
        waitFor(element("signup-email"))
        snap("02-sign-up")
        type(email, into: "signup-email")
        // iOS treats a form with two secure fields as account creation, and under XCUITest its
        // strong-password handling drops what's typed into the first one: type each twice.
        for _ in 0..<2 {
            for field in ["signup-password", "confirm-password"] {
                let input = element(field).secureTextFields.firstMatch
                focus(input, field)
                Thread.sleep(forTimeInterval: 1)
                if let value = input.value as? String, !value.isEmpty {
                    input.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: value.count))
                }
                input.typeText(Self.password)
            }
        }
        tap("continue")
        // A development server hands back the email's code, and the screen shows it.
        let notice = waitFor(element("dev-code"), timeout: 60, "the development code")
        let code = String(notice.label.filter(\.isNumber).suffix(6))
        type(code, into: "verification-code")
        tap("verify")
        let key = waitFor(element("kit-secret-key"), timeout: 60, "the Recovery Kit")
        // "Secret Key, OP1-…": the field's label, then its value.
        let label = key.label
        lastRecoveryCode = element("kit-recovery-code").label
        return label.range(of: "OP").map { String(label[$0.lowerBound...]) } ?? label
    }
}
