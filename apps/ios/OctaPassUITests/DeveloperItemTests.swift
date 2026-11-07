import XCTest

/// SSH keys and environments through their real screens (plan 17, phase 3): the editor, the item
/// view with its "Confirm it's you", the list's filters and groups. Screenshots in the language
/// and appearance the script sets.
final class DeveloperItemTests: UITestCase {
    func testGeneratedSshKeyAndItsGatedPrivateKey() {
        launchFresh()
        signUpAndOpenVault()
        newItem("sshKey")
        snap("50-editor-ssh-new")
        scrollAndTap("ssh-generate")
        // The key's type and fingerprint replace the choices once it's made.
        waitFor(element("ssh-fingerprint"), timeout: 60, "a generated key")
        type("me@phone", into: "ssh-comment")
        // A key is named after its comment when it has no title.
        tap("editor-save")
        gone(element("editor-save"))
        tap("item-me@phone")
        waitFor(element("ssh-public-key"))
        XCTAssertTrue(textContaining("SHA256:").exists)
        snap("51-ssh-key")
        XCTAssertFalse(element("ssh-private-key").exists, "the private key stays hidden")
        // Device unlock is on, and the Simulator's Face ID answers.
        scrollAndTap("ssh-show-private")
        let shown = waitFor(element("ssh-private-key"), timeout: 30, "the private key after confirming")
        XCTAssertTrue(shown.label.contains("BEGIN OPENSSH PRIVATE KEY"))
        snap("52-ssh-private-key")
    }

    func testEnvironmentWithPastedFileFiltersAndStage() {
        launchFresh()
        signUpAndOpenVault()
        openCategories()

        newItem("environment")
        type("Shop API staging", into: "editor-title")
        type("shop-api", into: "env-project")
        type("staging", into: "env-stage")
        scrollAndTap("env-paste")
        let paste = reveal("env-paste-text")
        paste.tap()
        paste.typeText("API_KEY=abc123\nDEBUG=1\n")
        scrollAndTap("env-add-pasted")
        waitFor(element("env-key-1"))
        snap("53-editor-environment")
        tap("editor-save")
        gone(element("editor-save"))
        assertNoSavePasswordSheet()

        newItem("environment")
        type("Shop API production", into: "editor-title")
        type("shop-api", into: "env-project")
        type("production", into: "env-stage")
        scrollAndTap("env-add")
        type("API_KEY", into: "env-key-0")
        type("live-key", into: "env-value-0")
        tap("editor-save")
        gone(element("editor-save"))
        assertNoSavePasswordSheet()

        // Grouped by project, each row with its stage.
        waitFor(element("item-Shop API production"))
        snap("54-environments")
        tap("item-Shop API production")
        waitFor(textContaining("API_KEY"))
        // A stage that lacks a name another stage has says so, and production warns.
        let missing = reveal("env-missing")
        XCTAssertTrue(missing.label.contains("DEBUG"), missing.label)
        XCTAssertTrue(reveal("env-production").exists)
        snap("55-environment")
    }

    /// An open vault covers revealing and copying (maintainer decision, plan 03 History
    /// 2026-11-06); export still asks.
    func testAConfirmedUnlockCoversRevealAndCopyButNotExport() {
        launchFresh()
        signUp(email: "ios-\(UUID().uuidString.prefix(8).lowercased())@example.com")
        tap("kit-saved")
        tap("kit-continue")
        tap("open-vault")
        tap("offer-not-now", timeout: 30)
        waitForVault()
        addLogin(title: "Gated", username: "ada", password: "hunter2-hunter2", website: "example.com")
        assertNoSavePasswordSheet()
        tap("item-Gated")
        waitFor(element("password-field"))
        tap("reveal-Password")
        waitFor(text("hunter2-hunter2"), timeout: 20, "the password without a second prompt")
        XCTAssertFalse(element("confirm-password").exists, "reveal asked again")
        tap("copy-Password")
        Thread.sleep(forTimeInterval: 2)
        XCTAssertFalse(element("confirm-password").exists, "copy asked again")
        snap("56-revealed-after-unlock")

        // Export asks every time: the master password, with no device unlock.
        let back = app.navigationBars.buttons["BackButton"]
        if back.exists { back.tap() }
        app.tabBars.buttons.element(boundBy: 3).tap()
        scrollAndTap("settings-export")
        // JSON: the encrypted format first wants a password for the file.
        tap("export-format")
        waitFor(app.buttons["JSON"].firstMatch).tap()
        tap("export-action")
        waitFor(element("confirm-password"), timeout: 20, "Confirm it's you before the export")
        snap("57-confirm-its-you-export")
        tap("confirm-cancel")
        gone(element("confirm-password"))
    }

    /// With the app-open gate off, reveal doesn't ask either, from the moment it's turned off and
    /// after the next unlock: an open vault covers it (maintainer decision, plan 03 History 2026-11-06).
    func testWithTheAppOpenGateOffRevealDoesntAsk() {
        launchFresh()
        signUpAndOpenVault()
        addLogin(title: "Gated", username: "ada", password: "hunter2-hunter2", website: "example.com")
        assertNoSavePasswordSheet()
        app.tabBars.buttons.element(boundBy: 3).tap()
        // Stay unlocked off first: the gate applies only then, and is greyed out while it's on
        // (plan 18).
        let stay = reveal("settings-stay-unlocked").switches.firstMatch
        if (stay.value as? String) == "1" { stay.tap() }
        // Off, then device unlock off too, so a "Confirm it's you" would be the master password
        // sheet a test can see (the Simulator answers Face ID by itself).
        let gate = reveal("settings-device-auth-open").switches.firstMatch
        if (gate.value as? String) == "1" { gate.tap() }
        // Device unlock is near the top of Settings, under Security.
        for _ in 0..<8 where !visible(element("settings-device-unlock")) { app.swipeDown() }
        let device = waitFor(element("settings-device-unlock"), timeout: 10, "the device unlock switch").switches.firstMatch
        if (device.value as? String) == "1" { device.tap() }
        Thread.sleep(forTimeInterval: 2)
        app.tabBars.buttons.element(boundBy: 0).tap()
        tap("item-Gated")
        tap("reveal-Password")
        waitFor(text("hunter2-hunter2"), timeout: 20, "the password without a prompt, gate off")
        XCTAssertFalse(element("confirm-password").exists, "reveal asked with the gate off")

        // After the next unlock, with the master password, it doesn't ask either.
        let back = app.navigationBars.buttons["BackButton"]
        if back.exists { back.tap() }
        lockNow()
        type(Self.password, into: "master-password")
        tap("unlock")
        waitForVault()
        tap("item-Gated")
        tap("reveal-Password")
        waitFor(text("hunter2-hunter2"), timeout: 20, "the password without a prompt after unlocking")
        XCTAssertFalse(element("confirm-password").exists, "reveal asked after unlocking")
        snap("58-revealed-gate-off")
    }

    /// iOS offers to save a closed secure field to its own password manager; a vault's secrets
    /// never go there (plan 17).
    private func assertNoSavePasswordSheet() {
        Thread.sleep(forTimeInterval: 3)
        for screen in [app, springboard] {
            XCTAssertFalse(screen.staticTexts["Save Password?"].exists, "iOS offered to save a vault secret")
        }
    }

    /// The category lists are one step back from All items on iPhone.
    private func openCategories() {
        let back = app.navigationBars.buttons["BackButton"]
        if back.exists { back.tap() }
        scrollAndTap("sidebar-environment")
    }

    private func newItem(_ type: String) {
        tap("new-item")
        waitFor(element("new-\(type)")).tap()
        waitFor(element("editor-save"))
    }
}
