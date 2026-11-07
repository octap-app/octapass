import XCTest

/// iPad: the split view with the vault's lists and tools in the sidebar, a list in the middle and
/// the item on the right. Run with DEVICE set to an iPad; on iPhone it's skipped.
final class IPadTests: UITestCase {
    func testSplitView() throws {
        try XCTSkipUnless(isPad, "iPad only")
        launchFresh()
        signUpAndOpenVault()
        addLogin(title: "GitHub", username: "octo", password: "hunter2-hunter2", website: "github.com")
        tap("item-GitHub")
        waitFor(element("password-field"))
        snap("50-ipad-split")
        // Tools are below the categories: in portrait the sidebar has to scroll to them.
        revealInSidebar("sidebar-generator").tap()
        waitFor(element("generated-password"))
        snap("51-ipad-generator")
    }

    /// Scrolls the sidebar until the row shows. `reveal` drags in the window's middle, which on an
    /// iPad is the list, not the sidebar.
    func revealInSidebar(_ identifier: String) -> XCUIElement {
        let window = app.windows.firstMatch
        for _ in 0..<12 where !visible(element(identifier)) {
            window.coordinate(withNormalizedOffset: CGVector(dx: 0.14, dy: 0.7))
                .press(forDuration: 0.05, thenDragTo: window.coordinate(withNormalizedOffset: CGVector(dx: 0.14, dy: 0.3)))
        }
        return element(identifier)
    }
}
