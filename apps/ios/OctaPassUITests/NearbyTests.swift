import CoreLocation
import XCTest

/// Nearby on a new account, with the Simulator's location set: a place saved from the location the
/// phone reads, an item added there, the place listed first as "Now nearby", another place after
/// it with its distance, and the offer to add a new item to the place the phone is at.
final class NearbyTests: UITestCase {
    /// Trafalgar Square, about where the Simulator says the phone is.
    private let office = CLLocation(latitude: 51.507351, longitude: -0.127758)

    func testThePlaceYoureAtComesFirstWithItsItems() {
        XCUIDevice.shared.location = XCUILocation(location: office)
        launchFresh()
        signUpAndOpenVault()
        openNearby()

        // The first place, where the phone is.
        tap("nearby-first-place")
        type("Office", into: "place-name")
        tap("place-use-current")
        let latitude = element("place-latitude")
        let read = NSPredicate { _, _ in (latitude.value as? String) == "51.507351" }
        XCTAssertEqual(XCTWaiter().wait(for: [XCTNSPredicateExpectation(predicate: read, object: nil)], timeout: 30), .completed,
                       "the location wasn't read into the form\n\(app.debugDescription)")
        tap("place-save")
        gone(element("place-save"))
        waitFor(element("place-Office"))
        XCTAssertEqual(element("place-Office").label, "Now nearby: Office")
        waitFor(text("By your location"))

        // An item that starts at the place.
        tap("place-menu-Office")
        waitFor(element("place-add-Office")).tap()
        type("Door code", into: "editor-title")
        tap("editor-save")
        gone(element("editor-save"))
        waitFor(element("item-Door code"))
        snap("60-nearby")

        // A place about 10 km north, typed in: listed after the office, with how far it is.
        tap("nearby-new-place")
        type("Cabin", into: "place-name")
        type("51.6", into: "place-latitude")
        type("-0.127758", into: "place-longitude")
        tap("place-save")
        gone(element("place-save"))
        waitFor(element("place-Cabin"))
        XCTAssertEqual(element("place-Cabin").label, "Cabin")
        waitFor(text("10 km away"))
        XCTAssertLessThan(element("place-Office").frame.minY, element("place-Cabin").frame.minY, "the place the phone is at comes first")

        // A new item saved at the office is offered to it, once.
        openList("all")
        addLogin(title: "Printer", username: "admin", password: "toner-Cartridge-42", website: "printer.example")
        let offer = waitFor(app.alerts["You’re at Office. Add this item to it?"], timeout: 30)
        offer.buttons["Add"].firstMatch.tap()
        gone(offer)
        openNearby()
        waitFor(element("item-Printer"))
        snap("61-nearby-offer")
    }

    private func openList(_ name: String) {
        let back = app.navigationBars.buttons["BackButton"]
        if back.exists { back.tap() }
        scrollAndTap("sidebar-\(name)")
    }

    /// Nearby, from the vault's lists (one step back from All items on an iPhone).
    private func openNearby() {
        let back = app.navigationBars.buttons["BackButton"]
        if back.exists { back.tap() }
        scrollAndTap("sidebar-nearby")
    }
}
