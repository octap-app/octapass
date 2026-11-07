import CoreLocation
import XCTest
@testable import OctaPassWifi

final class WifiTests: XCTestCase {
    private func request(_ json: String) throws -> JoinRequest {
        try JSONDecoder().decode(JoinRequest.self, from: Data(json.utf8))
    }

    func testPersonalWepAndOpenNetworks() throws {
        XCTAssertEqual(try request(#"{"ssid":"Home","password":"pw","security":"WPA","hidden":false}"#).kind, .personal("pw"))
        XCTAssertEqual(try request(#"{"ssid":"Old","password":"12345","security":"WEP","hidden":true}"#).kind, .wep("12345"))
        XCTAssertEqual(try request(#"{"ssid":"Cafe","security":"nopass","hidden":false}"#).kind, .open)
    }

    func testEnterpriseNetworks() throws {
        let peap = try request(#"{"ssid":"Corp","security":"WPA","hidden":false,"eap":{"method":"peap","username":"maya","password":"pw"}}"#)
        XCTAssertEqual(peap.kind, .enterprise(types: [25], ttlsInner: nil))
        let ttls = try request(#"{"ssid":"Uni","security":"WPA","hidden":false,"eap":{"method":"ttls","phase2":"pap","username":"maya"}}"#)
        XCTAssertEqual(ttls.kind, .enterprise(types: [21], ttlsInner: 0))
        // iOS can't join these from an app (TLS needs a client certificate).
        XCTAssertNil(try request(#"{"ssid":"Lab","security":"WPA","hidden":false,"eap":{"method":"tls","username":"u"}}"#).kind)
        XCTAssertNil(try request(#"{"ssid":"Old","security":"WPA","hidden":false,"eap":{"method":"leap","username":"u"}}"#).kind)
        XCTAssertNil(try request(#"{"ssid":"Corp","security":"WPA","hidden":false,"eap":{"method":"peap"}}"#).kind)
    }

    func testPermissionFollowsCoreLocation() {
        XCTAssertEqual(WifiReading.permission(.notDetermined, servicesEnabled: true), "prompt")
        XCTAssertEqual(WifiReading.permission(.denied, servicesEnabled: true), "denied")
        XCTAssertEqual(WifiReading.permission(.restricted, servicesEnabled: true), "denied")
        XCTAssertEqual(WifiReading.permission(.authorizedAlways, servicesEnabled: true), "granted")
        XCTAssertEqual(WifiReading.permission(.authorizedAlways, servicesEnabled: false), "denied")
    }

    func testNetworkNames() {
        XCTAssertEqual(WifiReading.ssid("Home 5G "), "Home 5G ")
        XCTAssertEqual(WifiReading.ssid("مقهى"), "مقهى")
        XCTAssertNil(WifiReading.ssid(""))
        XCTAssertNil(WifiReading.ssid(nil))
    }
}
