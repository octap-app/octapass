// iPhone only: joining needs NEHotspotConfiguration. The Mac's stand-in is in OctaPassMac/Platform.
#if os(iOS)
import CoreLocation
import Foundation
import NetworkExtension
import OctaPassVault
import OctaPassWifi

/// Joining a Wi-Fi item's network with `NEHotspotConfiguration` (Hotspot Configuration
/// entitlement), with `NEHotspotEAPSettings` for PEAP, TTLS and EAP-FAST, as the Tauri app did.
/// iOS asks the user to confirm the first time.
enum WifiConnect {
    enum Failure: Error {
        case unsupported, cancelled, failed
    }

    /// What `OctaPassWifi` joins: a typed Wi-Fi item, or an older one's network.
    static func request(_ network: WifiNetwork, details: WifiDetails?) -> JoinRequest? {
        var json: [String: Any] = [
            "ssid": network.ssid,
            "security": network.security == .wep ? "WEP" : network.security == .none ? "nopass" : "WPA",
            "hidden": network.hidden,
        ]
        if let password = network.password { json["password"] = password }
        if network.security == .enterprise {
            guard let details, let method = details.eapMethod else { return nil }
            var eap: [String: Any] = ["method": method]
            eap["phase2"] = details.phase2
            eap["username"] = details.username
            eap["password"] = details.password
            eap["identity"] = details.identity
            eap["serverDomain"] = details.serverDomain
            json["eap"] = eap
        }
        guard let data = try? JSONSerialization.data(withJSONObject: json) else { return nil }
        return try? JSONDecoder().decode(JoinRequest.self, from: data)
    }

    /// Whether iOS can join this kind of network from an app at all.
    static func canJoin(_ network: WifiNetwork, details: WifiDetails?) -> Bool {
        request(network, details: details)?.kind != nil
    }

    static func join(_ network: WifiNetwork, details: WifiDetails?) async throws {
        #if targetEnvironment(simulator)
        throw Failure.unsupported
        #else
        guard let request = request(network, details: details), let kind = request.kind else { throw Failure.unsupported }
        let configuration: NEHotspotConfiguration
        switch kind {
        case .open: configuration = NEHotspotConfiguration(ssid: request.ssid)
        case let .wep(key): configuration = NEHotspotConfiguration(ssid: request.ssid, passphrase: key, isWEP: true)
        case let .personal(passphrase): configuration = NEHotspotConfiguration(ssid: request.ssid, passphrase: passphrase, isWEP: false)
        case let .enterprise(types, inner):
            let settings = NEHotspotEAPSettings()
            settings.supportedEAPTypes = types.map { NSNumber(value: $0) }
            settings.username = request.eap?.username ?? ""
            settings.password = request.eap?.password ?? ""
            if let identity = request.eap?.identity, !identity.isEmpty { settings.outerIdentity = identity }
            if let inner, let type = NEHotspotEAPSettings.TTLSInnerAuthenticationType(rawValue: inner) { settings.ttlsInnerAuthenticationType = type }
            if let domain = request.eap?.serverDomain, !domain.isEmpty { settings.trustedServerNames = [domain] }
            configuration = NEHotspotConfiguration(ssid: request.ssid, eapSettings: settings)
        }
        configuration.hidden = request.hidden
        // Stay joined, like a network chosen in Settings.
        configuration.joinOnce = false
        do {
            try await NEHotspotConfigurationManager.shared.apply(configuration)
        } catch let error as NSError where error.domain == NEHotspotConfigurationErrorDomain {
            switch NEHotspotConfigurationError(rawValue: error.code) {
            case .alreadyAssociated: return
            case .userDenied: throw Failure.cancelled
            default: throw Failure.failed
            }
        }
        #endif
    }
}

/// The network the iPhone is on, for the Connected mark. iOS gives its name only with location
/// access (asked when the user opens Wi-Fi, never at start) and the Access Wi-Fi Information
/// entitlement; it can't list networks in range.
@MainActor @Observable
final class WifiRadar: NSObject, CLLocationManagerDelegate {
    static let shared = WifiRadar()
    private let manager = CLLocationManager()
    private(set) var permission = "prompt"
    private(set) var connected: String?

    override private init() {
        super.init()
        manager.delegate = self
        permission = WifiReading.permission(manager.authorizationStatus, servicesEnabled: CLLocationManager.locationServicesEnabled())
    }

    /// Asks for location once, then reads the current network.
    func refresh() async {
        if manager.authorizationStatus == .notDetermined {
            manager.requestWhenInUseAuthorization()
            return
        }
        permission = WifiReading.permission(manager.authorizationStatus, servicesEnabled: CLLocationManager.locationServicesEnabled())
        guard permission == "granted" else { return }
        connected = WifiReading.ssid(await NEHotspotNetwork.fetchCurrent()?.ssid)
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor in
            guard manager.authorizationStatus != .notDetermined else { return }
            await self.refresh()
        }
    }
}
#endif
