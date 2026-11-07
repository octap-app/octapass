import CoreLocation

/// A network from a Wi-Fi item, as the web view sends it (`src/wifi.ts`, `connectArgs`).
public struct JoinRequest: Decodable, Equatable {
    public let ssid: String
    public let password: String?
    /// `WPA`, `WEP` or `nopass`, as in `WIFI:` codes; Enterprise networks send `eap` too.
    public let security: String
    public let hidden: Bool
    public let eap: Eap?

    /// An Enterprise network's sign-in (802.1X).
    public struct Eap: Decodable, Equatable {
        /// `peap`, `ttls`, `tls`, `pwd`, `leap` or `fast`.
        public let method: String
        /// PEAP and TTLS: `mschapv2`, `gtc`, `pap`, `chap` or `mschap`.
        public let phase2: String?
        public let username: String?
        public let password: String?
        public let identity: String?
        public let serverDomain: String?
    }

    /// What iOS is asked to join.
    public enum Kind: Equatable {
        case open
        case wep(String)
        case personal(String)
        /// `NEHotspotEAPSettings`: its EAP types and, for TTLS, the inner method (raw values).
        case enterprise(types: [Int], ttlsInner: Int?)
    }

    /// `nil` for what iOS can't join from an app: PWD and LEAP, TLS (it needs a client certificate
    /// Octa Pass doesn't keep), or an Enterprise network without a username.
    public var kind: Kind? {
        if let eap {
            guard let type = Self.eapTypes[eap.method], eap.username?.isEmpty == false else { return nil }
            let inner = eap.method == "ttls" ? Self.ttlsInner[eap.phase2 ?? "mschapv2"] : nil
            return .enterprise(types: [type], ttlsInner: inner)
        }
        switch security {
        case "nopass": return .open
        case "WEP": return .wep(password ?? "")
        default: return .personal(password ?? "")
        }
    }

    /// `NEHotspotEAPSettings.EAPType`'s raw values.
    static let eapTypes = ["ttls": 21, "peap": 25, "fast": 43]
    /// `NEHotspotEAPSettings.TTLSInnerAuthenticationType`'s raw values.
    static let ttlsInner = ["pap": 0, "chap": 1, "mschap": 2, "mschapv2": 3, "gtc": 4]
}

public enum WifiReading {
    /// The web view's `WifiPermission` for CoreLocation's answer. iOS tells apps the network name
    /// only with location access ("While Using" is enough).
    public static func permission(_ status: CLAuthorizationStatus, servicesEnabled: Bool) -> String {
        guard servicesEnabled else { return "denied" }
        switch status {
        case .notDetermined: return "prompt"
        case .denied, .restricted: return "denied"
        default: return "granted"
        }
    }

    /// The network name `NEHotspotNetwork.fetchCurrent` gave: none when it's missing or empty.
    /// Spaces are kept: they can be part of a name.
    public static func ssid(_ raw: String?) -> String? {
        guard let raw, !raw.isEmpty else { return nil }
        return raw
    }
}
