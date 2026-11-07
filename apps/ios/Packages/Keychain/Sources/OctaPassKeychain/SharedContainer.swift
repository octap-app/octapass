import Foundation

/// The App Group container the app and the AutoFill extension share, and the account list the
/// app writes there (`accounts.json`, see `crates/octapass-mobile-vault/src/accounts.rs`).
public enum SharedContainer {
    /// From the target's Info.plist (`OctaPassAppGroup`), so each build names its own group.
    public static var appGroup: String {
        Bundle.main.object(forInfoDictionaryKey: "OctaPassAppGroup") as? String ?? "group.app.octap"
    }

    /// From the target's Info.plist (`OctaPassKeychainGroup`); nil means the app's default group.
    public static var keychainGroup: String? {
        (Bundle.main.object(forInfoDictionaryKey: "OctaPassKeychainGroup") as? String).flatMap { $0.isEmpty ? nil : $0 }
    }

    public static func url() -> URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
    }

    public struct Account: Codable, Equatable, Sendable {
        public let tag: String
        public let email: String
        public let serverUrl: String
        /// Set for a vault on this device only.
        public let local: Local?

        /// What the extension needs of a local vault. The app keeps more here; it's ignored.
        public struct Local: Codable, Equatable, Sendable {
            /// base64url, when the vault is bound to the device chip.
            public let chipContext: String?

            public init(chipContext: String?) {
                self.chipContext = chipContext
            }
        }

        public init(tag: String, email: String, serverUrl: String, local: Local? = nil) {
            self.tag = tag
            self.email = email
            self.serverUrl = serverUrl
            self.local = local
        }

        public var storeFile: String { "\(tag).opstore" }
        public var secretKeyName: String { "secretKey.\(tag)" }
        public var deviceSecretName: String { "deviceSecret.\(tag)" }
        public var chipKeyName: String { "chipKey.\(tag)" }
        /// The stay-unlocked key (plan 18): its Keychain item is there while the app has the setting on.
        public var stayUnlockedName: String { "stayUnlocked.\(tag)" }

        /// `chipContext` as bytes.
        public var chipContext: Data? {
            guard var text = local?.chipContext else { return nil }
            text = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            text += String(repeating: "=", count: (4 - text.count % 4) % 4)
            return Data(base64Encoded: text)
        }
    }

    struct Accounts: Codable {
        var accounts: [Account] = []
        var current: String?
    }

    /// The account the app has open (locked or not), or nil when nobody is signed in.
    public static func currentAccount(in directory: URL) -> Account? {
        guard let data = try? Data(contentsOf: directory.appendingPathComponent("accounts.json")),
              let accounts = try? JSONDecoder().decode(Accounts.self, from: data)
        else { return nil }
        return accounts.accounts.first { $0.tag == accounts.current }
    }
}
