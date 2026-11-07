import Foundation
import LocalAuthentication
import Security

public enum KeychainError: Error, Equatable {
    /// The user cancelled Face ID / Touch ID or the passcode sheet.
    case cancelled
    /// No device-unlock secret: never stored, or gone because a new face or fingerprint was
    /// enrolled (`.biometryCurrentSet`).
    case notFound
    /// The device has no passcode, so nothing can be stored behind it.
    case noDeviceLock
    case failed(OSStatus)
}

/// The app's Keychain items, in an access group the AutoFill extension shares.
///
/// Plain secrets (the Secret Key, the refresh token) are readable without a prompt while the
/// phone is unlocked, and never leave it (`…ThisDeviceOnly`). The device-unlock secret is only
/// released after Face ID / Touch ID or the device passcode (plan 03).
public struct Keychain: Sendable {
    public let accessGroup: String?
    let service: String

    public init(accessGroup: String? = SharedContainer.keychainGroup, service: String = "app.octap") {
        self.accessGroup = accessGroup
        self.service = service
    }

    // MARK: Plain secrets

    public func secret(_ name: String) throws -> String? {
        var query = base(name, service: service)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw KeychainError.failed(status) }
        return String(data: data, encoding: .utf8)
    }

    public func setSecret(_ value: String, for name: String) throws {
        try delete(name, service: service)
        var item = base(name, service: service)
        item[kSecValueData as String] = Data(value.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        try check(SecItemAdd(item as CFDictionary, nil))
    }

    public func deleteSecret(_ name: String) throws {
        try delete(name, service: service)
    }

    // MARK: The device-unlock secret

    /// Stores `secret` so that only Face ID / Touch ID or the device passcode releases it.
    public func storeDeviceSecret(_ secret: Data, for name: String) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.biometryCurrentSet, .or, .devicePasscode],
            &error
        ) else {
            throw KeychainError.failed(errSecParam)
        }
        try delete(name, service: deviceService)
        var item = base(name, service: deviceService)
        item[kSecValueData as String] = secret
        item[kSecAttrAccessControl as String] = access
        let status = SecItemAdd(item as CFDictionary, nil)
        if status == errSecDecode || status == errSecNotAvailable { throw KeychainError.noDeviceLock }
        try check(status)
    }

    /// Shows the system prompt (`reason` under Face ID, or the passcode sheet) and returns the
    /// secret. Blocks: never call it on the main thread.
    public func deviceSecret(_ name: String, reason: String, context: LAContext = LAContext()) throws -> Data {
        context.localizedReason = reason
        var query = base(name, service: deviceService)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw KeychainError.failed(status) }
            return data
        case errSecUserCanceled:
            throw KeychainError.cancelled
        case errSecItemNotFound, errSecAuthFailed:
            throw KeychainError.notFound
        default:
            throw KeychainError.failed(status)
        }
    }

    public func deleteDeviceSecret(_ name: String) throws {
        try delete(name, service: deviceService)
    }

    // MARK: The stay-unlocked key (plan 18)

    /// Keeps the stay-unlocked key where the phone's own lock guards it and nothing asks for it:
    /// readable by the app and the AutoFill extension while the phone is unlocked, never synced or
    /// restored to another phone, and deleted by iOS when the passcode is removed
    /// (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, no access-control flags). Throws
    /// `noDeviceLock` on a phone with no passcode.
    public func storeStayUnlockedKey(_ key: Data, for name: String) throws {
        try delete(name, service: stayUnlockedService)
        var item = base(name, service: stayUnlockedService)
        item[kSecValueData as String] = key
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        if status == errSecDecode || status == errSecNotAvailable { throw KeychainError.noDeviceLock }
        try check(status)
    }

    /// The stay-unlocked key, with no prompt. Nil when there's none, or while the phone is locked
    /// (the item can't be read then: the caller falls back to asking).
    public func stayUnlockedKey(_ name: String) throws -> Data? {
        var query = base(name, service: stayUnlockedService)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound || status == errSecInteractionNotAllowed { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw KeychainError.failed(status) }
        return data
    }

    /// Succeeds when there's none.
    public func deleteStayUnlockedKey(_ name: String) throws {
        try delete(name, service: stayUnlockedService)
    }

    // MARK: Helpers

    var deviceService: String { "\(service).device" }
    var stayUnlockedService: String { "\(service).stayUnlocked" }

    func base(_ name: String, service: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: name,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }

    func delete(_ name: String, service: String) throws {
        let status = SecItemDelete(base(name, service: service) as CFDictionary)
        if status != errSecItemNotFound { try check(status) }
    }

    func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw KeychainError.failed(status) }
    }
}

/// Face ID, Touch ID or Optic ID when enrolled, otherwise the passcode: what device unlock uses
/// here and what the unlock screen calls it.
public struct DeviceLock: Equatable, Sendable {
    public let available: Bool
    public let label: String

    public static func current(_ context: LAContext = LAContext()) -> DeviceLock {
        var error: NSError?
        let available = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
        let biometrics = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return DeviceLock(available: available, label: biometrics ? label(context.biometryType) : "Passcode")
    }

    static func label(_ type: LABiometryType) -> String {
        switch type {
        case .faceID: "Face ID"
        case .touchID: "Touch ID"
        case .opticID: "Optic ID"
        default: "Passcode"
        }
    }
}
