import CryptoKit
import Foundation
import Security

/// The device chip's part of a local vault's key (plan 03, *Local mode keys*): a Secure Enclave
/// P-256 key that binds the vault to this phone. It works with no prompt, because it's useless
/// without the master password, and only while the phone has been unlocked since it started.
///
/// The Enclave key's encrypted form is a Keychain item in the shared group, so the AutoFill
/// extension can use it too. The `context` kept next to the vault is the public half of a key
/// whose private half is thrown away at once: nobody knows that side's secret, so the agreement
/// can't be worked out from the Enclave key's public half.
extension Keychain {
    /// False on a Simulator, and on a phone with no passcode set.
    public var chipAvailable: Bool { SecureEnclave.isAvailable }

    /// Makes the key. `nil` when there's no Secure Enclave.
    public func createChipKey(_ name: String) throws -> (context: Data, secret: Data)? {
        guard SecureEnclave.isAvailable else { return nil }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error
        ) else {
            throw KeychainError.failed(errSecParam)
        }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            try setSecret(key.dataRepresentation.base64EncodedString(), for: name)
            let context = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
            return (context, try chipSecret(name, context: context))
        } catch let error as KeychainError {
            throw error
        } catch {
            return nil
        }
    }

    /// The same 32 bytes `createChipKey` returned. `notFound` when the key is gone.
    public func chipSecret(_ name: String, context: Data) throws -> Data {
        guard let stored = try secret(name), let data = Data(base64Encoded: stored) else { throw KeychainError.notFound }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
            let peer = try P256.KeyAgreement.PublicKey(x963Representation: context)
            let shared = try key.sharedSecretFromKeyAgreement(with: peer)
            return shared.withUnsafeBytes { Self.chipSecret(raw: Data($0)) }
        } catch {
            throw KeychainError.notFound
        }
    }

    public func deleteChipKey(_ name: String) throws {
        try deleteSecret(name)
    }

    /// As the desktop app's `chip_secret_from`: the shape doesn't depend on the chip.
    static func chipSecret(raw: Data) -> Data {
        Data(SHA256.hash(data: Data("octapass/v1/chip-secret|".utf8) + raw))
    }
}
