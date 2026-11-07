import AuthenticationServices
import Foundation
import LocalAuthentication
import OctaPassKeychain
import OctaPassResources
import OctaPassVault

/// What the vault asks the phone for (`NativePlatform`): Keychain items in the group the AutoFill
/// extension shares, the device-unlock secret behind Face ID / Touch ID or the passcode, and the
/// AutoFill suggestions. The vault calls it on its own threads, so the prompts may block.
final class VaultPlatform: NativePlatform, @unchecked Sendable {
    let keychain: Keychain

    init(keychain: Keychain = Keychain()) {
        self.keychain = keychain
    }

    func secret(name: String) throws -> String? {
        try mapped { try keychain.secret(name) }
    }

    func setSecret(name: String, value: String) throws {
        try mapped { try keychain.setSecret(value, for: name) }
    }

    func deleteSecret(name: String) throws {
        try mapped { try keychain.deleteSecret(name) }
    }

    func deviceLock() -> VaultDeviceLock {
        let lock = KeychainDeviceLock.current()
        return VaultDeviceLock(available: lock.available, label: lock.label)
    }

    /// Turning device unlock on asks for it once: the key is read back through the system prompt,
    /// so it's on only after the person's own Touch ID, Face ID or passcode has released it.
    /// Cancelled, the key goes again and device unlock stays off.
    func storeDeviceSecret(name: String, secret: Data) throws {
        try mapped {
            try keychain.storeDeviceSecret(secret, for: name)
            do {
                guard try keychain.deviceSecret(name, reason: Self.turnOnReason) == secret else {
                    throw KeychainError.notFound
                }
            } catch {
                try? keychain.deleteDeviceSecret(name)
                throw error
            }
        }
    }

    /// "Turn on Touch ID". The Mac shows it after "Octa Pass is trying to", so it starts lowercase there.
    private static var turnOnReason: String {
        let reason = L10n.phone.native.deviceUnlockTurnOn(method: KeychainDeviceLock.current().label)
        #if os(macOS)
        return reason.prefix(1).lowercased() + reason.dropFirst()
        #else
        return reason
        #endif
    }

    func deviceSecret(name: String, reason: String) throws -> Data {
        try mapped { try keychain.deviceSecret(name, reason: reason) }
    }

    func deleteDeviceSecret(name: String) throws {
        try mapped { try keychain.deleteDeviceSecret(name) }
    }

    /// What the prompt's reply said, read after it signalled.
    private final class PromptOutcome: @unchecked Sendable {
        var failure: Error?
    }

    /// The desktop services' approval on the Mac (plan 19): Touch ID or the Mac's password, with
    /// no secret behind it, for the browser extension's unlock, the CLI and each SSH signature.
    /// The Mac's prompt says "Octa Pass is trying to <reason>". The phones never ask.
    func verifyUser(reason: String) throws {
        let context = LAContext()
        var unavailable: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &unavailable) else {
            throw VaultError.Failed(code: .deviceUnlockUnsupported, reason: unavailable?.localizedDescription ?? "no device lock")
        }
        let done = DispatchSemaphore(value: 0)
        let outcome = PromptOutcome()
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { allowed, error in
            if !allowed { outcome.failure = error ?? LAError(.authenticationFailed) }
            done.signal()
        }
        done.wait()
        guard let failure = outcome.failure else { return }
        switch (failure as? LAError)?.code {
        case .userCancel?, .appCancel?, .systemCancel?, .userFallback?, .notInteractive?:
            throw VaultError.Failed(code: .deviceUnlockCancelled, reason: "cancelled")
        case .passcodeNotSet?, .biometryNotAvailable?, .biometryNotEnrolled?:
            throw VaultError.Failed(code: .deviceUnlockUnsupported, reason: failure.localizedDescription)
        default:
            throw VaultError.Failed(code: .deviceUnlockFailed, reason: failure.localizedDescription)
        }
    }

    /// Stay unlocked (plan 18): a Keychain item in the group the AutoFill extension shares,
    /// guarded by the passcode with no prompt. No passcode: `deviceUnlockUnsupported`.
    func storeStayUnlockedKey(name: String, key: Data) throws {
        guard KeychainDeviceLock.current().available else {
            throw VaultError.Failed(code: .deviceUnlockUnsupported, reason: "no passcode")
        }
        try mapped { try keychain.storeStayUnlockedKey(key, for: name) }
    }

    func stayUnlockedKey(name: String) throws -> Data? {
        try mapped { try keychain.stayUnlockedKey(name) }
    }

    func deleteStayUnlockedKey(name: String) throws {
        try mapped { try keychain.deleteStayUnlockedKey(name) }
    }

    /// The QuickType bar and the passkey sheet suggest these before the vault is unlocked;
    /// picking one opens the AutoFill extension with the item's id.
    func setCredentialIdentities(identities: [CredentialIdentity]) throws {
        let system = identities.compactMap(Self.system)
        Task.detached {
            let store = ASCredentialIdentityStore.shared
            // Nothing to update until Octa Pass is turned on in Settings → General → AutoFill.
            guard await store.state().isEnabled else { return }
            try? await store.replaceCredentialIdentities(system)
        }
    }

    static func system(_ identity: CredentialIdentity) -> ASCredentialIdentity? {
        switch identity {
        case let .password(itemId, url, user):
            guard let url = website(url) else { return nil }
            return ASPasswordCredentialIdentity(
                serviceIdentifier: ASCredentialServiceIdentifier(identifier: url, type: .URL),
                user: user, recordIdentifier: itemId)
        case let .passkey(itemId, rpId, userName, credentialId, userHandle):
            return ASPasskeyCredentialIdentity(
                relyingPartyIdentifier: rpId, userName: userName, credentialID: credentialId,
                userHandle: userHandle, recordIdentifier: itemId)
        case let .oneTimeCode(itemId, url, label):
            guard #available(iOS 18.0, macOS 15.0, *), let url = website(url) else { return nil }
            return ASOneTimeCodeCredentialIdentity(
                serviceIdentifier: ASCredentialServiceIdentifier(identifier: url, type: .URL),
                label: label, recordIdentifier: itemId)
        }
    }

    /// A saved URL as the `.URL` service identifier iOS matches pages against: a full `http`/`https`
    /// address. Logins are often saved as typed (`github.com`), which isn't a URL the system can
    /// read a host from, so it was never suggested; those get `https://`. Nil for what isn't a
    /// website (`androidapp://…`), which no page matches. The AutoFill extension reads the
    /// system's identifiers the same way (`SystemRequests.website`).
    static func website(_ saved: String) -> String? {
        let text = saved.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        let full: String
        if let scheme = text.firstMatch(of: #/^([A-Za-z][A-Za-z0-9+.\-]*):(?!\d)/#)?.1 {
            guard ["http", "https"].contains(scheme.lowercased()) else { return nil }
            full = text
        } else {
            full = "https://" + text
        }
        guard let host = URL(string: full)?.host(), !host.isEmpty else { return nil }
        return full
    }

    // MARK: Local vaults

    func chipAvailable() -> Bool { keychain.chipAvailable }

    func createChipKey(name: String) throws -> ChipKey? {
        try mapped { try keychain.createChipKey(name).map { ChipKey(context: $0.context, secret: $0.secret) } }
    }

    func chipSecret(name: String, context: Data) throws -> Data {
        try mapped { try keychain.chipSecret(name, context: context) }
    }

    func deleteChipKey(name: String) throws {
        try mapped { try keychain.deleteChipKey(name) }
    }

    /// The AutoFill extension gets about 120 MiB, and unlocks with the same parameters.
    func lowMemory() -> Bool { true }

    func backupFolderFiles(folder: String) throws -> [String] {
        try folderCall { try BackupFolder.list(folder) }
    }

    func writeBackupFile(folder: String, name: String, source: String) throws {
        try folderCall { try BackupFolder.write(folder, name: name, source: URL(filePath: source)) }
    }

    func deleteBackupFile(folder: String, name: String) throws {
        try folderCall { try BackupFolder.delete(folder, name: name) }
    }

    private func folderCall<T>(_ work: () throws -> T) throws -> T {
        do {
            return try work()
        } catch {
            throw VaultError.Failed(code: .unexpected, reason: "backup folder: \(error.localizedDescription)")
        }
    }

    /// Keychain failures as the vault's error codes, so the screens say what happened.
    private func mapped<T>(_ work: () throws -> T) throws -> T {
        do {
            return try work()
        } catch KeychainError.cancelled {
            throw VaultError.Failed(code: .deviceUnlockCancelled, reason: "cancelled")
        } catch KeychainError.notFound {
            throw VaultError.Failed(code: .deviceUnlockFailed, reason: "no device secret")
        } catch KeychainError.noDeviceLock {
            throw VaultError.Failed(code: .deviceUnlockUnsupported, reason: "no passcode")
        } catch let KeychainError.failed(status) {
            throw VaultError.Failed(code: .unexpected, reason: "keychain \(status)")
        }
    }
}
