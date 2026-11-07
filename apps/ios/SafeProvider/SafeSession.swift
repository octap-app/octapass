import FileProvider
import Foundation
import OctaPassKeychain
import OctaPassResources
import OctaPassVault

/// One Safe in this extension: the key the app left in the shared Keychain (plan 03 History,
/// 2026-11-04) and the drive opened with it. The key is kept only in memory, inside the drive;
/// when its record is gone or ran out, the drive is locked and every call says the vault is locked.
actor SafeSession {
    let itemId: String
    private let records: SafeKeyRecords
    /// The shared container's `safes` folder, the one the app opens Safes in.
    let folder: URL?
    private var drive: SafeDrive?
    /// What `drive` was opened with: a sync in the app moves the generation, a new key is another Safe.
    private var opened: (safeId: String, key: Data, generation: Int)?

    init(itemId: String, records: SafeKeyRecords = SafeKeyRecords(), folder: URL? = SafeStore.folder()) {
        self.itemId = itemId
        self.records = records
        self.folder = folder
    }

    /// The record to use, or `notAuthenticated` (and the drive locked) when there's none.
    func record() throws -> SafeKeyRecord {
        // A Keychain that can't be read (the phone is locked) counts as no key.
        guard let record = try? records.valid(itemId), SafeStore.isPlainId(record.safeId) else {
            close()
            throw ProviderErrors.notAuthenticated
        }
        return record
    }

    /// The open drive for `record`, opened again when the app changed the store since. Call it
    /// only while holding the Safe's store lock: opening clears the Safe's temporary files.
    func drive(for record: SafeKeyRecord) throws -> SafeDrive {
        if let drive, let opened, !drive.isLocked(), opened.safeId == record.safeId, opened.key == record.key,
           opened.generation == record.generation {
            return drive
        }
        guard let folder else { throw ProviderErrors.notAuthenticated }
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        // The old drive isn't locked here: a read still using it finishes, then it's freed.
        let fresh = try SafeDrive.openWithKey(folder: folder.path, safeId: record.safeId, key: record.key)
        drive = fresh
        opened = (record.safeId, record.key, record.generation)
        return fresh
    }

    /// Locks the drive when the record has gone or run out. The extension checks this on a timer.
    func check() {
        guard drive != nil else { return }
        if (try? records.valid(itemId)) == nil { close() }
    }

    /// Drops every key.
    func close() {
        try? drive?.lock()
        drive = nil
        opened = nil
    }
}

enum ProviderErrors {
    /// What Files shows when there's no key: unlock Octa Pass.
    static var notAuthenticated: Error {
        NSFileProviderError(.notAuthenticated, userInfo: [NSLocalizedDescriptionKey: L10n.phone.native.safesUnlockFirst])
    }

    static var noSuchItem: Error { NSFileProviderError(.noSuchItem) }

    /// The vault's errors as Files understands them. Their reasons never hold a secret.
    static func map(_ error: Error) -> Error {
        if error is NSFileProviderError { return error }
        if (error as NSError).domain == NSFileProviderErrorDomain { return error }
        guard let vaultError = error as? VaultError, case let .Failed(code, _) = vaultError else {
            if error is CancellationError { return CocoaError(.userCancelled) }
            return error
        }
        switch code {
        case .locked: return notAuthenticated
        case .notFound: return noSuchItem
        case .notAllowed: return CocoaError(.fileWriteNoPermission)
        default: return CocoaError(.fileReadUnknown)
        }
    }
}
