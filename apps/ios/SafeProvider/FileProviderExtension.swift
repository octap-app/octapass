import FileProvider
import Foundation
import notify
import OctaPassKeychain
import OctaPassVault
import UniformTypeIdentifiers

/// Octa Pass Safe in the Files app (plan 16 §4, plan 03 History 2026-11-04). One domain per Safe,
/// which the app adds while the vault is unlocked; the domain's identifier is the Safe's item id.
///
/// This process has no vault: it opens the Safe with the key the app left in the shared Keychain
/// (`SafeDrive.openWithKey`), on the same folder in the App Group container the app uses, and keeps
/// the key only in memory. With no valid record (the vault locked, the app was killed, or Open
/// Pass's auto-lock time passed since it was last used) every call answers `notAuthenticated`.
///
/// The app and this extension never change one Safe's folder at the same time: each step here
/// holds the Safe's `SafeStoreLock` (shared for reads, exclusive for changes), and the app syncs and
/// deletes under the same lock, then moves the record's generation so the drive here is opened
/// again. After a change here it posts `SafeStore.changed`, and the app syncs a synced Safe soon.
///
/// File contents leave the engine only in `fetchContents`, decrypted into a temporary file that
/// Files takes over; Files keeps such copies until the app removes the domain, which it does
/// (`.removeAll`) whenever the vault locks and at launch.
final class FileProviderExtension: NSObject, NSFileProviderReplicatedExtension {
    let domain: NSFileProviderDomain
    private let session: SafeSession
    private var watch: Task<Void, Never>?

    required init(domain: NSFileProviderDomain) {
        self.domain = domain
        session = SafeSession(itemId: domain.identifier.rawValue)
        super.init()
        // The record can disappear (the vault locked) or run out while Files has the Safe open.
        watch = Task { [session] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 15_000_000_000)
                await session.check()
            }
        }
    }

    func invalidate() {
        watch?.cancel()
        Task { [session] in await session.close() }
        // Decrypted copies Files didn't take over.
        if let temporary = try? temporaryFolder() { try? FileManager.default.removeItem(at: temporary) }
    }

    // MARK: Steps on the drive

    /// Runs `body` on the Safe's drive, holding its store lock.
    func withDrive<T>(exclusive: Bool, _ body: (SafeDrive, SafeKeyRecord) async throws -> T) async throws -> T {
        let first = try await session.record()
        guard let folder = session.folder else { throw ProviderErrors.notAuthenticated }
        let lock = try await SafeStoreLock.acquire(safeId: first.safeId, in: folder, exclusive: exclusive)
        defer { lock.release() }
        // Again, under the lock: the app may have synced or locked meanwhile.
        let record = try await session.record()
        guard record.safeId == first.safeId else { throw ProviderErrors.notAuthenticated }
        let drive = try await session.drive(for: record)
        let result = try await body(drive, record)
        // The app syncs a synced Safe soon after it changes.
        if exclusive { notify_post(SafeStore.changed) }
        return result
    }

    /// The items in a folder, or every item for the working set.
    func listing(_ container: NSFileProviderItemIdentifier) async throws -> [SafeFileItem] {
        try await withDrive(exclusive: false) { drive, record in
            if container == .trashContainer { return [] }
            guard container == .workingSet else {
                guard let folder = SafeIds.entryId(container) else { throw ProviderErrors.noSuchItem }
                return try drive.list(folder: folder).map { SafeFileItem($0, safeName: record.name) }
            }
            var items: [SafeFileItem] = []
            var folders = [SafeIds.root]
            var seen: Set<String> = [SafeIds.root]
            while let folder = folders.popLast() {
                for entry in try drive.list(folder: folder) {
                    items.append(SafeFileItem(entry, safeName: record.name))
                    if entry.folder, seen.insert(entry.id).inserted { folders.append(entry.id) }
                }
            }
            return items
        }
    }

    /// Runs `work` as the system's request, reporting through `completion` once.
    private func run(_ work: @escaping () async throws -> Void, failed: @escaping (Error) -> Void) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        let task = Task {
            do {
                try await work()
            } catch {
                failed(ProviderErrors.map(error))
            }
            progress.completedUnitCount = 1
        }
        progress.cancellationHandler = { task.cancel() }
        return progress
    }

    private func temporaryFolder() throws -> URL {
        let base = try NSFileProviderManager(for: domain)?.temporaryDirectoryURL()
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("octa-pass-safe", isDirectory: true)
    }

    // MARK: NSFileProviderReplicatedExtension

    func item(for identifier: NSFileProviderItemIdentifier, request: NSFileProviderRequest,
              completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void) -> Progress {
        run({
            guard let id = SafeIds.entryId(identifier) else { throw ProviderErrors.noSuchItem }
            let item = try await self.withDrive(exclusive: false) { drive, record in
                SafeFileItem(try drive.entry(id: id), safeName: record.name)
            }
            completionHandler(item, nil)
        }, failed: { completionHandler(nil, $0) })
    }

    func fetchContents(for itemIdentifier: NSFileProviderItemIdentifier, version requestedVersion: NSFileProviderItemVersion?,
                       request: NSFileProviderRequest,
                       completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void) -> Progress {
        run({
            guard let id = SafeIds.entryId(itemIdentifier) else { throw ProviderErrors.noSuchItem }
            let folder = try self.temporaryFolder()
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let file = folder.appendingPathComponent(UUID().uuidString)
            // Plaintext, so the strongest protection that still lets an open file be finished.
            FileManager.default.createFile(atPath: file.path, contents: nil,
                                           attributes: [.protectionKey: FileProtectionType.completeUnlessOpen])
            do {
                let item = try await self.withDrive(exclusive: false) { drive, record in
                    let entry = try drive.entry(id: id)
                    guard !entry.folder else { throw ProviderErrors.noSuchItem }
                    _ = try await drive.exportFile(id: id, path: file.path)
                    return SafeFileItem(try drive.entry(id: id), safeName: record.name)
                }
                completionHandler(file, item, nil)
            } catch {
                try? FileManager.default.removeItem(at: file)
                throw error
            }
        }, failed: { completionHandler(nil, nil, $0) })
    }

    func createItem(basedOn itemTemplate: NSFileProviderItem, fields: NSFileProviderItemFields, contents url: URL?,
                    options: NSFileProviderCreateItemOptions = [], request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        run({
            guard let parent = SafeIds.entryId(itemTemplate.parentItemIdentifier) else { throw ProviderErrors.noSuchItem }
            let type = itemTemplate.contentType ?? .data
            // Links and packages have no place in a Safe; only files and folders.
            if type.conforms(to: .symbolicLink) || type.conforms(to: .aliasFile) {
                throw CocoaError(.featureUnsupported)
            }
            let isFolder = type.conforms(to: .folder) || type.conforms(to: .directory)
            let item = try await self.withDrive(exclusive: true) { drive, record in
                let siblings = try drive.list(folder: parent)
                if options.contains(.mayAlreadyExist),
                   let existing = siblings.first(where: { $0.name == itemTemplate.filename && $0.folder == isFolder }) {
                    // Files is matching what it has with what's here, after a reset: keep this one.
                    return SafeFileItem(existing, safeName: record.name)
                }
                let name = SafeIds.uniqueName(itemTemplate.filename, taken: Set(siblings.map(\.name)))
                if isFolder {
                    return SafeFileItem(try drive.createFolder(folder: parent, name: name), safeName: record.name)
                }
                let created = try drive.createFile(folder: parent, name: name)
                if let url {
                    do {
                        _ = try await drive.importFile(id: created.id, path: url.path)
                    } catch {
                        // Not an empty file in its place.
                        try? drive.remove(id: created.id)
                        throw error
                    }
                }
                return SafeFileItem(try drive.entry(id: created.id), safeName: record.name)
            }
            completionHandler(item, [], false, nil)
        }, failed: { completionHandler(nil, [], false, $0) })
    }

    func modifyItem(_ item: NSFileProviderItem, baseVersion version: NSFileProviderItemVersion,
                    changedFields: NSFileProviderItemFields, contents newContents: URL?,
                    options: NSFileProviderModifyItemOptions = [], request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        run({
            guard let id = SafeIds.entryId(item.itemIdentifier) else { throw ProviderErrors.noSuchItem }
            let updated = try await self.withDrive(exclusive: true) { drive, record in
                var entry = try drive.entry(id: id)
                let moving = changedFields.contains(.parentItemIdentifier)
                // The top folder's name is the Safe's, which only the app changes.
                if id != SafeIds.root, changedFields.contains(.filename) || moving {
                    guard let parent = moving ? SafeIds.entryId(item.parentItemIdentifier) : entry.parent else {
                        // Into the trash: there's none.
                        throw CocoaError(.featureUnsupported)
                    }
                    let wanted = changedFields.contains(.filename) ? item.filename : entry.name
                    let taken = Set(try drive.list(folder: parent).filter { $0.id != id }.map(\.name))
                    try drive.rename(id: id, folder: parent, name: SafeIds.uniqueName(wanted, taken: taken))
                }
                if changedFields.contains(.contents), !entry.folder, let newContents {
                    _ = try await drive.importFile(id: id, path: newContents.path)
                }
                entry = try drive.entry(id: id)
                return SafeFileItem(entry, safeName: record.name)
            }
            // Dates, tags and the like aren't kept in a Safe: nothing is left pending.
            completionHandler(updated, [], false, nil)
        }, failed: { completionHandler(nil, [], false, $0) })
    }

    func deleteItem(identifier: NSFileProviderItemIdentifier, baseVersion version: NSFileProviderItemVersion,
                    options: NSFileProviderDeleteItemOptions = [], request: NSFileProviderRequest,
                    completionHandler: @escaping (Error?) -> Void) -> Progress {
        run({
            guard let id = SafeIds.entryId(identifier), id != SafeIds.root else { throw CocoaError(.featureUnsupported) }
            try await self.withDrive(exclusive: true) { drive, _ in
                let entry: SafeEntry
                do {
                    entry = try drive.entry(id: id)
                } catch let error as VaultError {
                    // Already gone is what was asked for.
                    if case .Failed(.notFound, _) = error { return }
                    throw error
                }
                if entry.folder, !options.contains(.recursive), !(try drive.list(folder: id)).isEmpty {
                    throw NSFileProviderError(.directoryNotEmpty)
                }
                try drive.remove(id: id)
            }
            completionHandler(nil)
        }, failed: { completionHandler($0) })
    }

    func enumerator(for containerItemIdentifier: NSFileProviderItemIdentifier, request: NSFileProviderRequest) throws -> NSFileProviderEnumerator {
        SafeEnumerator(container: containerItemIdentifier, provider: self)
    }
}
