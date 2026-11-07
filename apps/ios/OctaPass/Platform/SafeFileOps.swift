import CoreTransferable
import Foundation
import OctaPassKeychain
import OctaPassResources
import OctaPassVault
import UniformTypeIdentifiers

/// A folder of a Safe, as the app's Safe screens show it (`SafeBrowserView`).
struct SafeFolder: Hashable {
    /// The Safe's vault item.
    let itemId: String
    /// Names the Safe's folder in the shared container (its store lock).
    let safeId: String
    let safeName: String
    /// The folder's object in the Safe; `safeRootId()` at the top.
    let folderId: String
    /// The folder's name; the Safe's at the top.
    let name: String

    static func top(_ safe: SafeItem) -> SafeFolder {
        SafeFolder(itemId: safe.itemId, safeId: safe.safeId, safeName: safe.name, folderId: safeRootId(), name: safe.name)
    }

    func child(_ entry: SafeEntry) -> SafeFolder {
        SafeFolder(itemId: itemId, safeId: safeId, safeName: safeName, folderId: entry.id, name: entry.name)
    }
}

/// A file or folder of a Safe, as it's dragged or copied in the app: which Safe, which object.
/// Dragged within the app it's this (`octaPassSafeEntry`); dropped in Finder or another app, it's
/// a decrypted copy (`SafeFiles.export`).
struct SafeEntryRef: Codable, Hashable, Transferable {
    let itemId: String
    let safeId: String
    let safeName: String
    let entryId: String
    let name: String
    let folder: Bool

    init(_ entry: SafeEntry, in folder: SafeFolder) {
        itemId = folder.itemId
        safeId = folder.safeId
        safeName = folder.safeName
        entryId = entry.id
        name = entry.name
        self.folder = entry.folder
    }

    static var transferRepresentation: some TransferRepresentation {
        CodableRepresentation(contentType: .octaPassSafeEntry)
        // Elsewhere (Finder, Files, another app): the decrypted file, made when it's dropped, in
        // the app's temporary folder, which the vault empties when it locks.
        FileRepresentation(exportedContentType: .data) { ref in
            guard let files = await SafeFiles.current, let url = try await files.export([ref]).first else {
                throw CocoaError(.fileNoSuchFile)
            }
            return SentTransferredFile(url)
        }
    }
}

extension UTType {
    /// A Safe's file or folder dragged within Octa Pass (declared in each app's Info.plist).
    static let octaPassSafeEntry = UTType(exportedAs: "app.octap.safe-entry", conformingTo: .data)
}

enum SafeFileError: LocalizedError {
    case noContainer
    case intoItself

    var errorDescription: String? {
        switch self {
        case .noContainer: "no shared container"
        case .intoItself: L10n.phone.native.safeIntoItself
        }
    }
}

/// A Safe's files from the app, one step at a time (see `SafeFiles`).
extension SafeFiles {
    /// Runs `body` on the Safe's drive: its store lock taken (shared to read, exclusive to change),
    /// the Safe opened for this step and locked after it. A change moves the record's generation
    /// and signals Files, so the extension reads the Safe again before its next step. Never holds
    /// two Safes' locks at once.
    func withDrive<T>(itemId: String, safeId: String, exclusive: Bool, _ body: (SafeDrive) async throws -> T) async throws -> T {
        guard let folder else { throw SafeFileError.noContainer }
        let lock = try await SafeStoreLock.acquire(safeId: safeId, in: folder, exclusive: exclusive)
        defer { lock.release() }
        let drive = try await vault.openSafe(itemId: itemId, folder: folder.path)
        defer { try? drive.lock() }
        let result = try await body(drive)
        if exclusive {
            try? records.bumpGeneration(itemId)
            Self.signal(itemId)
            if open.first(where: { $0.itemId == itemId })?.sync == true { syncSoon(itemId) }
        }
        return result
    }

    private func withDrive<T>(_ folder: SafeFolder, exclusive: Bool, _ body: (SafeDrive) async throws -> T) async throws -> T {
        try await withDrive(itemId: folder.itemId, safeId: folder.safeId, exclusive: exclusive, body)
    }

    /// A folder's files and folders: folders first, then by name as Finder sorts them.
    func list(_ folder: SafeFolder) async throws -> [SafeEntry] {
        try await withDrive(folder, exclusive: false) { drive in
            try drive.list(folder: folder.folderId).sorted { a, b in
                a.folder != b.folder ? a.folder : a.name.localizedStandardCompare(b.name) == .orderedAscending
            }
        }
    }

    func createFolder(in folder: SafeFolder, name: String) async throws {
        _ = try await withDrive(folder, exclusive: true) { drive in
            let taken = Set(try drive.list(folder: folder.folderId).map(\.name))
            return try drive.createFolder(folder: folder.folderId, name: SafeStore.uniqueName(name, taken: taken))
        }
    }

    /// Files and folders from outside (a picker, a drop, the pasteboard), folders with everything
    /// in them, each under a name not taken. Opens each URL's security scope while it's read.
    func add(_ urls: [URL], to folder: SafeFolder) async throws {
        guard !urls.isEmpty else { return }
        try await withDrive(folder, exclusive: true) { drive in
            for url in urls {
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                try await Self.add(url, into: folder.folderId, drive: drive)
            }
        }
    }

    private static func add(_ url: URL, into parent: String, drive: SafeDrive) async throws {
        let taken = Set(try drive.list(folder: parent).map(\.name))
        let name = SafeStore.uniqueName(url.lastPathComponent, taken: taken)
        let isFolder = (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
        // Links and packages' insides are what Finder shows them as: a folder is walked, a link
        // isn't followed out of what was picked.
        if (try? url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true { return }
        if isFolder {
            let created = try drive.createFolder(folder: parent, name: name)
            let children = try FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: [.isDirectoryKey])
            for child in children { try await add(child, into: created.id, drive: drive) }
            return
        }
        let created = try drive.createFile(folder: parent, name: name)
        do {
            _ = try await drive.importFile(id: created.id, path: url.path)
        } catch {
            // Not an empty file in its place.
            try? drive.remove(id: created.id)
            throw error
        }
    }

    func rename(_ entry: SafeEntryRef, to name: String, in folder: SafeFolder) async throws {
        try await withDrive(itemId: entry.itemId, safeId: entry.safeId, exclusive: true) { drive in
            let taken = Set(try drive.list(folder: folder.folderId).filter { $0.id != entry.entryId }.map(\.name))
            try drive.rename(id: entry.entryId, folder: folder.folderId, name: SafeStore.uniqueName(name, taken: taken))
        }
    }

    /// Deletes files and folders (a folder with everything in it). Gone from the Safe; there's no
    /// trash, as in Files.
    func delete(_ entries: [SafeEntryRef]) async throws {
        for (key, group) in Dictionary(grouping: entries, by: { SafeKey($0) }) {
            try await withDrive(itemId: key.itemId, safeId: key.safeId, exclusive: true) { drive in
                for entry in group where entry.entryId != safeRootId() { try drive.remove(id: entry.entryId) }
            }
        }
    }

    /// Decrypted copies, for Quick Look, a save panel or the share sheet, the pasteboard or a drag
    /// out: in a new folder in the vault's own "opened" folder (the app's temporary storage, never
    /// the App Group), which the vault empties when it locks, on sign-out and at launch. Callers
    /// that are done with them sooner remove them with `discard`.
    func export(_ entries: [SafeEntryRef]) async throws -> [URL] {
        let target = Self.plaintextFolder().appending(path: UUID().uuidString, directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        var urls: [URL] = []
        do {
            for (key, group) in Dictionary(grouping: entries, by: { SafeKey($0) }) {
                try await withDrive(itemId: key.itemId, safeId: key.safeId, exclusive: false) { drive in
                    for entry in group {
                        urls.append(try await Self.export(entry.entryId, named: entry.name, folder: entry.folder, into: target, drive: drive))
                    }
                }
            }
        } catch {
            try? FileManager.default.removeItem(at: target)
            throw error
        }
        return urls
    }

    private static func export(_ id: String, named name: String, folder: Bool, into parent: URL, drive: SafeDrive) async throws -> URL {
        let url = PickedFiles.unique(name, in: parent)
        if folder {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
            for child in try drive.list(folder: id) {
                _ = try await export(child.id, named: child.name, folder: child.folder, into: url, drive: drive)
            }
        } else {
            FileManager.default.createFile(atPath: url.path, contents: nil)
            _ = try await drive.exportFile(id: id, path: url.path)
        }
        return url
    }

    /// The vault's folder for decrypted files it hands out (`opened` under the temporary folder
    /// the app gives the vault, `AppModel.live`): what's in it goes when the vault locks.
    static func plaintextFolder() -> URL {
        FileManager.default.temporaryDirectory.appending(path: "vault/opened", directoryHint: .isDirectory)
    }

    /// Removes decrypted copies `export` made: each one's folder.
    static func discard(_ urls: [URL]) {
        for folder in Set(urls.map { $0.deletingLastPathComponent() }) where folder.deletingLastPathComponent() == plaintextFolder() {
            try? FileManager.default.removeItem(at: folder)
        }
    }

    /// Files and folders dropped on a folder: within one Safe they move (or copy, `copying`);
    /// between Safes they're copied, as Finder copies between disks. A copy is decrypted into the
    /// app's temporary folder under the source's lock, added under the target's, then removed.
    /// Returns whether anything moved (rather than copied).
    @discardableResult
    func transfer(_ entries: [SafeEntryRef], to folder: SafeFolder, copying: Bool = false) async throws -> Bool {
        let same = entries.filter { $0.itemId == folder.itemId }
        let others = entries.filter { $0.itemId != folder.itemId }
        var moved = false
        if !same.isEmpty, !copying {
            try await move(same, to: folder)
            moved = true
        }
        let copies = copying ? entries : others
        if !copies.isEmpty {
            let urls = try await export(copies)
            defer { Self.discard(urls) }
            try await add(urls, to: folder)
        }
        return moved
    }

    private func move(_ entries: [SafeEntryRef], to folder: SafeFolder) async throws {
        try await withDrive(folder, exclusive: true) { drive in
            // The folder and the ones above it: none of them may be one of those moving.
            var above: Set<String> = [folder.folderId]
            var current = folder.folderId
            while current != safeRootId(), let parent = try? drive.entry(id: current).parent, !above.contains(parent) {
                above.insert(parent)
                current = parent
            }
            for entry in entries {
                if above.contains(entry.entryId) { throw SafeFileError.intoItself }
                guard try drive.entry(id: entry.entryId).parent != folder.folderId else { continue }
                let taken = Set(try drive.list(folder: folder.folderId).map(\.name))
                try drive.rename(id: entry.entryId, folder: folder.folderId, name: SafeStore.uniqueName(entry.name, taken: taken))
            }
        }
    }
}

/// Which Safe an entry is in, to take each Safe's lock once.
private struct SafeKey: Hashable {
    let itemId: String
    let safeId: String

    init(_ entry: SafeEntryRef) {
        itemId = entry.itemId
        safeId = entry.safeId
    }
}
