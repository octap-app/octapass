import Foundation

/// The folder automatic backups go to, picked in Files (iCloud Drive, Dropbox, OneDrive…). The
/// vault knows it by a security-scoped bookmark, as base64.
enum BackupFolder {
    /// What the vault keeps for a folder the picker returned, while its scope is open.
    static func reference(for url: URL) throws -> String {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        return try url.bookmarkData().base64EncodedString()
    }

    static func list(_ reference: String) throws -> [String] {
        try access(reference) { folder in
            try FileManager.default.contentsOfDirectory(atPath: folder.path)
        }
    }

    static func write(_ reference: String, name: String, source: URL) throws {
        try access(reference) { folder in
            try coordinate(folder.appending(path: name), forReplacing: true) { target in
                let data = try Data(contentsOf: source)
                try data.write(to: target, options: [.atomic])
            }
        }
    }

    static func delete(_ reference: String, name: String) throws {
        try access(reference) { folder in
            try coordinate(folder.appending(path: name), forReplacing: false) { target in
                try FileManager.default.removeItem(at: target)
            }
        }
    }

    private static func access<T>(_ reference: String, _ work: (URL) throws -> T) throws -> T {
        guard let bookmark = Data(base64Encoded: reference) else { throw CocoaError(.fileNoSuchFile) }
        var stale = false
        let folder = try URL(resolvingBookmarkData: bookmark, bookmarkDataIsStale: &stale)
        guard folder.startAccessingSecurityScopedResource() else { throw CocoaError(.fileReadNoPermission) }
        defer { folder.stopAccessingSecurityScopedResource() }
        return try work(folder)
    }

    /// Other apps sync these folders, so writes go through a file coordinator.
    private static func coordinate(_ url: URL, forReplacing: Bool, _ work: (URL) throws -> Void) throws {
        var failure: Error?
        var coordinated: NSError?
        NSFileCoordinator().coordinate(
            writingItemAt: url, options: forReplacing ? .forReplacing : .forDeleting, error: &coordinated
        ) { target in
            do { try work(target) } catch { failure = error }
        }
        if let error = coordinated ?? failure { throw error }
    }
}
