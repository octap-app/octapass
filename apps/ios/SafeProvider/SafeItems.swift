import CryptoKit
import FileProvider
import Foundation
import OctaPassKeychain
import OctaPassVault
import UniformTypeIdentifiers

/// The Safe's top folder is the domain's root container; every other object keeps its id.
enum SafeIds {
    static let root = safeRootId()

    static func identifier(_ entryId: String) -> NSFileProviderItemIdentifier {
        entryId == root ? .rootContainer : NSFileProviderItemIdentifier(entryId)
    }

    /// The Safe object behind an identifier; nil for the working set and the trash, which aren't objects.
    static func entryId(_ identifier: NSFileProviderItemIdentifier) -> String? {
        switch identifier {
        case .rootContainer: root
        case .workingSet, .trashContainer: nil
        default: identifier.rawValue
        }
    }

    /// `SafeStore.uniqueName`, which the app's own Safe screens use too.
    static func uniqueName(_ name: String, taken: Set<String>) -> String {
        SafeStore.uniqueName(name, taken: taken)
    }
}

/// A file or folder in a Safe, as Files sees it.
final class SafeFileItem: NSObject, NSFileProviderItem {
    let entry: SafeEntry
    /// The Safe's name: its top folder has none of its own.
    let safeName: String

    init(_ entry: SafeEntry, safeName: String) {
        self.entry = entry
        self.safeName = safeName
    }

    private var isRoot: Bool { entry.id == SafeIds.root }

    var itemIdentifier: NSFileProviderItemIdentifier { SafeIds.identifier(entry.id) }

    var parentItemIdentifier: NSFileProviderItemIdentifier {
        isRoot ? .rootContainer : SafeIds.identifier(entry.parent)
    }

    var filename: String { isRoot ? safeName : entry.name }

    var contentType: UTType {
        if entry.folder { return .folder }
        let suffix = (entry.name as NSString).pathExtension
        return suffix.isEmpty ? .data : UTType(filenameExtension: suffix) ?? .data
    }

    var documentSize: NSNumber? { entry.folder ? nil : NSNumber(value: entry.size) }

    var contentModificationDate: Date? {
        entry.modified > 0 ? Date(timeIntervalSince1970: TimeInterval(entry.modified) / 1000) : nil
    }

    var capabilities: NSFileProviderItemCapabilities {
        if isRoot { return [.allowsReading, .allowsContentEnumerating, .allowsAddingSubItems] }
        if entry.folder {
            return [.allowsReading, .allowsContentEnumerating, .allowsAddingSubItems, .allowsRenaming, .allowsReparenting, .allowsDeleting]
        }
        // No trash: a deleted file is gone from the Safe, as on the other platforms.
        return [.allowsReading, .allowsWriting, .allowsRenaming, .allowsReparenting, .allowsDeleting]
    }

    var itemVersion: NSFileProviderItemVersion {
        NSFileProviderItemVersion(
            contentVersion: Data("\(entry.size):\(entry.modified)".utf8),
            metadataVersion: Data("\(filename)\u{0}\(entry.parent)\u{0}\(entry.modified)".utf8))
    }
}

/// Lists a folder, or every object for the working set. Changes aren't kept as a log: the anchor
/// is a digest of what's listed, so an unchanged listing reports no changes and a changed one asks
/// Files to list again (`syncAnchorExpired`).
final class SafeEnumerator: NSObject, NSFileProviderEnumerator {
    private let container: NSFileProviderItemIdentifier
    private weak var provider: FileProviderExtension?

    init(container: NSFileProviderItemIdentifier, provider: FileProviderExtension) {
        self.container = container
        self.provider = provider
    }

    func invalidate() {}

    func enumerateItems(for observer: NSFileProviderEnumerationObserver, startingAt page: NSFileProviderPage) {
        Task {
            do {
                let items = try await listing()
                observer.didEnumerate(items)
                observer.finishEnumerating(upTo: nil)
            } catch {
                observer.finishEnumeratingWithError(ProviderErrors.map(error))
            }
        }
    }

    func enumerateChanges(for observer: NSFileProviderChangeObserver, from anchor: NSFileProviderSyncAnchor) {
        Task {
            do {
                let current = Self.anchor(try await listing())
                if current == anchor {
                    observer.finishEnumeratingChanges(upTo: current, moreComing: false)
                } else {
                    observer.finishEnumeratingWithError(NSFileProviderError(.syncAnchorExpired))
                }
            } catch {
                observer.finishEnumeratingWithError(ProviderErrors.map(error))
            }
        }
    }

    func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
        Task {
            completionHandler((try? await listing()).map(Self.anchor))
        }
    }

    private func listing() async throws -> [SafeFileItem] {
        guard let provider else { throw ProviderErrors.notAuthenticated }
        return try await provider.listing(container)
    }

    static func anchor(_ items: [SafeFileItem]) -> NSFileProviderSyncAnchor {
        var hash = SHA256()
        for item in items.sorted(by: { $0.entry.id < $1.entry.id }) {
            let entry = item.entry
            hash.update(data: Data("\(entry.id)\u{0}\(entry.parent)\u{0}\(item.filename)\u{0}\(entry.size)\u{0}\(entry.modified)\n".utf8))
        }
        return NSFileProviderSyncAnchor(Data(hash.finalize()))
    }
}
