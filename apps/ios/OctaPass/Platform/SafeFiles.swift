import FileProvider
import Foundation
import notify
import Observation
import OctaPassKeychain
import OctaPassVault
#if canImport(UIKit)
import UIKit
#else
import AppKit
#endif

/// Octa Pass Safe in the Files app, the app's half (plan 03 History, 2026-11-04). While the vault is
/// unlocked, every Safe in it is open in Files: a File Provider domain each (identifier = the
/// Safe's item id) and its key in the shared Keychain for the extension (`SafeKeyRecord`), good
/// until the auto-lock time after the app was last used. When the vault locks, someone signs out,
/// or the app starts (a killed app can't have locked), every record is deleted and every domain is
/// removed with `.removeAll`, which also deletes the plaintext copies Files kept of opened files.
///
/// On the Mac, a Safe stays in Finder while the app runs (plan 19): when the vault locks, its
/// record goes and its domain is removed with `.removeAll` as above, then added again empty, so
/// Finder still lists the Safe by name but holds none of its files or names, and the extension,
/// with no key, answers "not authenticated". Finder's Sign In then opens Octa Pass through the Safe
/// unlock extension (`SafeStore.unlockRequest`), and unlocking publishes the records and signals
/// the domains again. Signing out, another account, and quitting the app remove the domains.
///
/// Safes live in the App Group container's `safes` folder, which the extension opens too. To
/// keep the two processes from changing one Safe at once, everything the app does to a Safe's
/// files is one step under the Safe's `SafeStoreLock` (`withDrive`, `SafeFileOps.swift`): shared
/// to read, exclusive to change, the Safe opened for that step and locked again after it, and a
/// change moves the record's generation and signals Files, as a sync does. No step waits on the
/// person, so Files is never held up while someone only looks.
///
/// Synced Safes sync on their own, as the desktop app's do (`syncSoon`): a few seconds after one
/// changes here or in Files (the extension posts `SafeStore.changed`), after each vault sync, and
/// every two minutes while the vault is unlocked. Errors wait for the next round: offline is
/// normal. Sync now on the Safes screen does the same at once.
@MainActor @Observable
final class SafeFiles {
    let vault: OctaPassVault
    @ObservationIgnored let records = SafeKeyRecords()
    @ObservationIgnored private let custody = SafeKeyCustody()
    /// The shared container's `safes` folder.
    let folder: URL?
    /// The Safes in Files right now: open while the vault is unlocked; on the Mac, still listed
    /// (empty, asking for Octa Pass) while it's locked.
    private(set) var open: [SafeItem] = []
    @ObservationIgnored private var unlocked = false
    /// Whose Safes `open` are, so a lock keeps them only for the same account.
    @ObservationIgnored private var account: String?
    #if os(macOS)
    /// Finder's Sign In on a locked Safe: the app shows its window and asks to unlock.
    @ObservationIgnored var onUnlockRequest: (() -> Void)?
    @ObservationIgnored private var unlockRequestToken: Int32 = 0
    @ObservationIgnored private var quitObserver: NSObjectProtocol?
    #endif
    @ObservationIgnored private var lifetime: TimeInterval
    /// Moves on at every lock, so work started before it doesn't open anything after.
    @ObservationIgnored private var session = 0
    /// Domain and record changes, one after another.
    @ObservationIgnored private var queue: Task<Void, Never>?
    /// The two-minute round of synced Safes while unlocked.
    @ObservationIgnored private var autoSync: Task<Void, Never>?
    /// Syncs waiting a few seconds for changes to settle, by item id ("" for every synced Safe).
    @ObservationIgnored private var soon: [String: Task<Void, Never>] = [:]
    @ObservationIgnored private var syncingAll = false
    @ObservationIgnored private var syncAgain = false
    @ObservationIgnored private var changedToken: Int32 = 0
    static let syncEvery: Duration = .seconds(120)

    /// The app's one instance, for what has no environment (a drag's file, `SafeEntryRef`).
    static var current: SafeFiles?

    init(vault: OctaPassVault, autoLockMinutes: UInt32) {
        self.vault = vault
        lifetime = SafeKeyRecords.lifetime(autoLockMinutes: autoLockMinutes)
        folder = SafeStore.folder()
        Self.current = self
        // Whatever the last run left: it can't have locked if it was killed.
        try? custody.end()
        enqueue { await Self.removeDomains() }
        notify_register_dispatch(SafeStore.changed, &changedToken, .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.syncSoon() }
        }
        #if os(macOS)
        notify_register_dispatch(SafeStore.unlockRequest, &unlockRequestToken, .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.onUnlockRequest?() }
        }
        // Quitting: the keys and Finder's copies go, and so do the Safes (nothing would answer for
        // them). Waits for the system, briefly, since the app is about to end.
        quitObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification, object: nil, queue: .main
        ) { [custody] _ in
            try? custody.end()
            Self.removeDomainsBeforeQuitting()
        }
        #endif
    }

    // MARK: The session

    /// From `AppModel.sessionChanged`: unlocked opens the Safes in Files, anything else closes them.
    /// On the Mac, locked (the same account, not signed out) keeps them in Finder, emptied.
    /// `account` names the signed-in account; nil when signed out.
    func sessionChanged(unlocked now: Bool, account: String?) {
        if now {
            unlocked = true
            self.account = account
            refresh(force: true)
            startAutoSync()
            return
        }
        let wasUnlocked = unlocked
        unlocked = false
        stopAutoSync()
        #if os(macOS)
        let keep = account != nil && account == self.account && !open.isEmpty
        #else
        let keep = false
        #endif
        guard wasUnlocked || (!keep && !open.isEmpty) else { return }
        session += 1
        // At once, before anything queued: the extension must stop now.
        try? custody.end()
        #if os(macOS)
        if keep {
            let shown = open
            enqueue {
                // Again, in case a publish was running when the vault locked.
                try? self.custody.end()
                await Self.empty(shown)
            }
            return
        }
        #endif
        open = []
        self.account = nil
        enqueue {
            try? self.custody.end()
            await Self.removeDomains()
        }
    }

    /// Items changed (a Safe made, renamed or deleted, here or by a sync), or the app came back.
    /// `force` writes every record again with a new deadline.
    func refresh(force: Bool = false) {
        guard unlocked else { return }
        let current = session
        enqueue { await self.publish(session: current, force: force) }
    }

    /// The app was used: the records' deadline moves forward.
    func touch() {
        guard unlocked else { return }
        _ = try? custody.touch(lifetime: lifetime)
    }

    /// The auto-lock setting changed: the deadline follows it from now.
    func autoLockChanged(_ minutes: UInt32) {
        lifetime = SafeKeyRecords.lifetime(autoLockMinutes: minutes)
        guard unlocked else { return }
        try? records.extend(lifetime: lifetime)
    }

    private func publish(session current: Int, force: Bool) async {
        guard current == session, let folder else { return }
        // This device's Safes: one kept on another device has no files here.
        guard let safes = try? await vault.listSafes(folder: folder.path) else { return }
        // Only a plain id names a folder; anything else isn't offered (the vault refuses it too).
        let usable = safes.filter { SafeStore.isPlainId($0.safeId) }
        if !force, usable == open { return }
        var grants: [SafeKeyCustody.Grant] = []
        for safe in usable {
            guard let key = try? await vault.safeKey(itemId: safe.itemId) else { continue }
            grants.append(.init(itemId: safe.itemId, safeId: safe.safeId, name: safe.name, key: key))
        }
        guard current == session else { return }
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        do {
            try custody.publish(grants, lifetime: lifetime)
        } catch {
            return
        }
        let wanted = Set(grants.map(\.itemId))
        let shown = usable.filter { wanted.contains($0.itemId) }
        for domain in (try? await NSFileProviderManager.domains()) ?? [] where !wanted.contains(domain.identifier.rawValue) {
            _ = try? await NSFileProviderManager.remove(domain, mode: .removeAll)
        }
        for safe in shown {
            try? await NSFileProviderManager.add(Self.domain(safe))
        }
        guard current == session else {
            // Locked meanwhile: undo it all.
            try? custody.end()
            await Self.removeDomains()
            return
        }
        open = shown
        // Files may still show the "unlock Octa Pass" answer from before.
        for safe in shown { Self.signal(safe.itemId) }
    }

    // MARK: The Safes screen

    /// Sends and fetches a synced Safe's changes, holding its store lock so the Files extension
    /// waits, then has the extension read the Safe again. Also returns what the engine noticed.
    func sync(_ safe: SafeItem) async throws -> (SafeSyncSummary, [SafeWarning]) {
        guard let folder else { throw VaultError.Failed(code: .unexpected, reason: "no shared container") }
        let lock = try await SafeStoreLock.acquire(safeId: safe.safeId, in: folder)
        // iOS ends an app suspended while holding a lock in a shared container: finish first.
        #if os(iOS)
        let background = UIApplication.shared.beginBackgroundTask(withName: "Safe sync") {}
        defer {
            lock.release()
            UIApplication.shared.endBackgroundTask(background)
        }
        #else
        defer { lock.release() }
        #endif
        let drive = try await vault.openSafe(itemId: safe.itemId, folder: folder.path)
        defer { try? drive.lock() }
        let summary = try await vault.syncSafe(itemId: safe.itemId, drive: drive)
        let warnings = (try? drive.warnings()) ?? []
        try? drive.lock()
        try? records.bumpGeneration(safe.itemId)
        Self.signal(safe.itemId)
        return (summary, warnings)
    }

    /// Syncs the synced Safes in Files (or only `itemId`) in a few seconds, once changes have
    /// settled. Quietly: a failure waits for the next round.
    func syncSoon(_ itemId: String? = nil) {
        guard unlocked else { return }
        let key = itemId ?? ""
        soon[key]?.cancel()
        soon[key] = Task { [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard !Task.isCancelled, let self else { return }
            self.soon[key] = nil
            await self.syncAll(only: itemId)
        }
    }

    private func startAutoSync() {
        autoSync?.cancel()
        autoSync = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: Self.syncEvery)
                guard !Task.isCancelled, let self else { return }
                await self.syncAll()
            }
        }
    }

    private func stopAutoSync() {
        autoSync?.cancel()
        autoSync = nil
        for task in soon.values { task.cancel() }
        soon = [:]
    }

    /// One round at a time; asked again meanwhile, it goes round once more.
    private func syncAll(only itemId: String? = nil) async {
        guard unlocked else { return }
        if syncingAll {
            syncAgain = true
            return
        }
        syncingAll = true
        defer { syncingAll = false }
        let current = session
        repeat {
            syncAgain = false
            for safe in open where safe.sync && (itemId == nil || safe.itemId == itemId) {
                guard unlocked, current == session else { return }
                _ = try? await sync(safe)
            }
        } while syncAgain
    }

    /// Deletes a Safe: out of Files first (its copies go and the extension loses the key), then the
    /// item goes to the trash and its folder here is removed, under the store lock.
    func delete(_ safe: SafeItem) async throws {
        guard let folder else { throw VaultError.Failed(code: .unexpected, reason: "no shared container") }
        try? records.remove(safe.itemId)
        open.removeAll { $0.itemId == safe.itemId }
        _ = try? await NSFileProviderManager.remove(Self.domain(safe), mode: .removeAll)
        do {
            let lock = try await SafeStoreLock.acquire(safeId: safe.safeId, in: folder)
            defer { lock.release() }
            try await vault.deleteSafe(itemId: safe.itemId, folder: folder.path)
        } catch {
            // Still there: back in Files.
            refresh(force: true)
            throw error
        }
    }

    /// Opens the Files app (Finder on the Mac) at the Safe.
    func showInFiles(_ safe: SafeItem) async {
        let root = try? await NSFileProviderManager(for: Self.domain(safe))?.getUserVisibleURL(for: .rootContainer)
        #if os(iOS)
        var target = URL(string: "shareddocuments://")!
        if let root, var components = URLComponents(url: root, resolvingAgainstBaseURL: false) {
            components.scheme = "shareddocuments"
            target = components.url ?? target
        }
        _ = await UIApplication.shared.open(target)
        #else
        // The sandboxed app can't open the folder itself: it asks Finder to show it, inside the
        // URL's security scope.
        guard let root else { return }
        let scoped = root.startAccessingSecurityScopedResource()
        defer { if scoped { root.stopAccessingSecurityScopedResource() } }
        NSWorkspace.shared.activateFileViewerSelecting([root])
        #endif
    }

    // MARK: Helpers

    private func enqueue(_ work: @escaping @MainActor () async -> Void) {
        let previous = queue
        queue = Task { @MainActor in
            await previous?.value
            await work()
        }
    }

    private static func domain(_ safe: SafeItem) -> NSFileProviderDomain {
        NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: safe.itemId), displayName: safe.name)
    }

    /// Removes every domain, and with it what Files kept of the Safes' files.
    private static func removeDomains() async {
        for domain in (try? await NSFileProviderManager.domains()) ?? [] {
            _ = try? await NSFileProviderManager.remove(domain, mode: .removeAll)
        }
    }

    #if os(macOS)
    /// The vault locked (Mac): each Safe's domain goes with everything Finder kept of it (its
    /// files' copies and names), then comes back empty, so Finder lists the Safe and asks for Open
    /// Pass. Without a key the extension has nothing to show.
    private static func empty(_ safes: [SafeItem]) async {
        for safe in safes {
            _ = try? await NSFileProviderManager.remove(domain(safe), mode: .removeAll)
            try? await NSFileProviderManager.add(domain(safe))
        }
    }

    /// `removeDomains` for `willTerminate`, which can't wait for a task: blocks for at most five
    /// seconds. The system answers on its own queue, never the main one.
    nonisolated private static func removeDomainsBeforeQuitting() {
        let done = DispatchSemaphore(value: 0)
        NSFileProviderManager.getDomainsWithCompletionHandler { domains, _ in
            let group = DispatchGroup()
            for domain in domains {
                group.enter()
                NSFileProviderManager.remove(domain, mode: .removeAll) { _, _ in group.leave() }
            }
            group.notify(queue: .global()) { done.signal() }
        }
        _ = done.wait(timeout: .now() + 5)
    }
    #endif

    /// Files reads the Safe again: its folders, and (after an unlock) past the "not authenticated"
    /// answer it was holding back for.
    static func signal(_ itemId: String) {
        let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: itemId), displayName: "")
        guard let manager = NSFileProviderManager(for: domain) else { return }
        manager.signalErrorResolved(NSFileProviderError(.notAuthenticated)) { _ in }
        manager.signalEnumerator(for: .workingSet) { _ in }
        manager.signalEnumerator(for: .rootContainer) { _ in }
    }
}

extension SafeItem: @retroactive Identifiable {
    public var id: String { itemId }
}
