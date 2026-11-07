import Foundation
import notify
import Observation
import OctaPassKeychain
import OctaPassResources
import OctaPassVault
// The vault's `Settings`: on the Mac, SwiftUI has a `Settings` scene too.
import struct OctaPassVault.Settings
import SwiftUI
#if os(iOS)
import UIKit
#endif

/// The app's one vault and what the screens watch: the session, sync, and counters that tick when
/// items or sharing change, so lists load again. Everything else the screens ask the vault.
@MainActor @Observable
final class AppModel {
    let vault: OctaPassVault
    /// The "Octa Pass" server choice (the hosted service, or a test server in development builds).
    let defaultServerUrl: String
    private(set) var session: SessionSnapshot
    private(set) var sync: SyncState
    /// Goes up whenever items change, here or by a sync.
    private(set) var itemsVersion = 0
    private(set) var sharingVersion = 0
    private(set) var settings: Settings
    /// Shown at the bottom of the screen for a moment: a copy, a save, an error.
    var toast: Toast?
    /// "Use Face ID to unlock Octa Pass?", right after a sign-in or sign-up (plan 03): the device
    /// lock's name while it's offered.
    var offerDeviceUnlock: String?
    /// Sign-up is showing the Recovery Kit, or a new local vault its recovery code and first
    /// backup: the vault is open, but its screens wait.
    var signingUp = false
    /// Turn on sync is open over the vault. Kept here, not in a sheet: the vault becomes an account
    /// underneath, Settings loses the section that opened it, and the Recovery Kit has to stay.
    var turningOnSync = false
    /// Every vault on this phone only, read again when the session changes and on coming back.
    private(set) var localVaults: [LocalVaultInfo]
    /// "Forgot your master password?" is open over the signed-out or locked screen. Kept here so
    /// signing in when the reset finishes doesn't take the screen with it.
    var resettingPassword = false
    /// The server picked on the sign-in screen, for a reset started from there.
    var resetServerUrl: String?
    /// A new Recovery Kit the user hasn't confirmed saving. Kept here, in memory only, because
    /// it's the only copy: the screen that made it may be gone, and a lock must not lose it.
    var newKit: PendingRecoveryKit?
    /// One-time code links that opened the app, waiting for the vault to be unlocked.
    var openedLinks: [String] = []
    /// What other apps handed over (Credential Exchange), oldest first, waiting for the vault to
    /// be unlocked.
    var received: [ReceivedCredentials] = []
    /// The account was just deleted here: the goodbye screen shows until the user moves on.
    var accountDeleted = false
    /// Site rows open in item lists, kept while the vault stays unlocked (never on disk: hosts
    /// are vault data).
    var openSites: Set<String> = []
    /// Set when the user signs in or up here, until the vault next locks.
    private var justSignedIn = false
    /// The account whose unlock the user answered here (Face ID / Touch ID, the passcode or the
    /// master password), until the vault next locks or another account opens. Reveal and copy
    /// don't ask again while it's set (plan 03 History, 2026-11-05). With stay unlocked on, the
    /// first reveal's answer sets it too, and the phone locking or sleeping clears it (plan 18).
    /// Memory only, never a key.
    private var confirmedUnlock: String?
    /// The stay-unlocked attempt under way, so the unlock screen and coming back share one.
    private var openingStayUnlocked: Task<Bool, Never>?
    private var deviceLockObserver: NSObjectProtocol?
    /// The Apple Watch's codes. What it gets is decided in the vault.
    private let watch: WatchCodesLink
    /// The Safes open in the Files app while the vault is unlocked, and their keys for the
    /// Files extension.
    let safeFiles: SafeFiles

    init(vault: OctaPassVault, events: VaultEvents, defaultServerUrl: String) {
        self.vault = vault
        self.defaultServerUrl = defaultServerUrl
        session = vault.snapshot()
        sync = vault.syncState()
        watch = WatchCodesLink(vault: vault)
        let settings = vault.settings()
        self.settings = settings
        safeFiles = SafeFiles(vault: vault, autoLockMinutes: settings.autoLockMinutes)
        localVaults = vault.localVaults()
        events.model = self
        safeFiles.sessionChanged(unlocked: session.status == .unlocked, account: Self.safesAccount(session))
        #if os(macOS)
        safeFiles.onUnlockRequest = { [weak self] in self?.requestUnlock() }
        #endif
        applyLanguage()
        #if os(iOS)
        // The phone locked or went to sleep: the next reveal asks again (plan 18). Only phones with
        // a passcode post it, and only they can stay unlocked.
        deviceLockObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataWillBecomeUnavailableNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.deviceLocked() }
        }
        #if DEBUG
        // UI tests can't lock the Simulator, which has no passcode anyway: they post this instead.
        var token: Int32 = 0
        notify_register_dispatch("app.octap.test.deviceLocked", &token, .main) { _ in
            NotificationCenter.default.post(name: UIApplication.protectedDataWillBecomeUnavailableNotification, object: nil)
        }
        #endif
        #else
        // The Mac's screen locked or it went to sleep (plan 18).
        deviceLockObserver = MacDeviceLock.observe { [weak self] in self?.deviceLocked() }
        #endif
    }

    /// The app's vault in the App Group container the AutoFill extension shares.
    static func live() -> AppModel {
        let environment = ProcessInfo.processInfo.environment
        let files = FileManager.default
        var group = SharedContainer.url() ?? files.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        // Decrypted files and exports stay in the app's own storage, never the App Group.
        let temp = files.temporaryDirectory.appending(path: "vault")
        let icons = files.urls(for: .cachesDirectory, in: .userDomainMask)[0].appending(path: "site-icons")
        let server = environment["OCTAPASS_SERVER_URL"]
            ?? (Bundle.main.object(forInfoDictionaryKey: "OctaPassServerURL") as? String).flatMap { $0.isEmpty ? nil : $0 }
            ?? "https://vault.octap.app"
        #if DEBUG && os(macOS)
        // The Mac's UI tests run on the developer's own Mac: a store of their own, empty each run,
        // so they never erase the developer's vault and their accounts never show up in it.
        if environment["OCTAPASS_RESET"] == "1" {
            group = group.appending(path: "UITests", directoryHint: .isDirectory)
            try? files.removeItem(at: group)
            try? files.createDirectory(at: group, withIntermediateDirectories: true)
        }
        #elseif DEBUG
        // UI tests start from an empty phone.
        if environment["OCTAPASS_RESET"] == "1" {
            // Only the vault's files: the container's own (hidden metadata, Library) stay, or the
            // system stops sharing the folder with the AutoFill extension.
            let options: FileManager.DirectoryEnumerationOptions = [.skipsHiddenFiles]
            for file in (try? files.contentsOfDirectory(at: group, includingPropertiesForKeys: nil, options: options)) ?? []
                where file.lastPathComponent != "Library" {
                try? files.removeItem(at: file)
            }
            try? files.removeItem(at: icons)
            UserDefaults.standard.removePersistentDomain(forName: Bundle.main.bundleIdentifier ?? "")
        }
        #endif
        #if os(iOS)
        let device = UIDevice.current.userInterfaceIdiom == .pad ? "Octa Pass for iPad" : "Octa Pass for iPhone"
        let platform = DevicePlatform.ios
        #else
        let device = "Octa Pass for Mac"
        let platform = DevicePlatform.macos
        #endif
        let events = VaultEvents()
        do {
            let vault = try OctaPassVault(
                config: VaultConfig(
                    dataDir: group.path, tempDir: temp.path, deviceName: device, platform: platform,
                    pwnedPasswordsUrl: environment["OCTAPASS_PWNED_URL"] ?? "https://api.pwnedpasswords.com",
                    webVaultUrl: "https://vault.octap.app", defaultServerUrl: server,
                    cacheDir: icons.path),
                platform: VaultPlatform(), observer: events)
            let model = AppModel(vault: vault, events: events, defaultServerUrl: server)
            #if DEBUG
            // UI tests hand over CXF as another app would, without the system's sheet.
            if let json = environment["OCTAPASS_RECEIVE_CXF"] {
                model.received.append(.json(json, from: environment["OCTAPASS_RECEIVE_FROM"] ?? "Passwords"))
            }
            #endif
            return model
        } catch {
            // Only an unreadable App Group gets here; nothing on screen can fix it.
            fatalError("Octa Pass couldn't open its storage: \(error)")
        }
    }

    var isUnlocked: Bool { session.status == .unlocked }
    /// A vault on this phone only: there's no account behind it.
    var isLocal: Bool { session.serverUrl?.hasPrefix("local:") == true }
    var currentLocalVault: LocalVaultInfo? { localVaults.first(where: \.current) }

    func reloadLocalVaults() { localVaults = vault.localVaults() }

    // MARK: Vault events (on the main actor)

    fileprivate func sessionChanged(_ snapshot: SessionSnapshot) {
        let before = session.status
        session = snapshot
        // Signing out from the lock screen must not reveal a kit to whoever holds the phone.
        if snapshot.status == .signedOut { newKit = nil }
        reloadLocalVaults()
        if snapshot.status != .unlocked {
            offerDeviceUnlock = nil
            openSites = []
            SiteIconCache.shared.clear()
            HealthStore.shared.clear()
            if before == .unlocked { justSignedIn = false }
        }
        if snapshot.status != .unlocked || Self.account(snapshot) != confirmedUnlock { confirmedUnlock = nil }
        if snapshot.status == .unlocked, before != .unlocked {
            itemsVersion += 1
            if justSignedIn { Task { await considerDeviceUnlockOffer() } }
        }
        if snapshot.status != before { watchChanged() }
        // Locked or signed out: the Safes' keys and Files' copies go before anything else.
        safeFiles.sessionChanged(unlocked: snapshot.status == .unlocked, account: Self.safesAccount(snapshot))
    }

    fileprivate func itemsChanged() {
        itemsVersion += 1
        if settings.showCodesOnWatch { watch.update() }
        safeFiles.refresh()
    }

    /// A touch: the vault's auto-lock and the Safes' time in Files start again.
    func recordActivity() {
        vault.recordActivity()
        safeFiles.touch()
    }

    /// The session or the setting changed: the watch gets codes or a clear straight away.
    private func watchChanged() {
        watch.update()
        watch.keepFresh(isUnlocked && settings.showCodesOnWatch)
    }

    fileprivate func syncChanged(_ state: SyncState) {
        let synced = state.status == .idle && state.lastSyncedAt != sync.lastSyncedAt
        sync = state
        // The synced Safes follow the vault.
        if synced { safeFiles.syncSoon() }
    }
    fileprivate func sharingChanged() { sharingVersion += 1 }

    // MARK: Settings

    func update(_ change: (inout Settings) -> Void) {
        var next = settings
        change(&next)
        do {
            try vault.updateSettings(settings: next)
            let languageChanged = next.language != settings.language
            let watchChanged = next.showCodesOnWatch != settings.showCodesOnWatch
            let autoLockChanged = next.autoLockMinutes != settings.autoLockMinutes
            let stayUnlockedChanged = next.stayUnlocked != settings.stayUnlocked
            settings = next
            // Turning the app-open gate off ends what this unlock covered, until the next one, and
            // so does turning stay unlocked on or off: what counts as an answer changes.
            if !next.deviceAuthOnOpen || stayUnlockedChanged { confirmedUnlock = nil }
            if languageChanged { applyLanguage() }
            if watchChanged { self.watchChanged() }
            if autoLockChanged { safeFiles.autoLockChanged(next.autoLockMinutes) }
        } catch {
            show(error)
        }
    }

    /// Strings and the layout direction follow the language chosen in Settings, or the phone's.
    private(set) var languageVersion = 0

    private func applyLanguage() {
        switch settings.language {
        case .system: L10n.setLanguage(nil)
        case .en: L10n.setLanguage("en")
        case .ar: L10n.setLanguage("ar")
        }
        languageVersion += 1
    }

    var layoutDirection: LayoutDirection { L10n.language == "ar" ? .rightToLeft : .leftToRight }
    var locale: Locale { Locale(identifier: L10n.language) }

    var colorScheme: ColorScheme? {
        switch settings.theme {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }

    // MARK: Sign-in and the device unlock offer

    /// Called by the sign-in and sign-up screens before the session turns unlocked.
    func willSignIn() { justSignedIn = true }

    private func considerDeviceUnlockOffer() async {
        guard let email = session.email, DeviceUnlockOfferState.load(email) != .done,
              let methods = try? await vault.unlockMethods(),
              methods.deviceUnlockSupported, !methods.deviceUnlockEnabled
        else { return }
        // The reminder at a later unlock is the last time.
        if DeviceUnlockOfferState.load(email) == .declined { DeviceUnlockOfferState.save(.done, for: email) }
        offerDeviceUnlock = methods.label
    }

    /// A master-password unlock: the offer comes back once if it was put off.
    func didUnlockWithPassword() {
        guard let email = session.email, DeviceUnlockOfferState.load(email) == .declined else { return }
        Task { await considerDeviceUnlockOffer() }
    }

    // MARK: The unlock as confirmation

    private static func account(_ snapshot: SessionSnapshot) -> String {
        "\(snapshot.serverUrl ?? "")\n\(snapshot.email ?? "")"
    }

    /// Whose Safes are in Files (`SafeFiles`): nil when signed out.
    private static func safesAccount(_ snapshot: SessionSnapshot) -> String? {
        snapshot.status == .signedOut ? nil : account(snapshot)
    }

    /// Called by the screens that unlock the vault, right after the user's own answer opened it
    /// (the device prompt, the master password, signing in or up, a new or restored local vault).
    /// Stay unlocked opening the vault by itself isn't such an answer. Nothing else unlocks in this
    /// app; an unlock that doesn't come through here keeps asking. With the app-open gate off it
    /// isn't counted, whatever opened the vault (maintainer decision, plan 03 History 2026-11-05),
    /// unless stay unlocked is on: the gate doesn't apply then (plan 18).
    func unlockWasConfirmed() {
        let now = vault.snapshot()
        confirmedUnlock = now.status == .unlocked && answersCount ? Self.account(now) : nil
    }

    /// This unlock was the user's answer and the vault hasn't locked since. Asks the vault, not the
    /// last event, so a lock that hasn't reached the screens yet still counts.
    var unlockConfirmed: Bool {
        guard let confirmedUnlock, answersCount else { return false }
        let now = vault.snapshot()
        return now.status == .unlocked && Self.account(now) == confirmedUnlock
    }

    /// Whether an answer covers the reveals after it: the app-open gate is on, or stay unlocked is.
    private var answersCount: Bool { settings.deviceAuthOnOpen || staysUnlocked }

    /// The first reveal or copy since stay unlocked opened the vault was answered (plan 18): the
    /// rest don't ask until the vault or the phone locks, or another account opens.
    func revealWasConfirmed() {
        let now = vault.snapshot()
        guard staysUnlocked, now.status == .unlocked else { return }
        confirmedUnlock = Self.account(now)
    }

    /// The phone locked or slept: while staying unlocked, reveal and copy ask again (plan 18). With
    /// it off, plan 03's once-per-unlock rule is unchanged, as on Android, the desktop and the extension.
    func deviceLocked() {
        if staysUnlocked { confirmedUnlock = nil }
    }

    /// An open vault covers revealing and copying, however it was opened (maintainer decision,
    /// plan 03 History 2026-11-06): nothing asks while it's unlocked. Only export, saving to a file,
    /// the Secret Key, the Recovery Kit and the account's own settings ask (`confirmIdentity`).
    func unlockCoversReveal() async -> Bool {
        vault.snapshot().status == .unlocked
    }

    // MARK: Stay unlocked (plan 18)

    /// "Stay unlocked" is on and the phone has a passcode to guard it: the vault opens by itself,
    /// doesn't lock on a timer or in the background, and the two device-auth gates don't apply.
    var staysUnlocked: Bool { settings.stayUnlocked && KeychainDeviceLock.current().available }

    /// Opens the locked vault with the stay-unlocked key, without a prompt. False means it didn't
    /// (the setting is off, no passcode, "Lock now", the 14-day check, no key): unlock as before.
    /// One attempt at a time; it isn't the user's answer, so reveals still ask once.
    func openStayUnlocked() async -> Bool {
        if let openingStayUnlocked { return await openingStayUnlocked.value }
        let status = vault.snapshot().status
        guard settings.stayUnlocked, status == .locked else { return status == .unlocked }
        let attempt = Task { (try? await vault.unlockStayUnlocked()) ?? false }
        openingStayUnlocked = attempt
        let opened = await attempt.value
        openingStayUnlocked = nil
        return opened
    }

    // MARK: Lifecycle

    /// Locked by the person (Lock now, Ctrl+Cmd+L, the menu bar): the lock screen then waits for
    /// them to choose device unlock instead of asking at once. They've just locked it. Read once,
    /// by the lock screen; auto-lock and a fresh start still ask at once.
    var lockedByHand = false

    /// Goes up when something outside the app asks to unlock (on the Mac, Finder's Sign In on a
    /// locked Safe): the lock screen asks for Touch ID again.
    private(set) var unlockRequests = 0

    #if os(macOS)
    /// Finder's Sign In on a locked Safe (`SafeFiles.onUnlockRequest`): the vault window, and the
    /// device prompt at once, even after Lock now, since the person just asked for it.
    func requestUnlock() {
        guard vault.snapshot().status == .locked else { return }
        lockedByHand = false
        unlockRequests += 1
        MacWindows.showVault()
    }
    #endif

    func lockNow() {
        lockedByHand = true
        vault.lock()
    }

    func scenePhaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .background:
            vault.appDidEnterBackground()
            if vault.snapshot().status != .unlocked { confirmedUnlock = nil }
            // Uses wait a few seconds to be saved together, and the app may not get those seconds:
            // save them now. Never before the lock above: a vault that locks forgets them.
            Task { try? await vault.flushItemUses() }
        case .active:
            vault.appWillEnterForeground()
            if vault.snapshot().status != .unlocked {
                confirmedUnlock = nil
                // Locked while away (a restart, a passcode set since): stay unlocked opens it.
                if settings.stayUnlocked { Task { _ = await openStayUnlocked() } }
            }
            // Still unlocked after the auto-lock check: the Safes get a new deadline in Files (one
            // may have run out while the app was away).
            if vault.snapshot().status == .unlocked { safeFiles.refresh(force: true) }
            // A backup can have come due, or been written on the way out.
            reloadLocalVaults()
            if settings.showCodesOnWatch { watch.update() }
        default: break
        }
    }

    // MARK: Feedback

    func show(_ error: Error) {
        toast = Toast(message: error.message, tone: .danger)
        Haptics.error()
    }

    func confirm(_ message: String) {
        toast = Toast(message: message, tone: .success)
        Haptics.success()
    }
}

/// Hears the vault on its threads and hands each event to the model on the main actor.
final class VaultEvents: VaultObserver, @unchecked Sendable {
    @MainActor weak var model: AppModel?

    func sessionChanged(snapshot: SessionSnapshot) {
        Task { @MainActor in model?.sessionChanged(snapshot) }
    }

    func itemsChanged() {
        Task { @MainActor in model?.itemsChanged() }
    }

    func syncChanged(state: SyncState) {
        Task { @MainActor in model?.syncChanged(state) }
    }

    func sharingChanged() {
        Task { @MainActor in model?.sharingChanged() }
    }
}

/// Whether the device unlock offer was put off (asked once more later) or settled, per account,
/// as the web vault keeps it. A preference of this phone, never vault data.
enum DeviceUnlockOfferState: String {
    case declined, done

    static func key(_ email: String) -> String { "octapass.deviceUnlockOffer:\(email)" }

    static func load(_ email: String) -> DeviceUnlockOfferState? {
        UserDefaults.standard.string(forKey: key(email)).flatMap(Self.init(rawValue:))
    }

    static func save(_ state: DeviceUnlockOfferState, for email: String) {
        UserDefaults.standard.set(state.rawValue, forKey: key(email))
    }
}

struct Toast: Equatable, Identifiable {
    enum Tone { case success, danger, info }
    let id = UUID()
    let message: String
    let tone: Tone
}

#if os(iOS)
enum Haptics {
    static func success() { UINotificationFeedbackGenerator().notificationOccurred(.success) }
    static func error() { UINotificationFeedbackGenerator().notificationOccurred(.error) }
    static func tap() { UIImpactFeedbackGenerator(style: .light).impactOccurred() }
}
#else
/// Macs have no haptics for this; the toast is the feedback.
enum Haptics {
    static func success() {}
    static func error() {}
    static func tap() {}
}
#endif
