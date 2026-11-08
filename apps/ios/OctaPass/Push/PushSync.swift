import Foundation
import OctaPassVault
import os
import UIKit
import UserNotifications

private let log = Logger(subsystem: "app.octap.ios", category: "push")

/// Push sync (plan 04, "Push relay"). The app hands the vault the APNs token the system gives it at
/// every launch; the vault sends it to the account's server after the next sync (sign-in and unlock
/// included). A push carries only its kind ("sync" or "alert"), never account, vault or item data,
/// and makes the vault sync: in full when unlocked, the ciphertext only when locked.
@MainActor
final class PushSync {
    static let shared = PushSync()

    /// What a push asks for, from its `octapass` key. Anything else isn't ours and is ignored.
    enum Kind: String {
        /// Something changed in the vault: a background push, nothing shown.
        case sync
        /// Sharing, a family invite or emergency access: shown with the catalog's
        /// `phone.native.pushAlertTitle` / `pushAlertBody`, which iOS localises on the phone.
        case alert
    }

    /// Development builds are signed with `aps-environment` development, so their tokens belong to
    /// Apple's sandbox gateway; release builds to production (OCTAPASS_APS_ENVIRONMENT).
    #if DEBUG
    static let sandbox = true
    #else
    static let sandbox = false
    #endif

    /// iOS asks for a push's completion within 30 seconds; an answer before then keeps the app's
    /// background budget. The sync itself carries on.
    nonisolated static let deadline: Duration = .seconds(25)

    private var vault: OctaPassVault?
    /// A token that came before the vault opened (it shouldn't: the app opens it first).
    private var pendingToken: String?

    /// The app's vault, once it's open at launch.
    func attach(_ vault: OctaPassVault) {
        self.vault = vault
        if let token = pendingToken {
            pendingToken = nil
            send(token)
        }
    }

    /// The system's token, at every launch and whenever it changes. Best effort: the vault keeps it
    /// and tries again after the next sync, so a failure here only waits for that.
    func tokenReceived(_ deviceToken: Data) {
        send(Self.hex(deviceToken))
    }

    /// Registration failed (no `aps-environment` in an unsigned build, no network at first launch):
    /// the server stops sending to an old token. Syncs on opening and while open go on as before.
    func registrationFailed(_ error: Error) {
        log.info("Remote notifications unavailable: \(error.localizedDescription, privacy: .public)")
        pendingToken = nil
        guard let vault else { return }
        Task {
            do { try await vault.clearPushToken() } catch { log.error("Clearing the push token failed: \(error)") }
        }
    }

    /// A push arrived, in the foreground or the background.
    func received(_ userInfo: [AnyHashable: Any]) async -> UIBackgroundFetchResult {
        guard let vault else { return .noData }
        return await Self.handle(userInfo) { try await vault.syncOnPush() }
    }

    private func send(_ token: String) {
        guard let vault else {
            pendingToken = token
            return
        }
        Task {
            do {
                let registered = try await vault.setPushToken(platform: .apns, token: token, sandbox: Self.sandbox)
                log.info("Push token handed over; the server has it: \(registered, privacy: .public)")
            } catch {
                log.error("Handing over the push token failed: \(error)")
            }
        }
    }

    // MARK: Pure parts, tested in PushSyncTests

    /// The device token as the vault and the relay take it: lowercase hex, two digits a byte.
    nonisolated static func hex(_ token: Data) -> String {
        token.map { String(format: "%02x", $0) }.joined()
    }

    nonisolated static func kind(_ userInfo: [AnyHashable: Any]) -> Kind? {
        (userInfo["octapass"] as? String).flatMap(Kind.init(rawValue:))
    }

    /// Runs `sync` for one of our pushes and answers iOS: new data when it worked, failed when it
    /// didn't or ran past `deadline`, no data for a push that isn't ours.
    nonisolated static func handle(
        _ userInfo: [AnyHashable: Any],
        deadline: Duration = PushSync.deadline,
        sync: @escaping @Sendable () async throws -> Void
    ) async -> UIBackgroundFetchResult {
        guard let kind = kind(userInfo) else { return .noData }
        log.info("A \(kind.rawValue, privacy: .public) push: syncing")
        return await withCheckedContinuation { continuation in
            let answer = Once(continuation)
            let timer = Task {
                try await Task.sleep(for: deadline)
                log.error("A push's sync ran past the deadline")
                answer.resume(.failed)
            }
            Task {
                do {
                    try await sync()
                    log.info("A push's sync finished")
                    answer.resume(.newData)
                } catch {
                    log.error("A push's sync failed: \(error)")
                    answer.resume(.failed)
                }
                timer.cancel()
            }
        }
    }

    /// Notification permission, asked once and without a prompt: `.provisional` puts alert pushes
    /// quietly in Notification Center, where the first one offers Keep or Turn Off. A password
    /// manager has no business interrupting sign-up with a permission dialog for the rare sharing or
    /// emergency-access alert, and sync pushes need no permission at all (they're silent).
    static func requestQuietAlerts() {
        let center = UNUserNotificationCenter.current()
        Task {
            guard await center.notificationSettings().authorizationStatus == .notDetermined else { return }
            _ = try? await center.requestAuthorization(options: [.alert, .sound, .provisional])
        }
    }
}

/// Resumes a continuation the first time only: the sync and the deadline race.
private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<UIBackgroundFetchResult, Never>?

    init(_ continuation: CheckedContinuation<UIBackgroundFetchResult, Never>) {
        self.continuation = continuation
    }

    func resume(_ result: UIBackgroundFetchResult) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: result)
    }
}

/// The app's UIKit delegate, for what SwiftUI has no API for: remote notifications.
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(
        _ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        // Every launch: the token can change, and the vault keeps it in memory only.
        application.registerForRemoteNotifications()
        PushSync.requestQuietAlerts()
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        PushSync.shared.tokenReceived(deviceToken)
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        PushSync.shared.registrationFailed(error)
    }

    func application(
        _ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any],
        fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void
    ) {
        Task { @MainActor in completionHandler(await PushSync.shared.received(userInfo)) }
    }

    /// An alert push while the app is open shows as a banner too. Its sync runs through
    /// `didReceiveRemoteNotification` (it's content-available), not here.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        PushSync.kind(notification.request.content.userInfo) == .alert ? [.banner, .list, .sound] : []
    }

    /// The alert was tapped: the app opens, and its sync has run or is running.
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {}
}
