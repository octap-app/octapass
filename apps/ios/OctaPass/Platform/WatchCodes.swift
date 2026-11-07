// iPhone only: Macs don't pair with a watch. The Mac's stand-in is in OctaPassMac/Platform.
#if os(iOS)
import Foundation
import OctaPassVault
import OctaPassWatchCodes
import WatchConnectivity

/// Hands the Apple Watch what `OctaPassVault.watchPayload` returns. The Rust core decides what
/// that is, codes or a clear, from the session and the setting; this class only carries the text.
/// Works in the background too: a watch asking for codes wakes the app, and a phone that isn't
/// unlocked answers with a clear.
final class WatchCodesLink: NSObject, WCSessionDelegate, @unchecked Sendable {
    /// Codes last 15 minutes. Sending every 5 keeps a watch going while the app is open.
    private static let refreshInterval: Duration = .seconds(5 * 60)

    private let vault: OctaPassVault
    private var refreshing: Task<Void, Never>?

    init(vault: OctaPassVault) {
        self.vault = vault
        super.init()
        guard WCSession.isSupported() else { return }
        WCSession.default.delegate = self
        WCSession.default.activate()
    }

    /// iPads and other devices without a watch don't offer the setting.
    static var isSupported: Bool { WCSession.isSupported() }

    /// Sends what the watch should have now: after an unlock, a lock, a sign-out, an item change,
    /// or when the setting changes.
    func update() {
        Task { await send() }
    }

    /// While the app is unlocked and the setting is on, keeps the watch's codes from running out.
    func keepFresh(_ on: Bool) {
        refreshing?.cancel()
        refreshing = nil
        guard on else { return }
        refreshing = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: Self.refreshInterval)
                guard !Task.isCancelled, let self else { return }
                await self.send()
            }
        }
    }

    private func send() async {
        let session = WCSession.default
        guard WCSession.isSupported(), session.activationState == .activated,
              session.isPaired, session.isWatchAppInstalled else { return }
        let payload = await vault.watchPayload(atMs: nil)
        // The system keeps only the latest context, so a lock made while the watch is away reaches
        // it before any older codes could be read again.
        try? session.updateApplicationContext([WatchLink.payload: payload])
        if session.isReachable {
            session.sendMessage([WatchLink.payload: payload], replyHandler: nil, errorHandler: nil)
        }
    }

    func session(_ session: WCSession, didReceiveMessage message: [String: Any], replyHandler: @escaping ([String: Any]) -> Void) {
        guard message[WatchLink.refresh] != nil else {
            replyHandler([:])
            return
        }
        // Not an activity: a watch asking can't keep the vault unlocked.
        let vault = vault
        nonisolated(unsafe) let reply = replyHandler
        Task { reply([WatchLink.payload: await vault.watchPayload(atMs: nil)]) }
    }

    func session(_ session: WCSession, activationDidCompleteWith state: WCSessionActivationState, error: (any Error)?) {
        if state == .activated { update() }
    }

    func sessionDidBecomeInactive(_ session: WCSession) {}

    /// The user moved to another watch: start again for it.
    func sessionDidDeactivate(_ session: WCSession) {
        session.activate()
    }

    func sessionWatchStateDidChange(_ session: WCSession) {
        update()
    }
}
#endif
