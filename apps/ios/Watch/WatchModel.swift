import Foundation
import LocalAuthentication
import Observation
import OctaPassWatchCodes
import WatchConnectivity

/// What the screen shows: the codes the phone last sent, kept in memory only. Between launches the
/// system holds the phone's last payload in its own protected store (`receivedApplicationContext`);
/// this app writes nothing to disk.
@MainActor @Observable
final class WatchModel {
    private(set) var codes = WatchCodes()
    /// False on a watch with no passcode: nothing is asked for and nothing is shown.
    private(set) var hasPasscode = WatchModel.watchHasPasscode()
    @ObservationIgnored private lazy var link = PhoneLink { [weak self] text in self?.received(text) }

    func appeared() {
        hasPasscode = Self.watchHasPasscode()
        guard hasPasscode else {
            codes.apply(.clear(issuedAtMs: Self.nowMs))
            return
        }
        link.start()
        link.askForCodes()
    }

    func forgetExpired() {
        codes.forgetExpired(atMs: Self.nowMs)
    }

    private func received(_ text: String) {
        guard hasPasscode, let payload = WatchPayload.decode(text) else { return }
        codes.apply(payload)
    }

    static var nowMs: UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }

    private static func watchHasPasscode() -> Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }
}

/// Watch Connectivity's side of the link. Its delegate calls arrive on a background queue; only
/// the payload's text goes on to the model.
final class PhoneLink: NSObject, WCSessionDelegate, @unchecked Sendable {
    private let onPayload: @MainActor (String) -> Void
    private var askWhenActive = false

    init(onPayload: @escaping @MainActor (String) -> Void) {
        self.onPayload = onPayload
    }

    func start() {
        guard WCSession.isSupported(), WCSession.default.delegate == nil else { return }
        WCSession.default.delegate = self
        WCSession.default.activate()
    }

    /// Asks the phone for fresh codes. The phone answers with a clear unless it's unlocked and
    /// the setting is on. When it can't be reached, what's here stays until it expires.
    func askForCodes() {
        let session = WCSession.default
        guard session.activationState == .activated else {
            askWhenActive = true
            return
        }
        guard session.isReachable else { return }
        session.sendMessage([WatchLink.refresh: true], replyHandler: { [weak self] reply in
            self?.deliver(reply)
        }, errorHandler: { _ in })
    }

    private func deliver(_ message: [String: Any]) {
        guard let text = message[WatchLink.payload] as? String else { return }
        let onPayload = onPayload
        Task { @MainActor in onPayload(text) }
    }

    func session(_ session: WCSession, activationDidCompleteWith state: WCSessionActivationState, error: (any Error)?) {
        guard state == .activated else { return }
        deliver(session.receivedApplicationContext)
        if askWhenActive {
            askWhenActive = false
            askForCodes()
        }
    }

    func session(_ session: WCSession, didReceiveApplicationContext context: [String: Any]) {
        deliver(context)
    }

    func session(_ session: WCSession, didReceiveMessage message: [String: Any]) {
        deliver(message)
    }

    func sessionReachabilityDidChange(_ session: WCSession) {
        if session.isReachable { askForCodes() }
    }
}
