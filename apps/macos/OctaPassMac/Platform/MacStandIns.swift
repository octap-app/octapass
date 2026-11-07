import Foundation
import Observation
import OctaPassVault
import SwiftUI

// What the shared screens ask of iPhone-only services, answered for the Mac. Each says "not here"
// so the screens hide or explain the action; plan 19 phase 2 replaces the ones the Mac gets
// (Wi-Fi through CoreWLAN). AutoFill settings and Credential Exchange are shared with the iPhone
// (`apps/ios/OctaPass/Platform`).

/// No live camera scanner on the Mac: QR codes come from pictures (`readQrCodes`).
enum QrReader {
    @MainActor static var cameraAvailable: Bool { false }
}

/// Never shown, since `cameraAvailable` is false.
struct CameraQrScanner: View {
    let onCode: (String) -> Void
    var body: some View { EmptyView() }
}

/// Joining a Wi-Fi network from the app isn't built on the Mac yet.
enum WifiConnect {
    enum Failure: Error {
        case unsupported, cancelled, failed
    }

    static func canJoin(_ network: WifiNetwork, details: WifiDetails?) -> Bool { false }

    static func join(_ network: WifiNetwork, details: WifiDetails?) async throws {
        throw Failure.unsupported
    }
}

/// The current network's name isn't read on the Mac yet, so nothing is marked as connected and the
/// save offer doesn't appear.
@MainActor @Observable
final class WifiRadar {
    static let shared = WifiRadar()
    private(set) var permission = "unsupported"
    private(set) var connected: String?

    private init() {}

    func refresh() async {}
}

/// Macs don't pair with an Apple Watch.
final class WatchCodesLink: @unchecked Sendable {
    init(vault: OctaPassVault) {}
    static var isSupported: Bool { false }
    func update() {}
    func keepFresh(_ on: Bool) {}
}
