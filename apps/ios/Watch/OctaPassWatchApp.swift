import SwiftUI

/// The Apple Watch app: one list of one-time codes the iPhone sent. It holds no seed and makes no
/// code: what it shows was computed on the phone (`crates/octapass-mobile/src/watch.rs`).
@main
struct OctaPassWatchApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @State private var model = WatchModel()

    var body: some Scene {
        WindowGroup {
            CodesView(model: model)
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { model.appeared() }
        }
    }
}
