import SwiftUI

@main
struct OctaPassApp: App {
    @NSApplicationDelegateAdaptor private var delegate: AppDelegate

    var body: some Scene {
        Window("Octa Pass", id: "onboarding") {
            OnboardingView()
                .frame(width: 520, height: 660)
        }
        .windowResizability(.contentSize)
    }
}

private final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}
