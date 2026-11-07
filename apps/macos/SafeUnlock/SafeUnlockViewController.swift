import AppKit
import FileProvider
import FileProviderUI
import notify
import OctaPassKeychain
import OctaPassResources
import SwiftUI

/// Finder's Sign In on a locked Safe (plan 19). The Safes extension answers "not authenticated"
/// while the vault is locked; Finder then shows Sign In, and pressing it runs this. It holds no key
/// and touches no Safe: it opens Octa Pass and asks it to unlock (`SafeStore.unlockRequest`), and
/// the app, once unlocked, hands the Safes their keys and has Finder read them again.
final class SafeUnlockViewController: FPUIActionExtensionViewController {
    private let state = SafeUnlockState()

    override func loadView() {
        view = NSHostingView(rootView: SafeUnlockView(
            state: state,
            open: { [weak self] in self?.openApp() },
            cancel: { [weak self] in self?.cancel() }))
        preferredContentSize = NSSize(width: 360, height: 150)
    }

    override func prepare(forError error: Error) {
        openApp()
    }

    /// No actions are declared, so there's nothing to do.
    override func prepare(forAction actionIdentifier: String, itemIdentifiers: [NSFileProviderItemIdentifier]) {
        extensionContext.completeRequest()
    }

    /// The app this extension is in (`Octa Pass.app/Contents/PlugIns/OctaPassSafeUnlock.appex`),
    /// opened or brought forward, then asked to unlock. A launch asks by itself.
    private func openApp() {
        state.failed = false
        let app = Bundle.main.bundleURL.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        NSWorkspace.shared.openApplication(at: app, configuration: NSWorkspace.OpenConfiguration()) { running, error in
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                guard running != nil, error == nil else {
                    self.state.failed = true
                    return
                }
                notify_post(SafeStore.unlockRequest)
                self.extensionContext.completeRequest()
            }
        }
    }

    private func cancel() {
        extensionContext.cancelRequest(withError: NSError(
            domain: FPUIErrorDomain, code: Int(FPUIExtensionErrorCode.userCancelled.rawValue)))
    }
}

final class SafeUnlockState: ObservableObject {
    /// Octa Pass couldn't be opened: the person can try again.
    @Published var failed = false
}

struct SafeUnlockView: View {
    @ObservedObject var state: SafeUnlockState
    let open: () -> Void
    let cancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(L10n.phone.native.safesUnlockFirst, systemImage: "lock.doc")
                .font(.headline)
            HStack {
                if state.failed {
                    Spacer()
                    Button(L10n.common.cancel, action: cancel).keyboardShortcut(.cancelAction)
                    Button(L10n.phone.mac.openApp, action: open).keyboardShortcut(.defaultAction)
                } else {
                    ProgressView().controlSize(.small)
                    Spacer()
                }
            }
        }
        .padding(20)
        .frame(minWidth: 320, alignment: .topLeading)
    }
}
