import OctaPassResources
import OctaPassVault
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

#if os(iOS)
/// Shows SwiftUI above whatever is on screen, sheets included. SwiftUI's own sheets can only come
/// from a view that's still there and has no sheet up, and the gate is asked for from menus, list
/// rows and other sheets.
@MainActor
enum Modal {
    private static var top: UIViewController? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let window = scenes.flatMap(\.windows).first(where: \.isKeyWindow)
        var controller = window?.rootViewController
        while let next = controller?.presentedViewController { controller = next }
        return controller
    }

    /// `content` gets a function that closes it. It can't be swiped away, so it always gets to
    /// answer whoever is waiting.
    static func present(model: AppModel, @ViewBuilder content: (@escaping () -> Void) -> some View) {
        var host: UIViewController?
        let close = { host?.dismiss(animated: true); host = nil }
        let root = content(close)
            .environment(model)
            .tint(.button)
            .environment(\.layoutDirection, model.layoutDirection)
            .environment(\.locale, model.locale)
        let controller = UIHostingController(rootView: root)
        controller.isModalInPresentation = true
        controller.sheetPresentationController?.detents = [.medium(), .large()]
        host = controller
        top?.present(controller, animated: true)
    }

    /// The share sheet for a file written for it, deleted when the sheet closes.
    static func share(_ url: URL, finished: @escaping () -> Void) {
        guard let top else { return finished() }
        let sheet = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        sheet.completionWithItemsHandler = { _, _, _, _ in finished() }
        sheet.popoverPresentationController?.sourceView = top.view
        sheet.popoverPresentationController?.sourceRect = CGRect(x: top.view.bounds.midX, y: top.view.bounds.midY, width: 0, height: 0)
        sheet.popoverPresentationController?.permittedArrowDirections = []
        top.present(sheet, animated: true)
    }
}
#endif

extension AppModel {
    /// The gate for revealing and copying a field, showing a secret as a QR code, and showing an
    /// SSH key or environment values: no prompt while the vault is open, however it was opened
    /// (maintainer decision, plan 03 History 2026-11-06). Exports, the Secret Key and the account's
    /// own settings ask every time (`confirmIdentity`). "Confirm it's you" here only if the vault
    /// locked in the meantime.
    func confirmReveal() async -> Bool {
        if await unlockCoversReveal() { return true }
        guard await confirmIdentity() else { return false }
        revealWasConfirmed()
        return true
    }

    /// "Confirm it's you", every time: before an export, the Secret Key or a change to the account
    /// (plan 03, whatever the two gates say), and before a reveal the unlock doesn't cover. The
    /// device lock where it's on, the master password otherwise. A device with no lock has the
    /// master password as its only gate, so this never lets anyone through unasked. Cancelling the
    /// device prompt is an answer; the master password is offered when the device lock can't be
    /// used.
    func confirmIdentity() async -> Bool {
        let methods = try? await vault.unlockMethods()
        if let methods, methods.deviceUnlockEnabled, !methods.passwordRequired {
            do {
                try await vault.confirmUser(password: nil)
                return true
            } catch {
                if error.isVault(.deviceUnlockCancelled) { return false }
            }
        }
        return await withCheckedContinuation { continuation in
            Modal.present(model: self) { close in
                IdentityGateSheet { confirmed in
                    close()
                    continuation.resume(returning: confirmed)
                }
            }
        }
    }
}

private struct IdentityGateSheet: View {
    @Environment(AppModel.self) private var model
    let finish: (Bool) -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                ConfirmItsYou(deviceButton: false, note: L10n.identityGate.body) { finish(true) }
                    .padding(20)
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.common.cancel) { finish(false) }
                        .accessibilityIdentifier("confirm-cancel")
                }
            }
        }
        .onChange(of: model.session.status) { _, status in
            if status != .unlocked { finish(false) }
        }
    }
}
