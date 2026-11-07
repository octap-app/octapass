import AuthenticationServices
import OctaPassAutoFillKit
import SwiftUI

/// The AutoFill Credential Provider: passwords, passkeys (iOS 17, macOS 14) and one-time codes
/// (iOS 18, macOS 15) from the store the app shares through the App Group. Every request asks for
/// the device lock or the master password first, unless "Stay unlocked" is on in the app (plan 18).
/// The iPhone's and the Mac's extensions are built from these files (plan 19), so the Mac's works
/// with the app closed too.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    #if os(macOS)
    /// The sheet the system shows the extension in takes this size.
    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 520))
        preferredContentSize = view.frame.size
    }

    private func show(_ task: AutoFillTask) {
        let model = AutoFillModel(task: task) { [weak self] answer in self?.complete(answer) }
        let host = NSHostingView(rootView: AutoFillView(model: model))
        host.frame = view.bounds
        host.autoresizingMask = [.width, .height]
        view.subviews.forEach { $0.removeFromSuperview() }
        view.addSubview(host)
    }
    #else
    private func show(_ task: AutoFillTask) {
        let model = AutoFillModel(task: task) { [weak self] answer in self?.complete(answer) }
        let host = UIHostingController(rootView: AutoFillView(model: model))
        children.forEach { $0.willMove(toParent: nil); $0.view.removeFromSuperview(); $0.removeFromParent() }
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }
    #endif

    private func complete(_ answer: AutoFillAnswer) {
        let context = extensionContext
        switch answer {
        case .password(let credential):
            context.completeRequest(withSelectedCredential: credential)
        case .assertion(let credential):
            context.completeAssertionRequest(using: credential)
        case .registration(let credential):
            context.completeRegistrationRequest(using: credential)
        case .oneTimeCode(let code):
            if #available(iOS 18.0, macOS 15.0, *) {
                context.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code))
            } else {
                context.cancelRequest(withError: ASExtensionError(.failed))
            }
        case .cancel(let code):
            context.cancelRequest(withError: ASExtensionError(code))
        }
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(.passwords(urls: SystemRequests.urls(for: serviceIdentifiers)))
    }

    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        show(.passkeysOrPasswords(urls: SystemRequests.urls(for: serviceIdentifiers), parameters: requestParameters))
    }

    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(.oneTimeCodes(urls: SystemRequests.urls(for: serviceIdentifiers)))
    }

    /// A picked suggestion fills with no screen only while the app stays unlocked (plan 18);
    /// otherwise the extension answers `userInteractionRequired` and the system opens the screen.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        AutoFillModel(task: .credential(credentialRequest)) { [weak self] answer in self?.complete(answer) }
            .fillWithoutUserInteraction()
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        show(.credential(credentialRequest))
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest else {
            return extensionContext.cancelRequest(withError: ASExtensionError(.failed))
        }
        show(.registration(request))
    }
}
