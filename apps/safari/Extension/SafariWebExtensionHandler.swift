import SafariServices

/// Safari routes `runtime.sendNativeMessage` here, to the containing app, rather than to the
/// desktop app's native messaging host. The Safari build doesn't ask for `nativeMessaging`, so
/// nothing should arrive; anything that does gets the desktop host's "unsupported" error shape.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let response = NSExtensionItem()
        response.userInfo = [SFExtensionMessageKey: ["ok": false, "error": ["code": "unsupported"]]]
        context.completeRequest(returningItems: [response])
    }
}
