import SafariServices

enum ExtensionState {
    case unknown, off, on
}

/// The Safari Web Extension this app carries. macOS can always report its state and open its
/// settings; iOS can from 26.2, and before that the app can only explain where the switch is.
enum SafariExtension {
    static let identifier = "app.octap.safari.extension"

    static func state() async -> ExtensionState {
        #if os(macOS)
        guard let state = try? await SFSafariExtensionManager.stateOfSafariExtension(withIdentifier: identifier) else { return .unknown }
        return state.isEnabled ? .on : .off
        #else
        guard #available(iOS 26.2, *),
              let state = try? await SFSafariExtensionManager.stateOfExtension(withIdentifier: identifier) else { return .unknown }
        return state.isEnabled ? .on : .off
        #endif
    }

    static var canOpenSettings: Bool {
        #if os(macOS)
        true
        #else
        if #available(iOS 26.2, *) { true } else { false }
        #endif
    }

    static func openSettings() async throws {
        #if os(macOS)
        try await SFSafariApplication.showPreferencesForExtension(withIdentifier: identifier)
        #else
        if #available(iOS 26.2, *) {
            try await SFSafariSettings.openExtensionsSettings(forIdentifiers: [identifier])
        }
        #endif
    }
}
