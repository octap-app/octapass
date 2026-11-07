import AuthenticationServices
#if canImport(UIKit)
import UIKit
#else
import AppKit
#endif

/// Turning Octa Pass on as the AutoFill provider and as the app for setting up verification codes
/// ("Set Up Codes In"): Settings → General → AutoFill & Passwords on the iPhone, System Settings →
/// General → AutoFill & Passwords on the Mac (plan 19).
enum AutoFillSettings {
    /// Whether Octa Pass fills passwords, passkeys and codes now.
    static func isEnabled() async -> Bool {
        await withCheckedContinuation { done in
            ASCredentialIdentityStore.shared.getState { done.resume(returning: $0.isEnabled) }
        }
    }

    /// iOS 18 and macOS 15 ask in place ("Turn on AutoFill from Octa Pass?"); before that it opens
    /// the AutoFill settings. Resolves with whether Octa Pass is on afterwards (iOS 17, macOS 14:
    /// still the old state, Settings checks again when the app comes back).
    @MainActor
    static func turnOn() async -> Bool {
        if #available(iOS 18.0, macOS 15.0, *) {
            return await withCheckedContinuation { done in
                ASSettingsHelper.requestToTurnOnCredentialProviderExtension { done.resume(returning: $0) }
            }
        }
        await open { try await ASSettingsHelper.openCredentialProviderAppSettings() }
        return await isEnabled()
    }

    /// Whether `turnOn` asks in place rather than opening Settings.
    static var canAsk: Bool {
        if #available(iOS 18.0, macOS 15.0, *) { return true }
        return false
    }

    /// The verification-code setting ("Set Up Codes In"), on iOS 18 and macOS 15 and later; the
    /// AutoFill settings before that.
    @MainActor
    static func openCodeSettings() async {
        if #available(iOS 18.0, macOS 15.0, *) {
            await open { try await ASSettingsHelper.openVerificationCodeAppSettings() }
        } else {
            await open { try await ASSettingsHelper.openCredentialProviderAppSettings() }
        }
    }

    /// Falls back to Octa Pass's own page in Settings (on the Mac, AutoFill & Passwords) when the
    /// system can't go deeper.
    @MainActor
    private static func open(_ settings: () async throws -> Void) async {
        do {
            try await settings()
        } catch {
            #if os(iOS)
            if let url = URL(string: UIApplication.openSettingsURLString) {
                await UIApplication.shared.open(url)
            }
            #else
            if let url = URL(string: "x-apple.systempreferences:com.apple.Passwords-Settings.extension") {
                NSWorkspace.shared.open(url)
            }
            #endif
        }
    }
}
