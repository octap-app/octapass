import AuthenticationServices
import Foundation
#if canImport(UIKit)
import UIKit
#else
import AppKit
#endif

/// iOS 26 and macOS 26 Credential Exchange, moved from the Tauri app (`CredentialExchange.swift` in
/// its plugin). Another app's export (the Passwords app → Export Data to Another App) launches
/// Octa Pass with an `ASCredentialExchangeActivity` carrying a one-time token; the import manager
/// trades the token for the data, which is the FIDO Credential Exchange Format (CXF) and goes to
/// the vault in Rust (`previewReceived`, the same review as Android's credential transfer).
enum CredentialExchange {
    /// The activity's type. Apple's docs name the constant `ASCredentialExchangeActivityType`.
    static let activityType = "ASCredentialExchangeActivity"

    static var isAvailable: Bool {
        if #available(iOS 26.0, macOS 26.0, *) { return true }
        return false
    }

    /// The import token an activity carries, if it's a Credential Exchange.
    static func token(_ activity: NSUserActivity) -> UUID? {
        guard #available(iOS 26.0, macOS 26.0, *), activity.activityType == ASCredentialExchangeActivity else { return nil }
        return activity.userInfo?[ASCredentialImportToken] as? UUID
    }

    /// What `token` stands for, as CXF JSON, with the name of the app that sent it. Uses the
    /// token up.
    static func take(_ token: UUID) async throws -> (json: String, from: String) {
        guard #available(iOS 26.0, macOS 26.0, *) else { throw Unsupported() }
        let data = try await ASCredentialImportManager().importCredentials(token: token)
        let encoder = JSONEncoder()
        // CXF timestamps are Unix seconds; Foundation's default counts from 2001.
        encoder.dateEncodingStrategy = .secondsSince1970
        return (String(decoding: try encoder.encode(data), as: UTF8.self), data.exporterDisplayName)
    }

    /// Sends `json` (the vault's CXF export) to the app the user picks in the system's sheet.
    @MainActor
    static func send(_ json: Data) async throws {
        #if os(iOS)
        guard #available(iOS 26.0, *),
              let window = UIApplication.shared.connectedScenes.compactMap({ ($0 as? UIWindowScene)?.keyWindow }).first
        else { throw Unsupported() }
        #else
        guard #available(macOS 26.0, *), let window = NSApp.keyWindow ?? NSApp.mainWindow else { throw Unsupported() }
        #endif
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let data = try decoder.decode(ASExportedCredentialData.self, from: json)
        let manager = ASCredentialExportManager(presentationAnchor: window)
        _ = try await manager.requestExport(for: nil)
        try await manager.exportCredentials(data)
    }

    struct Unsupported: Error {}
}

/// Something another app handed over, waiting for the unlocked vault.
enum ReceivedCredentials: Equatable {
    /// A Credential Exchange import token.
    case token(UUID)
    /// CXF JSON as it came (UI tests hand one over at launch: `OCTAPASS_RECEIVE_CXF`).
    case json(String, from: String)

    func take() async throws -> (json: String, from: String) {
        switch self {
        case let .token(token): try await CredentialExchange.take(token)
        case let .json(json, from): (json, from)
        }
    }
}
