import OctaPassResources
import OctaPassVault
import SwiftUI

/// One-time code links that opened the app: Settings → AutoFill & Passwords → Set Up Codes In, a
/// website's `otpauth://` link, the Camera's QR button, or a Google Authenticator export
/// (`otpauth-migration://`). Kept until the vault is unlocked, then asked about, since any website
/// can open such a link.
enum OpenedLinks {
    static let schemes: Set<String> = ["otpauth", "otpauth-migration"]

    static func accepts(_ url: URL) -> Bool {
        schemes.contains(url.scheme?.lowercased() ?? "")
    }
}

struct OpenedLinksSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let links: [String]
    @State private var review: ImportReview?
    @State private var failed = false

    var body: some View {
        NavigationStack {
            Group {
                if let review {
                    VStack(spacing: 0) {
                        Notice(text: L10n.phone.linkCodeBody, tone: .warn).padding()
                        ImportReviewView(review: review) { _ in dismiss() }
                    }
                } else if failed {
                    EmptyStateView(icon: "questionmark.circle", title: L10n.phone.linkUnknown)
                } else {
                    ProgressView()
                }
            }
            .navigationTitle(L10n.phone.linkTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } } }
        }
        // Each code joins the login the user picks, as with a scanned code: any website can open
        // such a link, so nothing is saved without the review.
        .task {
            let scan = summarizeQrScans(texts: links)
            guard !scan.codes.isEmpty else { return failed = true }
            do { review = try await model.vault.reviewScannedCodes(links: scan.codes.map(\.uri)) } catch { failed = true }
        }
    }
}
