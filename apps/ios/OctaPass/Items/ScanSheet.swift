import OctaPassResources
import OctaPassVault
import SwiftUI

/// Scan a QR code (the list's scan button): one-time codes, every part of a Google Authenticator
/// export, Wi-Fi networks and contacts. Codes go through the import review, where each joins the
/// login the user picks; a Wi-Fi network or a contact becomes an item.
struct ScanSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    @Environment(\.dismiss) private var dismiss
    let onAdded: (String) -> Void
    @State private var review: ImportReview?

    var body: some View {
        NavigationStack {
            Group {
                if let review {
                    ImportReviewView(review: review) { _ in dismiss() }
                } else {
                    CodeCapture { texts, scan in Task { await handle(texts, scan) } }
                        .navigationTitle(L10n.phone.scan)
                }
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } }
            }
        }
    }

    private var vaultId: String {
        directory.personal?.id ?? directory.vaults.first(where: \.canWrite)?.id ?? ""
    }

    private func handle(_ texts: [String], _ scan: QrScan) async {
        do {
            if !scan.codes.isEmpty {
                review = try await model.vault.reviewScannedCodes(links: scan.codes.map(\.uri))
                return
            }
            // No one-time code: a Wi-Fi network or a contact becomes an item.
            for text in texts {
                guard let draft = scannedDraft(text: text, vaultId: vaultId) else { continue }
                let item = try await model.vault.saveItem(draft: draft)
                model.confirm(L10n.phone.scanAdded(title: item.title))
                dismiss()
                onAdded(item.id)
                return
            }
            model.toast = Toast(message: L10n.phone.scanUnknown, tone: .danger)
        } catch {
            model.show(error)
        }
    }
}
