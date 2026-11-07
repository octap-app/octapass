// The Mac has no live camera scanner; it reads pictures (OctaPassMac/Platform/MacStandIns.swift).
#if os(iOS)
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
import VisionKit

/// The live camera scanner. Pictures go to the core's reader (`readQrCodes`) instead.
enum QrReader {
    /// It needs a camera and a recent chip; the Simulator has neither.
    @MainActor static var cameraAvailable: Bool {
        DataScannerViewController.isSupported && DataScannerViewController.isAvailable
    }
}

/// The camera: each new QR code it reads, until it's closed (exports come in several codes).
struct CameraQrScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced, recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false, isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}

    static func dismantleUIViewController(_ controller: DataScannerViewController, coordinator: Coordinator) {
        controller.stopScanning()
    }

    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onCode: (String) -> Void
        private var seen: Set<String> = []
        init(onCode: @escaping (String) -> Void) { self.onCode = onCode }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
            for case let .barcode(code) in items {
                guard let text = code.payloadStringValue, seen.insert(text).inserted else { continue }
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                onCode(text)
            }
        }
    }
}
#endif
