import AppKit
import SwiftUI

// The shared screens hold pictures (site icons, decoded QR images) as `UIImage`. On the Mac that's
// `NSImage`; only what both have in common is used through this name.
typealias UIImage = NSImage

extension Image {
    init(uiImage: NSImage) {
        self.init(nsImage: uiImage)
    }
}

extension NSImage {
    convenience init(cgImage: CGImage) {
        self.init(cgImage: cgImage, size: .zero)
    }

    /// As `UIImage.jpegData`: nil when the picture can't be read.
    func jpegData(compressionQuality: CGFloat) -> Data? {
        guard let tiff = tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff) else { return nil }
        return bitmap.representation(using: .jpeg, properties: [.compressionFactor: compressionQuality])
    }
}
