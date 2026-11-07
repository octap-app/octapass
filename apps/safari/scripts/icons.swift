// Renders the app icons in App/Shared/Assets.xcassets from brand/logo-tile.svg, and the same iOS icon
// for the iPhone app (apps/ios) and the Tauri phone app. Rerun after a logo change:
//
//   swift apps/safari/scripts/icons.swift
//
// iOS masks the icon itself, so its PNG is the tile's gradient edge to edge. macOS shows the icon
// as drawn, so the tile sits on Apple's 1024 grid (an 824-point body) with a soft shadow.

import AppKit
import UniformTypeIdentifiers

let safari = URL(filePath: #filePath).absoluteURL.deletingLastPathComponent().deletingLastPathComponent()
let tileURL = safari.appending(path: "../../brand/logo-tile.svg").standardized
let iconSet = safari.appending(path: "App/Shared/Assets.xcassets/AppIcon.appiconset")
let tileSVG = try String(contentsOf: tileURL, encoding: .utf8)

/// The tile with its squircle replaced by a square, for iOS.
let squareSVG = tileSVG.replacingOccurrences(of: #"<path d="M64\.00 32\.00L[^"]*Z""#, with: #"<rect width="64" height="64""#, options: .regularExpression)
precondition(squareSVG != tileSVG, "brand/logo-tile.svg no longer starts with the squircle path")

func image(_ svg: String) -> NSImage {
    NSImage(data: Data(svg.utf8))!
}

/// iOS icons must be opaque; macOS icons have transparent corners.
func render(_ pixels: Int, to name: String, opaque: Bool = false, draw: (CGRect) -> Void) throws {
    let alpha = opaque ? CGImageAlphaInfo.noneSkipLast : .premultipliedLast
    let context = CGContext(data: nil, width: pixels, height: pixels, bitsPerComponent: 8, bytesPerRow: 0, space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: alpha.rawValue)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)
    draw(CGRect(x: 0, y: 0, width: pixels, height: pixels))
    NSGraphicsContext.restoreGraphicsState()
    let png = CGImageDestinationCreateWithURL(iconSet.appending(path: name) as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(png, context.makeImage()!, nil)
    guard CGImageDestinationFinalize(png) else { fatalError("Couldn't write \(name)") }
}

try render(1024, to: "ios-1024.png", opaque: true) { image(squareSVG).draw(in: $0) }

// The iPhone app's set holds only this 1024-pixel icon; Xcode makes the smaller sizes.
for phoneSet in ["../ios/OctaPass/Resources/Assets.xcassets/AppIcon.appiconset"] {
    let target = safari.appending(path: phoneSet).standardized.appending(path: "AppIcon.png")
    try? FileManager.default.removeItem(at: target)
    try FileManager.default.copyItem(at: iconSet.appending(path: "ios-1024.png"), to: target)
}

let tile = image(tileSVG)
for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        try render(points * scale, to: "mac-\(points)@\(scale)x.png") { canvas in
            let unit = canvas.width / 1024
            let shadow = NSShadow()
            shadow.shadowColor = NSColor.black.withAlphaComponent(0.3)
            shadow.shadowOffset = NSSize(width: 0, height: -10 * unit)
            shadow.shadowBlurRadius = 20 * unit
            shadow.set()
            tile.draw(in: CGRect(x: 100 * unit, y: 100 * unit, width: 824 * unit, height: 824 * unit))
        }
    }
}
print("Icons in \(iconSet.path) and apps/ios")
