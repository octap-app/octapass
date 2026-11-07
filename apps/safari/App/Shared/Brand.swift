import CoreText
import SwiftUI

// The brand colours and type from brand/README.md.

extension Color {
    static let trust = Color(red: 0x24 / 255, green: 0x56 / 255, blue: 0xF0 / 255)
    static let trustText = adaptive(light: 0x1D47D6, dark: 0x86A6FF)
    static let freedomText = adaptive(light: 0x077A54, dark: 0x4FE0A8)
    static let ink = adaptive(light: 0x0B1220, dark: 0xF5F6F8)
    static let mist = adaptive(light: 0x5E6576, dark: 0x9BA3B4)
    static let paper = adaptive(light: 0xFBFBFD, dark: 0x000000)
    static let tile = adaptive(light: 0xF2F3F7, dark: 0x12151E)
    static let line = adaptive(light: 0xE3E5EC, dark: 0x232838)

    private static func adaptive(light: UInt32, dark: UInt32) -> Color {
        #if os(macOS)
        Color(nsColor: NSColor(name: nil) { appearance in
            NSColor(rgb: appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light)
        })
        #else
        Color(uiColor: UIColor { traits in UIColor(rgb: traits.userInterfaceStyle == .dark ? dark : light) })
        #endif
    }
}

#if os(macOS)
private extension NSColor {
    convenience init(rgb: UInt32) {
        self.init(srgbRed: CGFloat(rgb >> 16 & 0xFF) / 255, green: CGFloat(rgb >> 8 & 0xFF) / 255, blue: CGFloat(rgb & 0xFF) / 255, alpha: 1)
    }
}
#else
private extension UIColor {
    convenience init(rgb: UInt32) {
        self.init(red: CGFloat(rgb >> 16 & 0xFF) / 255, green: CGFloat(rgb >> 8 & 0xFF) / 255, blue: CGFloat(rgb & 0xFF) / 255, alpha: 1)
    }
}
#endif

extension Font {
    /// Mona Sans at a weight and width (100 is normal; headlines use 112). Falls back to the system
    /// font if the bundled file is missing.
    static func monaSans(_ size: CGFloat, weight: CGFloat = 400, width: CGFloat = 100) -> Font {
        guard let base = monaSansDescriptor else { return .system(size: size) }
        let variation = [wdth: width, wght: weight] as CFDictionary
        let descriptor = CTFontDescriptorCreateCopyWithAttributes(base, [kCTFontVariationAttribute: variation] as CFDictionary)
        return Font(CTFontCreateWithFontDescriptor(descriptor, size, nil))
    }
}

private let wdth = 0x7764_7468
private let wght = 0x7767_6874

/// The variable font from @fontsource-variable/mona-sans, copied in by scripts/build.sh.
private let monaSansDescriptor: CTFontDescriptor? = {
    guard let url = Bundle.main.url(forResource: "MonaSans", withExtension: "woff2") else { return nil }
    return (CTFontManagerCreateFontDescriptorsFromURL(url as CFURL) as? [CTFontDescriptor])?.first
}()
