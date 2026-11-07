import OctaPassResources
import SwiftUI
#if os(iOS)
import UIKit
#else
import AppKit
#endif

/// The brand tokens (`packages/ui`, through `OctaPassResources`) as SwiftUI colours that follow
/// light and dark appearance. Fonts are the system's, so Dynamic Type works everywhere; secrets
/// and codes use its monospaced design.
extension Color {
    init(_ token: ThemedColor) {
        #if os(iOS)
        self.init(uiColor: UIColor { traits in
            let value = traits.userInterfaceStyle == .dark ? token.dark : token.light
            return UIColor(red: value.red, green: value.green, blue: value.blue, alpha: value.alpha)
        })
        #else
        self.init(nsColor: NSColor(name: nil) { appearance in
            let dark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            let value = dark ? token.dark : token.light
            return NSColor(srgbRed: value.red, green: value.green, blue: value.blue, alpha: value.alpha)
        })
        #endif
    }

    static let trust = Color(Tokens.Colors.trust)
    static let trustText = Color(Tokens.Colors.trustText)
    static let free = Color(Tokens.Colors.free)
    static let freeText = Color(Tokens.Colors.freeText)
    static let paper = Color(Tokens.Colors.paper)
    static let surface = Color(Tokens.Colors.surface)
    static let tile = Color(Tokens.Colors.tile)
    static let ink = Color(Tokens.Colors.ink)
    static let mist = Color(Tokens.Colors.mist)
    static let line = Color(Tokens.Colors.line)
    static let danger = Color(Tokens.Colors.danger)
    static let dangerText = Color(Tokens.Colors.dangerText)
    static let warn = Color(Tokens.Colors.warn)
    static let warnText = Color(Tokens.Colors.warnText)
    /// Buttons are always the light trust blue with white text (brand/README.md).
    static let button = Color(Tokens.Colors.button)
}

extension LinearGradient {
    /// The brand gradient: the logo, one headline per screen at most, never behind body text.
    static var brand: LinearGradient {
        // CSS 120deg: from the top left towards the bottom right.
        LinearGradient(
            stops: Tokens.Gradient.stops.map { .init(color: Color($0.color), location: $0.location) },
            startPoint: UnitPoint(x: 0.07, y: 0.25),
            endPoint: UnitPoint(x: 0.93, y: 0.75))
    }
}

extension Font {
    /// Passwords, codes, keys: real data.
    static func secret(_ style: Font.TextStyle = .body) -> Font {
        .system(style, design: .monospaced)
    }
}

/// The app's look for every screen: brand tint, the chosen appearance.
struct ThemeModifier: ViewModifier {
    let scheme: ColorScheme?

    func body(content: Content) -> some View {
        content
            .tint(.trust)
            .preferredColorScheme(scheme)
    }
}

#if os(iOS)
extension ListStyle where Self == InsetGroupedListStyle {
    /// Grouped rows on a background, as the iPhone's Settings: `.insetGrouped` there.
    static var platformGrouped: Self { .insetGrouped }
}
#else
extension ListStyle where Self == InsetListStyle {
    /// The Mac's closest list to the iPhone's grouped one.
    static var platformGrouped: Self { .inset }
}
#endif

#if os(iOS)
extension PickerStyle where Self == NavigationLinkPickerStyle {
    /// A long list of choices: its own screen on the iPhone.
    static var platformLong: Self { .navigationLink }
}
#else
extension PickerStyle where Self == MenuPickerStyle {
    /// A long list of choices: a pop-up menu on the Mac.
    static var platformLong: Self { .menu }
}
#endif

extension View {
    /// A toolbar button. On the Mac every toolbar item gets the Mac's toolbar button
    /// (`OctaPassMac/MacControls.swift`); `prominent` makes the confirming one, like Save, the
    /// accent-filled one. The iPhone's toolbar draws its own.
    @ViewBuilder func toolbarButton(prominent: Bool = false) -> some View {
        #if os(macOS)
        if prominent { buttonStyle(.borderedProminent) } else { buttonStyle(.automatic) }
        #else
        self
        #endif
    }
}
