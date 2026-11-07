import Testing
@testable import OctaPassResources
#if canImport(AppKit) && !targetEnvironment(macCatalyst)
import AppKit
#endif

struct TokensTests {
    @Test func colours() {
        #expect(Tokens.Colors.trust == ThemedColor(light: RGBA(0x2456F0), dark: RGBA(0x5C86FF)))
        // Buttons keep the light trust blue in both appearances.
        #expect(Tokens.Colors.button.light == Tokens.Colors.button.dark)
        // color-mix(in srgb, var(--trust) 11%, transparent)
        #expect(Tokens.Colors.selected.light == RGBA(0x2456F0, alpha: 0.11))
        #expect(Tokens.Colors.selected.dark == RGBA(0x5C86FF, alpha: 0.2))
        #expect(Tokens.Colors.hover.light == RGBA(0x0B1220, alpha: 0.045))
        #expect(Tokens.Colors.all["line-strong"] == Tokens.Colors.lineStrong)
        #expect(Tokens.Gradient.stops.map(\.location) == [0, 0.5, 1])
    }

    @Test func sizesAndMotion() {
        #expect(Tokens.TypeScale.md == 15)
        #expect(Tokens.TypeScale.xl2 == 25.6) // clamp(1.6rem, …): the minimum
        #expect(Tokens.Radius.base == 12)
        #expect(Tokens.Motion.fast == 0.14)
        #expect(Tokens.Motion.easeOut == CubicBezier(x1: 0.2, y1: 0.7, x2: 0.2, y2: 1))
        #expect(Tokens.Fonts.sans == "Mona Sans")
        #expect(Tokens.Fonts.mono == "Monaspace Neon")
    }

    #if canImport(AppKit) && !targetEnvironment(macCatalyst)
    @Test func followsTheAppearance() throws {
        func red(in appearance: NSAppearance.Name) throws -> Int {
            var value = -1
            try #require(NSAppearance(named: appearance)).performAsCurrentDrawingAppearance {
                value = Int(((Tokens.Colors.trust.nsColor.usingColorSpace(.sRGB)?.redComponent ?? -1) * 255).rounded())
            }
            return value
        }
        #expect(try red(in: .aqua) == 0x24)
        #expect(try red(in: .darkAqua) == 0x5C)
    }
    #endif
}
