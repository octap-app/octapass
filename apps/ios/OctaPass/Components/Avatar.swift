import OctaPassVault
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// An item's tile: its initial on a colour of its own (the web vault's `Avatar`), or the
/// website's icon once it loads through the user's server, when Show website icons is on.
struct Avatar: View {
    @Environment(AppModel.self) private var model
    let name: String
    var iconDomain: String?
    var size: CGFloat = 38
    @State private var icon: UIImage?

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.29, style: .continuous)
                .fill(LinearGradient(
                    colors: [Self.color(name, saturation: 0.72, lightness: 0.56), Self.color(name, hueShift: 30, saturation: 0.68, lightness: 0.42)],
                    startPoint: .topLeading, endPoint: .bottomTrailing))
            Text(Self.letter(name))
                .font(.system(size: size * 0.42, weight: .bold))
                .foregroundStyle(.white)
            if let icon {
                RoundedRectangle(cornerRadius: size * 0.29, style: .continuous)
                    .fill(Color.white)
                Image(uiImage: icon)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFit()
                    .padding(size * 0.14)
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: size * 0.29, style: .continuous))
        .accessibilityHidden(true)
        .task(id: TaskKey(domain: iconDomain, on: model.settings.showSiteIcons)) { await loadIcon() }
    }

    private struct TaskKey: Equatable {
        let domain: String?
        let on: Bool
    }

    private func loadIcon() async {
        guard model.settings.showSiteIcons, let iconDomain else {
            icon = nil
            return
        }
        icon = await SiteIconCache.shared.icon(for: iconDomain, vault: model.vault)
    }

    static func letter(_ name: String) -> String {
        name.trimmingCharacters(in: .whitespaces).first.map { String($0).uppercased() } ?? "?"
    }

    /// A stable hue per name, as the web vault's `hueFor`.
    static func hue(_ name: String) -> Int {
        var hash: UInt32 = 0
        for scalar in name.lowercased().unicodeScalars {
            hash = hash &* 31 &+ scalar.value
        }
        return Int(hash % 360)
    }

    static func color(_ name: String, hueShift: Int = 0, saturation: Double, lightness: Double) -> Color {
        let hue = Double((hue(name) + hueShift) % 360) / 360
        // HSL to HSB.
        let brightness = lightness + saturation * min(lightness, 1 - lightness)
        let hsbSaturation = brightness == 0 ? 0 : 2 * (1 - lightness / brightness)
        return Color(hue: hue, saturation: hsbSaturation, brightness: brightness)
    }
}

/// Icons already shown this run, so scrolling back doesn't ask the vault again. The vault keeps
/// them on the phone (hashed names) between runs; this is memory only, dropped on lock.
@MainActor
final class SiteIconCache {
    static let shared = SiteIconCache()
    private var images: [String: UIImage] = [:]
    private var missing: Set<String> = []

    func icon(for domain: String, vault: OctaPassVault) async -> UIImage? {
        if let image = images[domain] { return image }
        if missing.contains(domain) { return nil }
        guard let data = try? await vault.siteIcon(domain: domain), let image = UIImage(data: Data(data)) else {
            missing.insert(domain)
            return nil
        }
        images[domain] = image
        return image
    }

    func clear() {
        images.removeAll()
        missing.removeAll()
    }
}
