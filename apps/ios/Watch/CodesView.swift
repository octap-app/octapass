import OctaPassResources
import OctaPassWatchCodes
import SwiftUI

/// The codes, each with its countdown ring, or what to do when there are none. Redraws every
/// second; the watch is always dark, so colours take the tokens' dark values.
struct CodesView: View {
    let model: WatchModel

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let now = UInt64(context.date.timeIntervalSince1970 * 1000)
            let rows = model.codes.rows(atMs: now)
            Group {
                if !model.hasPasscode {
                    Message(title: L10n.phone.native.watchNoLock, help: L10n.phone.native.watchNoLockHelp)
                } else if rows.isEmpty {
                    if model.codes.isEmptyVault(atMs: now) {
                        Message(title: L10n.phone.native.watchNoCodes, help: nil)
                    } else {
                        Message(title: L10n.phone.native.watchEmptyIos, help: L10n.phone.native.watchEmptyHelp) {
                            model.appeared()
                        }
                    }
                } else {
                    List(rows, id: \.entry.id) { row in
                        CodeRow(title: row.entry.title, code: row.code)
                    }
                }
            }
            .onChange(of: rows.isEmpty) { model.forgetExpired() }
        }
        .onAppear { model.appeared() }
    }
}

private struct CodeRow: View {
    @Environment(\.isLuminanceReduced) private var wristDown
    let title: String
    let code: WatchCode

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title.isEmpty ? L10n.otp.untitled : title)
                    .font(.footnote)
                    .foregroundStyle(WatchColors.mist)
                    .lineLimit(1)
                // A code reads left to right in every language, and isn't left on the always-on
                // display with the wrist down.
                Text(wristDown ? "••• •••" : code.display)
                    .font(.system(.title3, design: .monospaced).weight(.semibold))
                    .foregroundStyle(WatchColors.ink)
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
                    .environment(\.layoutDirection, .leftToRight)
            }
            Spacer(minLength: 0)
            CountdownRing(code: code)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(L10n.phone.native.watchCodeLabel(title: title.isEmpty ? L10n.otp.untitled : title, code: code.text.map(String.init).joined(separator: " ")))
        .accessibilityValue(L10n.phone.native.watchCodeExpiresIn(count: code.remainingSeconds))
    }
}

private struct CountdownRing: View {
    let code: WatchCode

    private var color: Color {
        code.remainingSeconds <= 5 ? WatchColors.warn : WatchColors.free
    }

    var body: some View {
        ZStack {
            Circle().stroke(WatchColors.line, lineWidth: 3)
            Circle()
                .trim(from: 0, to: code.fraction)
                .stroke(color, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text(verbatim: "\(code.remainingSeconds)")
                .font(.system(size: 11, weight: .medium, design: .rounded))
                .foregroundStyle(WatchColors.mist)
        }
        .frame(width: 28, height: 28)
    }
}

private struct Message: View {
    let title: String
    let help: String?
    var refresh: (() -> Void)?

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {
                Text(title)
                    .font(.headline)
                    .foregroundStyle(WatchColors.ink)
                if let help {
                    Text(help)
                        .font(.footnote)
                        .foregroundStyle(WatchColors.mist)
                }
                if let refresh {
                    Button(L10n.phone.native.watchRefresh, action: refresh)
                        .tint(WatchColors.button)
                }
            }
            .multilineTextAlignment(.center)
        }
    }
}

/// The brand tokens' dark values.
private enum WatchColors {
    static let ink = color(Tokens.Colors.ink)
    static let mist = color(Tokens.Colors.mist)
    static let line = color(Tokens.Colors.line)
    static let free = color(Tokens.Colors.free)
    static let warn = color(Tokens.Colors.warn)
    /// Buttons are always the light trust blue (brand/README.md).
    static let button = Color(red: Tokens.Colors.button.light.red, green: Tokens.Colors.button.light.green, blue: Tokens.Colors.button.light.blue)

    private static func color(_ token: ThemedColor) -> Color {
        Color(red: token.dark.red, green: token.dark.green, blue: token.dark.blue, opacity: token.dark.alpha)
    }
}
