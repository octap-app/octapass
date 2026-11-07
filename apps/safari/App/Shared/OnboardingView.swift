import SwiftUI

/// The app's only screen: where to turn the extension on, and whether it is on already.
struct OnboardingView: View {
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.layoutDirection) private var direction
    @State private var state = ExtensionState.unknown
    @State private var settingsFailed = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                Image("Logo")
                    .resizable()
                    .frame(width: 64, height: 64)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 12) {
                    Text("Turn on Octa Pass in Safari")
                        .font(.monaSans(30, weight: 740, width: 112))
                        // Arabic letters join, so they take no letter-spacing.
                        .tracking(direction == .rightToLeft ? 0 : -1.2)
                        .foregroundStyle(Color.ink)
                    Text("Octa Pass fills passwords, suggests strong ones and signs in with passkeys on the websites you visit. Safari keeps extensions off until you turn them on.")
                        .font(.monaSans(17))
                        .foregroundStyle(Color.mist)
                }

                if state != .unknown {
                    StatusBadge(on: state == .on)
                }

                Steps(steps: Self.steps)

                if SafariExtension.canOpenSettings {
                    Button(action: openSettings) {
                        Text(Self.settingsButton)
                            .font(.monaSans(17, weight: 600))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .foregroundStyle(.white)
                            .background(Color.trust, in: .rect(cornerRadius: 12))
                    }
                    .buttonStyle(.plain)
                    if settingsFailed {
                        Text("Safari settings didn't open. Open Safari and go to Settings > Extensions.")
                            .font(.monaSans(15))
                            .foregroundStyle(Color.mist)
                    }
                }

                Text("Your vault is encrypted on your device before it syncs. The extension does its work inside Safari; this app only helps you turn it on.")
                    .font(.monaSans(13))
                    .foregroundStyle(Color.mist)
            }
            .frame(maxWidth: 480, alignment: .leading)
            .padding(.horizontal, 24)
            .padding(.vertical, 40)
            .frame(maxWidth: .infinity)
        }
        .background(Color.paper)
        .task(id: scenePhase) {
            if scenePhase == .active { state = await SafariExtension.state() }
        }
    }

    private func openSettings() {
        Task {
            do {
                try await SafariExtension.openSettings()
                settingsFailed = false
            } catch {
                settingsFailed = true
            }
        }
    }

    #if os(macOS)
    private static let settingsButton: LocalizedStringKey = "Open Safari settings"
    private static let steps: [LocalizedStringKey] = [
        "Click Open Safari settings below, or choose Safari > Settings > Extensions.",
        "Tick Octa Pass.",
        "Click Edit Websites and allow Octa Pass on other websites, so it can fill sign-in forms.",
    ]
    #else
    private static let settingsButton: LocalizedStringKey = "Open Safari extension settings"
    private static let steps: [LocalizedStringKey] = [
        "Open Settings, then go to Apps > Safari > Extensions.",
        "Tap Octa Pass and turn on Allow Extension.",
        "Under Permissions, allow Octa Pass on all websites, so it can fill sign-in forms.",
    ]
    #endif
}

private struct StatusBadge: View {
    let on: Bool

    var body: some View {
        Label(on ? LocalizedStringKey("Octa Pass is on in Safari") : LocalizedStringKey("Octa Pass is off in Safari"), systemImage: on ? "checkmark.circle.fill" : "circle")
            .font(.monaSans(15, weight: 600))
            .foregroundStyle(on ? Color.freedomText : Color.mist)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(Color.tile, in: .capsule)
    }
}

private struct Steps: View {
    let steps: [LocalizedStringKey]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    Text("\(index + 1)")
                        .font(.monaSans(15, weight: 700))
                        .foregroundStyle(Color.trustText)
                        .frame(width: 20, alignment: .leading)
                    Text(step)
                        .font(.monaSans(17))
                        .foregroundStyle(Color.ink)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.tile, in: .rect(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(Color.line))
    }
}
