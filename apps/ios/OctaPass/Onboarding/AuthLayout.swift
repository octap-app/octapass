import OctaPassResources
import SwiftUI

/// The frame of the signed-out screens, as the web vault's `AuthLayout`: the logo, a title and
/// subtitle, the form, and a footer line. Scrolls under the keyboard; wide screens get a column.
struct AuthLayout<Content: View, Footer: View>: View {
    let title: String
    var subtitle: String?
    var top: AnyView?
    @ViewBuilder let content: () -> Content
    @ViewBuilder var footer: () -> Footer

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                if let top { top }
                VStack(alignment: .leading, spacing: 10) {
                    Image("Logo")
                        .resizable()
                        .frame(width: 44, height: 44)
                        .accessibilityHidden(true)
                    Text(title)
                        .font(.largeTitle.weight(.bold))
                        .foregroundStyle(Color.ink)
                        .accessibilityAddTraits(.isHeader)
                    if let subtitle {
                        Text(subtitle)
                            .font(.body)
                            .foregroundStyle(Color.mist)
                    }
                }
                content()
                footer()
                    .font(.callout)
                    .frame(maxWidth: .infinity)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 24)
            .frame(maxWidth: 520)
            .frame(maxWidth: .infinity)
        }
        .scrollDismissesKeyboard(.interactively)
        .background(Color.paper.ignoresSafeArea())
    }
}

extension AuthLayout where Footer == EmptyView {
    init(title: String, subtitle: String? = nil, top: AnyView? = nil, @ViewBuilder content: @escaping () -> Content) {
        self.init(title: title, subtitle: subtitle, top: top, content: content, footer: { EmptyView() })
    }
}

/// Octa Pass's own server, or the address of a self-hosted one (plan 05).
struct ServerChoice: Equatable {
    var selfHosted = false
    var url = "https://"

    func serverUrl(hosted: String) -> String {
        selfHosted ? url.trimmingCharacters(in: .whitespaces) : hosted
    }
}

struct ServerPicker: View {
    @Binding var choice: ServerChoice
    var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Picker(L10n.server.legend, selection: $choice.selfHosted) {
                Text(L10n.server.hosted).tag(false)
                Text(L10n.server.selfHosted).tag(true)
            }
            .pickerStyle(.segmented)
            .accessibilityIdentifier("server-choice")
            if choice.selfHosted {
                TextInput(
                    label: L10n.server.urlLabel, text: $choice.url, hint: L10n.server.urlHint, error: error,
                    placeholder: "https://vault.example.com", content: .URL, keyboard: .URL)
                    .accessibilityIdentifier("server-url")
            }
        }
    }
}

/// The step dots above the sign-up screens.
struct SignUpProgress: View {
    let step: Int
    let total: Int

    var body: some View {
        HStack(spacing: 6) {
            ForEach(0..<total, id: \.self) { index in
                Capsule()
                    .fill(index <= step ? Color.trust : Color.line)
                    .frame(height: 4)
            }
        }
        .accessibilityElement()
        .accessibilityLabel(L10n.signUp.stepOf(step: step + 1, total: total))
    }
}
