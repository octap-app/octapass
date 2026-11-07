import OctaPassResources
import SwiftUI
#if os(macOS)
import AppKit
#endif

/// A labelled text field with an optional hint and error under it, as the web vault's
/// `TextField`. The label is what VoiceOver reads; the error is read after it.
struct LabeledField<Field: View>: View {
    let label: String
    var hint: String?
    var error: String?
    @ViewBuilder let field: () -> Field

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label)
                .font(.subheadline.weight(.medium))
                .foregroundStyle(Color.ink)
                .accessibilityHidden(true)
            // The field fills the box, so a tap anywhere in it lands on the field. It draws no box
            // of its own (the Mac's fields have one by default).
            field()
                .textFieldStyle(.plain)
                .padding(.horizontal, 12)
                .frame(minHeight: 46)
                .background(Color(Tokens.Colors.field), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .strokeBorder(error == nil ? Color(Tokens.Colors.lineStrong) : Color.danger, lineWidth: 1))
            if let error {
                // Read after the field, so VoiceOver users hear what to fix.
                Label(error, systemImage: "exclamationmark.circle.fill")
                    .font(.footnote)
                    .foregroundStyle(Color.dangerText)
            } else if let hint {
                Text(hint).font(.footnote).foregroundStyle(Color.mist)
            }
        }
        // The field stays an element of its own, with its own frame.
        .accessibilityElement(children: .contain)
    }
}

/// A one-line text field in a `LabeledField`.
struct TextInput: View {
    let label: String
    @Binding var text: String
    var hint: String?
    var error: String?
    var placeholder: String?
    var content: UITextContentType?
    var keyboard: UIKeyboardType = .default
    var mono = false
    var capitalization: TextInputAutocapitalization = .never

    var body: some View {
        LabeledField(label: label, hint: hint, error: error) {
            TextField(placeholder ?? "", text: $text)
                .textContentType(content)
                .keyboardType(keyboard)
                .textInputAutocapitalization(capitalization)
                .autocorrectionDisabled()
                .font(mono ? .secret() : .body)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
                .accessibilityLabel(label)
                .accessibilityHint(hint ?? "")
        }
    }
}

/// A password with a Show/Hide button, as the web vault's `PasswordInput`. Secrets are never
/// corrected, capitalised or remembered by the keyboard.
struct PasswordInput: View {
    let label: String
    @Binding var text: String
    var hint: String?
    var error: String?
    var content: UITextContentType? = .password
    var onSubmit: () -> Void = {}
    @State private var shown = false
    @FocusState private var focused: Bool

    var body: some View {
        LabeledField(label: label, hint: hint, error: error) {
            HStack(spacing: 8) {
                Group {
                    if shown {
                        TextField("", text: $text).font(.secret())
                    } else {
                        SecureField("", text: $text)
                    }
                }
                .textContentType(content)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .focused($focused)
                .onSubmit(onSubmit)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
                .accessibilityLabel(label)
                .accessibilityHint(hint ?? "")
                Button {
                    shown.toggle()
                    focused = true
                } label: {
                    Image(systemName: shown ? "eye.slash" : "eye")
                        .foregroundStyle(Color.mist)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(shown ? L10n.common.hide : L10n.common.show)
            }
        }
    }
}

/// The main action of a screen: full width, brand blue, a spinner while it runs.
struct PrimaryButton: View {
    let title: String
    var systemImage: String?
    var busy = false
    var disabled = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if busy {
                    ProgressView().tint(.white)
                } else if let systemImage {
                    Image(systemName: systemImage)
                }
                Text(title).fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity, minHeight: 50)
        }
        .buttonStyle(.borderedProminent)
        .tint(.button)
        .disabled(busy || disabled)
        .accessibilityAddTraits(busy ? .updatesFrequently : [])
    }
}

struct SecondaryButton: View {
    let title: String
    var systemImage: String?
    var disabled = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label {
                Text(title).fontWeight(.medium)
            } icon: {
                if let systemImage { Image(systemName: systemImage) }
            }
            .frame(maxWidth: .infinity, minHeight: 50)
        }
        .buttonStyle(.bordered)
        .disabled(disabled)
    }
}

/// A notice above a form: an error, or information.
struct Notice: View {
    enum Tone { case danger, info, warn, success }
    let text: String
    var tone: Tone = .danger

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: icon).foregroundStyle(color)
            Text(text).font(.callout).foregroundStyle(Color.ink)
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(color.opacity(0.1), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .accessibilityElement(children: .combine)
    }

    private var icon: String {
        switch tone {
        case .danger: "exclamationmark.triangle.fill"
        case .info: "info.circle.fill"
        case .warn: "exclamationmark.circle.fill"
        case .success: "checkmark.circle.fill"
        }
    }

    private var color: Color {
        switch tone {
        case .danger: .danger
        case .info: .trust
        case .warn: .warn
        case .success: .free
        }
    }
}

/// The toast at the bottom of every screen.
struct ToastOverlay: ViewModifier {
    @Binding var toast: Toast?

    func body(content: Content) -> some View {
        content.overlay(alignment: .bottom) {
            if let toast {
                Text(toast.message)
                    .font(.callout.weight(.medium))
                    .foregroundStyle(toast.tone == .danger ? Color.white : Color.ink)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                    .background {
                        if toast.tone == .danger {
                            Capsule().fill(Color.danger)
                        } else {
                            Capsule().fill(.thickMaterial).overlay(Capsule().strokeBorder(Color.line))
                        }
                    }
                    .shadow(color: .black.opacity(0.12), radius: 12, y: 4)
                    // Clear of the tab bar.
                    .padding(.bottom, 96)
                    .padding(.horizontal, 16)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .accessibilityAddTraits(.isStaticText)
                    .onTapGesture { self.toast = nil }
                    .task(id: toast.id) {
                        #if os(iOS)
                        UIAccessibility.post(notification: .announcement, argument: toast.message)
                        #else
                        NSAccessibility.post(
                            element: NSApp.mainWindow as Any, notification: .announcementRequested,
                            userInfo: [.announcement: toast.message, .priority: NSAccessibilityPriorityLevel.high.rawValue])
                        #endif
                        try? await Task.sleep(for: .seconds(2.5))
                        if self.toast?.id == toast.id { self.toast = nil }
                    }
            }
        }
        .animation(.snappy, value: toast)
    }
}
