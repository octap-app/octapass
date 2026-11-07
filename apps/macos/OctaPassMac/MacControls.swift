import SwiftUI

// The Mac's toolbar items and forms for the shared screens. These stand in for SwiftUI's, which
// this module's own declarations shadow, so the shared files read the same on both platforms.
//
// Toolbar items: the window gives text buttons no bezel, as on the iPhone (`MacTextButtonStyle` in
// `SceneRoot`), and a toolbar item inherits that: its icon was squeezed into a thin pill and
// Cancel ran into Save. These give the item the Mac's toolbar button back. A style set on the
// button itself still wins (Save's `toolbarButton(prominent:)`).

struct ToolbarItem<Content: View>: ToolbarContent {
    let placement: ToolbarItemPlacement
    let content: Content

    init(placement: ToolbarItemPlacement = .automatic, @ViewBuilder content: () -> Content) {
        self.placement = placement
        self.content = content()
    }

    var body: some ToolbarContent {
        SwiftUI.ToolbarItem(placement: placement) { content.buttonStyle(.automatic) }
    }
}

struct ToolbarItemGroup<Content: View>: ToolbarContent {
    let placement: ToolbarItemPlacement
    let content: Content

    init(placement: ToolbarItemPlacement = .automatic, @ViewBuilder content: () -> Content) {
        self.placement = placement
        self.content = content()
    }

    var body: some ToolbarContent {
        SwiftUI.ToolbarItemGroup(placement: placement) { content.buttonStyle(.automatic) }
    }
}

/// The shared screens' forms on the Mac: the grouped style (sections, as on the iPhone; the Mac's
/// default sizes itself to its widest row and pushed the editor past the window), and fields with
/// the Mac's bordered box. A grouped form puts the label beside the field, and the window's plain
/// fields (`SceneRoot`, for the onboarding fields that draw their own box) left an empty field
/// invisible there.
/// The shared screens' navigation stacks on the Mac, with a size of their own as a sheet. A list
/// has next to no height of its own, so a sheet with one collapsed to its first lines (the
/// opened-link review showed only part of its notice, and no code). Only a presented stack gets the
/// minimum; the window's columns and the Settings window give theirs their own size.
struct NavigationStack<Root: View>: View {
    /// Shown as a sheet: then it also has a minimum size, since the sheet didn't take the ideal one.
    @Environment(\.isPresented) private var presented
    private let path: Binding<[Route]>?
    private let root: Root

    init(@ViewBuilder root: () -> Root) {
        path = nil
        self.root = root()
    }

    init(path: Binding<[Route]>, @ViewBuilder root: () -> Root) {
        self.path = path
        self.root = root()
    }

    var body: some View {
        Group {
            if let path {
                SwiftUI.NavigationStack(path: path) { root }
            } else {
                SwiftUI.NavigationStack { root }
            }
        }
        .frame(minWidth: presented ? 500 : nil, idealWidth: 560, minHeight: presented ? 440 : nil, idealHeight: 600)
    }
}

struct Form<Content: View>: View {
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        SwiftUI.Form { content }
            .formStyle(.grouped)
            .textFieldStyle(.roundedBorder)
    }
}

/// The shared screens' activity indicators at the Mac's size. The iPhone's default spinner is far
/// larger than a Mac's, next to a button's title or in a row.
struct ProgressView: View {
    private let value: Double?
    private let total: Double

    init() {
        value = nil
        total = 1
    }

    init(value: Double, total: Double = 1) {
        self.value = value
        self.total = total
    }

    var body: some View {
        if let value {
            SwiftUI.ProgressView(value: value, total: total)
        } else {
            SwiftUI.ProgressView().controlSize(.small)
        }
    }
}

/// The window's text buttons: no bezel, as on the iPhone, in the accent colour, red for a
/// destructive one (the Mac's borderless style ignores the role), dimmed while disabled or pressed.
struct MacTextButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        Styled(configuration: configuration)
    }

    private struct Styled: View {
        @Environment(\.isEnabled) private var enabled
        let configuration: ButtonStyleConfiguration

        var body: some View {
            configuration.label
                .foregroundStyle(configuration.role == .destructive ? AnyShapeStyle(Color.dangerText) : AnyShapeStyle(.tint))
                .opacity(!enabled ? 0.4 : configuration.isPressed ? 0.6 : 1)
                .contentShape(Rectangle())
        }
    }
}
