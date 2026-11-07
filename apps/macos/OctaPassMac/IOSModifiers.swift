import SwiftUI

// The iPhone screens' iOS-only modifiers, as no-ops on the Mac, so the shared files read the same on
// both. Only modifiers with nothing to do on a Mac belong here: a navigation bar's title size, the
// software keyboard's layout and capitalization. Anything the Mac does differently goes behind
// `#if os(macOS)` where it's used. These declarations shadow SwiftUI's unavailable ones, since this
// module imports SwiftUI.

enum NavigationBarItem {
    enum TitleDisplayMode { case automatic, inline, large }
}

extension View {
    func navigationBarTitleDisplayMode(_ mode: NavigationBarItem.TitleDisplayMode) -> some View { self }
    func keyboardType(_ type: UIKeyboardType) -> some View { self }
    func textInputAutocapitalization(_ autocapitalization: TextInputAutocapitalization?) -> some View { self }
}

/// The software keyboard's layouts the iPhone screens ask for.
enum UIKeyboardType {
    case `default`, asciiCapable, numbersAndPunctuation, URL, numberPad, phonePad, namePhonePad,
         emailAddress, decimalPad, twitter, webSearch, asciiCapableNumberPad
}

struct TextInputAutocapitalization {
    static let never = Self()
    static let words = Self()
    static let sentences = Self()
    static let characters = Self()
}

extension View {
    /// Only the camera uses a full-screen cover, and the Mac never shows it (`cameraAvailable` is
    /// false); a sheet keeps the shared code the same.
    func fullScreenCover<Content: View>(
        isPresented: Binding<Bool>, onDismiss: (() -> Void)? = nil, @ViewBuilder content: @escaping () -> Content
    ) -> some View {
        sheet(isPresented: isPresented, onDismiss: onDismiss, content: content)
    }
}

/// The same content types exist on macOS 14 under AppKit's name, so the fields keep their hints.
typealias UITextContentType = NSTextContentType
