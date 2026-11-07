import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// The Mac's `Modal` (the iPhone's is in `Components/IdentityGate.swift`): SwiftUI shown as a sheet
/// on the vault window, above whatever sheet is already up, for the identity gate that menus, rows
/// and other sheets ask for.
@MainActor
enum Modal {
    private static var top: NSViewController? {
        let window = NSApp.keyWindow ?? NSApp.mainWindow ?? NSApp.windows.first { $0.isVisible }
        var controller = window?.contentViewController
        while let next = controller?.presentedViewControllers?.last { controller = next }
        return controller
    }

    /// `content` gets a function that closes it. Sheets on the Mac can't be swiped away, so it
    /// always gets to answer whoever is waiting.
    static func present(model: AppModel, @ViewBuilder content: (@escaping () -> Void) -> some View) {
        var host: NSViewController?
        let close = {
            if let host { host.presentingViewController?.dismiss(host) }
            host = nil
        }
        let root = content(close)
            .environment(model)
            .tint(.button)
            .environment(\.layoutDirection, model.layoutDirection)
            .environment(\.locale, model.locale)
            .frame(minWidth: 420, minHeight: 280)
        let controller = NSHostingController(rootView: root)
        host = controller
        top?.presentAsSheet(controller)
    }

    /// A file written for sharing: on the Mac it's saved where the user picks. Deleted by the
    /// caller once `finished` runs.
    static func share(_ url: URL, finished: @escaping () -> Void) {
        Task {
            _ = await MacFiles.save(url)
            finished()
        }
    }
}

/// Files the vault wrote for the user (exports, backups, keys), saved with the save panel.
@MainActor
enum MacFiles {
    /// Copies `url` to where the user picks. True when it was saved.
    static func save(_ url: URL) async -> Bool {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = url.lastPathComponent
        panel.canCreateDirectories = true
        if let type = UTType(filenameExtension: url.pathExtension) { panel.allowedContentTypes = [type] }
        let answer: NSApplication.ModalResponse
        if let window = NSApp.keyWindow ?? NSApp.mainWindow {
            answer = await panel.beginSheetModal(for: window)
        } else {
            answer = panel.runModal()
        }
        guard answer == .OK, let target = panel.url else { return false }
        do {
            let files = FileManager.default
            if files.fileExists(atPath: target.path) { try files.removeItem(at: target) }
            try files.copyItem(at: url, to: target)
            return true
        } catch {
            return false
        }
    }
}
