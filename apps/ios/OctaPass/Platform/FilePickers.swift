import AVFoundation
import PhotosUI
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
import UniformTypeIdentifiers

/// A file a picker copied into the app's own temporary folder (never the App Group). The vault
/// encrypts it into the outbox; the app deletes the copy.
struct PickedFile {
    let url: URL
    let name: String
    let mediaType: String
}

enum PickedFiles {
    /// A new folder for one pick, in the app's temporary directory.
    static func folder() throws -> URL {
        let folder = FileManager.default.temporaryDirectory.appending(path: "picked").appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder
    }

    /// `name`, or `name 2`, `name 3`… so nothing in `folder` is overwritten.
    static func unique(_ name: String, in folder: URL) -> URL {
        let base = (name as NSString).deletingPathExtension
        let ext = (name as NSString).pathExtension
        var candidate = folder.appending(path: name)
        var index = 2
        while FileManager.default.fileExists(atPath: candidate.path) {
            candidate = folder.appending(path: ext.isEmpty ? "\(base) \(index)" : "\(base) \(index).\(ext)")
            index += 1
        }
        return candidate
    }

    static func mediaType(of url: URL) -> String {
        UTType(filenameExtension: url.pathExtension)?.preferredMIMEType ?? ""
    }

    /// A file from the Files picker, copied while its security scope is open. `named` replaces its
    /// file name (a dropped file's own name, when the system's copy has another).
    static func copy(_ url: URL, named: String? = nil) throws -> PickedFile {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        var name = url.lastPathComponent
        if let named, !named.isEmpty {
            name = (named as NSString).pathExtension.isEmpty && !url.pathExtension.isEmpty ? "\(named).\(url.pathExtension)" : named
        }
        let target = unique(name, in: try folder())
        try FileManager.default.copyItem(at: url, to: target)
        return PickedFile(url: target, name: name, mediaType: mediaType(of: url))
    }

    /// A photo or video as the library has it (HEIC, JPEG, MOV…).
    static func copy(_ item: PhotosPickerItem) async -> PickedFile? {
        let type = item.supportedContentTypes.first { $0.conforms(to: .image) || $0.conforms(to: .movie) } ?? .jpeg
        guard let data = try? await item.loadTransferable(type: Data.self), let folder = try? folder() else { return nil }
        let ext = type.preferredFilenameExtension ?? "jpg"
        let name = "\(type.conforms(to: .movie) ? "Video" : "Photo") \(stamp()).\(ext)"
        let target = unique(name, in: folder)
        do {
            // Unreadable while the phone is locked, until the vault reads it.
            try data.write(to: target, options: [.completeFileProtection])
            return PickedFile(url: target, name: name, mediaType: type.preferredMIMEType ?? "")
        } catch {
            return nil
        }
    }

    #if os(iOS)
    static func save(photo: UIImage) -> PickedFile? {
        guard let data = photo.jpegData(compressionQuality: 0.9), let folder = try? folder() else { return nil }
        let name = "Photo \(stamp()).jpg"
        let target = unique(name, in: folder)
        do {
            try data.write(to: target, options: [.completeFileProtection])
            return PickedFile(url: target, name: name, mediaType: "image/jpeg")
        } catch {
            return nil
        }
    }
    #else
    /// Photos to attach come from files on the Mac.
    static func save(photo: UIImage) -> PickedFile? { nil }
    #endif

    static func discard(_ file: PickedFile) {
        try? FileManager.default.removeItem(at: file.url.deletingLastPathComponent())
    }

    private static func stamp() -> String {
        let format = DateFormatter()
        format.locale = Locale(identifier: "en_US_POSIX")
        format.dateFormat = "yyyy-MM-dd 'at' HH.mm.ss"
        return format.string(from: Date())
    }

    #if os(iOS)
    /// The camera only where there is one (not on the Simulator), and while access isn't off.
    static var cameraAvailable: Bool {
        guard UIImagePickerController.isSourceTypeAvailable(.camera) else { return false }
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        return status != .denied && status != .restricted
    }
    #else
    static var cameraAvailable: Bool { false }
    #endif
}

#if os(iOS)
/// The camera, for a photo to attach.
struct CameraPicker: UIViewControllerRepresentable {
    let onPick: (UIImage?) -> Void

    func makeUIViewController(context: Context) -> UIImagePickerController {
        let picker = UIImagePickerController()
        picker.sourceType = .camera
        picker.mediaTypes = [UTType.image.identifier]
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ controller: UIImagePickerController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(onPick: onPick) }

    final class Coordinator: NSObject, UIImagePickerControllerDelegate, UINavigationControllerDelegate {
        let onPick: (UIImage?) -> Void
        init(onPick: @escaping (UIImage?) -> Void) { self.onPick = onPick }

        func imagePickerController(_ picker: UIImagePickerController, didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]) {
            onPick(info[.originalImage] as? UIImage)
        }

        func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
            onPick(nil)
        }
    }
}

#else
/// Never shown on the Mac, since `cameraAvailable` is false.
struct CameraPicker: View {
    let onPick: (UIImage?) -> Void
    var body: some View { EmptyView() }
}
#endif

extension View {
    /// The Files picker. In debug builds, UI tests skip it: with `OCTAPASS_PICK_NAME` and
    /// `OCTAPASS_PICK_TEXT` set at launch, every pick is that file, written to the app's temporary
    /// folder, since a test can't drive the system's picker.
    func filePicker(isPresented: Binding<Bool>, multiple: Bool = false, types: [UTType] = [.item], onPick: @escaping ([URL]) -> Void) -> some View {
        #if DEBUG
        if TestPick.isSet {
            return AnyView(onChange(of: isPresented.wrappedValue) { _, open in
                guard open else { return }
                isPresented.wrappedValue = false
                if let file = TestPick.write() { onPick([file]) }
            })
        }
        #endif
        return AnyView(fileImporter(isPresented: isPresented, allowedContentTypes: types, allowsMultipleSelection: multiple) { result in
            if case let .success(urls) = result { onPick(urls) }
        })
    }
}

#if DEBUG
private enum TestPick {
    static var environment: [String: String] { ProcessInfo.processInfo.environment }
    static var isSet: Bool { environment["OCTAPASS_PICK_NAME"] != nil && environment["OCTAPASS_PICK_TEXT"] != nil }

    static func write() -> URL? {
        guard let name = environment["OCTAPASS_PICK_NAME"], let text = environment["OCTAPASS_PICK_TEXT"],
              let folder = try? PickedFiles.folder()
        else { return nil }
        let url = folder.appending(path: name)
        return (try? Data(text.utf8).write(to: url)) == nil ? nil : url
    }
}
#endif
