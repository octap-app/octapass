import OctaPassResources
import OctaPassVault
import PhotosUI
import QuickLook
import SwiftUI

/// An item's files (the web vault's `ItemFiles` on phones): each one opens in Quick Look, and can
/// be removed; new ones come from Files, Photos or the camera. Each file is encrypted on the phone
/// before it uploads; offline, it waits in the outbox.
struct FilesSection: View {
    @Environment(AppModel.self) private var model
    let item: Item
    let editable: Bool
    @State private var importing = false
    @State private var photos: [PhotosPickerItem] = []
    @State private var choosingPhotos = false
    @State private var camera = false
    @State private var busy = false
    @State private var preview: URL?
    @State private var opened: String?
    @State private var removing: Attachment?

    private var isDocument: Bool {
        if case .document = item.details { return true }
        return false
    }

    var body: some View {
        Section {
            if item.attachments.isEmpty {
                Text(isDocument ? L10n.files.documentHint : L10n.files.empty)
                    .font(.footnote).foregroundStyle(Color.mist)
            }
            ForEach(item.attachments, id: \.id) { attachment in
                Button { open(attachment) } label: { FileRow(attachment: attachment) }
                    .buttonStyle(.plain)
                    .accessibilityLabel(L10n.files.open(name: attachment.name))
                    .swipeActions {
                        if editable {
                            Button(role: .destructive) { removing = attachment } label: {
                                Label(L10n.common.remove, systemImage: "trash")
                            }
                        }
                    }
                    .contextMenu {
                        if editable {
                            Button(role: .destructive) { removing = attachment } label: {
                                Label(L10n.files.remove(name: attachment.name), systemImage: "trash")
                            }
                        }
                    }
            }
            if editable {
                Menu {
                    Button { importing = true } label: { Label(L10n.files.fromFiles, systemImage: "folder") }
                    Button { choosingPhotos = true } label: { Label(L10n.files.fromPhotos, systemImage: "photo.on.rectangle") }
                    if PickedFiles.cameraAvailable {
                        Button { camera = true } label: { Label(L10n.files.fromCamera, systemImage: "camera") }
                    }
                } label: {
                    HStack {
                        Label(item.attachments.isEmpty && isDocument ? L10n.files.attachOne : L10n.files.attach, systemImage: "paperclip")
                        if busy { Spacer(); ProgressView() }
                    }
                }
                .disabled(busy)
                .accessibilityIdentifier("attach-file")
            }
        } header: {
            Text(isDocument ? L10n.files.documentTitle : L10n.files.title)
        } footer: {
            if editable { Text(L10n.files.phoneHint) }
        }
        .filePicker(isPresented: $importing, multiple: true) { urls in
            attach(urls.compactMap { try? PickedFiles.copy($0) })
        }
        .photosPicker(isPresented: $choosingPhotos, selection: $photos, matching: .any(of: [.images, .videos]))
        .onChange(of: photos) { _, picked in
            guard !picked.isEmpty else { return }
            photos = []
            Task {
                var files: [PickedFile] = []
                for item in picked {
                    if let file = await PickedFiles.copy(item) { files.append(file) }
                }
                attach(files)
            }
        }
        .fullScreenCover(isPresented: $camera) {
            CameraPicker { image in
                camera = false
                if let image, let file = PickedFiles.save(photo: image) { attach([file]) }
            }
            .ignoresSafeArea()
        }
        .quickLookPreview($preview)
        .onChange(of: preview) { _, url in
            // Quick Look closed: the decrypted copy goes.
            if url == nil, let opened {
                model.vault.closeAttachment(path: opened)
                self.opened = nil
            }
        }
        .confirmationDialog(
            removing.map { L10n.files.removeTitle(name: $0.name) } ?? "",
            isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }),
            titleVisibility: .visible
        ) {
            Button(L10n.files.removeConfirm, role: .destructive) {
                if let removing { remove(removing) }
            }
        } message: {
            Text(L10n.files.removeBody)
        }
    }

    private func attach(_ files: [PickedFile]) {
        guard !files.isEmpty else { return }
        busy = true
        Task {
            defer { busy = false }
            for file in files {
                do {
                    _ = try await model.vault.addAttachment(itemId: item.id, path: file.url.path, name: file.name, mediaType: file.mediaType)
                    model.confirm(L10n.files.attached(name: file.name))
                } catch {
                    model.toast = Toast(message: L10n.files.attachFailed(name: file.name, reason: error.message), tone: .danger)
                    Haptics.error()
                }
                PickedFiles.discard(file)
            }
        }
    }

    private func open(_ attachment: Attachment) {
        busy = true
        Task {
            defer { busy = false }
            do {
                let path = try await model.vault.openAttachment(itemId: item.id, attachmentId: attachment.id)
                opened = path
                preview = URL(fileURLWithPath: path)
            } catch {
                model.show(error)
            }
        }
    }

    private func remove(_ attachment: Attachment) {
        Task {
            do {
                _ = try await model.vault.removeAttachment(itemId: item.id, attachmentId: attachment.id)
                model.confirm(L10n.files.removed(name: attachment.name))
            } catch {
                model.show(error)
            }
        }
    }
}

struct FileRow: View {
    let attachment: Attachment

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(Color.trust)
                .frame(width: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text(attachment.name).foregroundStyle(Color.ink).lineLimit(2)
                Text(attachment.pending ? L10n.files.waiting : details)
                    .font(.footnote)
                    .foregroundStyle(attachment.pending ? Color.warnText : Color.mist)
            }
            Spacer()
        }
        .contentShape(Rectangle())
    }

    private var details: String {
        let size = ByteCountFormatter.string(fromByteCount: Int64(attachment.size), countStyle: .file)
        let type = UTType(mimeType: attachment.mediaType)?.localizedDescription ?? attachment.mediaType
        return type.isEmpty ? size : L10n.files.sizeAndType(size: size, type: type)
    }

    private var icon: String {
        let type = UTType(mimeType: attachment.mediaType)
        if type?.conforms(to: .image) == true { return "photo" }
        if type?.conforms(to: .pdf) == true { return "doc.richtext" }
        if type?.conforms(to: .movie) == true { return "film" }
        return "doc"
    }
}
