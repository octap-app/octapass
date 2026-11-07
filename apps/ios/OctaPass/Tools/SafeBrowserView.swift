import OctaPassResources
import OctaPassVault
import QuickLook
import SwiftUI
import UniformTypeIdentifiers
#if os(macOS)
import AppKit
#endif

/// A folder of a Safe in the app (the web vault's Safe browser): its folders, then its files, by
/// name, with their sizes and dates. Folders open, files open in Quick Look; add files (from the
/// picker, or dropped from Finder, Files or another Safe), make a folder, rename, delete, and save
/// a decrypted copy. On the Mac also Copy and Paste with Finder, and the Delete key. Every step is
/// one `SafeFiles` operation under the Safe's store lock, so Files and Finder are never held up.
struct SafeBrowserView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.detailEditor) private var detailEditor
    let folder: SafeFolder
    @State private var entries: [SafeEntry]?
    @State private var selection: Set<String> = []
    @State private var version = 0
    @State private var busy = false
    @State private var adding = false
    @State private var naming = false
    @State private var newName = ""
    @State private var renaming: SafeEntry?
    @State private var deleting: [SafeEntry] = []
    @State private var preview: URL?
    @State private var previewed: [URL] = []
    @State private var dropTarget = false
    /// A subfolder opened on the iPhone and iPad (the Mac pushes onto its detail column).
    @State private var opened: SafeFolder?

    var body: some View {
        content
            // The whole column, so the path bar is at its top even over the empty state.
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .navigationTitle(folder.name)
            // The Mac's detail column: the path bar goes up, rather than a back button.
            .navigationBarBackButtonHidden(detailEditor != nil)
            .safeAreaInset(edge: .top, spacing: 0) {
                if detailEditor != nil { pathBar }
            }
            .task(id: version &+ model.itemsVersion) { await load() }
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    if busy { ProgressView().controlSize(.small) }
                    Button { naming = true } label: { Label(L10n.fileTools.newFolder, systemImage: "folder.badge.plus") }
                        .accessibilityIdentifier("safe-new-folder")
                    Button { adding = true } label: { Label(L10n.fileTools.addFiles, systemImage: "plus") }
                        .accessibilityIdentifier("safe-add-files")
                }
            }
            .filePicker(isPresented: $adding, multiple: true, types: [.item, .folder]) { urls in
                run { try await model.safeFiles.add(urls, to: folder) }
            }
            .navigationDestination(item: $opened) { SafeBrowserView(folder: $0) }
            .alert(L10n.fileTools.newFolder, isPresented: $naming) {
                TextField(L10n.fileTools.folderName, text: $newName)
                    .accessibilityIdentifier("safe-folder-name")
                Button(L10n.fileTools.createFolder) { makeFolder() }
                Button(L10n.common.cancel, role: .cancel) { newName = "" }
            }
            .alert(L10n.fileTools.rename, isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
                TextField(L10n.fileTools.newName, text: $newName)
                    .accessibilityIdentifier("safe-new-name")
                Button(L10n.fileTools.rename) { rename() }
                Button(L10n.common.cancel, role: .cancel) { renaming = nil }
            }
            // An alert, not a confirmation dialog: those don't show inside the Mac's split view.
            .alert(deleteTitle, isPresented: Binding(get: { !deleting.isEmpty }, set: { if !$0 { deleting = [] } })) {
                Button(L10n.fileTools.delete, role: .destructive) { delete(deleting) }
                Button(L10n.common.cancel, role: .cancel) { deleting = [] }
            }
            .quickLookPreview($preview)
            .onChange(of: preview) { _, url in
                // Quick Look closed: the decrypted copy goes.
                if url == nil {
                    SafeFiles.discard(previewed)
                    previewed = []
                }
            }
    }

    @ViewBuilder
    private var content: some View {
        if let entries, entries.isEmpty {
            EmptyStateView(icon: "folder", title: L10n.fileTools.emptyFolder, message: L10n.fileTools.emptyFolderHelp) {
                Button { adding = true } label: { Label(L10n.fileTools.addFiles, systemImage: "plus") }
                    .buttonStyle(.borderedProminent)
            }
            .onDrop(of: Self.dropTypes, isTargeted: $dropTarget) { drop($0, into: folder) }
        } else {
            List(selection: $selection) {
                if let entries {
                    ForEach(entries, id: \.id) { entry in
                        SafeEntryRow(entry: entry)
                            .draggable(SafeEntryRef(entry, in: folder))
                            .modifier(FolderDrop(entry: entry) { drop($0, into: folder.child(entry)) })
                            .accessibilityIdentifier("safe-entry-\(entry.name)")
                    }
                } else {
                    ProgressView().frame(maxWidth: .infinity)
                }
            }
            .contextMenu(forSelectionType: String.self) { ids in
                menu(for: chosen(ids))
            } primaryAction: { ids in
                if let entry = chosen(ids).first, ids.count == 1 { open(entry) }
            }
            .onDrop(of: Self.dropTypes, isTargeted: $dropTarget) { drop($0, into: folder) }
            #if os(macOS)
            .onCopyCommand {
                copy(chosen(selection))
                // The copies are written to the pasteboard once they're decrypted.
                return []
            }
            .onPasteCommand(of: [.fileURL]) { providers in _ = drop(providers, into: folder) }
            .onDeleteCommand { if !selection.isEmpty { deleting = chosen(selection) } }
            #endif
        }
    }

    @ViewBuilder
    private func menu(for chosen: [SafeEntry]) -> some View {
        if chosen.isEmpty {
            Button { naming = true } label: { Label(L10n.fileTools.newFolder, systemImage: "folder.badge.plus") }
            Button { adding = true } label: { Label(L10n.fileTools.addFiles, systemImage: "plus") }
            #if os(macOS)
            Button { paste() } label: { Label(L10n.phone.native.safePaste, systemImage: "doc.on.clipboard") }
            #endif
        } else {
            if chosen.count == 1, let entry = chosen.first {
                Button { open(entry) } label: { Label(L10n.fileTools.open, systemImage: entry.folder ? "folder" : "eye") }
                Button {
                    newName = entry.name
                    renaming = entry
                } label: { Label(L10n.fileTools.rename, systemImage: "pencil") }
            }
            #if os(macOS)
            Button { copy(chosen) } label: { Label(L10n.phone.native.safeCopy, systemImage: "doc.on.doc") }
            #endif
            Button { saveCopy(chosen) } label: { Label(L10n.fileTools.saveCopy, systemImage: "square.and.arrow.up") }
            Divider()
            Button(role: .destructive) { deleting = chosen } label: { Label(L10n.fileTools.delete, systemImage: "trash") }
        }
    }

    /// The folders from the Safe's top down to this one, with each one's place in the detail
    /// column's stack.
    private var steps: [(index: Int, folder: SafeFolder)] {
        let path = detailEditor?.path ?? []
        var steps: [(index: Int, folder: SafeFolder)] = []
        for (index, route) in path.enumerated() {
            guard case let .safeFolder(step) = route else { continue }
            steps.append((index, step))
            if step == folder { break }
        }
        return steps
    }

    /// Finder's path bar: the Safe, then each folder down to this one. A folder up the way opens
    /// with a click (Cmd+Up for the one above), and takes files dropped on it.
    private var pathBar: some View {
        let steps = steps
        return VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 4) {
                    ForEach(Array(steps.enumerated()), id: \.offset) { n, step in
                        if n > 0 {
                            Image(systemName: "chevron.forward")
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(Color.mist)
                        }
                        let label = Label(step.folder.name, systemImage: n == 0 ? "lock.doc" : "folder")
                            .lineLimit(1)
                        if n == steps.count - 1 {
                            label
                                .font(.callout.weight(.semibold))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 3)
                                .accessibilityIdentifier("safe-path-current")
                        } else {
                            let up = Button {
                                detailEditor?.navigate(Array((detailEditor?.path ?? []).prefix(step.index + 1)))
                            } label: {
                                label
                                    .font(.callout)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 3)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(Color.mist)
                            .onDrop(of: Self.dropTypes, isTargeted: nil) { drop($0, into: step.folder) }
                            .accessibilityIdentifier("safe-path-\(n)")
                            if n == steps.count - 2 {
                                up.keyboardShortcut(.upArrow, modifiers: .command)
                            } else {
                                up
                            }
                        }
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 7)
            }
            Divider()
        }
        .background(.bar)
    }

    private var deleteTitle: String {
        if deleting.count == 1, let entry = deleting.first { return L10n.fileTools.deleteConfirm(name: SafesView.isolate(entry.name)) }
        return L10n.phone.native.safeDeleteSelected
    }

    private func chosen(_ ids: Set<String>) -> [SafeEntry] {
        (entries ?? []).filter { ids.contains($0.id) }
    }

    private func refs(_ chosen: [SafeEntry]) -> [SafeEntryRef] {
        chosen.map { SafeEntryRef($0, in: folder) }
    }

    // MARK: Steps

    private func load() async {
        do {
            entries = try await model.safeFiles.list(folder)
            selection.formIntersection(Set(entries?.map(\.id) ?? []))
        } catch {
            entries = entries ?? []
            fail(error)
        }
    }

    /// One step, then the listing again. Errors become a toast.
    private func run(_ work: @escaping () async throws -> Void) {
        busy = true
        Task {
            defer {
                busy = false
                version += 1
            }
            do { try await work() } catch { fail(error) }
        }
    }

    private func fail(_ error: Error) {
        if let error = error as? SafeFileError, let text = error.errorDescription {
            model.toast = Toast(message: text, tone: .danger)
        } else {
            model.show(error)
        }
    }

    private func open(_ entry: SafeEntry) {
        if entry.folder {
            let next = folder.child(entry)
            if let detailEditor {
                detailEditor.navigate(detailEditor.path + [.safeFolder(next)])
            } else {
                opened = next
            }
            return
        }
        run {
            let urls = try await model.safeFiles.export(refs([entry]))
            previewed = urls
            preview = urls.first
        }
    }

    private func makeFolder() {
        let name = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        newName = ""
        guard !name.isEmpty else { return }
        run { try await model.safeFiles.createFolder(in: folder, name: name) }
    }

    private func rename() {
        guard let entry = renaming else { return }
        renaming = nil
        let name = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        newName = ""
        guard !name.isEmpty, name != entry.name else { return }
        run { try await model.safeFiles.rename(SafeEntryRef(entry, in: folder), to: name, in: folder) }
    }

    private func delete(_ chosen: [SafeEntry]) {
        deleting = []
        run { try await model.safeFiles.delete(refs(chosen)) }
    }

    /// The save panel on the Mac, the share sheet (Save to Files and the rest) elsewhere. The
    /// decrypted copies go once it closes.
    private func saveCopy(_ chosen: [SafeEntry]) {
        run {
            let urls = try await model.safeFiles.export(refs(chosen))
            for url in urls {
                await withCheckedContinuation { done in Modal.share(url) { done.resume() } }
            }
            SafeFiles.discard(urls)
        }
    }

    #if os(macOS)
    /// Edit ▸ Copy: decrypted copies on the pasteboard, to paste in Finder or another Safe. They
    /// stay in the app's temporary folder until the vault locks, so a paste after that finds nothing.
    private func copy(_ chosen: [SafeEntry]) {
        guard !chosen.isEmpty else { return }
        run {
            let urls = try await model.safeFiles.export(refs(chosen))
            let board = NSPasteboard.general
            board.clearContents()
            board.writeObjects(urls as [NSURL])
        }
    }

    private func paste() {
        let urls = NSPasteboard.general.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
        run { try await model.safeFiles.add(urls, to: folder) }
    }
    #endif

    // MARK: Dropping

    static let dropTypes: [UTType] = [.octaPassSafeEntry, .fileURL, .item]

    private func drop(_ providers: [NSItemProvider], into target: SafeFolder) -> Bool {
        let copying = SafeDrop.copying
        run { try await SafeDrop.perform(providers, into: target, copying: copying, model: model) }
        return true
    }
}

/// Files and folders dropped on a Safe's folder (a listing, a folder's row, a Safe's row): from the
/// same Safe they move there (Option on the Mac copies), from another Safe they're copied, as
/// Finder copies between disks, and from outside (Finder, Files, another app) they're added.
@MainActor
enum SafeDrop {
    /// Option held as the drop lands (the Mac).
    static var copying: Bool {
        #if os(macOS)
        NSEvent.modifierFlags.contains(.option)
        #else
        false
        #endif
    }

    static func perform(_ providers: [NSItemProvider], into target: SafeFolder, copying: Bool, model: AppModel) async throws {
        let dropped = await DroppedFiles.read(providers)
        defer { dropped.copies.forEach(PickedFiles.discard) }
        if !dropped.entries.isEmpty {
            let moved = try await model.safeFiles.transfer(dropped.entries, to: target, copying: copying)
            model.confirm(moved ? L10n.phone.native.safeMovedTo(name: target.name) : L10n.phone.native.safeCopiedTo(name: target.name))
        }
        try await model.safeFiles.add(dropped.urls + dropped.copies.map(\.url), to: target)
    }
}

/// A folder row takes drops into itself; a file row doesn't.
private struct FolderDrop: ViewModifier {
    let entry: SafeEntry
    let onDrop: ([NSItemProvider]) -> Bool
    @State private var targeted = false

    func body(content: Content) -> some View {
        if entry.folder {
            content
                .onDrop(of: SafeBrowserView.dropTypes, isTargeted: $targeted, perform: onDrop)
                .listRowBackground(targeted ? RoundedRectangle(cornerRadius: 6).fill(Color.trust.opacity(0.18)) : nil)
        } else {
            content
        }
    }
}

/// What was dropped: Safe entries from the app, file URLs (Finder, the pasteboard), or copies of
/// files another app handed over (Files on the iPhone), in the app's temporary folder.
struct DroppedFiles {
    var entries: [SafeEntryRef] = []
    var urls: [URL] = []
    var copies: [PickedFile] = []

    static func read(_ providers: [NSItemProvider]) async -> DroppedFiles {
        var dropped = DroppedFiles()
        for provider in providers {
            if provider.hasItemConformingToTypeIdentifier(UTType.octaPassSafeEntry.identifier) {
                if let entry = await entry(provider) { dropped.entries.append(entry) }
            } else if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
                if let url = await url(provider) { dropped.urls.append(url) }
            } else if let copy = await copy(provider) {
                dropped.copies.append(copy)
            }
        }
        return dropped
    }

    private static func entry(_ provider: NSItemProvider) async -> SafeEntryRef? {
        await withCheckedContinuation { done in
            _ = provider.loadTransferable(type: SafeEntryRef.self) { done.resume(returning: try? $0.get()) }
        }
    }

    private static func url(_ provider: NSItemProvider) async -> URL? {
        await withCheckedContinuation { done in
            _ = provider.loadObject(ofClass: URL.self) { url, _ in done.resume(returning: url) }
        }
    }

    /// The file another app offers, copied out before the system takes its copy away.
    private static func copy(_ provider: NSItemProvider) async -> PickedFile? {
        let name = provider.suggestedName
        return await withCheckedContinuation { done in
            _ = provider.loadFileRepresentation(forTypeIdentifier: UTType.item.identifier) { url, _ in
                done.resume(returning: url.flatMap { try? PickedFiles.copy($0, named: name) })
            }
        }
    }
}

/// A row of a Safe's listing.
struct SafeEntryRow: View {
    let entry: SafeEntry

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(entry.folder ? Color.trust : Color.mist)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.name).foregroundStyle(Color.ink).lineLimit(2)
                if !details.isEmpty { Text(details).font(.footnote).foregroundStyle(Color.mist) }
            }
            Spacer(minLength: 0)
        }
        .contentShape(Rectangle())
    }

    private var details: String {
        let date = entry.modified > 0
            ? Date(timeIntervalSince1970: TimeInterval(entry.modified) / 1000).formatted(date: .abbreviated, time: .shortened)
            : nil
        let size = entry.folder ? nil : ByteCountFormatter.string(fromByteCount: Int64(entry.size), countStyle: .file)
        return [size, date].compactMap { $0 }.joined(separator: " · ")
    }

    private var icon: String {
        if entry.folder { return "folder.fill" }
        guard let type = UTType(filenameExtension: (entry.name as NSString).pathExtension) else { return "doc" }
        if type.conforms(to: .image) { return "photo" }
        if type.conforms(to: .pdf) { return "doc.richtext" }
        if type.conforms(to: .movie) { return "film" }
        if type.conforms(to: .audio) { return "waveform" }
        if type.conforms(to: .archive) { return "doc.zipper" }
        if type.conforms(to: .text) || type.conforms(to: .sourceCode) { return "doc.text" }
        return "doc"
    }
}
