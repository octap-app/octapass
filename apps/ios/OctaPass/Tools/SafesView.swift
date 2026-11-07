import OctaPassResources
import OctaPassVault
import SwiftUI

/// The Safes in this account (Android's `SafesScreen`): making one (+ at the top of the list),
/// Sync now for synced ones and deleting one. A Safe opens its files here (`SafeBrowserView`), and
/// takes files dropped on its row; they're in the Files app (Finder on the Mac) too, through the
/// Safe extension. Each step the app takes on a Safe's files holds its store lock (`SafeFiles`), so
/// the app and the extension never write one Safe at once.
struct SafesView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.detailEditor) private var detailEditor
    @State private var safes: [SafeItem]?
    @State private var making = false
    @State private var syncing: Set<String> = []
    /// What the engine noticed at each Safe's last sync here.
    @State private var warnings: [String: [SafeWarning]] = [:]
    @State private var deleting: SafeItem?

    var body: some View {
        Group {
            if let safes, safes.isEmpty {
                // What a Safe is, once: before the first one.
                EmptyStateView(icon: "lock.doc", title: L10n.fileTools.noSafes, message: L10n.fileTools.safesHelp) {
                    Button(action: newSafe) { Label(L10n.fileTools.newSafe, systemImage: "plus") }
                        .buttonStyle(.borderedProminent)
                        .accessibilityIdentifier("safes-new-empty")
                }
            } else {
                List {
                    Section {
                        if let safes {
                            ForEach(safes) { safe in row(safe) }
                        } else {
                            ProgressView().frame(maxWidth: .infinity)
                        }
                    } header: {
                        // New Safe at the top of the list it adds to.
                        HStack {
                            Text(L10n.fileTools.safesTitle)
                            Spacer()
                            Button(action: newSafe) {
                                Image(systemName: "plus")
                                    .font(.body.weight(.semibold))
                                    .frame(width: 26, height: 26)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.borderless)
                                .accessibilityLabel(L10n.fileTools.newSafe)
                                .accessibilityIdentifier("safes-new")
                        }
                    } footer: {
                        // Where the files are, under the list rather than above it.
                        Text("\(Self.inFilesNote) \(Self.useFilesNote)")
                            .accessibilityIdentifier("safes-in-files")
                    }
                    if model.settings.lockOnBackground {
                        Section {
                            Notice(text: Self.lockInBackgroundNote, tone: .warn)
                                .accessibilityIdentifier("safes-lock-in-background")
                        }
                    }
                }
            }
        }
        .navigationTitle(L10n.fileTools.safesTitle)
        // Only this device's: a Safe kept on another device isn't here, though its item is.
        .task(id: model.itemsVersion) { safes = try? await model.vault.listSafes(folder: model.safeFiles.folder?.path) }
        .sheet(isPresented: $making) {
            NavigationStack { NewSafeView { making = false } }
        }
        .sheet(item: $deleting) { DeleteSafeSheet(safe: $0) }
    }

    /// The form for a new Safe: in the Mac's detail column, as a new item's editor; a sheet elsewhere.
    private func newSafe() {
        if let detailEditor { detailEditor.navigate([.newSafe]) } else { making = true }
    }

    /// Opens the Safe's files: in the Mac's detail column, as an item opens; pushed elsewhere.
    @ViewBuilder
    private func opener(_ safe: SafeItem, @ViewBuilder label: () -> some View) -> some View {
        let route = Route.safeFolder(.top(safe))
        if let detailEditor {
            Button { detailEditor.navigate([route]) } label: { label().contentShape(Rectangle()) }
                .buttonStyle(.plain)
                .accessibilityIdentifier("safes-open-\(safe.name)")
        } else {
            NavigationLink(value: route, label: label)
                .accessibilityIdentifier("safes-open-\(safe.name)")
        }
    }

    /// The Safe open in the Mac's detail column, highlighted in the list as an open item is.
    private func isOpen(_ safe: SafeItem) -> Bool {
        guard case let .safeFolder(folder) = detailEditor?.path.first else { return false }
        return folder.itemId == safe.itemId
    }

    private func row(_ safe: SafeItem) -> some View {
        let open = isOpen(safe)
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                opener(safe) { SafeRow(safe: safe) }
                if syncing.contains(safe.itemId) { ProgressView() }
                Menu {
                    actions(safe)
                } label: {
                    Image(systemName: "ellipsis")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(Color.mist)
                        .frame(width: 28, height: 28)
                        .contentShape(Rectangle())
                }
                .menuStyle(.button)
                .buttonStyle(.borderless)
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityLabel(safe.name)
                .accessibilityIdentifier("safes-actions")
            }
            ForEach(Array((warnings[safe.itemId] ?? []).enumerated()), id: \.offset) { _, warning in
                Notice(text: text(warning), tone: .warn)
            }
        }
        .listRowBackground(open ? RoundedRectangle(cornerRadius: 8).fill(Color.trust.opacity(0.18)).padding(.horizontal, 6) : nil)
        .accessibilityAddTraits(open ? .isSelected : [])
        // The same actions on a right-click (a long press on the iPhone).
        .contextMenu { actions(safe) }
        .swipeActions {
            Button(L10n.fileTools.deleteSafe, role: .destructive) { deleting = safe }
        }
        // Files and folders dropped on a Safe go to its top folder.
        .onDrop(of: SafeBrowserView.dropTypes, isTargeted: nil) { providers in
            let copying = SafeDrop.copying
            Task {
                do {
                    try await SafeDrop.perform(providers, into: .top(safe), copying: copying, model: model)
                } catch {
                    model.show(error)
                }
            }
            return true
        }
    }

    /// Show in Finder (Files) while it's open there, Sync now for a synced Safe, Delete.
    @ViewBuilder
    private func actions(_ safe: SafeItem) -> some View {
        if model.safeFiles.open.contains(where: { $0.itemId == safe.itemId }) {
            Button {
                Task { await model.safeFiles.showInFiles(safe) }
            } label: {
                Label(Self.showInFilesTitle, systemImage: "folder")
            }
        }
        if safe.sync, !model.isLocal {
            Button {
                Task { await syncNow(safe) }
            } label: {
                Label(L10n.fileTools.syncNow, systemImage: "arrow.triangle.2.circlepath")
            }
            .disabled(syncing.contains(safe.itemId))
            .accessibilityIdentifier("safes-sync-now")
        }
        Divider()
        Button(role: .destructive) {
            deleting = safe
        } label: {
            Label(L10n.fileTools.deleteSafe, systemImage: "trash")
        }
        .accessibilityIdentifier("safes-delete")
    }

    private func syncNow(_ safe: SafeItem) async {
        syncing.insert(safe.itemId)
        defer { syncing.remove(safe.itemId) }
        do {
            let (summary, found) = try await model.safeFiles.sync(safe)
            warnings[safe.itemId] = found
            let notes = summary.conflicts.map { L10n.fileTools.conflict(name: Self.isolate($0)) }
                + summary.tooBig.map { L10n.fileTools.tooBig(name: Self.isolate($0)) }
            if notes.isEmpty {
                model.confirm(L10n.fileTools.syncDone)
            } else {
                model.toast = Toast(message: notes.joined(separator: "\n"), tone: summary.tooBig.isEmpty ? .info : .danger)
            }
        } catch {
            model.show(error)
        }
    }

    private func text(_ warning: SafeWarning) -> String {
        switch warning {
        case .damaged: L10n.fileTools.warnings.damagedBlob
        case .rolledBack: L10n.fileTools.warnings.rolledBack
        case .missing: L10n.fileTools.warnings.missing
        case let .orphaned(name): L10n.fileTools.warnings.orphaned(name: Self.isolate(name))
        }
    }

    // Open Safes show in the Files app on the iPhone, in Finder on the Mac (each one's File Provider
    // extension, `SafeFiles`).
    #if os(macOS)
    static var inFilesNote: String { L10n.phone.native.safesInFinder }
    static var lockInBackgroundNote: String { L10n.phone.native.safesLockInBackgroundMac }
    static var useFilesNote: String { "\(L10n.phone.native.safesUseFinder) \(L10n.phone.native.safesFinderCopies)" }
    static var showInFilesTitle: String { L10n.phone.native.safesShowInFinder }
    #else
    static var inFilesNote: String { L10n.phone.native.safesInFiles }
    static var lockInBackgroundNote: String { L10n.phone.native.safesLockInBackground }
    static var useFilesNote: String { "\(L10n.phone.native.safesUseFiles) \(L10n.phone.native.safesFilesCopies)" }
    static var showInFilesTitle: String { L10n.phone.native.safesShowInFiles }
    #endif

    /// A file or Safe name inside a sentence, kept in its own direction (Arabic around a Latin name).
    static func isolate(_ name: String) -> String { "\u{2068}\(name)\u{2069}" }
}

/// A Safe in the list, as an item is: its tile, its name, and where its files are kept.
private struct SafeRow: View {
    let safe: SafeItem

    var body: some View {
        HStack(spacing: 12) {
            RoundedRectangle(cornerRadius: 11, style: .continuous)
                .fill(LinearGradient(colors: [Color.trust, Color.trust.opacity(0.72)], startPoint: .topLeading, endPoint: .bottomTrailing))
                .frame(width: 38, height: 38)
                .overlay {
                    Image(systemName: "lock.doc.fill")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(.white)
                }
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(safe.name)
                    .font(.body.weight(.medium))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Label(safe.sync ? L10n.fileTools.synced : L10n.fileTools.thisDevice, systemImage: safe.sync ? "arrow.triangle.2.circlepath" : Self.deviceIcon)
                    .labelStyle(.titleAndIcon)
                    .imageScale(.small)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 4)
        }
        .padding(.vertical, 2)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }

    #if os(macOS)
    static let deviceIcon = "laptopcomputer"
    #else
    static let deviceIcon = "iphone"
    #endif
}

/// Delete Safe: the name typed to confirm, as the web vault asks.
private struct DeleteSafeSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let safe: SafeItem
    @State private var typed = ""
    @State private var deleting = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(L10n.fileTools.deleteSafeConfirm(name: SafesView.isolate(safe.name)))
                    TextField(L10n.fileTools.typeSafeName(name: SafesView.isolate(safe.name)), text: $typed)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("safes-delete-name")
                }
                Section {
                    Button(role: .destructive) {
                        Task { await delete() }
                    } label: {
                        HStack { Text(L10n.fileTools.deleteSafe); if deleting { Spacer(); ProgressView() } }
                    }
                    .disabled(deleting || typed != safe.name)
                    .accessibilityIdentifier("safes-delete-confirm")
                }
            }
            .navigationTitle(L10n.fileTools.deleteSafe)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.common.cancel) { dismiss() }
                }
            }
        }
        .interactiveDismissDisabled(deleting)
    }

    private func delete() async {
        deleting = true
        defer { deleting = false }
        do {
            try await model.safeFiles.delete(safe)
            model.confirm(L10n.fileTools.safeDeleted(name: SafesView.isolate(safe.name)))
            dismiss()
        } catch {
            model.show(error)
        }
    }
}

/// A new Safe: its name and whether it syncs, with Cancel and Make Safe, as a new item's editor.
/// `onClose` after either; the list shows the new Safe as the vault changes.
struct NewSafeView: View {
    @Environment(AppModel.self) private var model
    let onClose: () -> Void
    @State private var name = ""
    @State private var sync = false
    @State private var creating = false
    @FocusState private var naming: Bool

    private var trimmed: String { name.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        Form {
            Section {
                TextField(L10n.fileTools.safeName, text: $name)
                    .focused($naming)
                    .onSubmit { Task { await create() } }
                    .accessibilityIdentifier("safes-name")
                // A vault on this device only has no server to keep it on.
                if !model.isLocal {
                    Toggle(isOn: $sync) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(L10n.fileTools.safeSync)
                            Text(L10n.fileTools.safeSyncHelp).font(.footnote).foregroundStyle(Color.mist)
                        }
                    }
                    .accessibilityIdentifier("safes-sync")
                }
            }
        }
        .navigationTitle(L10n.fileTools.newSafe)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button(L10n.common.cancel, action: onClose).disabled(creating)
            }
            ToolbarItem(placement: .confirmationAction) {
                Button {
                    Task { await create() }
                } label: {
                    if creating { ProgressView() } else { Text(L10n.fileTools.createSafe).fontWeight(.semibold) }
                }
                .disabled(creating || trimmed.isEmpty)
                .toolbarButton(prominent: true)
                .accessibilityIdentifier("safes-create")
            }
        }
        .onAppear { naming = true }
    }

    private func create() async {
        guard !trimmed.isEmpty, !creating else { return }
        creating = true
        defer { creating = false }
        do {
            // The item change opens it in Files (Finder on the Mac), through AppModel.
            _ = try await model.vault.createSafe(name: trimmed, sync: sync && !model.isLocal)
            onClose()
        } catch {
            model.show(error)
        }
    }
}
