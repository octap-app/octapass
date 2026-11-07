import OctaPassResources
import OctaPassVault
import SwiftUI

extension SshKeyDetails {
    static let empty = SshKeyDetails(privateKey: nil, publicKey: nil, keyType: nil, fingerprint: nil, comment: nil, passphrase: nil, notes: nil, customFields: [])
}

/// The editor's SSH key part (the web vault's `SshKeySection`): generate or read the key, then its
/// comment, passphrase and notes. The key itself changes only by generating or reading one.
struct SshKeyEditor: View {
    @Binding var key: SshKeyDetails
    let errors: [String: String]
    @State private var replacing = false

    var body: some View {
        Section(L10n.sshKey.key) {
            if key.privateKey != nil, !replacing {
                LabeledContent(L10n.sshKey.type, value: sshKeyTypeLabel(details: key) ?? "—")
                VStack(alignment: .leading, spacing: 3) {
                    Text(L10n.sshKey.fingerprint).font(.caption.weight(.medium)).foregroundStyle(Color.mist)
                    Text(key.fingerprint ?? "—").font(.secret(.footnote)).environment(\.layoutDirection, .leftToRight)
                        .accessibilityIdentifier("ssh-fingerprint")
                }
                Button { replacing = true } label: { Label(L10n.sshKey.replace, systemImage: "arrow.triangle.2.circlepath") }
                    .accessibilityIdentifier("ssh-replace")
            } else {
                if replacing { Notice(text: L10n.sshKey.replaceConfirm, tone: .warn) }
                SshKeySource(comment: key.comment ?? "", error: errors["privateKey"]) { material, passphrase in
                    key = withSshKey(details: key, key: material, passphrase: passphrase)
                    replacing = false
                }
                if replacing {
                    Button(L10n.common.cancel) { replacing = false }
                }
            }
            EditorField(label: L10n.sshKey.comment, text: $key.comment.text, hint: L10n.sshKey.commentHint, keyboard: .asciiCapable, ltr: true)
                .accessibilityIdentifier("ssh-comment")
            VStack(alignment: .leading, spacing: 4) {
                MaskedField(label: L10n.sshKey.passphrase, text: $key.passphrase.text)
                    .accessibilityIdentifier("ssh-passphrase")
                Text(L10n.sshKey.passphraseHint).font(.footnote).foregroundStyle(Color.mist)
            }
        }
        CustomFieldsEditor(fields: $key.customFields)
        Section(L10n.fields.notes) {
            TextEditor(text: $key.notes.text).frame(minHeight: 80).accessibilityLabel(L10n.fields.notes)
        }
    }
}

/// Generate a key, choose a key file or paste one. Asks for the passphrase when the key has one.
private struct SshKeySource: View {
    @Environment(AppModel.self) private var model
    /// Key files are a few kilobytes; anything much bigger isn't one.
    private static let maxFile = 64 * 1024
    let comment: String
    let error: String?
    let onKey: (SshKeyMaterial, String?) -> Void
    @State private var kind = SshKeyKind.ed25519
    @State private var pasted = ""
    @State private var busy = false
    @State private var picking = false

    var body: some View {
        Picker(L10n.sshKey.kind, selection: $kind) {
            ForEach(sshKeyKinds(), id: \.name) { choice in
                Text(L10n.text(forKey: "sshKey.kinds.\(choice.name)") ?? choice.name).tag(choice.kind)
            }
        }
        .accessibilityIdentifier("ssh-kind")
        VStack(alignment: .leading, spacing: 4) {
            Button { Task { await generate() } } label: {
                HStack {
                    Label(busy ? L10n.sshKey.generating : L10n.sshKey.generateAction, systemImage: "key")
                    if busy { Spacer(); ProgressView() }
                }
            }
            .disabled(busy)
            .accessibilityIdentifier("ssh-generate")
            Text(L10n.sshKey.kindHint).font(.footnote).foregroundStyle(Color.mist)
        }
        VStack(alignment: .leading, spacing: 4) {
            Button { picking = true } label: { Label(L10n.sshKey.importFile, systemImage: "square.and.arrow.down") }
                .disabled(busy)
                .accessibilityIdentifier("ssh-import-file")
                .filePicker(isPresented: $picking) { urls in
                    if let url = urls.first { Task { await readFile(url) } }
                }
            Text(L10n.sshKey.importFileHint).font(.footnote).foregroundStyle(Color.mist)
        }
        VStack(alignment: .leading, spacing: 4) {
            Text(L10n.sshKey.paste).font(.caption).foregroundStyle(Color.mist)
            TextEditor(text: $pasted)
                .font(.secret(.footnote))
                .frame(minHeight: 88)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .environment(\.layoutDirection, .leftToRight)
                .accessibilityLabel(L10n.sshKey.paste)
                .accessibilityIdentifier("ssh-paste")
            if let error { Text(error).font(.footnote).foregroundStyle(Color.dangerText) }
        }
        if !pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            Button { Task { await read(pasted) } } label: { Label(L10n.sshKey.pasteAction, systemImage: "doc.on.clipboard") }
                .disabled(busy)
                .accessibilityIdentifier("ssh-paste-action")
        }
    }

    private func generate() async {
        busy = true
        defer { busy = false }
        do {
            onKey(try await model.vault.generateSshKey(kind: kind, comment: comment), nil)
        } catch {
            model.show(error)
        }
    }

    private func readFile(_ url: URL) async {
        do {
            let file = try PickedFiles.copy(url)
            defer { PickedFiles.discard(file) }
            let size = (try? FileManager.default.attributesOfItem(atPath: file.url.path)[.size] as? Int) ?? 0
            guard size <= Self.maxFile, let text = try? String(contentsOf: file.url, encoding: .utf8) else {
                model.toast = Toast(message: L10n.errors.invalidSshKey, tone: .danger)
                return
            }
            await read(text)
        } catch {
            model.show(error)
        }
    }

    private func read(_ text: String) async {
        busy = true
        defer { busy = false }
        do {
            onKey(try await model.vault.readSshKey(text: text, passphrase: nil), nil)
            pasted = ""
        } catch {
            if error.isVault(.sshPassphraseRequired) {
                let model = model
                Modal.present(model: model) { close in
                    SshPassphraseSheet(text: text, close: close) { material, passphrase in
                        pasted = ""
                        onKey(material, passphrase)
                    }
                }
            } else {
                model.show(error)
            }
        }
    }
}

/// A protected key's passphrase, and whether to keep it for copies written out of the vault.
private struct SshPassphraseSheet: View {
    @Environment(AppModel.self) private var model
    let text: String
    let close: () -> Void
    let onKey: (SshKeyMaterial, String?) -> Void
    @State private var passphrase = ""
    @State private var keep = true
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(L10n.sshKey.passphraseBody).font(.callout).foregroundStyle(Color.mist)
                    MaskedField(label: L10n.sshKey.passphrase, text: $passphrase)
                        .accessibilityIdentifier("ssh-read-passphrase")
                    if let error { Text(error).font(.footnote).foregroundStyle(Color.dangerText) }
                    Toggle(L10n.sshKey.keepPassphrase, isOn: $keep)
                }
            }
            .navigationTitle(L10n.sshKey.passphraseTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel, action: close) }
                ToolbarItem(placement: .confirmationAction) {
                    Button { Task { await submit() } } label: {
                        if busy { ProgressView() } else { Text(L10n.sshKey.readAction).fontWeight(.semibold) }
                    }
                    .disabled(busy || passphrase.isEmpty)
                    .accessibilityIdentifier("ssh-read-action")
                }
            }
        }
    }

    private func submit() async {
        busy = true
        defer { busy = false }
        do {
            let material = try await model.vault.readSshKey(text: text, passphrase: passphrase)
            close()
            onKey(material, keep ? passphrase : nil)
        } catch {
            self.error = error.isVault(.wrongPassphrase) ? L10n.sshKey.wrongPassphrase : error.message
        }
    }
}

/// An SSH key's fields (the web vault's `SshKeyFields`). The private key is shown, copied or saved
/// only after confirming it's the owner (plan 16 §6); confirming covers this item while it's open,
/// and a confirmed unlock covers showing and copying it (plan 03 History, 2026-11-05).
struct SshKeyFields: View {
    @Environment(AppModel.self) private var model
    let item: Item
    let key: SshKeyDetails
    @State private var confirmed = false
    @State private var shown = false

    private var line: String { authorizedKeysLine(details: key) }
    private var fileName: String { sshKeyFileName(title: item.title, details: key) }

    var body: some View {
        Section {
            if !line.isEmpty {
                FieldRow(label: L10n.sshKey.publicKey, value: line, ltr: true, mono: true)
                    .accessibilityIdentifier("ssh-public-key")
            }
            if let fingerprint = key.fingerprint, !fingerprint.isEmpty {
                FieldRow(label: L10n.sshKey.fingerprint, value: fingerprint, ltr: true, mono: true)
            }
            if let label = sshKeyTypeLabel(details: key) {
                FieldRow(label: L10n.sshKey.type, value: label, copyable: false)
            }
            if let comment = key.comment, !comment.isEmpty {
                FieldRow(label: L10n.sshKey.comment, value: comment, ltr: true)
            }
            if key.privateKey != nil { privateKey }
            if let passphrase = key.passphrase, !passphrase.isEmpty {
                SecretFieldRow(label: L10n.sshKey.passphrase, value: passphrase)
            }
        }
        if let label = sshKeyTypeLabel(details: key), key.keyType != nil, !isUsableSshKey(details: key) {
            Notice(text: L10n.sshKey.notUsable(type: label), tone: .info).listRowBackground(Color.clear)
        }
        if !line.isEmpty || key.privateKey != nil {
            Section {
                if key.privateKey != nil {
                    Button { gated(export) } label: { Label(L10n.sshKey.exportPrivate, systemImage: "square.and.arrow.up") }
                        .accessibilityIdentifier("ssh-export-private")
                }
                if !line.isEmpty {
                    Button { Task { await savePublic() } } label: { Label(L10n.sshKey.exportPublic, systemImage: "square.and.arrow.up") }
                        .accessibilityIdentifier("ssh-export-public")
                }
            }
        }
        CustomFieldsSection(fields: key.customFields)
        if let notes = key.notes, !notes.isEmpty {
            Section(L10n.fields.notes) { SecretFieldRow(label: L10n.fields.notes, value: notes, multiline: true) }
        }
    }

    @ViewBuilder private var privateKey: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(L10n.sshKey.privateKey).font(.caption.weight(.medium)).foregroundStyle(Color.mist)
                Spacer()
                if shown {
                    Button { model.copy(key.privateKey ?? "", what: L10n.sshKey.privateKey, item: item.id) } label: { Image(systemName: "doc.on.doc") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(L10n.copy.action(what: L10n.sshKey.privateKey))
                    Button { shown = false } label: { Image(systemName: "eye.slash") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(L10n.sshKey.hidePrivate)
                } else {
                    Button { reveal() } label: { Label(L10n.sshKey.showPrivate, systemImage: "eye") }
                        .buttonStyle(.borderless)
                        .accessibilityIdentifier("ssh-show-private")
                }
            }
            if shown {
                Text(key.privateKey ?? "")
                    .font(.secret(.caption))
                    .textSelection(.enabled)
                    .environment(\.layoutDirection, .leftToRight)
                    .accessibilityIdentifier("ssh-private-key")
            } else {
                Text(String(repeating: "•", count: 16)).font(.secret()).accessibilityLabel(L10n.detail.hiddenValue)
            }
        }
        .onDisappear { shown = false }
    }

    /// Saving the private key to a file is an export: "Confirm it's you" every time, once for
    /// this item while it's open.
    private func gated(_ action: @escaping () -> Void) {
        if confirmed { return action() }
        Task {
            guard await model.confirmIdentity() else { return }
            confirmed = true
            action()
        }
    }

    /// Showing it doesn't ask again when the user answered this unlock (`confirmReveal`), or,
    /// with stay unlocked on, an earlier reveal (plan 18).
    private func reveal() {
        if confirmed { return shown = true }
        Task {
            let covered = await model.unlockCoversReveal()
            if !covered {
                guard await model.confirmReveal() else { return }
                confirmed = true
            }
            shown = true
        }
    }

    private func export() {
        let model = model
        let details = key
        let name = fileName
        Modal.present(model: model) { close in
            SshExportSheet(details: details, fileName: name, close: close)
        }
    }

    private func savePublic() async {
        await ShareFile.write(model: model, name: "\(fileName).pub", text: "\(line)\n", done: L10n.sshKey.exported(file: "\(fileName).pub"))
    }
}

/// The private key as a file: with a passphrase for the copy, offered from the item's own.
private struct SshExportSheet: View {
    @Environment(AppModel.self) private var model
    let details: SshKeyDetails
    let fileName: String
    let close: () -> Void
    @State private var passphrase = ""
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(L10n.sshKey.exportBody).font(.callout).foregroundStyle(Color.mist)
                    MaskedField(label: L10n.sshKey.exportPassphrase, text: $passphrase)
                        .accessibilityIdentifier("ssh-export-passphrase")
                    Text(L10n.sshKey.exportPassphraseHint).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            .navigationTitle(L10n.sshKey.exportTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel, action: close) }
                ToolbarItem(placement: .confirmationAction) {
                    Button { Task { await export() } } label: {
                        if busy { ProgressView() } else { Text(L10n.sshKey.exportAction).fontWeight(.semibold) }
                    }
                    .disabled(busy)
                    .accessibilityIdentifier("ssh-export-action")
                }
            }
        }
        .onAppear { passphrase = details.passphrase ?? "" }
    }

    private func export() async {
        busy = true
        defer { busy = false }
        do {
            let path = try await model.vault.exportSshKey(details: details, fileName: fileName, passphrase: passphrase.isEmpty ? nil : passphrase)
            close()
            ShareFile.share(model: model, path: path, done: L10n.sshKey.exported(file: fileName))
        } catch {
            model.show(error)
        }
    }
}

/// A file written for the share sheet: it's deleted when the sheet closes.
@MainActor
enum ShareFile {
    static func write(model: AppModel, name: String, text: String, done: String) async {
        do {
            share(model: model, path: try await model.vault.writeShareFile(fileName: name, text: text), done: done)
        } catch {
            model.show(error)
        }
    }

    static func share(model: AppModel, path: String, done: String) {
        Modal.share(URL(fileURLWithPath: path)) {
            model.vault.closeAttachment(path: path)
            model.confirm(done)
        }
    }
}
