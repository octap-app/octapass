import OctaPassResources
import OctaPassVault
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

/// "GitHub (octo@example.com)", or whichever of the two there is (`codeLabel` in the web vault).
func codeLabel(issuer: String?, account: String?, title: String? = nil) -> String {
    let name = [issuer, title].compactMap { $0 }.first { !$0.isEmpty }
    if let name, let account, !account.isEmpty { return "\(name) (\(account))" }
    return name ?? account.flatMap { $0.isEmpty ? nil : $0 } ?? L10n.otp.untitled
}

/// A login or password item whose only content is a one-time code (an authenticator import, a
/// scan): it can be moved into the login it belongs to.
func isCodeOnly(_ item: Item) -> Bool {
    switch item.details {
    case let .login(login), let .password(login):
        return !(login.totp ?? "").isEmpty && (login.password ?? "").isEmpty && item.urls.isEmpty && login.passkeys.isEmpty
    default:
        return false
    }
}

/// QR codes from the camera, a photo or an image file, or a pasted setup link: every text read
/// so far, and what they hold. All read on the phone (the core's reader for pictures).
struct CodeCapture: View {
    @Environment(AppModel.self) private var model
    /// Accept a bare secret key as well as links (adding a code to one login).
    var acceptsKey = false
    let onContinue: ([String], QrScan) -> Void
    @State private var texts: [String] = []
    @State private var camera = false
    @State private var photo: PhotosPickerItem?
    @State private var importing = false
    @State private var pasted = ""
    @State private var reading = false
    @State private var message: String?

    private var scan: QrScan { summarizeQrScans(texts: texts) }

    var body: some View {
        List {
            Section {
                Text(acceptsKey ? L10n.otp.addCodeHelp : L10n.otp.scanHelp).font(.subheadline).foregroundStyle(Color.mist)
            }
            if camera {
                Section {
                    CameraQrScanner { text in add([text]) }
                        .frame(height: 320)
                        .listRowInsets(EdgeInsets())
                }
            }
            Section {
                if QrReader.cameraAvailable, !camera {
                    Button { camera = true } label: { Label(L10n.otp.source.camera, systemImage: "camera") }
                        .accessibilityIdentifier("codes-camera")
                }
                PhotosPicker(selection: $photo, matching: .images) {
                    Label(L10n.otp.source.photo, systemImage: "photo.on.rectangle")
                }
                .accessibilityIdentifier("codes-photo")
                Button { importing = true } label: { Label(L10n.otp.chooseImage, systemImage: "folder") }
                    .accessibilityIdentifier("codes-file")
                HStack {
                    TextField(acceptsKey ? L10n.otp.pasteLinkOrKey : L10n.otp.pasteLink, text: $pasted)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.secret(.callout))
                        .accessibilityIdentifier("codes-paste")
                    Button(L10n.otp.addLink) { addPasted() }
                        .disabled(pasted.trimmingCharacters(in: .whitespaces).isEmpty)
                        .accessibilityIdentifier("codes-paste-add")
                }
            } footer: {
                Text(acceptsKey ? L10n.otp.pasteLinkOrKeyHint : L10n.otp.pasteLinkHint)
            }
            if reading {
                Section { Label(L10n.otp.reading, systemImage: "hourglass") }
            }
            if let message {
                Section { Notice(text: message, tone: .warn) }.listRowBackground(Color.clear).listRowInsets(EdgeInsets())
            }
            let scan = scan
            if !scan.codes.isEmpty || !scan.incomplete.isEmpty {
                Section {
                    ForEach(scan.incomplete, id: \.id) { batch in
                        Text(L10n.otp.batch(scanned: String(batch.scanned.count), size: String(batch.size))).font(.footnote)
                    }
                    ForEach(Array(scan.codes.enumerated()), id: \.offset) { _, code in
                        Label {
                            VStack(alignment: .leading) {
                                Text(codeLabel(issuer: code.issuer, account: code.account))
                                if code.counterBased { Text(L10n.otp.counterBased).font(.footnote).foregroundStyle(Color.mist) }
                            }
                        } icon: {
                            Image(systemName: "clock")
                        }
                    }
                    Button(L10n.otp.continue) { onContinue(texts, scan) }
                        .accessibilityIdentifier("codes-continue")
                } header: {
                    Text(L10n.otp.found(count: scan.codes.count))
                }
            }
        }
        .onChange(of: photo) { _, item in
            guard let item else { return }
            photo = nil
            Task {
                reading = true
                defer { reading = false }
                guard let data = try? await item.loadTransferable(type: Data.self) else { return }
                await read(data)
            }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.image]) { result in
            guard case let .success(url) = result else { return }
            Task {
                reading = true
                defer { reading = false }
                let scoped = url.startAccessingSecurityScopedResource()
                let data = try? Data(contentsOf: url)
                if scoped { url.stopAccessingSecurityScopedResource() }
                if let data { await read(data) }
            }
        }
    }

    private func read(_ image: Data) async {
        // Photos stored as HEIC go to the reader as JPEG.
        let bytes = UIImage(data: image).flatMap { $0.jpegData(compressionQuality: 0.95) } ?? image
        do {
            let found = try readQrCodes(image: bytes)
            if found.isEmpty {
                message = L10n.otp.noneFound
                return Haptics.error()
            }
            add(found)
        } catch {
            message = error.isVault(.invalidImage) ? L10n.otp.noneFound : error.message
        }
    }

    private func add(_ found: [String]) {
        let before = scan
        texts += found.filter { !texts.contains($0) }
        let after = scan
        if after.codes.count > before.codes.count || after.incomplete != before.incomplete {
            message = nil
            Haptics.success()
        } else if after.broken > before.broken {
            message = L10n.otp.broken
        } else {
            message = L10n.otp.notCode(count: max(1, Int(after.other - before.other)))
        }
    }

    private func addPasted() {
        let text = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
        pasted = ""
        if text.lowercased().hasPrefix("otpauth") {
            add([text])
        } else if acceptsKey, (try? totpCode(totp: text, atMs: nil)) != nil {
            // A bare key: the login keeps it as typed, as the editor does.
            onContinue([text], QrScan(codes: [ScannedCode(uri: text, issuer: nil, account: nil, counterBased: false)], incomplete: [], other: 0, broken: 0))
        } else {
            message = L10n.otp.invalidLink
        }
    }
}

/// Logins to pick from: search, the ones that already have a code marked, and (for the review)
/// keeping a code as an item of its own.
struct LoginPicker: View {
    @Environment(AppModel.self) private var model
    let label: String
    @Binding var selection: String?
    var exclude: String?
    var allowSeparate = true
    var taken: Set<String> = []
    @State private var query = ""
    @State private var logins: [ItemSummary] = []

    var body: some View {
        List {
            if allowSeparate {
                Button { selection = nil } label: {
                    HStack {
                        Text(L10n.otp.separate).foregroundStyle(Color.ink)
                        Spacer()
                        if selection == nil { Image(systemName: "checkmark").foregroundStyle(Color.trust) }
                    }
                }
            }
            Section(label) {
                if logins.isEmpty { Text(L10n.otp.noLogins).foregroundStyle(Color.mist) }
                ForEach(logins, id: \.id) { login in
                    let blocked = login.hasTotp || taken.contains(login.id)
                    Button { selection = login.id } label: {
                        HStack(spacing: 12) {
                            Avatar(name: login.title, iconDomain: login.iconDomain, size: 32)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(login.title).foregroundStyle(Color.ink)
                                if blocked {
                                    Text(login.hasTotp ? L10n.otp.hasCode : L10n.otp.takenByOther).font(.footnote).foregroundStyle(Color.mist)
                                } else if let subtitle = login.subtitle {
                                    Text(subtitle).font(.footnote).foregroundStyle(Color.mist)
                                }
                            }
                            Spacer()
                            if selection == login.id { Image(systemName: "checkmark").foregroundStyle(Color.trust) }
                        }
                    }
                    .disabled(blocked)
                }
            }
        }
        .searchable(text: $query, prompt: L10n.otp.searchLogins)
        .task(id: query) {
            var filter = ListScope.all.filter
            let text = query.trimmingCharacters(in: .whitespaces)
            filter.query = text.isEmpty ? nil : text
            let writable = Set(VaultDirectory.shared.vaults.filter(\.canWrite).map(\.id))
            logins = ((try? await model.vault.listItems(filter: filter)) ?? []).filter {
                $0.id != exclude && ($0.itemType == .login || $0.itemType == .password) && writable.contains($0.vaultId)
            }
        }
    }
}

/// Choose where each code goes (the import review): a matched login, another one, or an item of
/// its own. Nothing is saved before Save.
struct ImportReviewView: View {
    @Environment(AppModel.self) private var model
    let review: ImportReview
    let onDone: (Bool) -> Void
    @State private var targets: [UInt32: String?] = [:]
    @State private var picking: ReviewCode?
    @State private var busy = false

    private func target(_ code: ReviewCode) -> String? {
        targets[code.index] ?? code.loginId
    }

    var body: some View {
        List {
            Section { Text(L10n.otp.reviewHelp).font(.subheadline).foregroundStyle(Color.mist) }
            Section {
                ForEach(review.codes, id: \.index) { code in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(codeLabel(issuer: code.issuer, account: code.account, title: code.title))
                            ReviewTarget(loginId: target(code))
                        }
                        Spacer()
                        Button(L10n.otp.change) { picking = code }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(L10n.otp.pickerLabel(title: code.title))
                    }
                }
            }
            if !review.warnings.isEmpty {
                Section { ForEach(review.warnings, id: \.self) { Text($0).font(.footnote).foregroundStyle(Color.warnText) } }
            }
            Section {
                Button {
                    Task { await save() }
                } label: {
                    HStack { Text(L10n.otp.saveCodes(count: review.codes.count + Int(review.otherItems))); if busy { Spacer(); ProgressView() } }
                }
                .disabled(busy)
                .accessibilityIdentifier("review-save")
            }
        }
        .navigationTitle(L10n.otp.reviewTitle)
        .sheet(item: Binding(get: { picking.map(Picking.init) }, set: { if $0 == nil { picking = nil } })) { picking in
            NavigationStack {
                LoginPicker(label: L10n.otp.pickerLabel(title: picking.code.title),
                            selection: Binding(get: { target(picking.code) }, set: { targets[picking.code.index] = .some($0); self.picking = nil }),
                            taken: Set(review.codes.filter { $0.index != picking.code.index }.compactMap(target)))
                    .navigationTitle(codeLabel(issuer: picking.code.issuer, account: picking.code.account, title: picking.code.title))
                    .navigationBarTitleDisplayMode(.inline)
            }
        }
        .onDisappear { if !busy { model.vault.cancelImport(reviewId: review.id) } }
    }

    private struct Picking: Identifiable {
        let code: ReviewCode
        var id: UInt32 { code.index }
    }

    private func save() async {
        busy = true
        defer { busy = false }
        do {
            let links = review.codes.map { CodeLink(code: $0.index, loginId: target($0)) }
            _ = try await model.vault.finishImport(reviewId: review.id, links: links)
            model.confirm(L10n.otp.saved(count: review.codes.count))
            onDone(true)
        } catch {
            model.show(error)
        }
    }
}

/// "Joins GitHub", or "Keep as a separate item".
private struct ReviewTarget: View {
    @Environment(AppModel.self) private var model
    let loginId: String?
    @State private var title: String?

    var body: some View {
        Text(loginId == nil ? L10n.otp.separate : L10n.otp.goesTo(title: title ?? "…"))
            .font(.footnote)
            .foregroundStyle(Color.mist)
            .task(id: loginId) {
                guard let loginId else { return }
                title = try? await model.vault.getItem(id: loginId).title
            }
    }
}

/// Add one-time code to a login that has none: scan or paste, pick one if there are several.
struct AddCodeSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let item: Item
    @State private var codes: [ScannedCode]?
    @State private var chosen = 0
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Group {
                if let codes {
                    List {
                        Section(codes.count == 1 ? L10n.otp.foundOne : L10n.otp.chooseOne) {
                            Picker(L10n.otp.chooseOne, selection: $chosen) {
                                ForEach(Array(codes.enumerated()), id: \.offset) { index, code in
                                    Text(codeLabel(issuer: code.issuer, account: code.account)).tag(index)
                                }
                            }
                            .pickerStyle(.inline)
                            .labelsHidden()
                        }
                        Button(L10n.otp.save) { Task { await save(codes[chosen]) } }
                            .disabled(busy)
                            .accessibilityIdentifier("add-code-save")
                    }
                } else {
                    CodeCapture(acceptsKey: true) { _, scan in codes = scan.codes }
                }
            }
            .navigationTitle(L10n.otp.addCode)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } } }
        }
    }

    private func save(_ code: ScannedCode) async {
        busy = true
        defer { busy = false }
        var draft = itemDraft(item: item)
        switch draft.details {
        case var .login(login):
            login.totp = code.uri
            draft.details = .login(login: login)
        case var .password(login):
            login.totp = code.uri
            draft.details = .password(login: login)
        default:
            return
        }
        do {
            _ = try await model.vault.saveItem(draft: draft)
            model.confirm(L10n.otp.added)
            dismiss()
        } catch {
            model.show(error)
        }
    }
}

/// Link to a login: the code moves into the chosen login, and this item goes to the trash.
struct LinkToLoginSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let item: Item
    @State private var target: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Text(L10n.otp.linkHelp).font(.subheadline).foregroundStyle(Color.mist).padding()
                LoginPicker(label: L10n.otp.linkPicker, selection: $target, exclude: item.id, allowSeparate: false)
            }
            .navigationTitle(L10n.otp.linkTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.otp.linkAction) { Task { await link() } }
                        .disabled(target == nil || busy)
                }
            }
        }
    }

    private func link() async {
        guard let target else { return }
        busy = true
        defer { busy = false }
        do {
            let login = try await model.vault.getItem(id: target)
            var totp: String?
            if case let .login(details) = item.details { totp = details.totp }
            if case let .password(details) = item.details { totp = details.totp }
            var draft = itemDraft(item: login)
            switch draft.details {
            case var .login(details):
                details.totp = totp
                draft.details = .login(login: details)
            case var .password(details):
                details.totp = totp
                draft.details = .password(login: details)
            default:
                return
            }
            _ = try await model.vault.saveItem(draft: draft)
            try await model.vault.deleteItem(id: item.id)
            model.confirm(L10n.otp.linked(title: login.title))
            dismiss()
        } catch {
            model.show(error)
        }
    }
}
