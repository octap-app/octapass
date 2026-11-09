import OctaPassResources
import OctaPassVault
import PhotosUI
import SwiftUI

/// New and edited items, every type (the web vault's `ItemEditor`). Fields have no password
/// content types: the system would offer to save what's typed to its own password manager. The vault checks and cleans
/// the draft as the web vault's editor does (`validateDraft`, `saveItem`); this screen only shows
/// the fields and the errors next to them.
struct ItemEditorSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    @Environment(\.dismiss) private var dismiss
    @State private var draft: ItemDraft
    @State private var login = LoginDetails(username: nil, password: nil, totp: nil, notes: nil, passkeys: [], recovery: nil, customFields: [], passwordHistory: [])
    @State private var note = ""
    @State private var card = CardDetails(cardholder: nil, number: nil, expiry: nil, cvv: nil, pin: nil, brand: nil, notes: nil)
    @State private var identity = IdentityDetails(firstName: nil, lastName: nil, email: nil, phone: nil, address: nil, birthDate: nil, notes: nil)
    @State private var wifi = WifiDetails(ssid: "", security: "wpa2", password: nil, hidden: false, eapMethod: nil, phase2: nil, username: nil, identity: nil, serverDomain: nil, caCertificate: nil, captivePortal: false, managed: false, hotspot: false, notes: nil, customFields: [], passwordHistory: [])
    @State private var sshKey = SshKeyDetails.empty
    @State private var environment = EnvironmentDetails.empty
    @State private var documentNotes = ""
    @State private var structured = StructuredDetails.empty
    @State private var tags = ""
    @State private var errors: [String: String] = [:]
    @State private var formError: String?
    @State private var busy = false
    @State private var confirmDiscard = false
    /// A login already saved for the same site and username, while asking about a copy.
    @State private var sameLogin: ItemSummary?
    @State private var pendingFiles: [PickedFile] = []
    @State private var generating = false
    @Environment(\.detailEditor) private var detailEditor
    private let original: ItemDraft
    /// In the Mac's detail column (`DetailEditor`) rather than a sheet: called with the saved item's
    /// id, or nil for Cancel, instead of dismissing.
    private let onClose: ((String?) -> Void)?

    init(draft: ItemDraft, onClose: ((String?) -> Void)? = nil) {
        _draft = State(initialValue: draft)
        original = draft
        self.onClose = onClose
    }

    private var isNew: Bool { draft.id == nil }
    private var type: ItemType {
        switch draft.details {
        case .login: .login
        case .password: .password
        case .secureNote: .secureNote
        case .card: .card
        case .identity: .identity
        case .document: .document
        case .wifi: .wifi
        case .sshKey: .sshKey
        case .environment: .environment
        case .maskedEmailProvider: .maskedEmailProvider
        case let .structured(itemType, _): itemType
        case let .other(itemType, _): .other(name: itemType)
        }
    }

    var body: some View {
        Group {
            // In the Mac's detail column it's a page on that column's stack.
            if onClose != nil { form } else { NavigationStack { form } }
        }
        .interactiveDismissDisabled(changed)
        .onAppear(perform: load)
        // Leaving the Mac's detail column with unsaved changes asks first.
        .onChange(of: changed, initial: true) { _, now in
            if onClose != nil { detailEditor?.changed = now }
        }
        // Here rather than inside the form, where sheets don't always show.
        .sheet(isPresented: $generating) {
            GeneratorSheet(site: firstSite(urls: draft.urls, modes: draft.urlMatch)) { value in
                if type == .wifi { wifi.password = value } else { login.password = value }
            }
        }
    }

    private var form: some View {
            Form {
                if let formError {
                    Section { Notice(text: formError) }.listRowBackground(Color.clear).listRowInsets(EdgeInsets())
                }
                Section {
                    EditorField(label: L10n.fields.title, text: $draft.title, error: errors["title"],
                                placeholder: L10n.text(forKey: "editor.titlePlaceholder.\(type.name)"))
                        .accessibilityIdentifier("editor-title")
                }
                fields
                organise
            }
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle(isNew ? (L10n.text(forKey: "editor.new.\(type.name)") ?? type.typeName) : L10n.editor.editTitle(title: original.title))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.common.cancel) {
                        if changed { confirmDiscard = true } else { close() }
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        Task { await save() }
                    } label: {
                        if busy { ProgressView() } else { Text(L10n.common.save).fontWeight(.semibold) }
                    }
                    .disabled(busy)
                    .toolbarButton(prominent: true)
                    .accessibilityIdentifier("editor-save")
                }
            }
            .confirmationDialog(L10n.editor.discardTitle, isPresented: $confirmDiscard, titleVisibility: .visible) {
                Button(L10n.editor.discard, role: .destructive) { close() }
                Button(L10n.editor.keepEditing, role: .cancel) {}
            } message: {
                Text(L10n.editor.discardBody)
            }
            .confirmationDialog(L10n.editor.sameLoginTitle, isPresented: sameLoginShown, titleVisibility: .visible, presenting: sameLogin) { _ in
                Button(L10n.editor.saveAnyway) { Task { await save(copy: true) } }
                Button(L10n.editor.keepEditing, role: .cancel) {}
            } message: { same in
                Text(L10n.editor.sameLoginBody(title: same.title, vault: directory.vaults.first { $0.id == same.vaultId }?.name ?? ""))
            }
    }

    // MARK: Fields by type

    @ViewBuilder private var fields: some View {
        switch type {
        case .login, .password:
            LoginEditor(login: $login, urls: $draft.urls, urlMatch: $draft.urlMatch, generating: $generating, errors: errors, isLogin: type == .login)
        case .secureNote:
            Section(L10n.fields.note) {
                TextEditor(text: $note).frame(minHeight: 160).accessibilityLabel(L10n.fields.note)
            }
        case .card:
            CardEditor(card: $card, errors: errors)
        case .identity:
            IdentityEditor(identity: $identity, errors: errors)
        case .wifi:
            WifiEditor(wifi: $wifi, generating: $generating, errors: errors)
        case .sshKey:
            SshKeyEditor(key: $sshKey, errors: errors)
        case .environment:
            EnvironmentEditor(environment: $environment, errors: errors)
        case .document:
            if isNew { PendingFilesSection(files: $pendingFiles, document: true, error: errors["file"]) }
            Section(L10n.fields.notes) {
                TextEditor(text: $documentNotes).frame(minHeight: 100).accessibilityLabel(L10n.fields.notes)
            }
        case .bankAccount, .apiCredential, .softwareLicense, .idDocument, .cryptoWallet, .database, .custom, .customTemplate:
            StructuredEditor(type: type, vaultId: draft.vaultId, title: draft.title, isNew: isNew, details: $structured, errors: errors)
        case .maskedEmailProvider, .other:
            Section { Text(L10n.editor.readOnlyTitle).foregroundStyle(Color.mist) }
        }
        // An existing item's files are added and removed on its screen, at once.
        if isNew, type != .document { PendingFilesSection(files: $pendingFiles, document: false, error: nil) }
    }

    private var organise: some View {
        Section(L10n.editor.organise) {
            if isNew {
                Picker(L10n.fields.vault, selection: $draft.vaultId) {
                    ForEach(directory.vaults.filter(\.canWrite), id: \.id) { vault in
                        Text(vaultOption(vault)).tag(vault.id)
                    }
                }
            }
            EditorField(label: L10n.fields.tags, text: $tags, hint: L10n.editor.tagsHint, placeholder: L10n.editor.tagsPlaceholder)
            Toggle(L10n.fields.favorite, isOn: $draft.favorite)
            Toggle(L10n.fields.pinned, isOn: $draft.pinned)
        }
    }

    private func vaultOption(_ vault: Vault) -> String {
        switch vault.vaultType {
        case .shared: L10n.editor.sharedVaultOption(vault: vault.name)
        case .family: L10n.editor.familyVaultOption(vault: vault.name)
        case .personal: vault.name
        }
    }

    // MARK: Loading and saving

    private func load() {
        switch draft.details {
        case let .login(details), let .password(details): login = details
        case let .secureNote(details): note = details.notes
        case let .card(details): card = details
        case let .identity(details): identity = details
        case let .wifi(details): wifi = details
        case let .sshKey(details): sshKey = details
        case let .environment(details): environment = details
        case let .document(details): documentNotes = details.notes ?? ""
        case let .structured(_, details): structured = details
        default: break
        }
        tags = draft.tags.joined(separator: ", ")
        if draft.vaultId.isEmpty { draft.vaultId = directory.personal?.id ?? "" }
    }

    private var composed: ItemDraft {
        var next = draft
        next.tags = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        switch type {
        case .login: next.details = .login(login: login)
        case .password: next.details = .password(login: login)
        case .secureNote: next.details = .secureNote(note: SecureNoteDetails(notes: note))
        case .card: next.details = .card(card: card)
        case .identity: next.details = .identity(identity: identity)
        case .wifi: next.details = .wifi(wifi: wifi)
        case .sshKey: next.details = .sshKey(key: sshKey)
        case .environment: next.details = .environment(environment: environment)
        case .document: next.details = .document(document: DocumentDetails(notes: documentNotes))
        case .bankAccount, .apiCredential, .softwareLicense, .idDocument, .cryptoWallet, .database, .custom, .customTemplate:
            next.details = .structured(itemType: type, structured: structured)
        default: break
        }
        return next
    }

    private var changed: Bool { composed != original || !pendingFiles.isEmpty }

    private var sameLoginShown: Binding<Bool> {
        Binding(get: { sameLogin != nil }, set: { if !$0 { sameLogin = nil } })
    }

    /// `copy`: the person saw that the vault has this login already and wants another one.
    private func save(copy: Bool = false) async {
        let next = composed
        var found: [String: String] = [:]
        for error in validateDraft(draft: next) {
            found[error.field] = L10n.text(forKey: error.messageKey) ?? L10n.errors.unexpected
        }
        if type == .document, isNew, pendingFiles.isEmpty { found["file"] = L10n.files.documentRequired }
        errors = found
        formError = found.isEmpty ? nil : L10n.editor.fixErrors(count: found.count)
        guard found.isEmpty else { return Haptics.error() }
        busy = true
        defer { busy = false }
        do {
            // A check that fails (locked meanwhile, say) doesn't stop the save itself.
            if isNew, !copy, let same = try? await model.vault.sameLogin(draft: next) {
                sameLogin = same
                return
            }
            let saved = try await model.vault.saveItem(draft: next)
            for file in pendingFiles {
                do {
                    _ = try await model.vault.addAttachment(itemId: saved.id, path: file.url.path, name: file.name, mediaType: file.mediaType)
                } catch {
                    model.toast = Toast(message: L10n.files.attachFailed(name: file.name, reason: error.message), tone: .danger)
                }
                PickedFiles.discard(file)
            }
            pendingFiles = []
            model.confirm(L10n.editor.saved(title: saved.title))
            // At one of the user's places? Offer the new item to it (Nearby).
            if isNew {
                let vault = model.vault
                Task { await PlaceOffer.shared.consider(saved.id, vault: vault) }
            }
            if let onClose { onClose(saved.id) } else { dismiss() }
        } catch {
            formError = error.message
            Haptics.error()
        }
    }

    private func close() {
        pendingFiles.forEach(PickedFiles.discard)
        if let onClose { onClose(nil) } else { dismiss() }
    }
}

/// A labelled one-line field inside a form, with its error under it.
struct EditorField: View {
    @Environment(\.layoutDirection) private var direction
    let label: String
    @Binding var text: String
    var error: String?
    var hint: String?
    var placeholder: String?
    var keyboard: UIKeyboardType = .default
    var content: UITextContentType?
    var mono = false
    var ltr = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // The label in the body font: on the Mac it shows beside the field, which may be mono.
            TextField(text: $text, prompt: placeholder.map { Text($0) }) { Text(label).font(.body) }
                .keyboardType(keyboard)
                .textContentType(content)
                .textInputAutocapitalization(keyboard == .default && content == nil ? .sentences : .never)
                .autocorrectionDisabled(keyboard != .default || mono)
                .font(mono ? .secret() : .body)
                .environment(\.layoutDirection, ltr ? .leftToRight : direction)
                .accessibilityIdentifier("field-\(label)")
            if let error {
                Text(error).font(.footnote).foregroundStyle(Color.dangerText)
            } else if let hint {
                Text(hint).font(.footnote).foregroundStyle(Color.mist)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityHint(error ?? "")
    }
}

extension Binding where Value == String? {
    /// An optional text as a field's text: empty is none.
    var text: Binding<String> {
        Binding<String>(get: { wrappedValue ?? "" }, set: { wrappedValue = $0.isEmpty ? nil : $0 })
    }
}

/// The first website that names a site: a regular expression doesn't.
private func firstSite(urls: [String], modes: [String: String]) -> String? {
    let site = urls.first { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && modes[$0] != "regex" }
    return site?.trimmingCharacters(in: .whitespacesAndNewlines)
}

extension UrlMatchNames {
    /// What the two domain-wide rules fill, under the "Fill on" picker: they differ on other
    /// parts of the domain (shop.example.com for login.example.com).
    static func help(_ mode: String) -> String? {
        switch mode {
        case "subdomains": L10n.editor.matchHelp.subdomains
        case "baseDomain": L10n.editor.matchHelp.baseDomain
        default: nil
        }
    }
}

/// A secret in a form: dots at rest, the text while it's being edited or after Show. It's never a
/// `SecureField`: iOS offers to save what a secure field held to its own password manager when the
/// screen closes, whatever its content type, and a vault's secrets don't belong there (plan 17).
/// No autocorrection, so the keyboard doesn't learn them either.
struct MaskedField: View {
    let label: String
    @Binding var text: String
    var keyboard: UIKeyboardType = .default
    @State private var shown = false
    @FocusState private var focused: Bool

    var body: some View {
        HStack {
            if text.isEmpty || shown || focused {
                TextField(label, text: $text)
                    .font(.secret())
                    .textContentType(.oneTimeCode)
                    .keyboardType(keyboard)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .focused($focused)
                    .accessibilityIdentifier("field-\(label)")
            } else {
                Button {
                    shown = true
                    focused = true
                } label: {
                    Text(String(repeating: "•", count: min(max(text.count, 8), 16)))
                        .font(.secret())
                        .foregroundStyle(Color.ink)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(L10n.common.revealWhat(what: label))
                .accessibilityIdentifier("masked-\(label)")
            }
            if !text.isEmpty {
                Button { shown.toggle() } label: { Image(systemName: shown ? "eye.slash" : "eye").foregroundStyle(Color.mist) }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(shown ? L10n.common.hideWhat(what: label) : L10n.common.revealWhat(what: label))
            }
        }
        .environment(\.layoutDirection, .leftToRight)
    }
}

/// A `MaskedField` with its error or hint under it.
struct SecretEditorField: View {
    let label: String
    @Binding var text: String
    var error: String?
    var hint: String?
    var keyboard: UIKeyboardType = .default

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            MaskedField(label: label, text: $text, keyboard: keyboard)
            if let error {
                Text(error).font(.footnote).foregroundStyle(Color.dangerText)
            } else if let hint {
                Text(hint).font(.footnote).foregroundStyle(Color.mist)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityHint(error ?? "")
    }
}

/// A login's or password's fields: sign-in details with the generator and masked email, the
/// one-time code, websites with their match rules, recovery info, more fields and notes.
private struct LoginEditor: View {
    @Environment(AppModel.self) private var model
    @Binding var login: LoginDetails
    @Binding var urls: [String]
    @Binding var urlMatch: [String: String]
    @Binding var generating: Bool
    let errors: [String: String]
    let isLogin: Bool
    @State private var makingAlias = false
    @State private var hasMaskedEmail = false

    var body: some View {
        Section(L10n.editor.signIn) {
            if isLogin {
                EditorField(label: L10n.fields.username, text: $login.username.text, content: .username, ltr: true)
                    .accessibilityIdentifier("editor-username")
            }
            if isLogin, hasMaskedEmail {
                Button {
                    Task { await makeAlias() }
                } label: {
                    Label(makingAlias ? L10n.editor.makingMaskedEmail : L10n.editor.useMaskedEmail, systemImage: "envelope.badge.shield.half.filled")
                }
                .disabled(makingAlias)
            }
            HStack {
                SecretEditorField(label: L10n.fields.password, text: $login.password.text)
                    .accessibilityIdentifier("editor-password")
                Button { generating = true } label: { Image(systemName: "wand.and.stars") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(L10n.editor.generate)
                    .accessibilityIdentifier("editor-generate")
            }
            if let password = login.password, !password.isEmpty {
                StrengthMeter(estimate: model.vault.estimateStrength(password: password))
            }
            if isLogin {
                EditorField(label: L10n.fields.totp, text: $login.totp.text, error: errors["totp"], hint: L10n.editor.totpHint,
                            placeholder: L10n.editor.totpPlaceholder, keyboard: .asciiCapable, mono: true)
                EditorField(label: L10n.fields.httpRealm, text: $login.httpRealm.text, hint: L10n.editor.httpRealmHint, keyboard: .asciiCapable)
            }
        }
        if isLogin {
            Section(L10n.editor.websites) {
                ForEach(urls.indices, id: \.self) { index in
                    HStack {
                        EditorField(label: L10n.editor.websiteN(n: index + 1), text: website(index), error: errors["urls.\(index)"],
                                    placeholder: "example.com", keyboard: .URL, ltr: true)
                            .accessibilityIdentifier("editor-website-\(index)")
                        Button(role: .destructive) { removeWebsite(index) } label: { Image(systemName: "minus.circle.fill") }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(L10n.editor.removeWebsite)
                    }
                    let url = urls[index]
                    if !url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        let mode = urlMatch[url] ?? UrlMatchNames.defaultMode
                        Picker(L10n.editor.matchRule, selection: Binding(get: { mode }, set: { urlMatch[url] = $0 })) {
                            ForEach(urlMatchModes(), id: \.self) { Text(UrlMatchNames.name($0)).tag($0) }
                        }
                        .accessibilityIdentifier("editor-match-\(index)")
                        if mode == "regex" {
                            Text(L10n.editor.matchRegexWarning).font(.footnote).foregroundStyle(Color.warnText)
                        } else if let help = UrlMatchNames.help(mode) {
                            Text(help).font(.footnote).foregroundStyle(Color.mist)
                                .accessibilityIdentifier("editor-match-help-\(index)")
                        }
                    }
                }
                Button { urls.append("") } label: { Label(L10n.editor.addWebsite, systemImage: "plus") }
                    .accessibilityIdentifier("editor-add-website")
            }
        }
        if !login.passkeys.isEmpty {
            Section(L10n.detail.passkeys) {
                ForEach(Array(login.passkeys.enumerated()), id: \.offset) { _, passkey in
                    Label("\(passkey.userName) · \(passkey.rpId)", systemImage: "person.badge.key").foregroundStyle(Color.mist)
                }
                Text(L10n.editor.passkeysReadOnly).font(.footnote).foregroundStyle(Color.mist)
            }
        }
        if isLogin {
            RecoveryEditor(recovery: Binding(
                get: { login.recovery ?? RecoveryInfo(email: nil, emailSource: nil, phone: nil, phoneSource: nil, backupCodes: [], securityQuestions: [], twoFactorMethod: nil) },
                set: { login.recovery = $0 }), errors: errors, hasMaskedEmail: hasMaskedEmail, makingAlias: makingAlias) { makeRecoveryAlias() }
        }
        CustomFieldsEditor(fields: $login.customFields)
        Section(L10n.fields.notes) {
            TextEditor(text: $login.notes.text).frame(minHeight: 80).accessibilityLabel(L10n.fields.notes)
        }
        .task { hasMaskedEmail = !((try? await model.vault.maskedEmailConnections()) ?? []).isEmpty }
    }

    private func website(_ index: Int) -> Binding<String> {
        Binding(get: { urls.indices.contains(index) ? urls[index] : "" }, set: { setWebsite(index, to: $0) })
    }

    /// Modes are keyed by the URL as written, so they follow it as it's typed. A row with the same
    /// text keeps what they share.
    private func setWebsite(_ index: Int, to value: String) {
        guard urls.indices.contains(index) else { return }
        let old = urls[index]
        urls[index] = value
        guard old != value, let mode = urlMatch[old] else { return }
        if !urls.contains(old) { urlMatch[old] = nil }
        urlMatch[value] = mode
    }

    private func removeWebsite(_ index: Int) {
        let old = urls.remove(at: index)
        if !urls.contains(old) { urlMatch[old] = nil }
    }

    /// A new alias for the first website. It becomes the username and the recovery email, linked
    /// to its provider, as on the web.
    private func makeAlias() async {
        guard let alias = await newAlias() else { return }
        login.username = alias.email
        setRecovery(alias)
    }

    private func makeRecoveryAlias() {
        Task {
            if let alias = await newAlias() { setRecovery(alias) }
        }
    }

    private func setRecovery(_ alias: MaskedAlias) {
        var recovery = login.recovery ?? RecoveryInfo(email: nil, emailSource: nil, phone: nil, phoneSource: nil, backupCodes: [], securityQuestions: [], twoFactorMethod: nil)
        recovery.email = alias.email
        recovery.emailSource = RecoverySource(kind: "alias", itemId: nil, provider: alias.provider, aliasId: alias.aliasId)
        login.recovery = recovery
    }

    private func newAlias() async -> MaskedAlias? {
        guard let site = firstSite(urls: urls, modes: urlMatch) else {
            model.toast = Toast(message: L10n.editor.maskedEmailNeedsSite, tone: .info)
            return nil
        }
        makingAlias = true
        defer { makingAlias = false }
        do {
            let alias = try await model.vault.createAlias(site: site, connectionId: nil)
            model.confirm(L10n.editor.maskedEmailMade(email: alias.email))
            return alias
        } catch {
            model.show(error)
            return nil
        }
    }
}

/// Recovery info: two-step method, recovery email and phone, backup codes, security questions.
private struct RecoveryEditor: View {
    @Environment(AppModel.self) private var model
    @Binding var recovery: RecoveryInfo
    let errors: [String: String]
    var hasMaskedEmail = false
    var makingAlias = false
    var onMakeAlias: () -> Void = {}
    @State private var identities: [Item] = []
    @State private var pasting = false
    @State private var pasted = ""
    private static let methods = ["totp", "sms", "email", "key", "passkey", "none"]

    /// Typing breaks the link: the value no longer comes from the identity or alias.
    private var email: Binding<String> {
        Binding(get: { recovery.email ?? "" }, set: {
            recovery.email = $0.isEmpty ? nil : $0
            recovery.emailSource = nil
        })
    }

    private var phone: Binding<String> {
        Binding(get: { recovery.phone ?? "" }, set: {
            recovery.phone = $0.isEmpty ? nil : $0
            recovery.phoneSource = nil
        })
    }

    private func choices(_ field: KeyPath<IdentityDetails, String?>) -> [(value: String, source: RecoverySource)] {
        identities.compactMap { item in
            guard case let .identity(identity) = item.details, let value = identity[keyPath: field]?.trimmingCharacters(in: .whitespaces), !value.isEmpty else { return nil }
            return (value, RecoverySource(kind: "identity", itemId: item.id, provider: nil, aliasId: nil))
        }
    }

    var body: some View {
        Section {
            Picker(L10n.fields.twoFactorMethod, selection: $recovery.twoFactorMethod) {
                Text(L10n.editor.notSet).tag(String?.none)
                ForEach(Self.methods, id: \.self) { method in
                    Text(L10n.text(forKey: "twoFactor.\(method)") ?? method).tag(String?.some(method))
                }
            }
            EditorField(label: L10n.fields.recoveryEmail, text: email, error: errors["recovery.email"], keyboard: .emailAddress, content: .emailAddress, ltr: true)
            if hasMaskedEmail {
                Button(action: onMakeAlias) {
                    Label(makingAlias ? L10n.editor.makingMaskedEmail : L10n.editor.useMaskedEmail, systemImage: "envelope.badge.shield.half.filled")
                }
                .disabled(makingAlias)
            }
            ContactLink(source: recovery.emailSource, value: recovery.email, options: choices(\.email), identities: identities) {
                recovery.email = $0
                recovery.emailSource = $1
            } onUnlink: {
                recovery.emailSource = nil
            }
            EditorField(label: L10n.fields.recoveryPhone, text: phone, keyboard: .phonePad, content: .telephoneNumber, ltr: true)
            ContactLink(source: recovery.phoneSource, value: recovery.phone, options: choices(\.phone), identities: identities) {
                recovery.phone = $0
                recovery.phoneSource = $1
            } onUnlink: {
                recovery.phoneSource = nil
            }
            ForEach(recovery.backupCodes.indices, id: \.self) { index in
                HStack {
                    EditorField(label: L10n.editor.codeN(n: index + 1), text: $recovery.backupCodes[index].code, mono: true, ltr: true)
                    Toggle(L10n.detail.codeUsed, isOn: $recovery.backupCodes[index].used).labelsHidden()
                        .accessibilityLabel(L10n.detail.codeUsed)
                    Button(role: .destructive) { recovery.backupCodes.remove(at: index) } label: { Image(systemName: "minus.circle.fill") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(L10n.editor.removeCode(n: index + 1))
                }
            }
            Button { recovery.backupCodes.append(BackupCode(code: "", used: false)) } label: { Label(L10n.editor.addCode, systemImage: "plus") }
            if pasting {
                VStack(alignment: .leading, spacing: 4) {
                    TextEditor(text: $pasted).font(.secret(.footnote)).frame(minHeight: 88)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .environment(\.layoutDirection, .leftToRight)
                        .accessibilityLabel(L10n.editor.pasteCodes)
                    Text(L10n.editor.pasteCodesHint).font(.footnote).foregroundStyle(Color.mist)
                }
                Button(L10n.editor.addCodes) {
                    let codes = pasted.split(whereSeparator: { $0.isWhitespace || $0 == "," }).map { BackupCode(code: String($0), used: false) }
                    recovery.backupCodes += codes
                    pasted = ""
                    pasting = false
                }
            } else {
                Button { pasting = true } label: { Label(L10n.editor.pasteCodes, systemImage: "doc.on.clipboard") }
            }
            Text(L10n.fields.securityQuestions).font(.caption.weight(.medium)).foregroundStyle(Color.mist)
            ForEach(recovery.securityQuestions.indices, id: \.self) { index in
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        EditorField(label: L10n.editor.question(n: index + 1), text: $recovery.securityQuestions[index].question)
                            .accessibilityIdentifier("editor-question-\(index)")
                        Button(role: .destructive) { recovery.securityQuestions.remove(at: index) } label: { Image(systemName: "minus.circle.fill") }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(L10n.editor.removeQuestion(n: index + 1))
                    }
                    HStack(alignment: .bottom) {
                        // No content type: iOS would offer to save it as a password.
                        PasswordInput(label: L10n.fields.securityAnswer, text: $recovery.securityQuestions[index].answer, content: nil)
                            .accessibilityIdentifier("editor-answer-\(index)")
                        Button { recovery.securityQuestions[index].answer = Self.randomAnswer() } label: { Image(systemName: "wand.and.stars") }
                            .buttonStyle(.borderless)
                            .frame(minHeight: 46)
                            .accessibilityLabel(L10n.editor.randomAnswer)
                            .accessibilityIdentifier("editor-random-answer-\(index)")
                    }
                }
            }
            Button { recovery.securityQuestions.append(SecurityQuestion(question: "", answer: Self.randomAnswer())) } label: { Label(L10n.editor.addQuestion, systemImage: "plus") }
                .accessibilityIdentifier("editor-add-question")
            Text(L10n.editor.securityQuestionsHelp).font(.footnote).foregroundStyle(Color.mist)
        } header: {
            Text(L10n.detail.recovery)
        } footer: {
            Text(L10n.editor.recoveryHelp)
        }
        .task {
            let summaries = (try? await model.vault.listItems(filter: ListScope.type(.identity).filter)) ?? []
            var items: [Item] = []
            for summary in summaries {
                if let item = try? await model.vault.getItem(id: summary.id) { items.append(item) }
            }
            identities = items
        }
    }

    /// Words no one can look up, for a site that insists on a question.
    private static func randomAnswer() -> String {
        (try? generatePassword(options: .passphrase(words: 5, separator: " ", capitalize: false, includeNumber: false))) ?? ""
    }
}

/// Where a recovery email or phone came from with a way to unlink it, or else the identities'
/// values to pick from (the web vault's `ContactLink`).
private struct ContactLink: View {
    let source: RecoverySource?
    let value: String?
    let options: [(value: String, source: RecoverySource)]
    let identities: [Item]
    let onPick: (String, RecoverySource) -> Void
    let onUnlink: () -> Void

    var body: some View {
        if let source, let value, !value.isEmpty {
            HStack {
                Text(label(source)).font(.footnote).foregroundStyle(Color.mist)
                Spacer()
                Button(L10n.editor.unlink, action: onUnlink).font(.footnote).buttonStyle(.borderless)
            }
        } else {
            let choices = options.filter { $0.value != value }
            if !choices.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text(L10n.editor.fromIdentities).font(.footnote).foregroundStyle(Color.mist)
                    ForEach(choices, id: \.value) { choice in
                        Button { onPick(choice.value, choice.source) } label: {
                            Text(choice.value).environment(\.layoutDirection, .leftToRight)
                        }
                        .font(.footnote)
                        .buttonStyle(.borderless)
                        .accessibilityLabel(L10n.editor.useContact(value: choice.value))
                    }
                }
            }
        }
    }

    private func label(_ source: RecoverySource) -> String {
        if source.kind == "alias" { return L10n.editor.linkedAlias(provider: MaskedEmailNames.name(source.provider ?? "")) }
        let name = identities.first { $0.id == source.itemId }?.title ?? L10n.types.identity
        return L10n.editor.linkedIdentity(name: name)
    }
}

struct CustomFieldsEditor: View {
    @Binding var fields: [CustomField]

    var body: some View {
        Section(L10n.detail.moreFields) {
            ForEach(fields.indices, id: \.self) { index in
                VStack(alignment: .leading) {
                    HStack {
                        TextField(L10n.editor.fieldLabel, text: $fields[index].label)
                        Button(role: .destructive) { fields.remove(at: index) } label: { Image(systemName: "minus.circle.fill") }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(L10n.editor.removeField(label: fields[index].label.isEmpty ? L10n.editor.fieldN(n: index + 1) : fields[index].label))
                    }
                    if fields[index].hidden {
                        MaskedField(label: L10n.editor.fieldValue, text: $fields[index].value)
                    } else {
                        TextField(L10n.editor.fieldValue, text: $fields[index].value)
                    }
                    Toggle(L10n.editor.fieldHidden, isOn: $fields[index].hidden).font(.footnote)
                }
            }
            Button { fields.append(CustomField(label: "", value: "", hidden: false)) } label: { Label(L10n.editor.addField, systemImage: "plus") }
        }
    }
}

private struct CardEditor: View {
    @Binding var card: CardDetails
    let errors: [String: String]

    var body: some View {
        Section(L10n.editor.cardDetails) {
            EditorField(label: L10n.fields.cardholder, text: $card.cardholder.text, content: .name)
            SecretEditorField(label: L10n.fields.cardNumber, text: $card.number.text, error: errors["number"], keyboard: .numberPad)
            EditorField(label: L10n.fields.expiry, text: $card.expiry.text, error: errors["expiry"], placeholder: L10n.editor.expiryPlaceholder, keyboard: .numbersAndPunctuation, ltr: true)
            SecretEditorField(label: L10n.fields.cvv, text: $card.cvv.text, keyboard: .numberPad)
            SecretEditorField(label: L10n.fields.pin, text: $card.pin.text, keyboard: .numberPad)
            EditorField(label: L10n.fields.brand, text: $card.brand.text, hint: L10n.editor.brandHint)
        }
        Section(L10n.fields.notes) {
            TextEditor(text: $card.notes.text).frame(minHeight: 80).accessibilityLabel(L10n.fields.notes)
        }
    }
}

private struct IdentityEditor: View {
    @Binding var identity: IdentityDetails
    let errors: [String: String]

    private var address: Binding<Address> {
        Binding(get: { identity.address ?? Address(line1: nil, line2: nil, city: nil, region: nil, postalCode: nil, country: nil) },
                set: { identity.address = $0 })
    }

    var body: some View {
        Section(L10n.editor.person) {
            EditorField(label: L10n.fields.firstName, text: $identity.firstName.text, content: .givenName)
            EditorField(label: L10n.fields.lastName, text: $identity.lastName.text, content: .familyName)
            EditorField(label: L10n.fields.email, text: $identity.email.text, error: errors["email"], keyboard: .emailAddress, content: .emailAddress, ltr: true)
            EditorField(label: L10n.fields.phone, text: $identity.phone.text, keyboard: .phonePad, content: .telephoneNumber, ltr: true)
            BirthDatePicker(text: $identity.birthDate)
        }
        Section(L10n.fields.address) {
            EditorField(label: L10n.fields.addressLine1, text: address.line1.text, content: .streetAddressLine1)
            EditorField(label: L10n.fields.addressLine2, text: address.line2.text, content: .streetAddressLine2)
            EditorField(label: L10n.fields.city, text: address.city.text, content: .addressCity)
            EditorField(label: L10n.fields.region, text: address.region.text, content: .addressState)
            EditorField(label: L10n.fields.postalCode, text: address.postalCode.text, content: .postalCode)
            EditorField(label: L10n.fields.country, text: address.country.text, content: .countryName)
        }
        Section(L10n.fields.notes) {
            TextEditor(text: $identity.notes.text).frame(minHeight: 80).accessibilityLabel(L10n.fields.notes)
        }
    }
}

/// A birth date as `YYYY-MM-DD`, or none.
private struct BirthDatePicker: View {
    @Binding var text: String?
    private static let format: DateFormatter = {
        let format = DateFormatter()
        format.dateFormat = "yyyy-MM-dd"
        format.locale = Locale(identifier: "en_US_POSIX")
        format.timeZone = TimeZone(identifier: "UTC")
        return format
    }()

    var body: some View {
        if let date = text.flatMap(Self.format.date(from:)) {
            HStack {
                DatePicker(L10n.fields.birthDate, selection: Binding(get: { date }, set: { text = Self.format.string(from: $0) }), displayedComponents: .date)
                    .environment(\.timeZone, TimeZone(identifier: "UTC")!)
                Button(role: .destructive) { text = nil } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(L10n.common.remove)
            }
        } else {
            Button { text = "1990-01-01" } label: { Label(L10n.fields.birthDate, systemImage: "calendar.badge.plus") }
        }
    }
}

/// A Wi-Fi network's fields: the name exactly as broadcast, security, password, and the
/// Enterprise sign-in for the Enterprise kinds.
private struct WifiEditor: View {
    @Environment(AppModel.self) private var model
    @Binding var wifi: WifiDetails
    @Binding var generating: Bool
    let errors: [String: String]
    private let choices = wifiChoices()

    /// Personal networks share one password; an Enterprise network's is each person's own.
    private var shared: Bool { wifi.security != "open" && !WifiNames.isEnterprise(wifi.security) }

    var body: some View {
        Section(L10n.wifi.network) {
            VStack(alignment: .leading, spacing: 4) {
                // Spaces at either end are part of the name: kept as typed.
                TextField(L10n.wifi.ssid, text: $wifi.ssid)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("editor-ssid")
                if let error = errors["ssid"] {
                    Text(error).font(.footnote).foregroundStyle(Color.dangerText)
                } else {
                    Text(L10n.wifi.ssidHint).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            Picker(L10n.wifi.security, selection: $wifi.security) {
                ForEach(choices.securities, id: \.self) { Text(WifiNames.security($0)).tag($0) }
            }
            Text(wifi.security == "open" ? L10n.wifi.openHint : L10n.wifi.securityHint).font(.footnote).foregroundStyle(Color.mist)
            if shared {
                HStack {
                    SecretEditorField(label: L10n.fields.password, text: $wifi.password.text, error: errors["password"],
                                      hint: wifi.security == "wep" ? L10n.wifi.wepHint : L10n.wifi.wpaHint)
                    if wifi.security != "wep" {
                        Button { generating = true } label: { Image(systemName: "wand.and.stars") }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(L10n.editor.generate)
                    }
                }
                if let password = wifi.password, !password.isEmpty, wifi.security != "wep" {
                    StrengthMeter(estimate: model.vault.estimateStrength(password: password))
                }
            }
            Toggle(isOn: $wifi.hidden) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.wifi.hidden)
                    Text(L10n.wifi.hiddenHint).font(.footnote).foregroundStyle(Color.mist)
                }
            }
        }
        if WifiNames.isEnterprise(wifi.security) {
            Section {
                Picker(L10n.wifi.eapMethod, selection: $wifi.eapMethod) {
                    Text(L10n.editor.notSet).tag(String?.none)
                    ForEach(choices.eapMethods, id: \.self) { Text(WifiNames.eapMethod($0)).tag(String?.some($0)) }
                }
                if wifi.eapMethod == "peap" || wifi.eapMethod == "ttls" {
                    Picker(L10n.wifi.phase2, selection: $wifi.phase2) {
                        Text(L10n.editor.notSet).tag(String?.none)
                        ForEach(choices.phase2, id: \.self) { Text(WifiNames.phase2($0)).tag(String?.some($0)) }
                    }
                }
                EditorField(label: L10n.fields.username, text: $wifi.username.text, content: .username, ltr: true)
                if wifi.eapMethod != "tls" {
                    SecretEditorField(label: L10n.fields.password, text: $wifi.password.text)
                }
                EditorField(label: L10n.wifi.identity, text: $wifi.identity.text, hint: L10n.wifi.identityHint, ltr: true)
                EditorField(label: L10n.wifi.serverDomain, text: $wifi.serverDomain.text, hint: L10n.wifi.serverDomainHint, keyboard: .URL, ltr: true)
                VStack(alignment: .leading) {
                    Text(L10n.wifi.caCertificate).font(.caption).foregroundStyle(Color.mist)
                    TextEditor(text: $wifi.caCertificate.text).font(.secret(.footnote)).frame(minHeight: 80)
                        .accessibilityLabel(L10n.wifi.caCertificate)
                    Text(L10n.wifi.caCertificateHint).font(.footnote).foregroundStyle(Color.mist)
                }
            } header: {
                Text(L10n.wifi.enterprise)
            } footer: {
                Text(L10n.wifi.enterpriseHelp)
            }
        }
        Section(L10n.wifi.about) {
            Toggle(L10n.wifi.captivePortal, isOn: $wifi.captivePortal)
            Toggle(L10n.wifi.managed, isOn: $wifi.managed)
            Toggle(L10n.wifi.hotspot, isOn: $wifi.hotspot)
        }
        CustomFieldsEditor(fields: $wifi.customFields)
        Section(L10n.fields.notes) {
            TextEditor(text: $wifi.notes.text).frame(minHeight: 80).accessibilityLabel(L10n.fields.notes)
        }
    }
}

/// A new item's files, chosen before it's saved; they upload after the save.
private struct PendingFilesSection: View {
    @Binding var files: [PickedFile]
    let document: Bool
    let error: String?
    @State private var importing = false
    @State private var choosingPhotos = false
    @State private var photos: [PhotosPickerItem] = []
    @State private var camera = false

    var body: some View {
        Section {
            ForEach(files.indices, id: \.self) { index in
                HStack {
                    Label(files[index].name, systemImage: "doc")
                    Spacer()
                    Text(L10n.files.pending).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            Menu {
                Button { importing = true } label: { Label(L10n.files.fromFiles, systemImage: "folder") }
                Button { choosingPhotos = true } label: { Label(L10n.files.fromPhotos, systemImage: "photo.on.rectangle") }
                if PickedFiles.cameraAvailable {
                    Button { camera = true } label: { Label(L10n.files.fromCamera, systemImage: "camera") }
                }
            } label: {
                Label(document ? L10n.files.attachOne : L10n.files.attach, systemImage: "paperclip")
            }
            .accessibilityIdentifier("editor-attach")
            if let error { Text(error).font(.footnote).foregroundStyle(Color.dangerText) }
        } header: {
            Text(document ? L10n.files.documentTitle : L10n.files.title)
        } footer: {
            Text(document ? L10n.files.documentHint : L10n.files.phoneHint)
        }
        .filePicker(isPresented: $importing, multiple: true) { urls in
            files += urls.compactMap { try? PickedFiles.copy($0) }
        }
        .photosPicker(isPresented: $choosingPhotos, selection: $photos, matching: .any(of: [.images, .videos]))
        .onChange(of: photos) { _, picked in
            guard !picked.isEmpty else { return }
            photos = []
            Task {
                for item in picked {
                    if let file = await PickedFiles.copy(item) { files.append(file) }
                }
            }
        }
        .fullScreenCover(isPresented: $camera) {
            CameraPicker { image in
                camera = false
                if let image, let file = PickedFiles.save(photo: image) { files.append(file) }
            }
            .ignoresSafeArea()
        }
    }
}
