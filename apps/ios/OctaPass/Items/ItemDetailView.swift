import OctaPassResources
import OctaPassVault
import SwiftUI

/// One item (the web vault's `ItemDetail`): its fields by type, files, tags and where it lives.
/// Favourite, pin, trash, edit, version history, and the More menu (share a copy, move, copy, QR code);
/// in the trash, restore. Kept fresh as the vault changes.
struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    @Environment(\.dismiss) private var dismiss
    let itemId: String
    @State private var item: Item?
    @State private var error: Error?
    @State private var editing = false
    @State private var busy = false
    @State private var showingQr = false
    @State private var sharingLink = false
    @State private var moveCopy: MoveCopyMode?
    @State private var addingCode = false
    @State private var linkingCode = false
    @State private var showingHistory = false
    @State private var sharingGuestLink = false
    @State private var memberCount: Int?
    @Environment(\.detailEditor) private var detailEditor

    var body: some View {
        Group {
            if let item {
                content(item)
            } else if let error {
                EmptyStateView(
                    icon: "exclamationmark.triangle",
                    title: error.isVault(.notFound) ? L10n.detail.notFound : L10n.detail.loadFailed,
                    message: error.isVault(.notFound) ? L10n.detail.notFoundBody : error.message)
            } else {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        // First on the Mac's detail column: Back would only go to "Select an item".
        .navigationBarBackButtonHidden(detailEditor?.path.first == .item(itemId))
        .task(id: model.itemsVersion) { await load() }
    }

    private func load() async {
        do {
            item = try await model.vault.getItem(id: itemId)
            error = nil
        } catch {
            self.error = error
        }
    }

    private func content(_ item: Item) -> some View {
        let vault = directory.vault(item.vaultId)
        let readOnly = vault.map { !$0.canWrite } ?? false
        let trashed = item.deletedAt != nil
        let onGuestLink: (() -> Void)? = trashed ? nil : { sharingGuestLink = true }
        return List {
            if trashed, let deleted = item.deletedAt.flatMap(Dates.parse) {
                Notice(text: L10n.trash.itemNotice(count: max(0, Int(ceil(Double(trashDays) - Date().timeIntervalSince(deleted) / 86_400)))), tone: .warn)
                    .listRowBackground(Color.clear)
            }
            if readOnly, let vault {
                Notice(text: L10n.detail.readOnly(vault: vault.name), tone: .info)
                    .listRowBackground(Color.clear)
            }
            Section { header(item) }
                .listRowBackground(Color.clear)
            if case .document = item.details, !model.isLocal {
                FilesSection(item: item, editable: !trashed && !readOnly)
            }
            ItemTypeFields(item: item, onShowQr: { showingQr = true }, hotpItemId: trashed || readOnly ? nil : item.id, onGuestLink: onGuestLink)
            codeActions(item, editable: !trashed && !readOnly)
            if case .document = item.details {} else if item.itemType != .customTemplate, !model.isLocal, !item.attachments.isEmpty || (!trashed && !readOnly) {
                FilesSection(item: item, editable: !trashed && !readOnly)
            }
            if !item.tags.isEmpty {
                Section(L10n.fields.tags) {
                    Text(item.tags.joined(separator: " · ")).foregroundStyle(Color.ink)
                }
            }
            if !trashed { ItemPlacesSection(item: item, editable: !readOnly) }
            Section {
                meta(item, vault)
                // Version history lives on the server; a vault on this device only keeps none.
                if !trashed, !model.isLocal {
                    Button { showingHistory = true } label: { Label(L10n.history.action, systemImage: "clock") }
                        .accessibilityIdentifier("item-history")
                }
            }
        }
        .listStyle(.platformGrouped)
        // Copying a field here, or opening the website, counts as using the item.
        .environment(\.usedItemId, trashed ? nil : item.id)
        .navigationTitle(item.title.isEmpty ? L10n.detail.untitled : item.title)
        .toolbar { toolbar(item, readOnly: readOnly, trashed: trashed) }
        .focusedSceneValue(\.itemCommand, trashed ? nil : command(item))
        .sheet(isPresented: $editing) { ItemEditorSheet(draft: itemDraft(item: item)) }
        .sheet(isPresented: $showingQr) { QrSheet(item: item) }
        .sheet(isPresented: $sharingLink) { ShareLinkSheet(item: item) }
        .sheet(item: $moveCopy) { MoveCopySheet(item: item, mode: $0) }
        .sheet(isPresented: $addingCode) { AddCodeSheet(item: item) }
        .sheet(isPresented: $linkingCode) { LinkToLoginSheet(item: item) }
        .sheet(isPresented: $showingHistory) { ItemHistorySheet(item: item, editable: !readOnly) }
        .sheet(isPresented: $sharingGuestLink) { WifiGuestSheet(item: item) }
    }

    /// A one-time code without opening the editor: add one to a login, or move a code that came
    /// in on an item of its own into the login it belongs to.
    @ViewBuilder
    private func codeActions(_ item: Item, editable: Bool) -> some View {
        let login: LoginDetails? = {
            switch item.details {
            case let .login(details), let .password(details): details
            default: nil
            }
        }()
        if editable, let login {
            if (login.totp ?? "").isEmpty {
                Section {
                    Button { addingCode = true } label: { Label(L10n.otp.addCode, systemImage: "plus") }
                        .accessibilityIdentifier("add-code")
                }
            } else if isCodeOnly(item) {
                Section {
                    Button { linkingCode = true } label: { Label(L10n.otp.linkAction, systemImage: "link") }
                        .accessibilityIdentifier("link-code")
                }
            }
        }
    }

    private func header(_ item: Item) -> some View {
        HStack(spacing: 14) {
            Avatar(name: item.title, iconDomain: iconDomain(urls: item.urls), size: 64)
            VStack(alignment: .leading, spacing: 4) {
                Text(item.title.isEmpty ? L10n.detail.untitled : item.title)
                    .font(.title2.weight(.bold))
                    .foregroundStyle(Color.ink)
                    .accessibilityAddTraits(.isHeader)
                if let host = item.urls.first(where: { item.urlMatch[$0] != "regex" }).flatMap(Self.host) {
                    Text(host).foregroundStyle(Color.mist).environment(\.layoutDirection, .leftToRight)
                } else {
                    Text(item.itemType.typeName).foregroundStyle(Color.mist)
                }
                Label(L10n.detail.encrypted, systemImage: "lock.fill")
                    .font(.caption)
                    .foregroundStyle(Color.freeText)
            }
        }
        .listRowInsets(EdgeInsets())
    }

    static func host(_ url: String) -> String? {
        let text = url.contains("://") ? url : "https://\(url)"
        return URLComponents(string: text)?.host.map { $0.hasPrefix("www.") ? String($0.dropFirst(4)) : $0 }
    }

    @ViewBuilder
    private func meta(_ item: Item, _ vault: Vault?) -> some View {
        if let vault {
            Label(memberCount.map { L10n.detail.inSharedVault(vault: vault.name, count: $0) } ?? L10n.detail.inVault(vault: vault.name), systemImage: vault.icon)
                .task(id: vault.id) {
                    if vault.vaultType != .personal, let members = try? await model.vault.listMembers(vaultId: vault.id) { memberCount = members.count }
                }
        }
        Label(L10n.detail.updated(date: Dates.long(item.shownUpdatedAt ?? item.updatedAt)), systemImage: "clock.arrow.circlepath")
        Label(L10n.detail.created(date: Dates.long(item.shownCreatedAt ?? item.createdAt)), systemImage: "calendar")
        if let changed = item.passwordChangedAt {
            Label(L10n.detail.passwordChanged(date: Dates.long(changed)), systemImage: "key")
        }
        if let used = item.lastUsedAt {
            Label(L10n.detail.lastUsed(date: Dates.long(used)), systemImage: "hand.tap")
        }
    }

    @ToolbarContentBuilder
    private func toolbar(_ item: Item, readOnly: Bool, trashed: Bool) -> some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            if trashed {
                Button {
                    run({ try await model.vault.restoreItem(id: item.id) }, L10n.detail.restored(title: item.title))
                } label: {
                    Label(L10n.trash.restore, systemImage: "arrow.uturn.backward")
                }
                .disabled(busy)
            } else {
                if !readOnly {
                    Button(L10n.common.edit) { edit(item) }
                        .accessibilityIdentifier("edit-item")
                }
                moreMenu(item, readOnly: readOnly)
            }
        }
    }

    /// The editor: in the Mac's detail column, a sheet elsewhere.
    private func edit(_ item: Item) {
        if let detailEditor { detailEditor.open(itemDraft(item: item)) } else { editing = true }
    }

    /// The Mac's Copy username, password and one-time code commands, for a login or password.
    /// They copy as the item's own buttons do: the password asks "Confirm it's you" unless this
    /// unlock covers it, and each counts as using the item.
    private func command(_ item: Item) -> ItemCommand {
        let login: LoginDetails? = {
            switch item.details {
            case let .login(details), let .password(details): details
            default: nil
            }
        }()
        func present(_ value: String?) -> String? { value.flatMap { $0.isEmpty ? nil : $0 } }
        let model = model
        var command = ItemCommand()
        if let username = present(login?.username) {
            command.copyUsername = { model.copy(username, what: L10n.fields.username, secret: false, item: item.id) }
        }
        if let password = present(login?.password) {
            command.copyPassword = {
                Task {
                    guard await model.confirmReveal() else { return }
                    model.copy(password, what: L10n.fields.password, item: item.id)
                }
            }
        }
        if let secret = present(login?.totp) {
            command.copyCode = {
                if let code = try? totpCode(totp: secret, atMs: nil) {
                    model.copy(code.code, what: L10n.fields.totp, item: item.id)
                } else {
                    model.toast = Toast(message: L10n.copy.failed, tone: .danger)
                }
            }
        }
        return command
    }

    private func moreMenu(_ item: Item, readOnly: Bool) -> some View {
        let otherVaults = directory.vaults.contains { $0.id != item.vaultId && $0.canWrite }
        return Menu {
            if !readOnly {
                Button {
                    run({ _ = try await model.vault.setFavorite(id: item.id, favorite: !item.favorite) },
                        item.favorite ? L10n.detail.unfavorited : L10n.detail.favorited)
                } label: {
                    Label(item.favorite ? L10n.detail.removeFavorite : L10n.detail.addFavorite, systemImage: item.favorite ? "star.slash" : "star")
                }
                Button {
                    run({ _ = try await model.vault.setPinned(id: item.id, pinned: !item.pinned) },
                        item.pinned ? L10n.detail.unpinned : L10n.detail.pinned)
                } label: {
                    Label(item.pinned ? L10n.detail.unpin : L10n.detail.pin, systemImage: item.pinned ? "pin.slash" : "pin")
                }
                .accessibilityIdentifier("item-pin")
            }
            if !qrChoices(item: item).isEmpty {
                Button { showingQr = true } label: { Label(L10n.phone.showQr, systemImage: "qrcode") }
            }
            if !model.isLocal {
                Button { sharingLink = true } label: { Label(L10n.shareLink.action, systemImage: "link") }
            }
            if otherVaults && !readOnly {
                Button { moveCopy = .move } label: { Label(L10n.moveCopy.move, systemImage: "folder") }
            }
            if otherVaults {
                Button { moveCopy = .copy } label: { Label(L10n.moveCopy.copy, systemImage: "plus.square.on.square") }
            }
            if !readOnly {
                Divider()
                Button(role: .destructive) {
                    run({ try await model.vault.deleteItem(id: item.id) }, L10n.detail.trashed(title: item.title)) { dismiss() }
                } label: {
                    Label(L10n.detail.moveToTrash, systemImage: "trash")
                }
                .accessibilityIdentifier("move-to-trash")
            }
        } label: {
            Label(L10n.detail.more, systemImage: "ellipsis.circle")
        }
        .disabled(busy)
        .accessibilityIdentifier("item-more")
    }

    private func run(_ action: @escaping () async throws -> Void, _ message: String, after: @escaping () -> Void = {}) {
        busy = true
        Task {
            defer { busy = false }
            do {
                try await action()
                model.confirm(message)
                after()
            } catch {
                model.show(error)
            }
        }
    }
}

/// The fields of each type, in the web vault's order. `hotpItemId`: the item a counter-based code
/// can be moved on, left out where nothing can be saved. `past`: an old version, which shows the
/// fields and nothing that acts on the item or network as they are now.
struct ItemTypeFields: View {
    let item: Item
    var onShowQr: () -> Void = {}
    var hotpItemId: String?
    var onGuestLink: (() -> Void)?
    var past = false

    var body: some View {
        switch item.details {
        case let .login(login), let .password(login):
            LoginFields(item: item, login: login, onShowQr: onShowQr, hotpItemId: hotpItemId, past: past)
        case let .card(card):
            CardFields(card: card)
        case let .identity(identity):
            IdentityFields(identity: identity)
        case let .secureNote(note):
            if !note.notes.isEmpty {
                Section { SecretFieldRow(label: L10n.fields.note, value: note.notes, multiline: true) }
            }
        case let .wifi(wifi):
            WifiFields(item: item, wifi: wifi, onShowQr: onShowQr, onGuestLink: onGuestLink, past: past)
        case let .document(document):
            if let notes = document.notes, !notes.isEmpty {
                Section(L10n.fields.notes) { SecretFieldRow(label: L10n.fields.notes, value: notes, multiline: true) }
            }
        case let .sshKey(key):
            SshKeyFields(item: item, key: key)
        case let .environment(environment):
            EnvironmentFields(item: item, environment: environment)
        case let .structured(itemType, structured):
            StructuredFields(item: item, type: itemType, details: structured)
        case .maskedEmailProvider, .other:
            EmptyView()
        }
    }
}

private struct LoginFields: View {
    @Environment(AppModel.self) private var model
    let item: Item
    let login: LoginDetails
    let onShowQr: () -> Void
    let hotpItemId: String?
    let past: Bool

    var body: some View {
        if !past { ReusedPasswordSection(itemId: item.id) }
        Section {
            if let username = login.username, !username.isEmpty {
                FieldRow(label: L10n.fields.username, value: username)
            }
            if let password = login.password, !password.isEmpty {
                SecretFieldRow(label: L10n.fields.password, value: password)
                    .accessibilityIdentifier("password-field")
            }
            if let totp = login.totp, !totp.isEmpty {
                if isHotp(totp: totp) {
                    HotpField(itemId: hotpItemId, secret: totp)
                } else {
                    HStack {
                        Text(L10n.fields.totp).font(.caption.weight(.medium)).foregroundStyle(Color.mist)
                        Spacer()
                        LiveCode(secret: totp, large: true)
                    }
                }
            }
            // Each site once: other apps write one site several ways (`https://a.example/`, `/login`, `www.`).
            ForEach(Array(uniqueWebsites(urls: item.urls, urlMatch: item.urlMatch).enumerated()), id: \.offset) { index, url in
                WebsiteRow(label: index == 0 ? L10n.fields.website : L10n.fields.otherWebsite, url: url, mode: item.urlMatch[url])
            }
            if let realm = login.httpRealm, !realm.isEmpty {
                FieldRow(label: L10n.fields.httpRealm, value: realm, copyable: false)
            }
        }
        // For "Password used on 3 other logins": after edits, and for what changed elsewhere.
        .task(id: model.itemsVersion) { if !past { await ReusedPasswordSection.load(model) } }
        if !login.passkeys.isEmpty {
            Section(L10n.detail.passkeys) {
                ForEach(Array(login.passkeys.enumerated()), id: \.offset) { _, passkey in
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(passkey.userName).foregroundStyle(Color.ink)
                            Text("\(passkey.rpId) · \(L10n.detail.passkeySaved(date: Dates.long(passkey.createdAt)))")
                                .font(.footnote).foregroundStyle(Color.mist)
                        }
                    } icon: {
                        Image(systemName: "person.badge.key")
                    }
                }
            }
        }
        if let recovery = login.recovery {
            RecoveryFields(itemId: item.id, recovery: recovery, past: past)
        }
        CustomFieldsSection(fields: login.customFields)
        if let notes = login.notes, !notes.isEmpty {
            Section(L10n.fields.notes) { SecretFieldRow(label: L10n.fields.notes, value: notes, multiline: true) }
        }
        PasswordHistorySection(history: login.passwordHistory)
        if !past, let network = item.wifi {
            Section { WifiActions(network: network, details: nil, onShowQr: onShowQr) }
        }
    }
}

/// "Password used on 3 other logins", from Health's reused groups (the same password, whatever the
/// username), with the report Health keeps; a group dismissed in Health shows nothing.
private struct ReusedPasswordSection: View {
    @State private var store = HealthStore.shared
    let itemId: String

    var body: some View {
        let others = ReusedPasswordSection.others(of: itemId, in: store)
        if !others.isEmpty {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Label {
                        Text(L10n.detail.reuseTitle(count: others.count)).font(.subheadline.weight(.semibold)).foregroundStyle(Color.ink)
                    } icon: {
                        Image(systemName: "exclamationmark.circle.fill").foregroundStyle(Color.warn)
                    }
                    Text(L10n.detail.reuseBody).font(.footnote).foregroundStyle(Color.mist)
                }
                .accessibilityElement(children: .combine)
                NavigationLink(L10n.detail.reuseSee, value: Route.reusedPasswords(itemId))
                    .accessibilityIdentifier("reused-password-list")
            }
        }
    }

    /// Health's report, built once and again after edits; LoginFields asks for it.
    @MainActor static func load(_ model: AppModel) async {
        let store = HealthStore.shared
        await store.load(model.vault, again: store.report != nil)
    }

    /// The other logins in this item's reused group, unless the group was dismissed.
    static func others(of itemId: String, in store: HealthStore) -> [HealthEntry] {
        guard let group = store.report?.reused.first(where: { $0.contains { $0.itemId == itemId } }),
              group.contains(where: store.isShown) else { return [] }
        return group.filter { $0.itemId != itemId }
    }
}

/// The other logins with this password: each opens its item, and "Change password" opens the
/// site's change-password page, then the generator to save the new one.
struct ReusedPasswordList: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @State private var store = HealthStore.shared
    @State private var changing: HealthEntry?
    let itemId: String

    var body: some View {
        List {
            ForEach(ReusedPasswordSection.others(of: itemId, in: store), id: \.itemId) { entry in
                Section {
                    // The change-password address is on the login's first website, so its host names the site.
                    let site = entry.changePasswordUrl.flatMap(ItemDetailView.host)
                    let subtitle = [entry.subtitle, site].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
                    HealthRow(entry: entry, subtitle: subtitle.isEmpty ? nil : subtitle)
                    Button {
                        if let url = entry.changePasswordUrl.flatMap(URL.init(string:)) { openURL(url) }
                        changing = entry
                    } label: {
                        Label(L10n.health.change.action, systemImage: entry.changePasswordUrl == nil ? "key" : "arrow.up.right")
                    }
                }
            }
        }
        .navigationTitle(L10n.detail.reuseList)
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $changing) { entry in
            GeneratorSheet { password in
                Task {
                    try? await model.vault.updatePassword(itemId: entry.itemId, password: password)
                    await store.load(model.vault, again: true)
                }
            }
        }
    }
}

/// A website: opens in the browser; Copy copies the address. Its match rule shows unless it's the
/// default, and a regular expression is shown as text: it isn't an address to open.
struct WebsiteRow: View {
    @Environment(\.openURL) private var openURL
    @Environment(AppModel.self) private var model
    @Environment(\.usedItemId) private var usedItemId
    let label: String
    let url: String
    var mode: String?

    var body: some View {
        HStack(spacing: 12) {
            if mode == "regex" {
                VStack(alignment: .leading, spacing: 3) {
                    Text(label).font(.caption.weight(.medium)).foregroundStyle(Color.mist)
                    Text(url)
                        .font(.secret(.callout))
                        .foregroundStyle(Color.ink)
                        .textSelection(.enabled)
                        .environment(\.layoutDirection, .leftToRight)
                    modeName
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Button {
                    if let target = URL(string: url.contains("://") ? url : "https://\(url)") {
                        openURL(target)
                        // Opening the website counts as using the login, as copying from it does.
                        if let usedItemId { model.vault.recordItemUse(id: usedItemId) }
                    }
                } label: {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(label).font(.caption.weight(.medium)).foregroundStyle(Color.mist)
                        HStack(spacing: 4) {
                            Text(ItemDetailView.host(url) ?? url).foregroundStyle(Color.trustText)
                            Image(systemName: "arrow.up.right").font(.caption).foregroundStyle(Color.trustText)
                        }
                        .environment(\.layoutDirection, .leftToRight)
                        modeName
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.plain)
            }
            CopyButton(value: url, what: L10n.fields.website, secret: false)
        }
    }

    @ViewBuilder private var modeName: some View {
        if let mode, mode != UrlMatchNames.defaultMode {
            Text(UrlMatchNames.name(mode)).font(.caption).foregroundStyle(Color.mist)
        }
    }
}

/// The catalog's names for website match rules.
enum UrlMatchNames {
    static let defaultMode = "subdomains"

    static func name(_ mode: String) -> String { L10n.text(forKey: "editor.match.\(mode)") ?? mode }
}

struct CustomFieldsSection: View {
    let fields: [CustomField]

    var body: some View {
        if !fields.isEmpty {
            Section(L10n.detail.moreFields) {
                ForEach(Array(fields.enumerated()), id: \.offset) { _, field in
                    if field.hidden {
                        SecretFieldRow(label: field.label, value: field.value)
                    } else {
                        FieldRow(label: field.label, value: field.value)
                    }
                }
            }
        }
    }
}

struct PasswordHistorySection: View {
    let history: [PasswordHistoryEntry]

    var body: some View {
        if !history.isEmpty {
            Section {
                DisclosureGroup(L10n.detail.passwordHistory(count: history.count)) {
                    ForEach(Array(history.enumerated()), id: \.offset) { _, entry in
                        SecretFieldRow(label: L10n.detail.changedOn(date: Dates.long(entry.changedAt)), value: entry.password, what: L10n.detail.oldPassword)
                    }
                }
            }
        }
    }
}

/// Recovery info: the two-step method, the recovery email and phone with where they came from
/// and how many other logins they reset (the recovery map), security questions and backup codes.
private struct RecoveryFields: View {
    @Environment(AppModel.self) private var model
    let itemId: String
    let recovery: RecoveryInfo
    let past: Bool
    @State private var showCodes = false
    @State private var identityTitle: String?
    @State private var report: HealthReport?

    var body: some View {
        Section(L10n.detail.recovery) {
            if let method = recovery.twoFactorMethod, !method.isEmpty {
                FieldRow(label: L10n.fields.twoFactorMethod, value: L10n.text(forKey: "twoFactor.\(method)") ?? method, copyable: false)
            }
            if let email = recovery.email, !email.isEmpty {
                contact(L10n.fields.recoveryEmail, email, recovery.emailSource)
            }
            if let phone = recovery.phone, !phone.isEmpty {
                contact(L10n.fields.recoveryPhone, phone, recovery.phoneSource)
            }
            ForEach(Array(recovery.securityQuestions.enumerated()), id: \.offset) { _, entry in
                SecretFieldRow(label: entry.question, value: entry.answer, what: L10n.fields.securityAnswer)
            }
            if !recovery.backupCodes.isEmpty {
                let left = recovery.backupCodes.filter { !$0.used }.count
                DisclosureGroup(isExpanded: $showCodes) {
                    ForEach(Array(recovery.backupCodes.enumerated()), id: \.offset) { _, code in
                        HStack {
                            Text(code.code).font(.secret()).strikethrough(code.used)
                                .foregroundStyle(code.used ? Color.mist : Color.ink)
                            Spacer()
                            Text(code.used ? L10n.detail.codeUsed : L10n.detail.codeUnused).font(.footnote).foregroundStyle(Color.mist)
                        }
                        .environment(\.layoutDirection, .leftToRight)
                    }
                } label: {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(L10n.fields.backupCodes).font(.caption.weight(.medium)).foregroundStyle(Color.mist)
                        Text(L10n.detail.codesLeft(left: left, count: recovery.backupCodes.count))
                            .foregroundStyle(left <= 2 ? Color.warnText : Color.ink)
                    }
                }
            }
        }
        .task {
            let id = recovery.emailSource?.kind == "identity" ? recovery.emailSource?.itemId : recovery.phoneSource?.itemId
            if let id, let item = try? await model.vault.getItem(id: id) { identityTitle = item.title }
            report = try? await model.vault.healthReport()
        }
    }

    /// How many other logins this email or phone resets (the recovery map).
    private func alsoResets(_ value: String) -> Int? {
        let contact = value.trimmingCharacters(in: .whitespaces).lowercased()
        return report?.recovery.first { $0.value.lowercased() == contact && $0.logins.contains { $0.itemId == itemId } }
            .map { $0.logins.filter { $0.itemId != itemId }.count }
    }

    private func contact(_ label: String, _ value: String, _ source: RecoverySource?) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            FieldRow(label: label, value: value, ltr: true)
            if let others = alsoResets(value), others > 0 {
                if report != nil {
                    NavigationLink(value: Route.recoveryMap) {
                        Text(L10n.detail.alsoResets(count: others)).font(.footnote)
                    }
                }
            }
            if let source {
                if source.kind == "alias", let provider = source.provider {
                    Text(L10n.detail.linkedAlias(provider: MaskedEmailNames.name(provider))).font(.footnote).foregroundStyle(Color.mist)
                } else if source.kind == "identity", let identityTitle, let id = source.itemId {
                    if past {
                        Text(L10n.detail.linkedIdentity(name: identityTitle)).font(.footnote).foregroundStyle(Color.mist)
                    } else {
                        NavigationLink(value: Route.item(id)) {
                            Text(L10n.detail.linkedIdentity(name: identityTitle)).font(.footnote)
                        }
                    }
                }
            }
        }
    }
}

private struct CardFields: View {
    let card: CardDetails

    var body: some View {
        Section {
            CardFace(card: card).listRowInsets(EdgeInsets()).listRowBackground(Color.clear)
        }
        Section {
            if let holder = card.cardholder, !holder.isEmpty { FieldRow(label: L10n.fields.cardholder, value: holder) }
            if let number = card.number, !number.isEmpty {
                SecretFieldRow(label: L10n.fields.cardNumber, value: number, format: CardFace.formatNumber)
            }
            if let expiry = card.expiry, !expiry.isEmpty { FieldRow(label: L10n.fields.expiry, value: expiry, ltr: true) }
            if let cvv = card.cvv, !cvv.isEmpty { SecretFieldRow(label: L10n.fields.cvv, value: cvv) }
            if let pin = card.pin, !pin.isEmpty { SecretFieldRow(label: L10n.fields.pin, value: pin) }
            if let brand = card.brand, !brand.isEmpty { FieldRow(label: L10n.fields.brand, value: brand, copyable: false) }
        }
        if let notes = card.notes, !notes.isEmpty {
            Section(L10n.fields.notes) { SecretFieldRow(label: L10n.fields.notes, value: notes, multiline: true) }
        }
    }
}

/// The card as a card: last four digits, holder, expiry, brand. Never the full number.
struct CardFace: View {
    let card: CardDetails

    static func formatNumber(_ number: String) -> String {
        let digits = number.filter { !$0.isWhitespace }
        return stride(from: 0, to: digits.count, by: 4).map { index in
            let start = digits.index(digits.startIndex, offsetBy: index)
            let end = digits.index(start, offsetBy: min(4, digits.count - index))
            return String(digits[start..<end])
        }.joined(separator: " ")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                RoundedRectangle(cornerRadius: 4).fill(Color.white.opacity(0.75)).frame(width: 34, height: 26)
                Spacer()
                if let brand = card.brand { Text(brand).font(.headline).foregroundStyle(.white) }
            }
            Text("•••• \(String(card.number?.filter(\.isNumber).suffix(4) ?? "••••"))")
                .font(.secret(.title3))
                .foregroundStyle(.white)
            HStack {
                Text(card.cardholder?.uppercased() ?? "")
                Spacer()
                Text(card.expiry ?? "")
            }
            .font(.footnote.weight(.medium))
            .foregroundStyle(.white.opacity(0.9))
        }
        .environment(\.layoutDirection, .leftToRight)
        .padding(20)
        .frame(maxWidth: 360)
        .background(LinearGradient.brand, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .frame(maxWidth: .infinity)
        .accessibilityHidden(true)
    }
}

private struct IdentityFields: View {
    let identity: IdentityDetails

    var body: some View {
        let name = [identity.firstName, identity.lastName].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " ")
        Section {
            if !name.isEmpty { FieldRow(label: L10n.fields.fullName, value: name) }
            if let email = identity.email, !email.isEmpty { FieldRow(label: L10n.fields.email, value: email, ltr: true) }
            if let phone = identity.phone, !phone.isEmpty { FieldRow(label: L10n.fields.phone, value: phone, ltr: true) }
            if let birth = identity.birthDate, !birth.isEmpty { FieldRow(label: L10n.fields.birthDate, value: Self.date(birth)) }
            if let address = identity.address.map(Self.lines), !address.isEmpty { FieldRow(label: L10n.fields.address, value: address) }
        }
        if let notes = identity.notes, !notes.isEmpty {
            Section(L10n.fields.notes) { SecretFieldRow(label: L10n.fields.notes, value: notes, multiline: true) }
        }
    }

    static func lines(_ address: Address) -> String {
        let city = [address.city, address.region].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: ", ")
        return [address.line1, address.line2, city, address.postalCode, address.country]
            .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: "\n")
    }

    static func date(_ text: String) -> String {
        DateText.long(text)
    }
}

/// A `YYYY-MM-DD` date as words; anything else as it is.
enum DateText {
    static func long(_ text: String) -> String {
        let parser = DateFormatter()
        parser.dateFormat = "yyyy-MM-dd"
        parser.locale = Locale(identifier: "en_US_POSIX")
        guard let date = parser.date(from: text) else { return text }
        return date.formatted(Date.FormatStyle(date: .long, time: .omitted).locale(L10n.formatLocale))
    }
}

/// An item's past versions (the web vault's `ItemHistory`): the last 10, encrypted like the item,
/// read from the server only when this opens. Restoring is an ordinary edit, so it can be undone
/// from the same list.
struct ItemHistorySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let item: Item
    let editable: Bool
    @State private var versions: [ItemVersion]?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            List {
                Section { Text(L10n.history.help).font(.subheadline).foregroundStyle(Color.mist) }
                if let error {
                    Section { Notice(text: error) }.listRowBackground(Color.clear).listRowInsets(EdgeInsets())
                } else if let versions {
                    Section {
                        if versions.isEmpty { Text(L10n.history.empty).foregroundStyle(Color.mist) }
                        ForEach(versions, id: \.revision) { version in
                            NavigationLink {
                                ItemVersionView(version: version, editable: editable) { await restore(version) }
                            } label: {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(Dates.medium(version.updatedAt)).foregroundStyle(Color.ink)
                                    Text(version.item.title.isEmpty ? L10n.detail.untitled : version.item.title)
                                        .font(.footnote)
                                        .foregroundStyle(Color.mist)
                                }
                            }
                            .accessibilityIdentifier("version-\(version.revision)")
                        }
                    }
                } else {
                    ProgressView().frame(maxWidth: .infinity)
                }
            }
            .navigationTitle(L10n.history.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.phone.close) { dismiss() } }
            }
        }
        .task(id: item.revision) { await load() }
    }

    private func load() async {
        do {
            versions = try await model.vault.itemVersions(id: item.id)
            error = nil
        } catch {
            self.error = error.message
        }
    }

    private func restore(_ version: ItemVersion) async {
        do {
            _ = try await model.vault.restoreItemVersion(id: item.id, revision: version.revision)
            model.confirm(L10n.history.restored)
            dismiss()
        } catch {
            model.show(error)
        }
    }
}

/// One past version, with the same fields as the item, so its secrets stay hidden until revealed.
private struct ItemVersionView: View {
    let version: ItemVersion
    let editable: Bool
    let onRestore: () async -> Void
    @State private var confirming = false
    @State private var busy = false

    var body: some View {
        List {
            Section {
                FieldRow(label: L10n.fields.title, value: version.item.title.isEmpty ? L10n.detail.untitled : version.item.title, copyable: false)
            }
            ItemTypeFields(item: version.item, past: true)
            if editable {
                Section {
                    Button { confirming = true } label: {
                        HStack {
                            Label(L10n.history.restore, systemImage: "arrow.uturn.backward")
                            if busy { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(busy)
                    .accessibilityIdentifier("version-restore")
                }
            }
        }
        .listStyle(.platformGrouped)
        .navigationTitle(Dates.medium(version.updatedAt))
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog(L10n.history.confirmTitle, isPresented: $confirming, titleVisibility: .visible) {
            Button(L10n.history.restore) {
                Task {
                    busy = true
                    await onRestore()
                    busy = false
                }
            }
            Button(L10n.common.cancel, role: .cancel) {}
        } message: {
            Text(L10n.history.confirmBody(date: Dates.medium(version.updatedAt)))
        }
    }
}

enum MoveCopyMode: String, Identifiable {
    case move, copy
    var id: String { rawValue }
}
