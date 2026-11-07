import OctaPassResources
import OctaPassVault
import SwiftUI

/// Emergency access (the web vault's `EmergencyPage`): people you chose, who can ask for your
/// vaults and get them after a wait unless you deny it; and people who chose you.
struct EmergencyView: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    @State private var contacts: EmergencyContacts?
    @State private var adding = false
    @State private var removing: EmergencyContact?
    @State private var requesting: EmergencyContact?
    @State private var renewing: EmergencyContact?

    var body: some View {
        List {
            Section { Text(L10n.emergency.how).font(.subheadline).foregroundStyle(Color.mist) }
            if let contacts {
                Section(L10n.emergency.contacts) {
                    if contacts.granted.isEmpty { Text(L10n.emergency.noContacts).foregroundStyle(Color.mist) }
                    ForEach(contacts.granted, id: \.id) { contact in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(contact.contactEmail).environment(\.layoutDirection, .leftToRight)
                            Text("\(L10n.emergency.days(count: Int(contact.waitDays))) · \(scope(contact)) · \(level(contact))")
                                .font(.footnote).foregroundStyle(Color.mist)
                            Text(grantedStatus(contact)).font(.footnote)
                                .foregroundStyle(contact.status == .idle ? Color.mist : Color.warnText)
                            if contact.keyStale {
                                Notice(text: L10n.emergency.keyStale, tone: .warn)
                                Button(L10n.emergency.renew) { renewing = contact }
                                    .buttonStyle(.bordered)
                                    .accessibilityIdentifier("emergency-renew")
                            }
                            if contact.status == .requested {
                                HStack {
                                    Button(L10n.emergency.approve) { run({ try await model.vault.approveEmergencyAccess(id: contact.id) }, L10n.emergency.approved(email: contact.contactEmail)) }
                                    Button(L10n.emergency.deny, role: .destructive) { run({ try await model.vault.denyEmergencyAccess(id: contact.id) }, L10n.emergency.denied) }
                                }
                                .buttonStyle(.bordered)
                            } else if contact.status == .released {
                                Button(L10n.emergency.denyReleased, role: .destructive) { run({ try await model.vault.denyEmergencyAccess(id: contact.id) }, L10n.emergency.denied) }
                                    .buttonStyle(.bordered)
                            }
                        }
                        .swipeActions {
                            Button(L10n.common.remove, role: .destructive) { removing = contact }
                        }
                    }
                    Button { adding = true } label: { Label(L10n.emergency.add, systemImage: "person.badge.plus") }
                        .accessibilityIdentifier("emergency-add")
                }
                Section(L10n.emergency.received) {
                    if contacts.received.isEmpty { Text(L10n.emergency.noReceived).foregroundStyle(Color.mist) }
                    ForEach(contacts.received, id: \.id) { contact in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(receivedStatus(contact)).font(.subheadline)
                            if contact.keyStale, contact.status == .released {
                                Text(L10n.emergency.receivedStale(email: contact.grantorEmail))
                                    .font(.footnote).foregroundStyle(Color.warnText)
                            }
                            switch contact.status {
                            case .idle:
                                Button(L10n.emergency.request) { requesting = contact }.buttonStyle(.bordered)
                            case .released:
                                // The organiser can reset an account, never read it.
                                if !contact.organiserRecovery {
                                    NavigationLink { EmergencyVaultScreen(contact: contact) } label: { Text(L10n.emergency.open) }
                                }
                            case .requested:
                                EmptyView()
                            }
                        }
                        .swipeActions {
                            Button(L10n.emergency.stepDown, role: .destructive) { removing = contact }
                        }
                        // A row of its own: two links in one row would both open from a tap.
                        if canTakeOver(contact) {
                            NavigationLink { TakeoverView(contact: contact) } label: {
                                Text(L10n.takeover.action).foregroundStyle(Color.dangerText)
                            }
                            .accessibilityIdentifier("emergency-takeover")
                        }
                    }
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.emergency.title)
        .task(id: model.sharingVersion) { await load() }
        .sheet(isPresented: $adding) { AddEmergencyContactSheet { await load() } }
        .sheet(isPresented: Binding(get: { renewing != nil }, set: { if !$0 { renewing = nil } })) {
            if let contact = renewing {
                // The fingerprint comes first: the action only shows once it's on screen.
                AddPersonSheet(title: L10n.emergency.renewTitle(email: contact.contactEmail), help: L10n.emergency.renewBody, action: L10n.emergency.renew, fixedEmail: contact.contactEmail) { account, _ in
                    try await model.vault.renewEmergencyKey(id: contact.id, account: account)
                    model.confirm(L10n.emergency.renewed(email: contact.contactEmail))
                    await load()
                }
            }
        }
        .confirmationDialog(removeTitle, isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), titleVisibility: .visible) {
            Button(removing.map { contact in contacts?.granted.contains { $0.id == contact.id } == true ? L10n.common.remove : L10n.emergency.stepDown } ?? L10n.common.remove, role: .destructive) {
                guard let contact = removing else { return }
                let mine = contacts?.granted.contains { $0.id == contact.id } ?? false
                run({ try await model.vault.removeEmergencyContact(id: contact.id) },
                    mine ? L10n.emergency.removed(email: contact.contactEmail) : L10n.emergency.steppedDown(email: contact.grantorEmail))
            }
        } message: {
            Text(removing.map { contact in contacts?.granted.contains { $0.id == contact.id } == true ? L10n.emergency.removeBody : L10n.emergency.stepDownBody } ?? "")
        }
        .confirmationDialog(requesting.map { L10n.emergency.requestTitle(email: $0.grantorEmail) } ?? "", isPresented: Binding(get: { requesting != nil }, set: { if !$0 { requesting = nil } }), titleVisibility: .visible) {
            Button(L10n.emergency.request) {
                guard let contact = requesting else { return }
                Task {
                    do {
                        try await model.vault.requestEmergencyAccess(id: contact.id)
                        let updated = try await model.vault.listEmergencyContacts().received.first { $0.id == contact.id }
                        model.confirm(L10n.emergency.requested(date: Dates.long(updated?.releasesAt ?? Date().ISO8601Format())))
                        await load()
                    } catch { model.show(error) }
                }
            }
        } message: {
            Text(requesting.map { L10n.emergency.requestBody(email: $0.grantorEmail) } ?? "")
        }
    }

    private var removeTitle: String {
        guard let contact = removing else { return "" }
        return contacts?.granted.contains { $0.id == contact.id } == true
            ? L10n.emergency.removeTitle(email: contact.contactEmail) : L10n.emergency.stepDownTitle(email: contact.grantorEmail)
    }

    private func scope(_ contact: EmergencyContact) -> String {
        switch contact.scope {
        case .account: L10n.emergency.scopeAccount
        case let .vault(id): L10n.emergency.scopeVault(vault: directory.vault(id)?.name ?? L10n.scopes.vault)
        }
    }

    private func level(_ contact: EmergencyContact) -> String {
        if contact.organiserRecovery { return L10n.emergency.organiserRecovery }
        return contact.accessLevel == .view ? L10n.emergency.view : L10n.emergency.takeover
    }

    /// Released, and for the whole account: a vault's key can't open an account.
    private func canTakeOver(_ contact: EmergencyContact) -> Bool {
        guard contact.status == .released, contact.accessLevel == .takeover else { return false }
        if case .account = contact.scope { return true }
        return false
    }

    private func grantedStatus(_ contact: EmergencyContact) -> String {
        switch contact.status {
        case .idle: L10n.emergency.statusIdle
        case .requested: L10n.emergency.statusRequested(date: Dates.long(contact.requestedAt ?? ""), release: Dates.long(contact.releasesAt ?? ""))
        case .released: L10n.emergency.statusReleased(date: Dates.long(contact.releasedAt ?? ""))
        }
    }

    private func receivedStatus(_ contact: EmergencyContact) -> String {
        switch contact.status {
        case .idle: L10n.emergency.receivedIdle(email: contact.grantorEmail, days: L10n.emergency.days(count: Int(contact.waitDays)))
        case .requested: L10n.emergency.receivedRequested(date: Dates.long(contact.requestedAt ?? ""), release: Dates.long(contact.releasesAt ?? ""), email: contact.grantorEmail)
        case .released: contact.organiserRecovery
            ? L10n.emergency.organiserReleased(date: Dates.long(contact.releasedAt ?? ""))
            : L10n.emergency.receivedReleased(date: Dates.long(contact.releasedAt ?? ""))
        }
    }

    private func load() async {
        do { contacts = try await model.vault.listEmergencyContacts() } catch { model.show(error) }
    }

    private func run(_ action: @escaping () async throws -> Void, _ message: String) {
        Task {
            do {
                try await action()
                model.confirm(message)
                await load()
            } catch { model.show(error) }
        }
    }
}

private struct AddEmergencyContactSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    let onAdded: () async -> Void
    @State private var waitDays: UInt32 = 7
    @State private var level = EmergencyAccessLevel.view
    @State private var vaultId: String?

    var body: some View {
        AddPersonSheet(title: L10n.emergency.add, help: L10n.emergency.how, action: L10n.emergency.addAction) { account, _ in
            let scope: EmergencyScope = vaultId.map { .vault(vaultId: $0) } ?? .account
            _ = try await model.vault.addEmergencyContact(account: account, waitDays: waitDays, accessLevel: level, scope: scope)
            model.confirm(L10n.emergency.added(email: account.email))
            await onAdded()
        }
        .safeAreaInset(edge: .bottom) {
            Form {
                Picker(L10n.emergency.waitDays, selection: $waitDays) {
                    ForEach([UInt32(1), 2, 3, 7, 14, 30], id: \.self) { Text(L10n.emergency.days(count: Int($0))).tag($0) }
                }
                Picker(L10n.emergency.scope, selection: $vaultId) {
                    Text(L10n.emergency.scopeAccount).tag(String?.none)
                    // Only what you own can be handed over.
                    ForEach(directory.vaults.filter { $0.role == .owner && !$0.untrusted }, id: \.id) { Text($0.name).tag(String?.some($0.id)) }
                }
                Picker(L10n.emergency.accessLevel, selection: $level) {
                    Text(L10n.emergency.view).tag(EmergencyAccessLevel.view)
                    Text(L10n.emergency.takeover).tag(EmergencyAccessLevel.takeover)
                }
                Text(level == .view ? L10n.emergency.viewHelp : L10n.emergency.takeoverHelp).font(.footnote).foregroundStyle(Color.mist)
                if level == .takeover {
                    Text(L10n.emergency.takeoverWarning).font(.footnote).foregroundStyle(Color.dangerText)
                }
            }
            .frame(height: level == .takeover ? 340 : 260)
            // Takeover needs the whole account: the server refuses it for one vault.
            .onChange(of: level) { _, new in if new == .takeover { vaultId = nil } }
            .onChange(of: vaultId) { _, new in if new != nil { level = .view } }
        }
    }
}

/// As the contact of a released takeover record: this account's own master password, a new one
/// for the grantor, then the new Recovery Kit, the only copy (`TakeoverDialog`).
struct TakeoverView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let contact: EmergencyContact
    @State private var own = ""
    @State private var new = ""
    @State private var confirm = ""
    @State private var ownError: String?
    @State private var newError: String?
    @State private var confirmError: String?
    @State private var formError: String?
    @State private var busy = false

    private var email: String { contact.grantorEmail }

    var body: some View {
        Form {
            Section { Notice(text: L10n.takeover.warning(email: email), tone: .danger) }
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets())
            Section {
                PasswordInput(label: L10n.takeover.ownPassword, text: $own, error: ownError, content: .oneTimeCode)
                    .accessibilityIdentifier("takeover-own-password")
                PasswordInput(label: L10n.takeover.newPassword(email: email), text: $new, error: newError, content: .oneTimeCode)
                    .accessibilityIdentifier("takeover-new-password")
                PasswordStrength(password: new)
                PasswordInput(label: L10n.fields.confirmPassword, text: $confirm, error: confirmError, content: .oneTimeCode)
                    .accessibilityIdentifier("takeover-confirm-password")
            }
            Section {
                Button(role: .destructive) {
                    Task { await submit() }
                } label: {
                    HStack {
                        Text(L10n.takeover.submit)
                        if busy { Spacer(); ProgressView() }
                    }
                }
                .disabled(busy)
                .accessibilityIdentifier("takeover-submit")
            }
            if let formError {
                Section { Notice(text: formError) }
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
            }
        }
        .navigationTitle(L10n.takeover.title(email: email))
        .navigationBarTitleDisplayMode(.inline)
    }

    private func validate() -> Bool {
        ownError = own.isEmpty ? L10n.validation.passwordRequired : nil
        if new.isEmpty {
            newError = L10n.changePassword.newRequired
        } else if model.vault.estimateStrength(password: new).score < minimumScore {
            newError = L10n.validation.passwordTooWeak
        } else {
            newError = nil
        }
        confirmError = confirm == new ? nil : L10n.validation.passwordsDontMatch
        return ownError == nil && newError == nil && confirmError == nil
    }

    private func submit() async {
        formError = nil
        guard validate(), !busy else {
            Haptics.error()
            return
        }
        busy = true
        defer { busy = false }
        do {
            let kit = try await model.vault.takeOverAccount(id: contact.id, contactPassword: own, newPassword: new)
            own = ""
            new = ""
            confirm = ""
            model.newKit = PendingRecoveryKit(kit: kit, title: L10n.takeover.kitTitle, message: L10n.takeover.kitBody(email: email))
            Haptics.success()
            dismiss()
        } catch {
            Haptics.error()
            own = ""
            if error.isVault(.invalidCredentials) {
                ownError = L10n.takeover.wrongOwn
            } else {
                formError = error.message
            }
        }
    }
}

/// As the contact, once released: the grantor's vaults in scope, read-only.
private struct EmergencyVaultScreen: View {
    @Environment(AppModel.self) private var model
    let contact: EmergencyContact
    @State private var view: EmergencyVaultView?
    @State private var failed = false

    var body: some View {
        List {
            Section { Notice(text: L10n.emergency.vaultReadOnly, tone: .info) }.listRowBackground(Color.clear).listRowInsets(EdgeInsets())
            if let view {
                if view.items.isEmpty { Text(L10n.emergency.vaultEmpty).foregroundStyle(Color.mist) }
                ForEach(view.vaults, id: \.id) { vault in
                    let items = view.items.filter { $0.vaultId == vault.id }.sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
                    if !items.isEmpty {
                        Section(vault.name) {
                            ForEach(items, id: \.id) { row($0) }
                        }
                    }
                }
            } else if failed {
                Text(L10n.emergency.vaultFailed).foregroundStyle(Color.dangerText)
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.emergency.vaultTitle(email: contact.grantorEmail))
        .task {
            do { view = try await model.vault.openEmergencyAccess(id: contact.id) } catch { failed = true }
        }
    }

    private func row(_ item: Item) -> some View {
        NavigationLink {
            List {
                ItemTypeFields(item: item)
                EmergencyFiles(contactId: contact.id, item: item)
            }
            .navigationTitle(item.title)
        } label: {
            HStack(spacing: 12) {
                Avatar(name: item.title)
                VStack(alignment: .leading) {
                    Text(item.title)
                    if let subtitle = item.subtitle { Text(subtitle).font(.subheadline).foregroundStyle(Color.mist) }
                }
            }
        }
    }
}

/// The grantor's files, read-only: each opens in Quick Look, decrypted on this phone.
private struct EmergencyFiles: View {
    @Environment(AppModel.self) private var model
    let contactId: String
    let item: Item
    @State private var opened: String?
    @State private var preview: URL?
    @State private var busy: String?

    var body: some View {
        if !item.attachments.isEmpty {
            Section(L10n.files.title) {
                ForEach(item.attachments, id: \.id) { file in
                    Button { open(file) } label: {
                        HStack {
                            Label(file.name, systemImage: "doc")
                            Spacer()
                            if busy == file.id { ProgressView() }
                        }
                    }
                    .disabled(busy != nil)
                }
            }
            .quickLookPreview($preview)
            .onChange(of: preview) { _, url in
                if url == nil, let opened {
                    model.vault.closeAttachment(path: opened)
                    self.opened = nil
                }
            }
        }
    }

    private func open(_ file: Attachment) {
        busy = file.id
        Task {
            defer { busy = nil }
            do {
                let path = try await model.vault.openEmergencyAttachment(id: contactId, itemId: item.id, attachmentId: file.id)
                opened = path
                preview = URL(fileURLWithPath: path)
            } catch {
                model.show(error)
            }
        }
    }
}
