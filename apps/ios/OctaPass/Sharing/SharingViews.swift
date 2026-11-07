import OctaPassResources
import OctaPassVault
import SwiftUI

/// Sharing (the web vault's `SharingPage`): shared vaults, the family, your fingerprint, and the
/// share links you made.
struct SharingView: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    @State private var links: [ShareLinkInfo]?
    @State private var fingerprint: Fingerprint?
    @State private var creating = false

    var body: some View {
        List {
            Section {
                ForEach(directory.vaults.filter { $0.vaultType != .personal }, id: \.id) { vault in
                    NavigationLink {
                        VaultMembersView(vault: vault)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Label(vault.name, systemImage: vault.icon)
                            Text([L10n.sharing.roleIn(role: RoleNames.name(vault.role)), vault.untrusted ? L10n.vault.untrusted : nil].compactMap { $0 }.joined(separator: " · "))
                                .font(.footnote).foregroundStyle(vault.untrusted ? Color.warnText : Color.mist)
                        }
                    }
                }
                if !directory.vaults.contains(where: { $0.vaultType == .shared }) {
                    Text(L10n.sharing.noVaults).foregroundStyle(Color.mist)
                }
                Button { creating = true } label: { Label(L10n.sharing.newVault, systemImage: "plus") }
                    .accessibilityIdentifier("sharing-new-vault")
            } header: {
                Text(L10n.sharing.vaults)
            } footer: {
                Text(L10n.sharing.vaultsHelp)
            }
            Section {
                NavigationLink { FamilyView() } label: { Label(L10n.family.title, systemImage: "house") }
                    .accessibilityIdentifier("sharing-family")
            }
            if let fingerprint {
                Section {
                    FingerprintView(fingerprint: fingerprint)
                } header: {
                    Text(L10n.fingerprint.yours)
                } footer: {
                    Text(L10n.fingerprint.yoursHelp)
                }
            }
            Section {
                if let links {
                    if links.isEmpty { Text(L10n.sharing.noLinks).foregroundStyle(Color.mist) }
                    ForEach(links, id: \.id) { link in
                        VStack(alignment: .leading, spacing: 2) {
                            if let itemId = link.itemId {
                                NavigationLink(value: Route.item(itemId)) { Text(link.itemTitle ?? L10n.sharing.linkItem) }
                            } else {
                                Text(link.itemTitle ?? L10n.sharing.linkItem)
                            }
                            Text([L10n.sharing.linkViews(views: Int(link.views), count: Int(link.maxViews)),
                                  L10n.sharing.linkExpires(date: Dates.medium(link.expiresAt)),
                                  link.passphraseRequired ? L10n.sharing.linkPassphrase : nil].compactMap { $0 }.joined(separator: " · "))
                                .font(.footnote).foregroundStyle(Color.mist)
                        }
                        .swipeActions {
                            Button(L10n.sharing.revoke, role: .destructive) { Task { await revoke(link) } }
                        }
                        .contextMenu {
                            Button(L10n.sharing.revokeLink(title: link.itemTitle ?? L10n.sharing.linkItem), role: .destructive) { Task { await revoke(link) } }
                        }
                    }
                } else {
                    ProgressView()
                }
            } header: {
                Text(L10n.sharing.links)
            } footer: {
                Text(L10n.sharing.linksHelp)
            }
        }
        .navigationTitle(L10n.sharing.title)
        .sheet(isPresented: $creating) { CreateVaultSheet() }
        .task(id: model.sharingVersion) {
            links = try? await model.vault.listShareLinks()
            fingerprint = try? await model.vault.myFingerprint()
        }
    }

    private func revoke(_ link: ShareLinkInfo) async {
        do {
            try await model.vault.revokeShareLink(id: link.id)
            model.confirm(L10n.sharing.revoked)
            links = try? await model.vault.listShareLinks()
        } catch { model.show(error) }
    }
}

enum RoleNames {
    static func name(_ role: VaultRole) -> String {
        switch role {
        case .owner: L10n.roles.owner
        case .manage: L10n.roles.manage
        case .write: L10n.roles.write
        case .read: L10n.roles.read
        }
    }

    static func help(_ role: VaultRole) -> String {
        switch role {
        case .owner: L10n.roles.ownerHelp
        case .manage: L10n.roles.manageHelp
        case .write: L10n.roles.writeHelp
        case .read: L10n.roles.readHelp
        }
    }
}

/// Six groups of digits and the emoji with their names, to compare out loud.
struct FingerprintView: View {
    let fingerprint: Fingerprint

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(fingerprint.digits).font(.secret(.callout)).environment(\.layoutDirection, .leftToRight)
                .textSelection(.enabled)
            HStack(spacing: 10) {
                ForEach(Array(fingerprint.emoji.enumerated()), id: \.offset) { _, emoji in
                    VStack(spacing: 2) {
                        Text(emoji.emoji).font(.title2)
                        Text(emoji.name).font(.caption2).foregroundStyle(Color.mist)
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(emoji.name)
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(L10n.fingerprint.title)
    }
}

struct CreateVaultSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(L10n.sharing.vaultName, text: $name, prompt: Text(L10n.sharing.vaultNamePlaceholder))
                        .accessibilityIdentifier("new-vault-name")
                } footer: {
                    Text(L10n.sharing.newVaultHelp)
                }
            }
            .navigationTitle(L10n.sharing.newVaultTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.sharing.create) {
                        Task {
                            busy = true
                            defer { busy = false }
                            do {
                                _ = try await model.vault.createVault(name: name.trimmingCharacters(in: .whitespaces))
                                dismiss()
                            } catch { model.show(error) }
                        }
                    }
                    .disabled(busy || name.trimmingCharacters(in: .whitespaces).isEmpty)
                    .accessibilityIdentifier("new-vault-create")
                }
            }
        }
        .presentationDetents([.medium])
    }
}

/// A shared vault's members: fingerprints compared or not, roles, adding and removing people
/// (removing gives the vault a new key), renaming, leaving.
struct VaultMembersView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let vault: Vault
    @State private var members: [VaultMember]?
    @State private var adding = false
    @State private var removing: VaultMember?
    @State private var leaving = false
    @State private var renaming: String?

    private var myRole: VaultRole { vault.role }
    private var canManage: Bool { (myRole == .manage || myRole == .owner) && !vault.untrusted }
    private var lastOwner: Bool { myRole == .owner && (members?.filter { $0.role == .owner }.count ?? 0) <= 1 }

    var body: some View {
        List {
            Section {
                NavigationLink(value: Route.list(.vault(vault.id))) { Label(L10n.members.openVault, systemImage: "lock.rectangle.stack") }
            }
            if let members {
                if vault.untrusted {
                    Section { Notice(text: L10n.vault.untrustedBody(vault: vault.name), tone: .warn) }
                        .listRowBackground(Color.clear).listRowInsets(EdgeInsets())
                }
                let unverified = members.filter { !$0.isYou && !$0.verified }.count
                if unverified > 0 {
                    Section { Notice(text: L10n.members.unverifiedCount(count: unverified), tone: .warn) }
                        .listRowBackground(Color.clear).listRowInsets(EdgeInsets())
                }
                Section(L10n.vault.members) {
                    ForEach(members, id: \.accountId) { member in
                        MemberRow(vault: vault, member: member, canManage: canManage && !member.isYou && (myRole == .owner || member.role != .owner), roles: myRole == .owner ? [.owner, .manage, .write, .read] : [.manage, .write, .read]) {
                            removing = member
                        }
                    }
                    if canManage, vault.vaultType == .shared {
                        Button { adding = true } label: { Label(L10n.members.invite, systemImage: "person.badge.plus") }
                            .accessibilityIdentifier("members-invite")
                    }
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
            if vault.vaultType == .shared {
                Section {
                    if myRole != .read, !vault.untrusted {
                        Button(L10n.common.rename) { renaming = vault.name }
                    }
                    Button(L10n.members.leave, role: .destructive) { leaving = true }
                        .disabled(lastOwner)
                } footer: {
                    Text(lastOwner ? L10n.members.lastOwner : L10n.members.leaveHelp)
                }
            } else {
                Section {
                    Notice(text: L10n.members.familyVault, tone: .info)
                    NavigationLink { FamilyView() } label: { Text(L10n.members.familyLink) }
                }
            }
        }
        .navigationTitle(vault.name)
        .task(id: model.sharingVersion) { await load() }
        .sheet(isPresented: $adding) { AddPersonSheet(title: L10n.members.invite, help: L10n.members.inviteHelp, action: L10n.members.inviteAction, roles: true, offersOwner: myRole == .owner) { account, role in
            try await model.vault.addMember(vaultId: vault.id, account: account, role: role ?? .write)
            model.confirm(L10n.members.invited(email: account.email, vault: vault.name))
            await load()
        } }
        .confirmationDialog(removing.map { L10n.members.removeTitle(email: $0.email) } ?? "", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), titleVisibility: .visible) {
            Button(L10n.members.removeAction, role: .destructive) {
                guard let member = removing else { return }
                Task {
                    do {
                        try await model.vault.removeMember(vaultId: vault.id, accountId: member.accountId)
                        model.confirm(L10n.members.removed(email: member.email))
                        await load()
                    } catch { model.show(error) }
                }
            }
        } message: {
            Text(L10n.members.removeBody(vault: vault.name))
        }
        .confirmationDialog(L10n.members.leaveTitle(vault: vault.name), isPresented: $leaving, titleVisibility: .visible) {
            Button(L10n.members.leave, role: .destructive) {
                Task {
                    do {
                        try await model.vault.leaveVault(vaultId: vault.id)
                        model.confirm(L10n.members.left(vault: vault.name))
                        dismiss()
                    } catch { model.show(error) }
                }
            }
        } message: {
            Text(L10n.members.leaveBody)
        }
        .alert(L10n.members.rename, isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
            TextField(L10n.sharing.vaultName, text: Binding(get: { renaming ?? "" }, set: { renaming = $0 }))
            Button(L10n.common.save) {
                guard let name = renaming?.trimmingCharacters(in: .whitespaces), !name.isEmpty else { return }
                Task {
                    do {
                        try await model.vault.renameVault(vaultId: vault.id, name: name)
                        model.confirm(L10n.members.renamed)
                    } catch { model.show(error) }
                }
            }
            Button(L10n.common.cancel, role: .cancel) {}
        }
    }

    private func load() async {
        do { members = try await model.vault.listMembers(vaultId: vault.id) } catch { model.show(error) }
    }
}

private struct MemberRow: View {
    @Environment(AppModel.self) private var model
    let vault: Vault
    let member: VaultMember
    let canManage: Bool
    var roles: [VaultRole] = [.read, .write, .manage]
    let onRemove: () -> Void
    @State private var showFingerprint = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Avatar(name: member.email, size: 32)
                VStack(alignment: .leading, spacing: 2) {
                    Text(member.isYou ? L10n.members.you(email: member.email) : member.email)
                        .environment(\.layoutDirection, .leftToRight)
                    HStack(spacing: 6) {
                        Text(RoleNames.name(member.role))
                        Text(L10n.members.added(date: Dates.medium(member.addedAt)))
                        if !member.isYou {
                            Text(member.verified ? L10n.fingerprint.verified : L10n.fingerprint.unverified)
                                .foregroundStyle(member.verified ? Color.freeText : Color.warnText)
                        }
                    }
                    .font(.footnote).foregroundStyle(Color.mist)
                }
                Spacer()
                if canManage {
                    Menu {
                        Picker(L10n.roles.label, selection: Binding(get: { member.role }, set: { role in Task { await change(role) } })) {
                            ForEach(roles, id: \.self) { Text(RoleNames.name($0)).tag($0) }
                        }
                        Button(L10n.members.remove(email: member.email), role: .destructive, action: onRemove)
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                    .accessibilityLabel(L10n.roles.label)
                }
            }
            if !member.isYou {
                DisclosureGroup(L10n.fingerprint.verify, isExpanded: $showFingerprint) {
                    Text(L10n.fingerprint.compareHelp(email: member.email)).font(.footnote).foregroundStyle(Color.mist)
                    FingerprintView(fingerprint: member.fingerprint)
                    if !member.verified {
                        Button(L10n.fingerprint.markVerified) { Task { await verify() } }
                    }
                }
                .font(.footnote)
            }
        }
    }

    private func change(_ role: VaultRole) async {
        do {
            try await model.vault.changeRole(vaultId: vault.id, accountId: member.accountId, role: role)
            model.confirm(L10n.members.roleChanged(email: member.email, role: RoleNames.name(role)))
        } catch { model.show(error) }
    }

    private func verify() async {
        do {
            // What was compared is the fingerprint on screen, not whatever the server says now.
            try await model.vault.markVerified(account: AccountLookup(accountId: member.accountId, email: member.email, publicEncKey: "", publicSignKey: "", fingerprint: member.fingerprint))
            model.confirm(L10n.fingerprint.markedVerified)
        } catch { model.show(error) }
    }
}

/// A vault's members, from its list.
struct VaultMembersRoute: View {
    @Environment(VaultDirectory.self) private var directory
    let vaultId: String

    var body: some View {
        if let vault = directory.vault(vaultId) { VaultMembersView(vault: vault) }
    }
}

/// Finding someone by email, comparing their fingerprint, then adding them (a vault member, a
/// family member, an emergency contact).
struct AddPersonSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let title: String
    let help: String
    let action: String
    var roles = false
    /// The one account this can be: looked up at once, and the email can't be changed.
    var fixedEmail: String?
    /// Only owners hand out `owner` (plan 15).
    var offersOwner = false
    let onAdd: (AccountLookup, VaultRole?) async throws -> Void
    @State private var email = ""
    @State private var found: AccountLookup?
    @State private var role = VaultRole.write
    @State private var verified = false
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(L10n.people.email, text: $email)
                        .keyboardType(.emailAddress)
                        .textContentType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .disabled(found != nil || fixedEmail != nil)
                        .accessibilityIdentifier("person-email")
                    if found == nil {
                        Button(L10n.people.find) { Task { await find() } }
                            .disabled(busy || email.isEmpty)
                            .accessibilityIdentifier("person-find")
                    } else if fixedEmail == nil {
                        Button(L10n.people.change) { found = nil; verified = false }
                    }
                    if let error { Text(error).font(.footnote).foregroundStyle(Color.dangerText) }
                } footer: {
                    Text(help)
                }
                if let found {
                    Section {
                        Text(L10n.fingerprint.compareHelp(email: found.email)).font(.footnote)
                        FingerprintView(fingerprint: found.fingerprint)
                        Toggle(L10n.fingerprint.matches(email: found.email), isOn: $verified)
                    } header: {
                        Text(L10n.people.found)
                    }
                    if roles {
                        Section {
                            Picker(L10n.roles.label, selection: $role) {
                                ForEach(offersOwner ? [VaultRole.owner, .manage, .write, .read] : [VaultRole.manage, .write, .read], id: \.self) { Text(RoleNames.name($0)).tag($0) }
                            }
                            Text(RoleNames.help(role)).font(.footnote).foregroundStyle(Color.mist)
                        }
                    }
                    Section {
                        Button(action) { Task { await add(found) } }
                            .disabled(busy)
                            .accessibilityIdentifier("person-add")
                    }
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } } }
        }
        .task {
            guard let fixedEmail, found == nil else { return }
            email = fixedEmail
            await find()
        }
    }

    private func find() async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            found = try await model.vault.lookupAccount(email: normalizeEmail(email: email))
        } catch {
            self.error = error.message
        }
    }

    private func add(_ account: AccountLookup) async {
        busy = true
        defer { busy = false }
        do {
            if verified { try await model.vault.markVerified(account: account) }
            try await onAdd(account, roles ? role : nil)
            dismiss()
        } catch {
            self.error = error.message
        }
    }
}

/// The family: one organiser, members, invites, and its shared Family vault.
struct FamilyView: View {
    @Environment(AppModel.self) private var model
    @State private var state: FamilyState?
    @State private var inviting = false
    @State private var confirm: Confirm?
    /// Who the user chose, for finding their own organiser recovery record.
    @State private var contacts: EmergencyContacts?
    @State private var recoveryDays: UInt32 = 7
    @State private var turningOnRecovery: String?
    @State private var turningOffRecovery: EmergencyContact?

    private static let recoveryWaits: [UInt32] = [1, 2, 3, 7, 14, 30]

    enum Confirm: Identifiable {
        case remove(FamilyMember), leave, delete
        var id: String {
            switch self {
            case let .remove(member): "remove-\(member.accountId)"
            case .leave: "leave"
            case .delete: "delete"
            }
        }
    }

    var body: some View {
        List {
            if let state {
                ForEach(state.invitations, id: \.familyId) { invite in
                    Section {
                        Text(L10n.family.invitation(email: invite.organiserEmail))
                        Text(L10n.family.invitedOn(date: Dates.long(invite.invitedAt))).font(.footnote).foregroundStyle(Color.mist)
                        Button(L10n.family.accept) { run({ try await model.vault.acceptFamilyInvite(familyId: invite.familyId) }, L10n.family.joined) }
                        Button(L10n.family.decline, role: .destructive) { run({ try await model.vault.declineFamilyInvite(familyId: invite.familyId) }, L10n.family.declined) }
                    }
                }
                if let family = state.family {
                    Section {
                        Text(L10n.family.count(members: family.members.count + family.invites.count, max: Int(family.maxMembers))).foregroundStyle(Color.mist)
                        ForEach(family.members, id: \.accountId) { member in
                            HStack {
                                Text(member.isYou ? L10n.members.you(email: member.email) : member.email)
                                Spacer()
                                Text(member.role == .organiser ? L10n.family.organiser : L10n.family.member).font(.footnote).foregroundStyle(Color.mist)
                            }
                            .swipeActions {
                                if family.isOrganiser, !member.isYou {
                                    Button(L10n.common.remove, role: .destructive) { confirm = .remove(member) }
                                }
                            }
                        }
                        ForEach(family.invites, id: \.accountId) { invite in
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(invite.email)
                                    Text("\(L10n.family.pending) · \(L10n.family.invitedOn(date: Dates.long(invite.invitedAt)))").font(.footnote).foregroundStyle(Color.mist)
                                }
                                Spacer()
                                Button(L10n.common.cancel) {
                                    run({ try await model.vault.cancelFamilyInvite(accountId: invite.accountId) }, L10n.family.cancelled)
                                }
                                .buttonStyle(.borderless)
                                .accessibilityLabel(L10n.family.cancelInvite(email: invite.email))
                            }
                        }
                        if family.isOrganiser {
                            if family.members.count + family.invites.count < Int(family.maxMembers) {
                                Button { inviting = true } label: { Label(L10n.family.invite, systemImage: "person.badge.plus") }
                            } else {
                                Text(L10n.family.full).foregroundStyle(Color.mist)
                            }
                        }
                    } header: {
                        Text(L10n.family.title)
                    }
                    Section {
                        NavigationLink(value: Route.list(.vault(family.vaultId))) { Label(L10n.family.vault, systemImage: "house") }
                        if family.isOrganiser {
                            Button(L10n.family.delete, role: .destructive) { confirm = .delete }
                        } else {
                            Button(L10n.family.leave, role: .destructive) { confirm = .leave }
                        }
                    }
                    if !family.isOrganiser, let organiser = family.members.first(where: { $0.accountId == family.organiserId }) {
                        organiserRecovery(organiser.email)
                    }
                } else {
                    Section {
                        Text(L10n.family.help(count: 6)).foregroundStyle(Color.mist)
                        Button { run({ try await model.vault.createFamily() }, L10n.family.created) } label: {
                            Label(L10n.family.create, systemImage: "house")
                        }
                        .accessibilityIdentifier("family-create")
                    }
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.family.title)
        .task(id: model.sharingVersion) { await load() }
        .sheet(isPresented: $inviting) {
            AddPersonSheet(title: L10n.family.invite, help: L10n.family.help(count: Int(state?.family?.maxMembers ?? 6)), action: L10n.family.inviteAction) { account, _ in
                try await model.vault.inviteToFamily(account: account)
                model.confirm(L10n.family.invited(email: account.email))
                await load()
            }
        }
        .sheet(isPresented: Binding(get: { turningOnRecovery != nil }, set: { if !$0 { turningOnRecovery = nil } })) {
            if let organiser = turningOnRecovery {
                // The organiser's fingerprint comes first: the action only shows once it's on screen.
                AddPersonSheet(title: L10n.family.recovery.title, help: L10n.family.recovery.warning, action: L10n.family.recovery.turnOn, fixedEmail: organiser) { account, _ in
                    _ = try await model.vault.enableOrganiserRecovery(account: account, waitDays: recoveryDays)
                    model.confirm(L10n.family.recovery.turnedOn)
                    await load()
                }
            }
        }
        .confirmationDialog(L10n.family.recovery.offTitle, isPresented: Binding(get: { turningOffRecovery != nil }, set: { if !$0 { turningOffRecovery = nil } }), titleVisibility: .visible) {
            Button(L10n.family.recovery.turnOff, role: .destructive) {
                guard let record = turningOffRecovery else { return }
                run({ try await model.vault.removeEmergencyContact(id: record.id) }, L10n.family.recovery.turnedOff)
            }
        } message: {
            Text(L10n.family.recovery.offBody)
        }
        .confirmationDialog(confirmTitle, isPresented: Binding(get: { confirm != nil }, set: { if !$0 { confirm = nil } }), titleVisibility: .visible) {
            switch confirm {
            case let .remove(member)?:
                Button(L10n.common.remove, role: .destructive) {
                    run({ try await model.vault.removeFamilyMember(accountId: member.accountId) }, L10n.family.removed(email: member.email))
                }
            case .leave?:
                Button(L10n.family.leave, role: .destructive) { run({ try await model.vault.leaveFamily() }, L10n.family.left) }
            case .delete?:
                Button(L10n.family.delete, role: .destructive) { run({ try await model.vault.deleteFamily() }, L10n.family.deleted) }
            case nil:
                EmptyView()
            }
        } message: {
            switch confirm {
            case .remove?: Text(L10n.family.removeBody)
            case .leave?: Text(L10n.family.leaveBody)
            case .delete?: Text(L10n.family.deleteBody)
            case nil: EmptyView()
            }
        }
    }

    /// As a member: the organiser helping recover this account. Off unless the member turns it on.
    private func organiserRecovery(_ organiser: String) -> some View {
        Section(L10n.family.recovery.title) {
            if let contacts {
                if let record = contacts.granted.first(where: \.organiserRecovery) {
                    Text(L10n.family.recovery.on(email: record.contactEmail, days: L10n.emergency.days(count: Int(record.waitDays))))
                    Button(L10n.family.recovery.turnOff, role: .destructive) { turningOffRecovery = record }
                        .accessibilityIdentifier("family-recovery-off")
                } else {
                    Text(L10n.family.recovery.help(email: organiser))
                    Notice(text: L10n.family.recovery.warning, tone: .warn)
                    Picker(L10n.emergency.waitDays, selection: $recoveryDays) {
                        ForEach(Self.recoveryWaits, id: \.self) { Text(L10n.emergency.days(count: Int($0))).tag($0) }
                    }
                    .accessibilityIdentifier("family-recovery-wait")
                    Button(L10n.family.recovery.turnOn) { turningOnRecovery = organiser }
                        .accessibilityIdentifier("family-recovery-on")
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
    }

    private var confirmTitle: String {
        switch confirm {
        case let .remove(member)?: L10n.family.removeTitle(email: member.email)
        case .leave?: L10n.family.leaveTitle
        case .delete?: L10n.family.deleteTitle
        case nil: ""
        }
    }

    private func load() async {
        do {
            let next = try await model.vault.getFamily()
            state = next
            if let family = next.family, !family.isOrganiser {
                contacts = try await model.vault.listEmergencyContacts()
            }
        } catch { model.show(error) }
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

/// Share a copy (a one-time link): how long it works, how many views, an optional passphrase.
/// The copy is encrypted on the phone; the key is in the link after #.
struct ShareLinkSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let item: Item
    @State private var hours: UInt32 = 24
    @State private var views: UInt32 = 1
    @State private var passphrase = ""
    @State private var created: CreatedShareLink?
    @State private var busy = false

    private static let expiries: [UInt32] = [1, 24, 72, 168, 720]

    var body: some View {
        NavigationStack {
            Form {
                if let created {
                    Section {
                        Text(L10n.shareLink.readyBody(date: Dates.medium(created.expiresAt)))
                        Text(created.url).font(.secret(.footnote)).textSelection(.enabled).environment(\.layoutDirection, .leftToRight)
                            .accessibilityIdentifier("share-link-url")
                        Button { model.copy(created.url, what: L10n.shareLink.linkWhat) } label: { Label(L10n.shareLink.copyLink, systemImage: "doc.on.doc") }
                        ShareLink(item: created.url) { Label(L10n.phone.native.kitShare, systemImage: "square.and.arrow.up") }
                        NavigationLink { SharingView() } label: { Text(L10n.shareLink.manage) }
                        if !passphrase.isEmpty { Text(L10n.shareLink.sendPassphrase).font(.footnote).foregroundStyle(Color.mist) }
                    } header: {
                        Text(L10n.shareLink.ready)
                    }
                } else {
                    Section { Text(L10n.shareLink.intro).font(.subheadline).foregroundStyle(Color.mist) }
                    Section {
                        Picker(L10n.shareLink.expires, selection: $hours) {
                            ForEach(Self.expiries, id: \.self) { Text(Self.expiry($0)).tag($0) }
                        }
                        Stepper("\(L10n.shareLink.views): \(views)", value: $views, in: 1...100)
                        Text(L10n.shareLink.viewsHint).font(.footnote).foregroundStyle(Color.mist)
                        MaskedField(label: L10n.shareLink.passphrase, text: $passphrase)
                        Text(L10n.shareLink.passphraseHint).font(.footnote).foregroundStyle(Color.mist)
                    }
                    Section {
                        Button {
                            Task { await create() }
                        } label: {
                            HStack { Text(L10n.shareLink.create); if busy { Spacer(); ProgressView() } }
                        }
                        .disabled(busy)
                        .accessibilityIdentifier("share-link-create")
                    }
                }
            }
            .navigationTitle(L10n.shareLink.title(title: item.title))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button(created == nil ? L10n.common.cancel : L10n.common.done) { dismiss() } } }
        }
    }

    static func expiry(_ hours: UInt32) -> String {
        hours < 24 ? L10n.shareLink.hours(count: Int(hours)) : L10n.shareLink.days(count: Int(hours / 24))
    }

    private func create() async {
        busy = true
        defer { busy = false }
        do {
            created = try await model.vault.createShareLink(itemId: item.id, options: ShareLinkOptions(
                expiresInHours: hours, maxViews: views, passphrase: passphrase.isEmpty ? nil : passphrase))
        } catch { model.show(error) }
    }
}

/// Move (a copy there, the original to the trash) or copy an item to another vault.
struct MoveCopySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    @Environment(\.dismiss) private var dismiss
    let item: Item
    let mode: MoveCopyMode
    @State private var target: String?
    @State private var busy = false

    var body: some View {
        let targets = directory.vaults.filter { $0.id != item.vaultId && $0.canWrite }
        NavigationStack {
            Form {
                Section { Text(mode == .move ? L10n.moveCopy.moveIntro : L10n.moveCopy.copyIntro).foregroundStyle(Color.mist) }
                if targets.isEmpty {
                    Text(L10n.moveCopy.noTargets).foregroundStyle(Color.mist)
                } else {
                    Picker(L10n.moveCopy.vault, selection: $target) {
                        ForEach(targets, id: \.id) { Text($0.name).tag(String?.some($0.id)) }
                    }
                    .pickerStyle(.inline)
                }
            }
            .navigationTitle(mode == .move ? L10n.moveCopy.moveTitle(title: item.title) : L10n.moveCopy.copyTitle(title: item.title))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(mode == .move ? L10n.moveCopy.moveAction : L10n.moveCopy.copyAction) {
                        Task { await run(targets) }
                    }
                    .disabled(busy || target == nil)
                }
            }
            .onAppear { target = targets.first?.id }
        }
    }

    private func run(_ targets: [Vault]) async {
        guard let target, let vault = targets.first(where: { $0.id == target }) else { return }
        busy = true
        defer { busy = false }
        do {
            if mode == .move {
                _ = try await model.vault.moveItem(id: item.id, toVaultId: target)
                model.confirm(L10n.moveCopy.moved(vault: vault.name))
            } else {
                _ = try await model.vault.copyItem(id: item.id, toVaultId: target)
                model.confirm(L10n.moveCopy.copied(vault: vault.name))
            }
            dismiss()
        } catch { model.show(error) }
    }
}
