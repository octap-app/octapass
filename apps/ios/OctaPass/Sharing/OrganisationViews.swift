import OctaPassResources
import OctaPassVault
import SwiftUI

/// Organisation (the web vault's `OrganisationPage`): invitations, or creating one; then the
/// organisation itself, whose sections depend on the member's role. The calls are the desktop
/// app's, through `OctaPassVault` (`crates/octapass-mobile/src/organisations.rs`). Only the
/// access review seals a key, on this device, to people confirmed by their fingerprint.
struct OrganisationView: View {
    @Environment(AppModel.self) private var model
    @State private var state: OrgState?
    @State private var reviews: [OrgAccessReview] = []
    @State private var creating = false
    @State private var leaving = false
    @State private var orphaning = false
    @State private var deleting = false

    var body: some View {
        List {
            if let state {
                ForEach(state.invitations, id: \.id) { invitation in
                    InvitationSection(invitation: invitation, joined: state.organisation != nil) { await load() }
                }
                if let organisation = state.organisation {
                    member(organisation)
                } else {
                    create
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(state?.organisation?.name ?? L10n.organisation.title)
        .task(id: model.sharingVersion) { await load() }
        .confirmationDialog(L10n.organisation.leaveTitle(organisation: state?.organisation?.name ?? ""), isPresented: $leaving, titleVisibility: .visible) {
            Button(L10n.organisation.leave, role: .destructive) { Task { await leave() } }
        } message: {
            Text(orphaning ? L10n.organisation.removeOrphans : L10n.organisation.leaveBody)
        }
        .sheet(isPresented: $deleting) {
            if let organisation = state?.organisation { DeleteOrganisationSheet(organisation: organisation) }
        }
        .sheet(isPresented: $creating) { CreateOrganisationSheet { await load() } }
    }

    private var create: some View {
        Section {
            Button { creating = true } label: { Label(L10n.organisation.createAction, systemImage: "building.2") }
                .accessibilityIdentifier("org-create-start")
        } header: {
            Text(L10n.organisation.create)
        } footer: {
            Text(L10n.organisation.createHelp)
        }
    }

    @ViewBuilder private func member(_ organisation: Organisation) -> some View {
        let admin = organisation.role != .member
        let owner = organisation.role == .owner
        if organisation.accessWithheld {
            Section { Notice(text: "\(L10n.organisation.withheldTitle). \(L10n.organisation.withheldBody)", tone: .warn) }
                .listRowBackground(Color.clear).listRowInsets(EdgeInsets())
        }
        if !reviews.isEmpty {
            Section {
                ForEach(reviews, id: \.vaultId) { review in
                    NavigationLink(value: Route.orgSection(.access(review.vaultId))) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(OrgNames.vault(review.vaultName, review.shortId))
                            Text(review.canApply ? L10n.organisation.accessApply(count: review.grants.count) : L10n.organisation.accessWaiting(count: review.grants.count))
                                .font(.footnote).foregroundStyle(review.canApply ? Color.warnText : Color.mist)
                        }
                    }
                    .accessibilityIdentifier("org-review")
                }
            } header: {
                Text(L10n.organisation.accessTitle)
            } footer: {
                Text(L10n.organisation.accessHelp)
            }
        }
        Section(L10n.organisation.about) {
            VStack(alignment: .leading, spacing: 2) {
                Text(L10n.organisation.yourRole(role: OrgNames.role(organisation.role)))
                    .accessibilityIdentifier("org-role")
                Text(L10n.organisation.since(date: Dates.long(organisation.createdAt), count: Int(organisation.memberCount)))
                    .font(.footnote).foregroundStyle(Color.mist)
            }
            let rules = OrgNames.rules(organisation.policies)
            if !owner, !rules.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text(L10n.organisation.joinRules).font(.subheadline.weight(.semibold))
                    ForEach(rules, id: \.self) { Text("• \($0)").font(.footnote) }
                }
            }
        }
        if admin {
            Section(L10n.organisation.sections) {
                NavigationLink(value: Route.orgSection(.members(owner: owner))) { Label(L10n.organisation.tabMembers, systemImage: "person.2") }
                    .accessibilityIdentifier("org-members")
                NavigationLink(value: Route.orgSection(.groups)) { Label(L10n.organisation.tabGroups, systemImage: "person.3") }
                    .accessibilityIdentifier("org-groups")
                NavigationLink(value: Route.orgSection(.vaults)) { Label(L10n.organisation.tabVaults, systemImage: "lock.rectangle.stack") }
                    .accessibilityIdentifier("org-vaults")
                if owner {
                    NavigationLink(value: Route.orgSection(.policies)) { Label(L10n.organisation.tabPolicies, systemImage: "checklist") }
                        .accessibilityIdentifier("org-policies")
                    NavigationLink(value: Route.orgSection(.sso)) { Label(L10n.organisation.tabSso, systemImage: "person.badge.key") }
                    NavigationLink(value: Route.orgSection(.scim)) { Label(L10n.organisation.tabScim, systemImage: "arrow.triangle.2.circlepath") }
                }
                NavigationLink(value: Route.orgSection(.activity)) { Label(L10n.organisation.tabActivity, systemImage: "list.bullet.rectangle") }
            }
        }
        Section(L10n.organisation.danger) {
            Button(L10n.organisation.leave, role: .destructive) {
                orphaning = false
                leaving = true
            }
            .accessibilityIdentifier("org-leave")
            if owner {
                Button(L10n.organisation.delete, role: .destructive) { deleting = true }
                    .accessibilityIdentifier("org-delete")
            }
        }
    }

    private func load() async {
        do {
            let next = try await model.vault.getOrganisation()
            state = next
            reviews = next.organisation == nil ? [] : (try? await model.vault.orgAccess()) ?? []
        } catch { model.show(error) }
    }

    private func leave() async {
        do {
            try await model.vault.leaveOrganisation(orphanVaults: orphaning)
            model.confirm(L10n.organisation.left)
            await load()
        } catch {
            if error.isVault(.orgVaultOrphaned) {
                orphaning = true
                leaving = true
            } else { model.show(error) }
        }
    }
}

/// A new organisation, with this account as its owner.
private struct CreateOrganisationSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let created: () async -> Void
    @State private var name = ""
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(L10n.organisation.name, text: $name)
                        .accessibilityIdentifier("org-name")
                } footer: {
                    Text(L10n.organisation.nameHint)
                }
            }
            .navigationTitle(L10n.organisation.create)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.organisation.createAction) {
                        Task {
                            busy = true
                            defer { busy = false }
                            do {
                                _ = try await model.vault.createOrganisation(name: name.trimmingCharacters(in: .whitespaces))
                                model.confirm(L10n.organisation.created)
                                await created()
                                dismiss()
                            } catch { model.show(error) }
                        }
                    }
                    .disabled(busy || name.trimmingCharacters(in: .whitespaces).isEmpty)
                    .accessibilityIdentifier("org-create")
                }
            }
        }
        .presentationDetents([.medium])
    }
}

/// The organisation's screens below its own, as routes, so the whole stack is in the navigation
/// path (and the Mac's detail column drops them with the rest).
enum OrgSection: Hashable {
    case members(owner: Bool), groups, vaults, vault(String), access(String), policies, sso, scim, activity
}

struct OrgSectionView: View {
    let section: OrgSection

    var body: some View {
        switch section {
        case let .members(owner): OrgMembersView(owner: owner)
        case .groups: OrgGroupsView()
        case .vaults: OrgVaultsView()
        case let .vault(id): OrgVaultView(vaultId: id)
        case let .access(id): OrgAccessReviewView(vaultId: id)
        case .policies: OrgPoliciesView()
        case .sso: OrgSsoView()
        case .scim: OrgScimView()
        case .activity: OrgActivityView()
        }
    }
}

/// Names and summaries the organisation screens share.
enum OrgNames {
    static func role(_ role: OrgRole) -> String {
        switch role {
        case .owner: L10n.organisation.role_owner
        case .admin: L10n.organisation.role_admin
        case .member: L10n.organisation.role_member
        }
    }

    /// A shared vault's name is inside it: without the key, part of its id.
    static func vault(_ name: String?, _ shortId: String) -> String {
        name ?? L10n.organisation.vaultWithId(id: shortId)
    }

    /// The rules a policy set brings, in words (`policySummary`).
    static func rules(_ policies: OrgPolicies) -> [String] {
        var lines: [String] = []
        if policies.requireSso { lines.append(L10n.organisation.policySso) }
        if policies.requireTwoStep { lines.append(L10n.organisation.policyTwoStep) }
        if policies.disableShareLinks { lines.append(L10n.organisation.policyShareLinks) }
        if policies.disableEmergencyAccess { lines.append(L10n.organisation.policyEmergency) }
        if policies.disableExport { lines.append(L10n.organisation.policyExport) }
        if let minutes = policies.maxAutoLockMinutes, minutes > 0 { lines.append(L10n.organisation.policyAutoLock(minutes: String(minutes))) }
        if let length = policies.minPasswordLength, length > 0 { lines.append(L10n.organisation.policyPassword(length: String(length))) }
        return lines
    }
}

/// An invitation: what joining means, the rules that come with it, then Join or Decline.
private struct InvitationSection: View {
    @Environment(AppModel.self) private var model
    let invitation: OrgInvitation
    let joined: Bool
    let reload: () async -> Void
    @State private var busy = false

    var body: some View {
        Section {
            Text(L10n.organisation.joinPrivacy).font(.footnote)
            Text(L10n.organisation.joinOwners).font(.footnote)
            let rules = OrgNames.rules(invitation.policies)
            if !rules.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text(L10n.organisation.joinRules).font(.subheadline.weight(.semibold))
                    ForEach(rules, id: \.self) { Text("• \($0)").font(.footnote) }
                }
            }
            if joined { Notice(text: L10n.organisation.oneAtATime, tone: .info) }
            Button(L10n.organisation.accept) {
                run({ _ = try await model.vault.acceptOrgInvite(orgId: invitation.orgId, inviteId: invitation.id) }, L10n.organisation.joined)
            }
            .disabled(joined || busy)
            .accessibilityIdentifier("org-accept")
            Button(L10n.organisation.decline, role: .destructive) {
                run({ try await model.vault.declineOrgInvite(orgId: invitation.orgId, inviteId: invitation.id) }, L10n.organisation.declined)
            }
            .disabled(busy)
        } header: {
            Text(L10n.organisation.invitation(organisation: invitation.orgName))
        } footer: {
            if let by = invitation.invitedBy { Text(L10n.organisation.invitedBy(email: by)) }
        }
    }

    private func run(_ action: @escaping () async throws -> Void, _ message: String) {
        Task {
            busy = true
            defer { busy = false }
            do {
                try await action()
                model.confirm(message)
                await reload()
            } catch { model.show(error) }
        }
    }
}

/// Deleting the organisation: its name typed, and the master password.
private struct DeleteOrganisationSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let organisation: Organisation
    @State private var confirmName = ""
    @State private var password = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section { Text(L10n.organisation.deleteBody) }
                Section {
                    TextField(L10n.organisation.deleteConfirm(organisation: organisation.name), text: $confirmName)
                        .autocorrectionDisabled()
                    PasswordInput(label: L10n.organisation.masterPassword, text: $password, error: error)
                }
                Section {
                    Button(L10n.organisation.delete, role: .destructive) { Task { await submit() } }
                        .disabled(busy || confirmName != organisation.name || password.isEmpty)
                }
            }
            .navigationTitle(L10n.organisation.deleteTitle(organisation: organisation.name))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } } }
        }
    }

    private func submit() async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            try await model.vault.deleteOrganisation(password: password, confirmName: confirmName)
            model.confirm(L10n.organisation.deleted)
            dismiss()
        } catch {
            self.error = error.message
        }
    }
}

/// One vault's waiting grants: each person's fingerprint, computed on this device, ticked one by
/// one. Only the ticked people are sealed to, checked again against the fingerprint shown.
struct OrgAccessReviewView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let vaultId: String
    @State private var review: OrgAccessReview?
    @State private var confirmed: Set<String> = []
    @State private var busy = false

    var body: some View {
        List {
            if let review {
                Section { Text(L10n.organisation.accessHelp).font(.footnote).foregroundStyle(Color.mist) }
                ForEach(review.grants, id: \.accountId) { grant in
                    Section {
                        HStack {
                            Avatar(name: grant.email, size: 32)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(grant.email).environment(\.layoutDirection, .leftToRight)
                                HStack(spacing: 6) {
                                    Text(RoleNames.name(grant.role))
                                    if grant.upgrade { Text(L10n.organisation.accessUpgrade) }
                                    if grant.verified { Text(L10n.fingerprint.verified).foregroundStyle(Color.freeText) }
                                }
                                .font(.footnote).foregroundStyle(Color.mist)
                            }
                        }
                        FingerprintView(fingerprint: grant.fingerprint)
                        if review.canApply {
                            Toggle(L10n.organisation.accessConfirm(email: grant.email), isOn: Binding(
                                get: { confirmed.contains(grant.accountId) },
                                set: { on in if on { confirmed.insert(grant.accountId) } else { confirmed.remove(grant.accountId) } }))
                                .disabled(grant.keyChanged)
                                .accessibilityIdentifier("org-review-confirm")
                        }
                        if grant.keyChanged { Notice(text: L10n.organisation.accessKeyChanged, tone: .warn) }
                    }
                }
                if review.canApply {
                    Section {
                        if !review.grants.isEmpty {
                            Button(L10n.organisation.accessApply(count: confirmed.count)) { Task { await apply(review) } }
                                .disabled(busy || confirmed.isEmpty)
                                .accessibilityIdentifier("org-review-apply")
                        }
                        if review.rotate {
                            Button(L10n.organisation.rotate) { Task { await rotate() } }.disabled(busy)
                        }
                    }
                } else {
                    Section { Text(L10n.organisation.accessWaiting(count: review.grants.count)).foregroundStyle(Color.mist) }
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(review.map { OrgNames.vault($0.vaultName, $0.shortId) } ?? L10n.organisation.accessTitle)
        .task { await load() }
    }

    private func load() async {
        do {
            review = try await model.vault.orgAccess().first { $0.vaultId == vaultId }
            if review == nil { dismiss() }
        } catch { model.show(error) }
    }

    private func apply(_ review: OrgAccessReview) async {
        busy = true
        defer { busy = false }
        let chosen = review.grants.filter { confirmed.contains($0.accountId) }
            .map { ConfirmedGrant(accountId: $0.accountId, fingerprintDigits: $0.fingerprint.digits) }
        do {
            _ = try await model.vault.applyOrgAccess(vaultId: vaultId, confirmed: chosen)
            model.confirm(L10n.organisation.accessApplied)
            confirmed = []
            await load()
        } catch { model.show(error) }
    }

    private func rotate() async {
        busy = true
        defer { busy = false }
        do {
            try await model.vault.rotateOrgVault(vaultId: vaultId)
            model.confirm(L10n.organisation.rotated)
            await load()
        } catch { model.show(error) }
    }
}

/// Members and pending invites. Only owners change roles or remove an owner.
struct OrgMembersView: View {
    @Environment(AppModel.self) private var model
    let owner: Bool
    @State private var data: OrgMembers?
    @State private var email = ""
    @State private var role = OrgRole.member
    @State private var removing: OrgMember?
    @State private var orphaning = false
    @State private var busy = false

    var body: some View {
        List {
            if let data {
                Section(L10n.organisation.tabMembers) {
                    ForEach(data.members, id: \.accountId) { member in
                        HStack {
                            Avatar(name: member.email, size: 32)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(member.isYou ? L10n.members.you(email: member.email) : member.email)
                                    .environment(\.layoutDirection, .leftToRight)
                                HStack(spacing: 6) {
                                    Text(OrgNames.role(member.role))
                                    Text(member.twoStep ? L10n.organisation.twoStepOn : L10n.organisation.twoStepOff)
                                        .foregroundStyle(member.twoStep ? Color.freeText : Color.mist)
                                    if member.ssoLinked { Text(L10n.organisation.ssoLinked) }
                                }
                                .font(.footnote).foregroundStyle(Color.mist)
                            }
                            Spacer()
                            if owner || (!member.isYou && member.role != .owner) {
                                Menu {
                                    if owner {
                                        Picker(L10n.organisation.roleOf(email: member.email), selection: Binding(get: { member.role }, set: { next in Task { await setRole(member, next) } })) {
                                            ForEach([OrgRole.owner, .admin, .member], id: \.self) { Text(OrgNames.role($0)).tag($0) }
                                        }
                                    }
                                    if !member.isYou {
                                        Button(L10n.organisation.remove(email: member.email), role: .destructive) {
                                            orphaning = false
                                            removing = member
                                        }
                                    }
                                } label: { Image(systemName: "ellipsis.circle") }
                                .accessibilityLabel(L10n.organisation.roleOf(email: member.email))
                            }
                        }
                    }
                    ForEach(data.invites, id: \.id) { invite in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(invite.email).environment(\.layoutDirection, .leftToRight)
                                Text("\(L10n.family.pending) · \(OrgNames.role(invite.role)) · \(L10n.family.invitedOn(date: Dates.medium(invite.invitedAt)))")
                                    .font(.footnote).foregroundStyle(Color.mist)
                            }
                            Spacer()
                            Button(L10n.common.cancel) { Task { await cancel(invite) } }
                                .buttonStyle(.borderless)
                                .accessibilityLabel(L10n.family.cancelInvite(email: invite.email))
                        }
                    }
                }
                Section(L10n.organisation.invite) {
                    TextField(L10n.organisation.inviteEmail, text: $email)
                        .keyboardType(.emailAddress)
                        .textContentType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("org-invite-email")
                    Picker(L10n.roles.label, selection: $role) {
                        ForEach([OrgRole.member, .admin], id: \.self) { Text(OrgNames.role($0)).tag($0) }
                    }
                    Button(L10n.organisation.inviteAction) { Task { await invite() } }
                        .disabled(busy || !email.contains("@"))
                        .accessibilityIdentifier("org-invite-send")
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.organisation.tabMembers)
        .task(id: model.sharingVersion) { await load() }
        .confirmationDialog(removing.map { L10n.organisation.removeTitle(email: $0.email) } ?? "", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), titleVisibility: .visible) {
            Button(L10n.common.remove, role: .destructive) {
                guard let member = removing else { return }
                Task { await remove(member) }
            }
        } message: {
            Text(orphaning ? L10n.organisation.removeOrphans : L10n.organisation.removeBody)
        }
    }

    private func load() async {
        do { data = try await model.vault.listOrgMembers() } catch { model.show(error) }
    }

    private func invite() async {
        busy = true
        defer { busy = false }
        let address = email.trimmingCharacters(in: .whitespaces)
        do {
            try await model.vault.inviteOrgMember(email: address, role: role)
            model.confirm(L10n.organisation.invited(email: address))
            email = ""
            await load()
        } catch { model.show(error) }
    }

    private func cancel(_ invite: OrgInvite) async {
        do {
            try await model.vault.cancelOrgInvite(inviteId: invite.id)
            model.confirm(L10n.family.cancelled)
            await load()
        } catch { model.show(error) }
    }

    private func setRole(_ member: OrgMember, _ role: OrgRole) async {
        do {
            try await model.vault.setOrgMemberRole(accountId: member.accountId, role: role)
            model.confirm(L10n.organisation.roleChanged)
            await load()
        } catch { model.show(error) }
    }

    private func remove(_ member: OrgMember) async {
        do {
            try await model.vault.removeOrgMember(accountId: member.accountId, orphanVaults: orphaning)
            await load()
        } catch {
            if error.isVault(.orgVaultOrphaned) {
                orphaning = true
                removing = member
            } else { model.show(error) }
        }
    }
}

/// Groups: lists of people. Adding someone only asks a vault manager to give them the key.
struct OrgGroupsView: View {
    @Environment(AppModel.self) private var model
    @State private var groups: [OrgGroup]?
    @State private var people: [OrgMember] = []
    @State private var name = ""
    @State private var deleting: OrgGroup?
    @State private var renaming: OrgGroup?
    @State private var newName = ""

    var body: some View {
        List {
            if let groups {
                Section { Text(L10n.organisation.groupsHelp).font(.footnote).foregroundStyle(Color.mist) }
                if groups.isEmpty { Text(L10n.organisation.noGroups).foregroundStyle(Color.mist) }
                ForEach(groups, id: \.id) { group in
                    Section {
                        ForEach(group.members, id: \.self) { accountId in
                            let email = people.first { $0.accountId == accountId }?.email ?? accountId
                            HStack {
                                Text(email).environment(\.layoutDirection, .leftToRight)
                                Spacer()
                                Button { run({ try await model.vault.removeOrgGroupMember(groupId: group.id, accountId: accountId) }) } label: {
                                    Image(systemName: "minus.circle")
                                }
                                .buttonStyle(.borderless)
                                .accessibilityLabel(L10n.organisation.removeFromGroup(email: email, name: group.name))
                            }
                        }
                        let others = people.filter { !group.members.contains($0.accountId) }
                        if !others.isEmpty {
                            // A picker that adds whoever is chosen, as the web vault's select does.
                            Picker(L10n.organisation.addToGroup(name: group.name), selection: Binding<String?>(get: { nil }, set: { accountId in
                                guard let accountId else { return }
                                run({ try await model.vault.addOrgGroupMember(groupId: group.id, accountId: accountId) })
                            })) {
                                Text(L10n.organisation.chooseMember).tag(String?.none)
                                ForEach(others, id: \.accountId) { Text($0.email).tag(String?.some($0.accountId)) }
                            }
                            .accessibilityIdentifier("org-group-add")
                        }
                    } header: {
                        HStack {
                            Text(group.name)
                            Spacer()
                            Menu {
                                Button(L10n.common.rename) { newName = group.name; renaming = group }
                                Button(L10n.organisation.deleteGroup, role: .destructive) { deleting = group }
                            } label: { Image(systemName: "ellipsis.circle") }
                            .accessibilityLabel(L10n.organisation.deleteGroupNamed(name: group.name))
                        }
                    }
                }
                Section(L10n.organisation.newGroup) {
                    TextField(L10n.organisation.groupName, text: $name)
                        .accessibilityIdentifier("org-group-name")
                    Button(L10n.organisation.createGroup) {
                        let chosen = name.trimmingCharacters(in: .whitespaces)
                        run({ _ = try await model.vault.createOrgGroup(name: chosen); name = "" }, L10n.organisation.groupCreated)
                    }
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                    .accessibilityIdentifier("org-group-create")
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.organisation.tabGroups)
        .task(id: model.sharingVersion) { await load() }
        .confirmationDialog(deleting.map { L10n.organisation.deleteGroupTitle(name: $0.name) } ?? "", isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }), titleVisibility: .visible) {
            Button(L10n.organisation.deleteGroup, role: .destructive) {
                guard let group = deleting else { return }
                run({ try await model.vault.deleteOrgGroup(groupId: group.id) })
            }
        } message: {
            Text(L10n.organisation.deleteGroupBody)
        }
        .alert(L10n.common.rename, isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
            TextField(L10n.organisation.groupName, text: $newName)
            Button(L10n.common.save) {
                guard let group = renaming else { return }
                let chosen = newName.trimmingCharacters(in: .whitespaces)
                run({ try await model.vault.renameOrgGroup(groupId: group.id, name: chosen) })
            }
            Button(L10n.common.cancel, role: .cancel) {}
        }
    }

    private func load() async {
        do {
            groups = try await model.vault.listOrgGroups()
            people = try await model.vault.listOrgMembers().members
        } catch { model.show(error) }
    }

    private func run(_ action: @escaping () async throws -> Void, _ message: String? = nil) {
        Task {
            do {
                try await action()
                if let message { model.confirm(message) }
                await load()
            } catch { model.show(error) }
        }
    }
}

/// The organisation's vaults, named when this account can open them.
struct OrgVaultsView: View {
    @Environment(AppModel.self) private var model
    @State private var vaults: [OrgVault]?
    @State private var name = ""
    @State private var busy = false

    var body: some View {
        List {
            if let vaults {
                Section { Text(L10n.organisation.vaultsHelp).font(.footnote).foregroundStyle(Color.mist) }
                Section(L10n.organisation.tabVaults) {
                    if vaults.isEmpty { Text(L10n.organisation.noVaults).foregroundStyle(Color.mist) }
                    ForEach(vaults, id: \.id) { vault in
                        NavigationLink(value: Route.orgSection(.vault(vault.id))) {
                            VStack(alignment: .leading, spacing: 2) {
                                Label(OrgNames.vault(vault.name, vault.shortId), systemImage: "lock.rectangle.stack")
                                Text([L10n.organisation.vaultMembers(count: Int(vault.memberCount)),
                                      vault.rotationPending ? L10n.organisation.rotationDue : nil,
                                      vault.managerCount == 0 ? L10n.organisation.noManagers : nil].compactMap { $0 }.joined(separator: " · "))
                                    .font(.footnote).foregroundStyle(Color.mist)
                            }
                        }
                        .accessibilityIdentifier("org-vault")
                    }
                }
                Section(L10n.organisation.newVault) {
                    TextField(L10n.organisation.vaultName, text: $name)
                        .accessibilityIdentifier("org-vault-name")
                    Button {
                        Task { await create() }
                    } label: {
                        HStack { Text(L10n.organisation.createVault); if busy { Spacer(); ProgressView() } }
                    }
                    .disabled(busy || name.trimmingCharacters(in: .whitespaces).isEmpty)
                    .accessibilityIdentifier("org-vault-create")
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.organisation.tabVaults)
        .task(id: model.sharingVersion) { await load() }
    }

    private func load() async {
        do { vaults = try await model.vault.listOrgVaults() } catch { model.show(error) }
    }

    private func create() async {
        busy = true
        defer { busy = false }
        do {
            _ = try await model.vault.createOrgVault(name: name.trimmingCharacters(in: .whitespaces))
            name = ""
            model.confirm(L10n.organisation.vaultCreated)
            await load()
        } catch { model.show(error) }
    }
}

/// One organisation vault: the groups with access and their roles, linking another, deleting.
struct OrgVaultView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let vaultId: String
    @State private var vault: OrgVault?
    @State private var groups: [OrgGroup] = []
    @State private var linking: String?
    @State private var role = VaultRole.read
    @State private var deleting = false

    private static let roles: [VaultRole] = [.read, .write, .manage]

    var body: some View {
        List {
            if let vault {
                let title = OrgNames.vault(vault.name, vault.shortId)
                if vault.role != nil {
                    Section {
                        NavigationLink(value: Route.list(.vault(vault.id))) { Label(L10n.members.openVault, systemImage: "lock.rectangle.stack") }
                            .accessibilityIdentifier("org-vault-open")
                    }
                }
                Section(L10n.organisation.vaultGroups(name: title)) {
                    ForEach(vault.groups, id: \.groupId) { link in
                        let group = groups.first { $0.id == link.groupId }
                        HStack {
                            Text(group?.name ?? link.groupId)
                            Spacer()
                            Picker(L10n.organisation.groupRole(name: group?.name ?? ""), selection: Binding(get: { link.role }, set: { next in
                                run({ try await model.vault.linkOrgVaultGroup(vaultId: vault.id, groupId: link.groupId, role: next) }, L10n.organisation.linked)
                            })) {
                                ForEach(Self.roles, id: \.self) { Text(RoleNames.name($0)).tag($0) }
                            }
                            .labelsHidden()
                            Button { run({ try await model.vault.unlinkOrgVaultGroup(vaultId: vault.id, groupId: link.groupId) }) } label: {
                                Image(systemName: "minus.circle")
                            }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(L10n.organisation.unlink(name: group?.name ?? ""))
                        }
                    }
                    let unlinked = groups.filter { group in !vault.groups.contains { $0.groupId == group.id } }
                    if !unlinked.isEmpty {
                        Picker(L10n.organisation.linkGroup, selection: $linking) {
                            Text(L10n.organisation.chooseGroup).tag(String?.none)
                            ForEach(unlinked, id: \.id) { Text($0.name).tag(String?.some($0.id)) }
                        }
                        .accessibilityIdentifier("org-link-group")
                        Picker(L10n.roles.label, selection: $role) {
                            ForEach(Self.roles, id: \.self) { Text(RoleNames.name($0)).tag($0) }
                        }
                        .accessibilityIdentifier("org-link-role")
                        Button(L10n.organisation.link) {
                            guard let groupId = linking else { return }
                            run({ try await model.vault.linkOrgVaultGroup(vaultId: vault.id, groupId: groupId, role: role); linking = nil }, L10n.organisation.linked)
                        }
                        .disabled(linking == nil)
                        .accessibilityIdentifier("org-link")
                    }
                }
                Section {
                    Button(L10n.organisation.deleteVault, role: .destructive) { deleting = true }
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(vault.map { OrgNames.vault($0.name, $0.shortId) } ?? L10n.organisation.tabVaults)
        .task(id: model.sharingVersion) { await load() }
        .sheet(isPresented: $deleting) {
            if let vault {
                PasswordConfirmSheet(title: L10n.organisation.deleteVaultTitle(name: OrgNames.vault(vault.name, vault.shortId)), message: L10n.organisation.deleteVaultBody, action: L10n.organisation.deleteVault) { password in
                    try await model.vault.deleteOrgVault(password: password, vaultId: vault.id)
                    model.confirm(L10n.organisation.vaultDeleted)
                    dismiss()
                }
            }
        }
    }

    private func load() async {
        do {
            vault = try await model.vault.listOrgVaults().first { $0.id == vaultId }
            groups = try await model.vault.listOrgGroups()
        } catch { model.show(error) }
    }

    private func run(_ action: @escaping () async throws -> Void, _ message: String? = nil) {
        Task {
            do {
                try await action()
                if let message { model.confirm(message) }
                await load()
            } catch { model.show(error) }
        }
    }
}

/// Something that needs the master password again: deleting an organisation vault.
private struct PasswordConfirmSheet: View {
    @Environment(\.dismiss) private var dismiss
    let title: String
    let message: String
    let action: String
    let onConfirm: (String) async throws -> Void
    @State private var password = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section { Text(message) }
                Section { PasswordInput(label: L10n.organisation.masterPassword, text: $password, error: error) }
                Section {
                    Button(action, role: .destructive) {
                        Task {
                            busy = true
                            error = nil
                            defer { busy = false }
                            do {
                                try await onConfirm(password)
                                dismiss()
                            } catch { self.error = error.message }
                        }
                    }
                    .disabled(busy || password.isEmpty)
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } } }
        }
    }
}

/// Owner: the organisation's rules, the server's and the apps'.
struct OrgPoliciesView: View {
    @Environment(AppModel.self) private var model
    @State private var loaded: OrgPolicies?

    var body: some View {
        if let loaded {
            OrgPoliciesForm(policies: loaded)
        } else {
            ProgressView().frame(maxWidth: .infinity)
                .navigationTitle(L10n.organisation.tabPolicies)
                .task {
                    do { loaded = try await model.vault.getOrganisation().organisation?.policies } catch { model.show(error) }
                }
        }
    }
}

private struct OrgPoliciesForm: View {
    @Environment(AppModel.self) private var model
    @State var policies: OrgPolicies
    @State private var autoLock = ""
    @State private var minPassword = ""
    @State private var busy = false

    var body: some View {
        Form {
            Section {
                Toggle(isOn: $policies.requireTwoStep) { help(L10n.organisation.requireTwoStep, L10n.organisation.requireTwoStepHelp) }
                Toggle(isOn: $policies.requireSso) { help(L10n.organisation.requireSso, L10n.organisation.requireSsoHelp) }
                Stepper(value: $policies.ssoMaxAgeHours, in: 0...8760) {
                    help("\(L10n.organisation.ssoMaxAge): \(policies.ssoMaxAgeHours)", L10n.organisation.ssoMaxAgeHelp)
                }
                Toggle(isOn: $policies.disableShareLinks) { help(L10n.organisation.disableShareLinks, L10n.organisation.disableShareLinksHelp) }
                Toggle(isOn: $policies.disableEmergencyAccess) { help(L10n.organisation.disableEmergency, L10n.organisation.disableEmergencyHelp) }
            } header: {
                Text(L10n.organisation.policiesServer)
            } footer: {
                Text(L10n.organisation.policiesServerHelp)
            }
            Section {
                Toggle(isOn: $policies.disableExport) { help(L10n.organisation.disableExport, L10n.organisation.disableExportHelp) }
                LabeledContent {
                    TextField("", text: $autoLock).keyboardType(.numberPad).multilineTextAlignment(.trailing)
                        .accessibilityIdentifier("org-policy-auto-lock")
                } label: { help(L10n.organisation.maxAutoLock, L10n.organisation.maxAutoLockHelp) }
                LabeledContent {
                    TextField("", text: $minPassword).keyboardType(.numberPad).multilineTextAlignment(.trailing)
                } label: { help(L10n.organisation.minPassword, L10n.organisation.minPasswordHelp) }
            } header: {
                Text(L10n.organisation.policiesClient)
            } footer: {
                Text(L10n.organisation.policiesClientHelp)
            }
            Section {
                Button(L10n.organisation.savePolicies) { Task { await save() } }
                    .disabled(busy)
                    .accessibilityIdentifier("org-policies-save")
            }
        }
        .navigationTitle(L10n.organisation.tabPolicies)
        .onAppear {
            autoLock = policies.maxAutoLockMinutes.map(String.init) ?? ""
            minPassword = policies.minPasswordLength.map(String.init) ?? ""
        }
    }

    private func help(_ title: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
            Text(text).font(.footnote).foregroundStyle(Color.mist)
        }
    }

    private func save() async {
        busy = true
        defer { busy = false }
        var next = policies
        next.maxAutoLockMinutes = UInt32(autoLock.trimmingCharacters(in: .whitespaces)).flatMap { $0 > 0 ? $0 : nil }
        next.minPasswordLength = UInt32(minPassword.trimmingCharacters(in: .whitespaces)).flatMap { $0 > 0 ? $0 : nil }
        do {
            policies = try await model.vault.setOrgPolicies(policies: next)
            model.confirm(L10n.organisation.policiesSaved)
        } catch { model.show(error) }
    }
}

/// Owner: single sign-on with OpenID Connect or SAML 2.0. Sign-in only: the provider can't open
/// a vault.
struct OrgSsoView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @State private var policies = OrgPolicies(requireTwoStep: false, requireSso: false, ssoMaxAgeHours: 168, disableShareLinks: false, disableEmergencyAccess: false, disableExport: false, maxAutoLockMinutes: nil, minPasswordLength: nil)
    @State private var sso: OrgSso?
    @State private var proto = SsoProtocol.oidc
    @State private var issuer = ""
    @State private var clientId = ""
    @State private var clientSecret = ""
    @State private var metadata = ""
    @State private var entityId = ""
    @State private var ssoUrl = ""
    @State private var certificate = ""
    @State private var busy = false

    var body: some View {
        Form {
            Section { Text(L10n.organisation.ssoHelp).font(.footnote).foregroundStyle(Color.mist) }
            Section(L10n.organisation.ssoSignInOnly) { Text(L10n.organisation.ssoSignInOnlyHelp).font(.footnote) }
            if let sso {
                Section {
                    if let tested = sso.testedAt {
                        Text(L10n.organisation.ssoTested(date: Dates.medium(tested)))
                    } else if sso.protocol != nil {
                        Text(L10n.organisation.ssoNotTested).foregroundStyle(Color.warnText)
                    }
                    if let saml = sso.saml {
                        Text(L10n.organisation.samlSaved(entity: saml.entityId)).font(.footnote)
                        ForEach(saml.certificates, id: \.sha256) { Text(L10n.organisation.samlCertificate(sha256: $0.sha256)).font(.caption).textSelection(.enabled) }
                    }
                }
                if policies.requireSso {
                    Section { Notice(text: L10n.organisation.ssoLocked, tone: .info) }
                        .listRowBackground(Color.clear).listRowInsets(EdgeInsets())
                }
                Section {
                    Picker(L10n.organisation.ssoProtocol, selection: $proto) {
                        Text(L10n.organisation.ssoOidc).tag(SsoProtocol.oidc)
                        Text(L10n.organisation.ssoSaml).tag(SsoProtocol.saml)
                    }
                    if proto == .oidc {
                        copyRow(L10n.organisation.ssoRedirect, sso.callbackUrl)
                        TextField(L10n.organisation.ssoIssuer, text: $issuer).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField(L10n.organisation.ssoClientId, text: $clientId).textInputAutocapitalization(.never).autocorrectionDisabled()
                        PasswordInput(label: L10n.organisation.ssoClientSecret, text: $clientSecret, hint: sso.hasClientSecret ? L10n.organisation.ssoSecretKept : L10n.organisation.ssoSecretHelp)
                    } else {
                        copyRow(L10n.organisation.samlSpEntity, sso.samlEntityId)
                        copyRow(L10n.organisation.samlAcs, sso.samlAcsUrl)
                        VStack(alignment: .leading) {
                            Text(L10n.organisation.samlMetadata).font(.footnote)
                            TextEditor(text: $metadata).frame(minHeight: 80).font(.secret(.caption))
                            Text(L10n.organisation.samlMetadataHelp).font(.caption).foregroundStyle(Color.mist)
                        }
                        TextField(L10n.organisation.samlEntityId, text: $entityId).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField(L10n.organisation.samlSsoUrl, text: $ssoUrl).textInputAutocapitalization(.never).autocorrectionDisabled()
                        VStack(alignment: .leading) {
                            Text(L10n.organisation.samlCertificateField).font(.footnote)
                            TextEditor(text: $certificate).frame(minHeight: 60).font(.secret(.caption))
                            Text(L10n.organisation.samlCertificateHelp).font(.caption).foregroundStyle(Color.mist)
                        }
                    }
                    if sso.protocol != nil, sso.protocol != proto { Text(L10n.organisation.ssoReplaces).font(.footnote).foregroundStyle(Color.warnText) }
                }
                .disabled(policies.requireSso)
                Section {
                    Button(L10n.organisation.ssoSave) { Task { await save() } }.disabled(busy || policies.requireSso)
                    if sso.protocol != nil {
                        Button(L10n.organisation.ssoTest) { Task { await test() } }.disabled(busy)
                        Button(L10n.organisation.ssoRefresh) { Task { await load() } }
                        Button(L10n.organisation.ssoRemove, role: .destructive) { Task { await remove() } }.disabled(busy || policies.requireSso)
                    }
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.organisation.tabSso)
        .task { await load() }
    }

    private func copyRow(_ label: String, _ value: String) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.caption).foregroundStyle(Color.mist)
                Text(value).font(.secret(.footnote)).textSelection(.enabled).environment(\.layoutDirection, .leftToRight)
            }
            Spacer()
            Button { model.copy(value, what: label, secret: false) } label: { Image(systemName: "doc.on.doc") }
                .buttonStyle(.borderless)
                .accessibilityLabel(L10n.organisation.scimCopy)
        }
    }

    private func load() async {
        do {
            if let current = try await model.vault.getOrganisation().organisation?.policies { policies = current }
            let next = try await model.vault.orgSso()
            if sso == nil {
                proto = next.protocol ?? .oidc
                issuer = next.issuer ?? ""
                clientId = next.clientId ?? ""
            }
            sso = next
        } catch { model.show(error) }
    }

    private func save() async {
        busy = true
        defer { busy = false }
        do {
            if proto == .oidc {
                sso = try await model.vault.saveOrgSso(settings: OidcSettings(issuer: issuer, clientId: clientId, clientSecret: clientSecret.isEmpty ? nil : clientSecret))
            } else {
                sso = try await model.vault.saveOrgSaml(settings: SamlSettings(
                    metadataXml: metadata.isEmpty ? nil : metadata, entityId: entityId.isEmpty ? nil : entityId,
                    ssoUrl: ssoUrl.isEmpty ? nil : ssoUrl, certificates: certificate.isEmpty ? [] : [certificate]))
            }
            clientSecret = ""
            model.confirm(L10n.organisation.ssoSaved)
        } catch { model.show(error) }
    }

    private func test() async {
        do {
            if let url = URL(string: try await model.vault.testOrgSso()) { openURL(url) }
        } catch { model.show(error) }
    }

    private func remove() async {
        do {
            try await model.vault.removeOrgSso()
            model.confirm(L10n.organisation.ssoRemoved)
            await load()
        } catch { model.show(error) }
    }
}

/// Owner: SCIM tokens for an identity provider. A new token's secret shows once.
struct OrgScimView: View {
    @Environment(AppModel.self) private var model
    @State private var scim: OrgScim?
    @State private var name = ""
    @State private var created: CreatedScimToken?

    var body: some View {
        List {
            Section { Text(L10n.organisation.scimHelp).font(.footnote).foregroundStyle(Color.mist) }
            Section(L10n.organisation.scimWhatItDoes) { Text(L10n.organisation.scimWhatItDoesHelp).font(.footnote) }
            if let scim {
                Section(L10n.organisation.scimBaseUrl) {
                    HStack {
                        Text(scim.baseUrl).font(.secret(.footnote)).textSelection(.enabled).environment(\.layoutDirection, .leftToRight)
                        Spacer()
                        Button(L10n.organisation.scimCopy) { model.copy(scim.baseUrl, what: L10n.organisation.scimBaseUrl, secret: false) }.buttonStyle(.borderless)
                    }
                }
                if let created {
                    Section {
                        Text(created.secret).font(.secret(.footnote)).textSelection(.enabled).environment(\.layoutDirection, .leftToRight)
                        Button(L10n.organisation.scimCopy) { model.copy(created.secret, what: L10n.organisation.scimNewToken) }
                        Button(L10n.organisation.scimDone) { self.created = nil }
                    } header: {
                        Text(L10n.organisation.scimNewToken)
                    } footer: {
                        Text(L10n.organisation.scimNewTokenHelp)
                    }
                }
                Section {
                    if scim.tokens.isEmpty { Text(L10n.organisation.scimNoTokens).foregroundStyle(Color.mist) }
                    ForEach(scim.tokens, id: \.id) { token in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(token.name)
                                Text([L10n.organisation.scimCreated(date: Dates.medium(token.createdAt)),
                                      token.lastUsedAt.map { L10n.organisation.scimLastUsed(date: Dates.medium($0)) } ?? L10n.organisation.scimNeverUsed].joined(separator: " · "))
                                    .font(.footnote).foregroundStyle(Color.mist)
                            }
                            Spacer()
                            Button(L10n.organisation.scimRevoke, role: .destructive) { Task { await revoke(token) } }.buttonStyle(.borderless)
                        }
                    }
                }
                Section {
                    TextField(L10n.organisation.scimTokenName, text: $name)
                    Button(L10n.organisation.scimCreate) { Task { await create() } }
                        .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                } footer: {
                    Text(L10n.organisation.scimTokenNameHelp)
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.organisation.tabScim)
        .task { await load() }
    }

    private func load() async {
        do { scim = try await model.vault.orgScim() } catch { model.show(error) }
    }

    private func create() async {
        do {
            created = try await model.vault.createOrgScimToken(name: name.trimmingCharacters(in: .whitespaces))
            name = ""
            await load()
        } catch { model.show(error) }
    }

    private func revoke(_ token: ScimToken) async {
        do {
            try await model.vault.revokeOrgScimToken(tokenId: token.id)
            model.confirm(L10n.organisation.scimRevoked)
            await load()
        } catch { model.show(error) }
    }
}

/// What members and admins did, newest first. Names and ids only, never vault contents.
struct OrgActivityView: View {
    @Environment(AppModel.self) private var model
    @State private var events: [OrgEvent]?

    var body: some View {
        List {
            Section { Text(L10n.organisation.activityHelp).font(.footnote).foregroundStyle(Color.mist) }
            if let events {
                if events.isEmpty { Text(L10n.organisation.noActivity).foregroundStyle(Color.mist) }
                ForEach(events, id: \.id) { event in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(orgEventMessageKey(eventType: event.eventType).flatMap { L10n.text(forKey: $0) } ?? event.eventType)
                        Text([event.actor ?? (event.eventType.hasPrefix("scim-") ? L10n.organisation.byIdentityProvider : nil),
                              event.subject, Dates.medium(event.createdAt)].compactMap { $0 }.joined(separator: " · "))
                            .font(.footnote).foregroundStyle(Color.mist)
                    }
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.organisation.tabActivity)
        .task(id: model.sharingVersion) {
            do { events = try await model.vault.orgEvents() } catch { model.show(error) }
        }
    }
}
