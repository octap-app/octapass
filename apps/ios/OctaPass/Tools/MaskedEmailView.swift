import OctaPassResources
import OctaPassVault
import SwiftUI

/// Masked email (the web vault's `MaskedEmailPage`): the services connected with the user's own
/// API token (kept in the vault, used only from this phone), making an alias for a site, and the
/// aliases logins use.
struct MaskedEmailView: View {
    @Environment(AppModel.self) private var model
    @State private var health = HealthStore.shared
    @State private var connections: [MaskedEmailConnection]?
    @State private var connecting = false
    @State private var disconnecting: MaskedEmailConnection?
    @State private var deleting: RecoveryContact?
    @State private var changing = false
    @State private var site = ""
    @State private var connectionId: String?
    @State private var made: MaskedAlias?
    @State private var making = false

    var body: some View {
        List {
            Section { Text(L10n.maskedEmail.subtitle).font(.subheadline).foregroundStyle(Color.mist) }
            Section {
                if let connections {
                    if connections.isEmpty { Text(L10n.maskedEmail.none).foregroundStyle(Color.mist) }
                    ForEach(connections, id: \.itemId) { connection in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(MaskedEmailNames.name(connection.provider))
                            if let detail = connection.domain ?? connection.baseUrl {
                                Text(detail).font(.footnote).foregroundStyle(Color.mist).environment(\.layoutDirection, .leftToRight)
                            }
                        }
                        .swipeActions {
                            Button(L10n.maskedEmail.disconnect, role: .destructive) { disconnecting = connection }
                        }
                        .contextMenu {
                            Button(L10n.maskedEmail.disconnect, role: .destructive) { disconnecting = connection }
                        }
                    }
                } else {
                    ProgressView()
                }
                Button { connecting = true } label: { Label(L10n.maskedEmail.connect, systemImage: "plus") }
                    .accessibilityIdentifier("masked-connect")
            } header: {
                Text(L10n.maskedEmail.providers)
            } footer: {
                Text(L10n.maskedEmail.providersHelp)
            }
            if connections?.isEmpty == false {
                Section(L10n.maskedEmail.make) {
                    TextField(L10n.maskedEmail.site, text: $site, prompt: Text(L10n.maskedEmail.sitePlaceholder))
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    if let connections, connections.count > 1 {
                        Picker(L10n.maskedEmail.provider, selection: Binding(get: { connectionId ?? connections[0].itemId }, set: { connectionId = $0 })) {
                            ForEach(connections, id: \.itemId) { Text(MaskedEmailNames.name($0.provider)).tag($0.itemId) }
                        }
                    }
                    Button {
                        Task { await make() }
                    } label: {
                        HStack { Text(L10n.maskedEmail.make); if making { Spacer(); ProgressView() } }
                    }
                    .disabled(making || site.trimmingCharacters(in: .whitespaces).isEmpty)
                    if let made {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(L10n.maskedEmail.created).font(.caption).foregroundStyle(Color.mist)
                                Text(made.email).textSelection(.enabled).environment(\.layoutDirection, .leftToRight)
                            }
                            Spacer()
                            CopyButton(value: made.email, what: L10n.fields.email, secret: false)
                        }
                    }
                }
            }
            aliases
        }
        .navigationTitle(L10n.maskedEmail.title)
        .task(id: model.itemsVersion) { connections = try? await model.vault.maskedEmailConnections() }
        .task(id: model.itemsVersion) { await health.load(model.vault, again: true) }
        .sheet(isPresented: $connecting) { ConnectMaskedEmailSheet() }
        .confirmationDialog(disconnecting.map { L10n.maskedEmail.disconnectTitle(provider: MaskedEmailNames.name($0.provider)) } ?? "",
                            isPresented: Binding(get: { disconnecting != nil }, set: { if !$0 { disconnecting = nil } }), titleVisibility: .visible) {
            Button(L10n.maskedEmail.disconnect, role: .destructive) {
                guard let connection = disconnecting else { return }
                Task {
                    do {
                        try await model.vault.disconnectMaskedEmail(itemId: connection.itemId)
                        model.confirm(L10n.maskedEmail.disconnected(provider: MaskedEmailNames.name(connection.provider)))
                    } catch { model.show(error) }
                }
            }
        } message: {
            Text(disconnecting.map { L10n.maskedEmail.disconnectBody(provider: MaskedEmailNames.name($0.provider)) } ?? "")
        }
        .confirmationDialog(L10n.maskedEmail.deleteTitle, isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }), titleVisibility: .visible) {
            Button(L10n.maskedEmail.delete, role: .destructive) {
                guard let alias = deleting else { return }
                change(done: L10n.maskedEmail.deleted) {
                    try await model.vault.deleteAlias(provider: alias.aliasProvider ?? "", aliasId: alias.aliasId ?? alias.value, email: alias.value, loginIds: alias.logins.map(\.itemId))
                }
            }
        } message: {
            Text(deleting.map { L10n.maskedEmail.deleteBody(provider: MaskedEmailNames.name($0.aliasProvider ?? ""), alias: $0.value) } ?? "")
        }
    }

    private func change(done: String, _ call: @escaping () async throws -> Void) {
        changing = true
        Task {
            defer { changing = false }
            do {
                try await call()
                model.confirm(done)
            } catch { model.show(error) }
        }
    }

    /// Turn off, turn on and delete. The list comes from the vault, not the provider, so it doesn't
    /// know whether an alias is on right now: both switches are offered, and repeating one does nothing.
    @ViewBuilder
    private func aliasActions(_ alias: RecoveryContact) -> some View {
        let provider = alias.aliasProvider ?? ""
        let aliasId = alias.aliasId ?? alias.value
        let name = MaskedEmailNames.name(provider)
        if !canManageAlias(provider: provider, aliasId: aliasId, email: alias.value) {
            Text(L10n.maskedEmail.manageThere(provider: name)).font(.footnote).foregroundStyle(Color.mist)
        } else if connections?.contains(where: { $0.provider == provider }) != true {
            Text(L10n.maskedEmail.connectToManage(provider: name)).font(.footnote).foregroundStyle(Color.mist)
        } else {
            Button(L10n.maskedEmail.turnOff) {
                change(done: L10n.maskedEmail.turnedOff) { try await model.vault.setAliasEnabled(provider: provider, aliasId: aliasId, email: alias.value, enabled: false) }
            }
            .disabled(changing)
            .accessibilityLabel(L10n.maskedEmail.turnOffAlias(alias: alias.value))
            Button(L10n.maskedEmail.turnOn) {
                change(done: L10n.maskedEmail.turnedOn) { try await model.vault.setAliasEnabled(provider: provider, aliasId: aliasId, email: alias.value, enabled: true) }
            }
            .disabled(changing)
            .accessibilityLabel(L10n.maskedEmail.turnOnAlias(alias: alias.value))
            Button(L10n.maskedEmail.delete, role: .destructive) { deleting = alias }
                .disabled(changing)
                .accessibilityLabel(L10n.maskedEmail.deleteAlias(alias: alias.value))
        }
    }

    /// The aliases logins use, from the recovery map (the web vault's `AliasesSection`): which
    /// logins use which alias.
    private var aliases: some View {
        Section {
            if let report = health.report {
                let aliases = report.recovery.filter { $0.aliasProvider != nil }
                if aliases.isEmpty { Text(L10n.maskedEmail.noAliases).foregroundStyle(Color.mist) }
                ForEach(aliases, id: \.value) { alias in
                    VStack(alignment: .leading, spacing: 2) {
                        Label {
                            Text(alias.value).environment(\.layoutDirection, .leftToRight)
                        } icon: {
                            Image(systemName: "envelope")
                        }
                        Text("\(MaskedEmailNames.name(alias.aliasProvider ?? "")) · \(L10n.maskedEmail.usedBy(count: alias.logins.count))")
                            .font(.footnote).foregroundStyle(Color.mist)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("masked-alias")
                    ForEach(alias.logins, id: \.itemId) { HealthRow(entry: $0) }
                    aliasActions(alias)
                }
            } else {
                ProgressView()
            }
        } header: {
            Text(L10n.maskedEmail.aliases)
        } footer: {
            Text(L10n.maskedEmail.aliasesHelp)
        }
    }

    private func make() async {
        making = true
        defer { making = false }
        do {
            made = try await model.vault.createAlias(site: site.trimmingCharacters(in: .whitespaces), connectionId: connectionId)
            Haptics.success()
        } catch { model.show(error) }
    }
}

private struct ConnectMaskedEmailSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    private let providers = maskedEmailProviders()
    @State private var providerId = ""
    @State private var token = ""
    @State private var domain = ""
    @State private var selfHosted = false
    @State private var baseUrl = ""
    @State private var error: String?
    @State private var busy = false

    private var provider: MaskedEmailProvider? { providers.first { $0.id == providerId } }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker(L10n.maskedEmail.provider, selection: $providerId) {
                        ForEach(providers, id: \.id) { Text($0.name).tag($0.id) }
                    }
                    if let provider {
                        MaskedField(label: L10n.maskedEmail.token, text: $token)
                            .accessibilityIdentifier("masked-token")
                        Text(L10n.maskedEmail.tokenHint(provider: provider.name)).font(.footnote).foregroundStyle(Color.mist)
                        if let url = URL(string: provider.tokenUrl) {
                            Button(L10n.maskedEmail.getToken) { openURL(url) }
                        }
                        if provider.needsDomain {
                            TextField(L10n.maskedEmail.domain, text: $domain).textInputAutocapitalization(.never).autocorrectionDisabled()
                            Text(L10n.maskedEmail.domainHint).font(.footnote).foregroundStyle(Color.mist)
                        }
                        if provider.defaultBaseUrl != nil {
                            Toggle(L10n.maskedEmail.selfHosted, isOn: $selfHosted)
                            if selfHosted {
                                TextField("https://", text: $baseUrl).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                                Text(L10n.maskedEmail.selfHostedHint(provider: provider.name)).font(.footnote).foregroundStyle(Color.mist)
                            }
                        }
                    }
                    if let error { Text(error).font(.footnote).foregroundStyle(Color.dangerText) }
                }
            }
            .navigationTitle(L10n.maskedEmail.connect)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.maskedEmail.connectButton) { Task { await connect() } }
                        .disabled(busy || token.isEmpty || provider == nil)
                }
            }
            .onAppear { if providerId.isEmpty { providerId = providers.first?.id ?? "" } }
        }
    }

    private func connect() async {
        guard let provider else { return }
        busy = true
        defer { busy = false }
        do {
            _ = try await model.vault.connectMaskedEmail(
                provider: provider.id, token: token,
                baseUrl: selfHosted && !baseUrl.isEmpty ? baseUrl : nil,
                domain: domain.isEmpty ? nil : domain)
            model.confirm(L10n.maskedEmail.connected(provider: provider.name))
            dismiss()
        } catch {
            self.error = error.message
        }
    }
}
