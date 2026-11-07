import OctaPassResources
import OctaPassVault
import SwiftUI

/// A list of items (the web vault's `ItemsPage`): sorted and in sections with headers that stay
/// at the top, logins for one website as one row that opens in place, search, the Sort and group
/// menu, new items, and swipe actions.
struct ItemListView: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    let scope: ListScope
    @State private var query = ""
    @State private var arrangement: ListArrangement?
    @State private var sections: [ListSection]?
    @State private var plain: [ItemSummary]?
    @State private var failed = false
    @State private var newItem: ItemType?
    @Environment(\.detailEditor) private var detailEditor
    @State private var scanning = false
    @State private var opened: String?
    @State private var filterChoices = EnvironmentChoices(projects: [], stages: [])
    @State private var projectFilter: String?
    @State private var stageFilter: String?

    private var isEnvironment: Bool { scope == .type(.environment) }
    private var isWifi: Bool { scope == .type(.wifi) }
    @State private var radar = WifiRadar.shared
    @State private var explainingImport = false
    private var isTrash: Bool { scope == .trash }
    /// Recently created, Frequently used, Recently used, Recently modified: their own order.
    private var smartList: SmartList? {
        if case let .smart(list) = scope { return list }
        return nil
    }
    private var trimmed: String { query.trimmingCharacters(in: .whitespaces) }
    private var vault: Vault? {
        if case let .vault(id) = scope { return directory.vault(id) }
        return nil
    }
    private var canAdd: Bool { !isTrash && (vault?.canWrite ?? true) && !(model.isLocal && scope == .type(.document)) }
    /// A document is its files, and a local vault can't hold files.
    private var newItemTypes: [ItemType] {
        model.isLocal ? ListScope.itemTypes.filter { $0 != .document } : ListScope.itemTypes
    }
    private var combine: Bool { model.settings.combineSites && offersSiteRows(view: scope.view) }
    private var groupings: [ListGrouping] { listGroupings(view: scope.view, vaultCount: UInt32(directory.vaults.count)) }

    var body: some View {
        content
            .navigationTitle(scope.title(vaults: directory.vaults))
            .searchable(text: $query, prompt: searchPrompt)
            .toolbar { toolbar }
            .task(id: LoadKey(scope: scope, query: trimmed, arrangement: arrangement, combine: combine, version: model.itemsVersion, project: projectFilter, stage: stageFilter)) {
                await load()
            }
            .onAppear {
                arrangement = model.vault.listArrangement(view: scope.view, vaultCount: UInt32(directory.vaults.count))
            }
            .sheet(item: $newItem) { type in
                ItemEditorSheet(draft: starting(type))
            }
            .focusedSceneValue(\.newItemCommand, canAdd ? NewItemCommand(types: newItemTypes, add: add) : nil)
            .sheet(isPresented: $scanning) {
                ScanSheet { id in
                    if let detailEditor { detailEditor.navigate([.item(id)]) } else { opened = id }
                }
            }
            .navigationDestination(item: $opened) { ItemDetailView(itemId: $0) }
            .task(id: isWifi) { if isWifi { await radar.refresh() } }
            .alert(L10n.wifi.phoneImportTitle, isPresented: $explainingImport) {
                Button(L10n.common.close, role: .cancel) {}
            } message: {
                Text(L10n.wifi.iosImport)
            }
    }

    /// Opens the item. On the Mac it goes on the detail column's stack itself (`DetailEditor`):
    /// a link from this column doesn't reach that stack, and leaving an editor with changes asks
    /// first. The open item's row is highlighted there, as a Mac list's selection.
    @ViewBuilder
    private func opener(_ item: ItemSummary, @ViewBuilder label: () -> some View) -> some View {
        if let detailEditor {
            let open = detailEditor.path.first == .item(item.id)
            Button { detailEditor.navigate([.item(item.id)]) } label: {
                label().contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .listRowBackground(open ? RoundedRectangle(cornerRadius: 8).fill(Color.trust.opacity(0.18)).padding(.horizontal, 6) : nil)
            .accessibilityAddTraits(open ? .isSelected : [])
        } else {
            NavigationLink(value: Route.item(item.id), label: label)
        }
    }

    /// The editor for a new item: in the Mac's detail column, a sheet elsewhere.
    private func add(_ type: ItemType) {
        if let detailEditor { detailEditor.open(starting(type)) } else { newItem = type }
    }

    /// A new item here: a favourite when the list is the favourites, pinned when it's Pinned.
    private func starting(_ type: ItemType) -> ItemDraft {
        var draft = newItemDraft(itemType: type, vaultId: defaultVaultId)
        draft.favorite = scope == .favorites
        draft.pinned = scope == .pinned
        return draft
    }

    private struct LoadKey: Equatable {
        let scope: ListScope
        let query: String
        let arrangement: ListArrangement?
        let combine: Bool
        let version: Int
        let project: String?
        let stage: String?
    }

    private var searchPrompt: String {
        guard let count = sections.map({ $0.reduce(0) { $0 + $1.items.count } }) ?? plain?.count, trimmed.isEmpty else {
            return L10n.list.search
        }
        return L10n.list.searchPlaceholder(count: count)
    }

    /// New items go to the vault showing, else the personal vault.
    private var defaultVaultId: String {
        vault?.id ?? directory.personal?.id ?? directory.vaults.first?.id ?? ""
    }

    @ViewBuilder private var content: some View {
        if failed {
            EmptyStateView(icon: "exclamationmark.triangle", title: L10n.list.loadFailed) {
                Button(L10n.common.tryAgain) { Task { await load() } }
            }
        } else if let plain {
            if plain.isEmpty { empty } else { plainList(plain) }
        } else if let sections {
            if sections.isEmpty, projectFilter != nil || stageFilter != nil {
                EmptyStateView(icon: "magnifyingglass", title: L10n.env.noMatches) {
                    Button(L10n.env.clearFilters) {
                        projectFilter = nil
                        stageFilter = nil
                    }
                }
            } else if sections.isEmpty {
                empty
            } else {
                sectionList(sections)
            }
        } else {
            ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func plainList(_ items: [ItemSummary]) -> some View {
        List {
            notes
            ForEach(items, id: \.id) { row($0) }
        }
        .listStyle(.plain)
    }

    private func sectionList(_ sections: [ListSection]) -> some View {
        let grouping = arrangement?.grouping ?? .none
        return List {
            notes
            // The network the phone is on comes first (the web vault's `nearbyFirst`).
            if isWifi, let connected = connectedItem(sections) {
                Section(L10n.list.inRange) { row(connected) }
            }
            ForEach(sections, id: \.key) { section in
                if grouping == .none {
                    rows(section)
                } else {
                    Section {
                        rows(section)
                    } header: {
                        HStack {
                            Text(sectionLabel(grouping, section.key))
                            Spacer()
                            Text(section.items.count.formatted(.number.locale(L10n.formatLocale)))
                                .monospacedDigit()
                        }
                        .accessibilityElement(children: .ignore)
                        .accessibilityLabel("\(sectionLabel(grouping, section.key)), \(L10n.list.sectionCount(count: section.items.count))")
                        .accessibilityAddTraits(.isHeader)
                    }
                }
            }
        }
        // Plain lists keep each section's header at the top while its rows pass under it.
        .listStyle(.plain)
    }

    private func connectedItem(_ sections: [ListSection]) -> ItemSummary? {
        guard let ssid = radar.connected else { return nil }
        return sections.flatMap(\.items).first { $0.itemType == .wifi && $0.subtitle == ssid }
    }

    @ViewBuilder private var notes: some View {
        if !isTrash { BackupReminder() }
        #if os(iOS)
        if isWifi, radar.permission != "granted" {
            WifiPermissionNote()
        }
        #endif
        if isEnvironment, !filterChoices.projects.isEmpty || !filterChoices.stages.isEmpty {
            EnvironmentFilters(choices: filterChoices, project: $projectFilter, stage: $stageFilter)
        }
        if isTrash, plain?.isEmpty == false {
            Text(L10n.trash.note(days: trashDays)).font(.footnote).foregroundStyle(Color.mist)
        }
        if !trimmed.isEmpty, !isTrash, smartList == nil, let arrangement, arrangement.grouping != .none || arrangement.sort != .name, plain?.isEmpty == false {
            Text(L10n.list.searchNote).font(.footnote).foregroundStyle(Color.mist)
        }
        if let vault, vault.untrusted {
            Notice(text: L10n.vault.untrustedBody(vault: vault.name), tone: .warn)
        }
    }

    @ViewBuilder private func rows(_ section: ListSection) -> some View {
        if section.entries.isEmpty {
            ForEach(section.items, id: \.id) { row($0) }
        } else {
            ForEach(Array(section.entries.enumerated()), id: \.offset) { _, entry in
                switch entry {
                case let .item(item): row(item)
                case let .site(host, items): SiteRow(host: host, items: items) { row($0, indented: true) }
                }
            }
        }
    }

    private func row(_ item: ItemSummary, indented: Bool = false) -> some View {
        opener(item) {
            ItemRow(item: item, vault: directory.vault(item.vaultId), scope: scope)
        }
        .padding(.leading, indented ? 20 : 0)
        .accessibilityIdentifier("item-\(item.title)")
        .swipeActions(edge: .trailing, allowsFullSwipe: true) {
            if isTrash {
                Button { restore(item) } label: { Label(L10n.trash.restore, systemImage: "arrow.uturn.backward") }
                    .tint(.free)
            } else if directory.vault(item.vaultId)?.canWrite ?? true {
                Button(role: .destructive) { delete(item) } label: { Label(L10n.detail.moveToTrash, systemImage: "trash") }
            }
        }
        .swipeActions(edge: .leading) {
            if !isTrash {
                Button { favorite(item) } label: {
                    Label(item.favorite ? L10n.detail.removeFavorite : L10n.detail.addFavorite, systemImage: item.favorite ? "star.slash" : "star")
                }
                .tint(.warn)
                Button { pin(item) } label: {
                    Label(item.pinned ? L10n.detail.unpin : L10n.detail.pin, systemImage: item.pinned ? "pin.slash" : "pin")
                }
                .tint(.trust)
            }
        }
        .contextMenu { ItemCopyMenu(itemId: item.id) }
    }

    @ViewBuilder private var empty: some View {
        if !trimmed.isEmpty {
            EmptyStateView(icon: "magnifyingglass", title: L10n.empty.searchTitle(query: trimmed), message: L10n.empty.searchBody) {
                Button(L10n.empty.clearSearch) { query = "" }
            }
        } else {
            switch scope {
            case .trash: EmptyStateView(icon: "trash", title: L10n.empty.trashTitle, message: L10n.empty.trashBody)
            case .favorites: EmptyStateView(icon: "star", title: L10n.empty.favoritesTitle, message: L10n.empty.favoritesBody)
            case .pinned: EmptyStateView(icon: "pin", title: L10n.empty.pinnedTitle, message: L10n.empty.pinnedBody)
            case .smart(.frequent): EmptyStateView(icon: "chart.line.uptrend.xyaxis", title: L10n.empty.usedTitle, message: L10n.empty.frequentBody)
            case .smart(.used): EmptyStateView(icon: "clock.arrow.circlepath", title: L10n.empty.usedTitle, message: L10n.empty.usedBody)
            case .passkeys: EmptyStateView(icon: "person.badge.key", title: L10n.empty.passkeysTitle, message: L10n.empty.passkeysBody)
            case .codes: EmptyStateView(icon: "clock", title: L10n.empty.codesTitle, message: L10n.empty.codesBody)
            default:
                EmptyStateView(icon: "lock.rectangle.stack", title: L10n.empty.vaultTitle, message: L10n.empty.vaultBody) {
                    if canAdd {
                        Button { add(scope.newItemType) } label: { Label(L10n.empty.addItem, systemImage: "plus") }
                            .buttonStyle(.borderedProminent)
                        NavigationLink { ImportView() } label: { Label(L10n.empty.import, systemImage: "square.and.arrow.down") }
                    }
                }
            }
        }
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            // Reading the current network, and why saved ones can't be read: the iPhone's (the Mac
            // reads Wi-Fi in plan 19 phase 2).
            #if os(iOS)
            if isWifi {
                Button { Task { await radar.refresh() } } label: { Label(L10n.wifi.refresh, systemImage: "arrow.clockwise") }
                Button { explainingImport = true } label: { Label(L10n.wifi.importAction, systemImage: "square.and.arrow.down") }
            }
            #endif
            if let vault, vault.vaultType != .personal {
                NavigationLink(value: Route.vaultMembers(vault.id)) { Label(L10n.vault.members, systemImage: "person.2") }
                    .accessibilityIdentifier("vault-members")
            }
            if !isTrash, smartList == nil, let arrangement {
                SortMenu(arrangement: arrangement, groupings: groupings, combineSites: offersSiteRows(view: scope.view) ? model.settings.combineSites : nil) { next in
                    self.arrangement = next
                    try? model.vault.setListArrangement(view: scope.view, arrangement: next)
                } onCombine: { on in
                    model.update { $0.combineSites = on }
                }
            }
            if canAdd {
                Button { scanning = true } label: { Label(L10n.phone.scan, systemImage: "qrcode.viewfinder") }
                    .accessibilityIdentifier("scan")
                Menu {
                    ForEach(newItemTypes, id: \.self) { type in
                        Button { add(type) } label: { Label(type.typeName, systemImage: type.icon) }
                            .accessibilityIdentifier("new-\(type.name)")
                    }
                } label: {
                    Label(L10n.list.newItem, systemImage: "plus")
                }
                .accessibilityIdentifier("new-item")
            }
        }
    }

    private func sectionLabel(_ grouping: ListGrouping, _ key: String) -> String {
        switch grouping {
        case .type:
            let type = ItemType.from(name: key)
            if ListScope.itemTypes.contains(type) { return type.categoryName }
            return key == "maskedEmailProvider" ? L10n.types.maskedEmailProvider : L10n.list.otherType
        case .vault:
            return directory.vault(key)?.name ?? L10n.scopes.vault
        case .project:
            return key.isEmpty ? L10n.env.noProject : key
        default:
            return key
        }
    }

    private func load() async {
        guard let arrangement else { return }
        var filter = scope.filter
        filter.query = trimmed.isEmpty ? nil : trimmed
        do {
            if isEnvironment {
                filterChoices = environmentChoices(items: try await model.vault.listItems(filter: scope.filter))
                filter.project = projectFilter
                filter.stage = stageFilter
            }
            // Recently created, Frequently used, Recently used and Recently modified keep their
            // own order, searched or not; so do search results and the trash.
            if let smartList {
                let found = try await model.vault.smartList(list: smartList, query: trimmed.isEmpty ? nil : trimmed)
                plain = found
                sections = nil
                if !trimmed.isEmpty {
                    AccessibilityNotification.Announcement(L10n.list.results(count: found.count)).post()
                }
            } else if !trimmed.isEmpty || isTrash {
                let found = try await model.vault.listItems(filter: filter)
                plain = found
                sections = nil
                if !trimmed.isEmpty {
                    AccessibilityNotification.Announcement(L10n.list.results(count: found.count)).post()
                }
            } else {
                sections = try await model.vault.arrangeItems(filter: filter, sort: arrangement.sort, grouping: arrangement.grouping, combineSites: combine)
                plain = nil
            }
            failed = false
        } catch {
            failed = true
        }
    }

    private func delete(_ item: ItemSummary) {
        Task {
            do {
                try await model.vault.deleteItem(id: item.id)
                model.confirm(L10n.detail.trashed(title: item.title))
            } catch { model.show(error) }
        }
    }

    private func restore(_ item: ItemSummary) {
        Task {
            do {
                try await model.vault.restoreItem(id: item.id)
                model.confirm(L10n.detail.restored(title: item.title))
            } catch { model.show(error) }
        }
    }

    private func favorite(_ item: ItemSummary) {
        Task {
            do {
                _ = try await model.vault.setFavorite(id: item.id, favorite: !item.favorite)
                Haptics.tap()
            } catch { model.show(error) }
        }
    }

    private func pin(_ item: ItemSummary) {
        Task {
            do {
                _ = try await model.vault.setPinned(id: item.id, pinned: !item.pinned)
                Haptics.tap()
            } catch { model.show(error) }
        }
    }
}

/// Days an item stays in the trash, as the server keeps it.
let trashDays = 30

extension ItemType: Identifiable {
    public var id: String { name }

    static func from(name: String) -> ItemType {
        ListScope.itemTypes.first { $0.name == name } ?? (name == "maskedEmailProvider" ? .maskedEmailProvider : .other(name: name))
    }
}

/// A list row: the tile, the title with a star for favourites and a pin for pinned items, the subtitle, and marks for
/// passkeys and one-time codes. In the trash, the days left; in the codes list, the code.
struct ItemRow: View {
    let item: ItemSummary
    let vault: Vault?
    let scope: ListScope

    var body: some View {
        HStack(spacing: 12) {
            Avatar(name: item.title, iconDomain: item.iconDomain)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(item.title.isEmpty ? L10n.detail.untitled : item.title)
                        .font(.body.weight(.medium))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    if item.favorite {
                        Image(systemName: "star.fill")
                            .font(.caption2)
                            .foregroundStyle(Color.warn)
                            .accessibilityLabel(L10n.list.favorite)
                    }
                    if item.pinned {
                        Image(systemName: "pin.fill")
                            .font(.caption2)
                            .foregroundStyle(Color.mist)
                            .accessibilityLabel(L10n.list.pinned)
                    }
                }
                HStack(spacing: 6) {
                    if let subtitle {
                        Text(subtitle).lineLimit(1)
                    }
                    if item.itemType == .environment, scope != .trash, let stage = item.stage {
                        Text(StageNames.label(stage))
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(StageNames.color(stage))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1)
                            .background(StageNames.color(stage).opacity(0.12), in: Capsule())
                    }
                    if let vault, vault.vaultType == .shared, scope != .vault(vault.id) {
                        Text(vault.name)
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1)
                            .background(Color.tile, in: Capsule())
                    }
                }
                .font(.subheadline)
                .foregroundStyle(.secondary)
            }
            Spacer(minLength: 4)
            if scope == .codes {
                LiveCode(itemId: item.id, title: item.title, updatedAt: item.updatedAt, canAdvance: vault?.canWrite ?? true)
            } else {
                HStack(spacing: 6) {
                    if item.itemType == .wifi, scope != .trash, WifiRadar.shared.connected == item.subtitle {
                        ConnectedMark()
                    }
                    if item.hasPasskey {
                        Image(systemName: "person.badge.key").accessibilityLabel(L10n.list.hasPasskey)
                    }
                    if item.hasTotp {
                        Image(systemName: "clock").accessibilityLabel(L10n.list.hasTotp)
                    }
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }

    private var subtitle: String? {
        if scope == .trash, let deleted = item.deletedAt.flatMap(Dates.parse) {
            let days = max(0, Int(ceil(Double(trashDays) - Date().timeIntervalSince(deleted) / 86_400)))
            return L10n.trash.daysLeft(count: days)
        }
        return item.subtitle
    }
}

/// Two or more logins for one website as one row; it opens in place with the logins under it,
/// and stays open while the vault is unlocked (the web vault's `SiteGroup`).
struct SiteRow<Row: View>: View {
    @Environment(AppModel.self) private var model
    let host: String
    let items: [ItemSummary]
    @ViewBuilder let row: (ItemSummary) -> Row

    var body: some View {
        let open = model.openSites.contains(host)
        Button {
            withAnimation(.snappy) {
                if open { model.openSites.remove(host) } else { model.openSites.insert(host) }
            }
        } label: {
            HStack(spacing: 12) {
                Avatar(name: host, iconDomain: iconDomain(urls: items.first?.urls ?? []))
                VStack(alignment: .leading, spacing: 2) {
                    Text(host).font(.body.weight(.medium)).foregroundStyle(Color.ink).lineLimit(1)
                        .environment(\.layoutDirection, .leftToRight)
                    Text(L10n.list.siteAccounts(count: items.count)).font(.subheadline).foregroundStyle(Color.mist)
                }
                Spacer()
                Image(systemName: "chevron.down")
                    .rotationEffect(.degrees(open ? 180 : 0))
                    .foregroundStyle(Color.mist)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityValue(open ? L10n.phone.native.expanded : L10n.phone.native.collapsed)
        .accessibilityIdentifier("site-\(host)")
        if open {
            ForEach(items, id: \.id) { row($0) }
        }
    }
}

/// The Sort and group menu: sort orders, groupings this list offers, and Combine accounts for the
/// same website where the list has logins.
struct SortMenu: View {
    let arrangement: ListArrangement
    let groupings: [ListGrouping]
    let combineSites: Bool?
    let onChange: (ListArrangement) -> Void
    let onCombine: (Bool) -> Void

    private static let sorts: [ListSort] = [.name, .nameDesc, .newest, .oldest, .changed]

    var body: some View {
        Menu {
            Picker(L10n.list.sortBy, selection: Binding(get: { arrangement.sort }, set: { onChange(ListArrangement(sort: $0, grouping: arrangement.grouping)) })) {
                ForEach(Self.sorts, id: \.self) { Text(Self.label($0)).tag($0) }
            }
            .pickerStyle(.inline)
            if groupings.count > 1 {
                Picker(L10n.list.groupBy, selection: Binding(get: { arrangement.grouping }, set: { onChange(ListArrangement(sort: arrangement.sort, grouping: $0)) })) {
                    ForEach(groupings, id: \.self) { Text(Self.label($0)).tag($0) }
                }
                .pickerStyle(.inline)
            }
            if let combineSites {
                Toggle(L10n.list.combineSites, isOn: Binding(get: { combineSites }, set: onCombine))
            }
        } label: {
            Label(L10n.list.arrange, systemImage: "arrow.up.arrow.down")
        }
        .accessibilityIdentifier("sort-menu")
    }

    static func label(_ sort: ListSort) -> String {
        switch sort {
        case .name: L10n.list.sorts.name
        case .nameDesc: L10n.list.sorts.nameDesc
        case .newest: L10n.list.sorts.newest
        case .oldest: L10n.list.sorts.oldest
        case .changed: L10n.list.sorts.changed
        }
    }

    static func label(_ grouping: ListGrouping) -> String {
        switch grouping {
        case .type: L10n.list.groupings.type
        case .letter: L10n.list.groupings.letter
        case .vault: L10n.list.groupings.vault
        case .project: L10n.list.groupings.project
        case .none: L10n.list.groupings.none
        }
    }
}

/// A screen with nothing to show: what's missing, and what to do about it.
struct EmptyStateView<Actions: View>: View {
    let icon: String
    let title: String
    var message: String?
    @ViewBuilder var actions: () -> Actions

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: icon)
        } description: {
            if let message { Text(message) }
        } actions: {
            actions()
        }
    }
}

extension EmptyStateView where Actions == EmptyView {
    init(icon: String, title: String, message: String? = nil) {
        self.init(icon: icon, title: title, message: message, actions: { EmptyView() })
    }
}
