import OctaPassResources
import OctaPassVault
import SwiftUI

/// The unlocked vault. iPhone: tabs for Items, Safes, Health and Settings, the vault's lists
/// one level above the list showing (like the web vault's drawer). iPad and wide windows: a
/// split view with the lists and tools in the sidebar.
struct MainView: View {
    @Environment(\.horizontalSizeClass) private var sizeClass

    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if sizeClass == .regular {
                SplitShell()
            } else {
                TabShell()
            }
        }
        .sheet(isPresented: Binding(get: { !model.openedLinks.isEmpty && model.offerDeviceUnlock == nil },
                                    set: { if !$0 { model.openedLinks = [] } })) {
            OpenedLinksSheet(links: model.openedLinks).environment(VaultDirectory.shared)
        }
        .modifier(ReceivedCredentialsReview())
    }
}

/// What the vault's screens look up often: the vaults and the sidebar's counts. Loaded again
/// whenever items or sharing change.
@MainActor @Observable
final class VaultDirectory {
    /// The one the shells keep loaded.
    static let shared = VaultDirectory()
    var vaults: [Vault] = []
    var counts: [String: UInt32] = [:]

    func load(_ vault: OctaPassVault) async {
        async let vaults = vault.listVaults()
        async let counts = vault.itemCounts()
        if let vaults = try? await vaults { self.vaults = vaults.map(Self.display) }
        if let counts = try? await counts { self.counts = counts }
    }

    /// A vault with the default name for its type (stored in English) shows that name in the
    /// reader's language, as the web vault's `displayVault`.
    static func display(_ vault: Vault) -> Vault {
        var shown = vault
        switch (vault.vaultType, vault.name) {
        case (.personal, "Personal"): shown.name = L10n.vault.names.personal
        case (.shared, "Shared vault"): shown.name = L10n.vault.names.shared
        case (.family, "Family"): shown.name = L10n.vault.names.family
        default: break
        }
        return shown
    }

    func vault(_ id: String) -> Vault? { vaults.first { $0.id == id } }
    var personal: Vault? { vaults.first { $0.vaultType == .personal } }
}

private struct TabShell: View {
    @Environment(AppModel.self) private var model
    @State private var directory = VaultDirectory.shared
    @State private var tab = Tab.items
    // Opens on All items, with the vault's lists one step back.
    @State private var itemsPath: [Route] = [.list(.all)]

    enum Tab { case items, safes, health, settings }

    var body: some View {
        TabView(selection: $tab) {
            NavigationStack(path: $itemsPath) {
                SidebarView(compact: true)
                    .navigationDestination(for: Route.self) { RouteView(route: $0) }
            }
            .tabItem { Label(L10n.nav.items, systemImage: "lock.rectangle.stack") }
            .tag(Tab.items)
            NavigationStack {
                SafesView()
                    .navigationDestination(for: Route.self) { RouteView(route: $0) }
            }
            .tabItem { Label(L10n.fileTools.safesTitle, systemImage: "lock.doc") }
            .tag(Tab.safes)
            NavigationStack {
                HealthView()
                    .navigationDestination(for: Route.self) { RouteView(route: $0) }
            }
            .tabItem { Label(L10n.nav.health, systemImage: "checkmark.shield") }
            .tag(Tab.health)
            NavigationStack {
                SettingsView()
                    .navigationDestination(for: Route.self) { RouteView(route: $0) }
            }
            .tabItem { Label(L10n.nav.settings, systemImage: "gearshape") }
            .tag(Tab.settings)
        }
        .modifier(WifiSaveOffer())
        .modifier(PlaceSaveOffer())
        .environment(directory)
        .task(id: model.itemsVersion &+ model.sharingVersion) { await directory.load(model.vault) }
    }
}

private struct SplitShell: View {
    @Environment(AppModel.self) private var model
    @State private var directory = VaultDirectory.shared
    @State private var selection: Route? = .list(.all)
    /// The detail column's path, and the Mac's editor in it.
    @State private var editor = DetailEditor()
    /// The Mac's middle column: a page opened from the list there (a Health check) takes its place.
    @State private var listPath: [Route] = []

    var body: some View {
        NavigationSplitView {
            SidebarView(compact: false, selection: Binding(get: { selection }, set: { next in editor.leave { selection = next } }))
                .desktopColumnWidth(min: 210, ideal: 240, max: 320)
        } content: {
            middle
                .desktopColumnWidth(min: 300, ideal: 360, max: 520)
        } detail: {
            NavigationStack(path: Binding(get: { editor.path }, set: { editor.navigate($0) })) {
                NoSelectionView()
                    .navigationDestination(for: Route.self) { RouteView(route: $0) }
            }
        }
        .onChange(of: selection) {
            editor.path = []
            listPath = []
        }
        // The Mac's quick access: Open in Octa Pass shows the item here, in whatever list is open.
        .onChange(of: model.itemToShow, initial: true) {
            guard let id = model.itemToShow else { return }
            model.itemToShow = nil
            editor.navigate([.item(id)])
        }
        // An alert: a confirmation dialog on the whole split view doesn't show on the Mac.
        .alert(L10n.editor.discardTitle, isPresented: Binding(
            get: { editor.pending != nil }, set: { if !$0 { editor.pending = nil } }
        )) {
            Button(L10n.editor.discard, role: .destructive) { editor.discard() }
            Button(L10n.editor.keepEditing, role: .cancel) { editor.pending = nil }
        } message: {
            Text(L10n.editor.discardBody)
        }
        // Only the Mac edits in the detail column; the iPad keeps its sheets.
        .environment(\.detailEditor, Self.editsInDetail ? editor : nil)
        .modifier(PlaceSaveOffer())
        .environment(directory)
        .task(id: model.itemsVersion &+ model.sharingVersion) { await directory.load(model.vault) }
    }

    /// What the sidebar chose, or on the Mac a page opened from it (a Health check) in its place,
    /// with a back button. Not a stack of its own: the column stays as the split view lays it out.
    /// An item opened from such a page goes to the detail column (`DetailLink`).
    private var middle: some View {
        Group {
            if let page = listPath.last {
                MiddlePage(route: page) { listPath.removeLast() }
            } else if let selection {
                RouteView(route: selection)
            } else {
                NoSelectionView()
            }
        }
        .environment(\.openInMiddle, Self.editsInDetail ? MiddleOpener { listPath.append($0) } : nil)
        .navigationDestination(for: Route.self) { RouteView(route: $0) }
    }

    #if os(macOS)
    static let editsInDetail = true
    #else
    static let editsInDetail = false
    #endif
}

/// The Mac edits an item in the detail column, as the web vault does, rather than in a sheet: a
/// sheet on the Mac is a window of its own. The editor is a page on the detail column's stack
/// (`Route.editor`), so the stack stays put underneath: on the item for Edit, replacing what was
/// there for a new item. `SplitShell` offers it on the Mac only; screens that find none (iPhone,
/// iPad) open their sheet.
@MainActor @Observable
final class DetailEditor {
    struct Session: Identifiable {
        let id = UUID()
        let draft: ItemDraft
    }

    /// The detail column's stack.
    var path: [Route] = []
    private(set) var session: Session?
    /// The open editor has unsaved changes (it reports them).
    var changed = false
    /// Where the person wanted to go while the editor had changes: asked about first.
    var pending: (() -> Void)?

    func open(_ draft: ItemDraft) {
        leave {
            let session = Session(draft: draft)
            self.session = session
            if draft.id == nil { self.path = [.editor(session.id)] } else { self.path.append(.editor(session.id)) }
        }
    }

    /// The stack's own changes: a list row opening an item, say. Leaving the editor asks first.
    func navigate(_ next: [Route]) {
        if let session, next.last == .editor(session.id) {
            path = next
            return
        }
        leave { self.path = next }
    }

    /// Goes somewhere else, closing the editor; with unsaved changes, after asking.
    func leave(then go: @escaping () -> Void) {
        if session != nil, changed {
            pending = go
            return
        }
        close()
        go()
    }

    func discard() {
        let go = pending
        pending = nil
        close()
        go?()
    }

    /// Save (with the item's id) or Cancel (nil): a new item opens once saved; an edited one is
    /// showing underneath already.
    func finish(saved: String?) {
        guard let session else { return }
        close()
        if let saved, session.draft.id == nil { path = [.item(saved)] }
    }

    private func close() {
        if let session { path.removeAll { $0 == .editor(session.id) } }
        session = nil
        changed = false
    }
}

/// The editor page on the Mac's detail column.
private struct DetailEditorPage: View {
    @Environment(\.detailEditor) private var editor
    let id: UUID

    var body: some View {
        if let editor, let session = editor.session, session.id == id {
            ItemEditorSheet(draft: session.draft) { editor.finish(saved: $0) }
                .id(session.id)
                // Cancel, or the discard question, are the ways out; Back would lose changes unasked.
                .navigationBarBackButtonHidden(true)
        }
    }
}

/// The new-Safe form on the Mac's detail column; Cancel or Make Safe leaves it.
private struct NewSafePage: View {
    @Environment(\.detailEditor) private var editor

    var body: some View {
        NewSafeView { editor?.navigate([]) }
            .navigationBarBackButtonHidden(true)
    }
}

/// A page opened in the Mac's middle column, in place of the list it came from, with a back button
/// to that list (a toolbar item: the Mac's toolbar button, see MacControls.swift).
private struct MiddlePage: View {
    let route: Route
    let back: () -> Void

    var body: some View {
        RouteView(route: route)
            .id(route)
            .toolbar {
                ToolbarItem(placement: .navigation) {
                    Button(action: back) {
                        Image(systemName: "chevron.backward")
                    }
                    .help(L10n.common.back)
                    .accessibilityLabel(L10n.common.back)
                }
            }
    }
}

extension EnvironmentValues {
    /// The Mac's detail-column editor; nil on the iPhone and iPad.
    @Entry var detailEditor: DetailEditor?
    /// The Mac's middle column: opens a page there, in place of the list. Nil elsewhere.
    @Entry var openInMiddle: MiddleOpener?
}

/// What the Mac's menu commands act on: the list showing (New item) and the item open (copy).
/// Published with `focusedSceneValue`; nothing reads them on the iPhone and iPad.
struct NewItemCommand {
    let types: [ItemType]
    let add: (ItemType) -> Void
}

struct ItemCommand {
    var copyUsername: (() -> Void)?
    var copyPassword: (() -> Void)?
    var copyCode: (() -> Void)?
}

extension FocusedValues {
    @Entry var newItemCommand: NewItemCommand?
    @Entry var itemCommand: ItemCommand?
}

extension View {
    /// On the Mac a column's width also sizes its part of the window's toolbar: the default sidebar
    /// (140 points) pushes Lock into the toolbar's overflow menu. The iPad's defaults fit.
    @ViewBuilder func desktopColumnWidth(min: CGFloat, ideal: CGFloat, max: CGFloat) -> some View {
        #if os(macOS)
        navigationSplitViewColumnWidth(min: min, ideal: ideal, max: max)
        #else
        self
        #endif
    }
}

/// The screen for a route, wherever it shows.
struct RouteView: View {
    let route: Route

    var body: some View {
        switch route {
        case let .list(scope): ItemListView(scope: scope)
        case let .item(id): ItemDetailView(itemId: id)
        case .generator: GeneratorView()
        case .health: HealthView()
        case .settings: SettingsView()
        case .sharing: AccountOnly(title: L10n.nav.sharing) { SharingView() }
        case .organisation: AccountOnly(title: L10n.nav.organisation) { OrganisationView() }
        case let .orgSection(section): AccountOnly(title: L10n.nav.organisation) { OrgSectionView(section: section) }
        case .maskedEmail: AccountOnly(title: L10n.nav.maskedEmail) { MaskedEmailView() }
        case .tools: DeveloperToolsView()
        case .safes: SafesView()
        case .emergency: AccountOnly(title: L10n.nav.emergency) { EmergencyView() }
        case let .vaultMembers(id): AccountOnly(title: L10n.nav.sharing) { VaultMembersRoute(vaultId: id) }
        case .nearby: NearbyView()
        case let .editor(id): DetailEditorPage(id: id)
        case .newSafe: NewSafePage()
        // A view of its own per folder: another Safe chosen in its place lists that Safe's files.
        case let .safeFolder(folder): SafeBrowserView(folder: folder).id(folder)
        case let .healthCheck(check): HealthCheckView(check: check)
        case .recoveryMap: RecoveryMapRoute()
        case let .reusedPasswords(id): ReusedPasswordList(itemId: id)
        }
    }
}

/// The detail pane before anything is chosen.
struct NoSelectionView: View {
    var body: some View {
        VStack(spacing: 14) {
            Image("Logo").resizable().frame(width: 64, height: 64).opacity(0.85)
            Text(L10n.detail.noSelection).foregroundStyle(Color.mist)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.paper)
        .accessibilityElement(children: .combine)
    }
}

/// The vault's lists and tools (the web vault's `Sidebar`): vaults, categories with their counts,
/// tools, the health score and the account.
struct SidebarView: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    let compact: Bool
    var selection: Binding<Route?>?
    @State private var creatingVault = false
    #if os(macOS)
    /// The browser extension card's height, kept clear at the foot of the sidebar's list.
    @State private var offerHeight: CGFloat = 0
    #endif
    @State private var health = HealthStore.shared

    var body: some View {
        list
            .navigationTitle(L10n.nav.vault)
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        model.lockNow()
                    } label: {
                        Label(L10n.nav.lockNow, systemImage: "lock")
                    }
                    .accessibilityIdentifier("lock-now")
                }
            }
            .sheet(isPresented: $creatingVault) { CreateVaultSheet() }
            // The score beside Health is there from the start, as on the web vault, and follows edits.
            .task(id: model.itemsVersion) {
                guard !compact else { return }
                await health.load(model.vault, again: health.report != nil)
            }
    }

    @ViewBuilder private var list: some View {
        if let selection {
            #if os(macOS)
            // The browser extension, until it has reached the app (OctaPassMac/BrowserExtensionOffer.swift).
            // An overlay with the list's content kept clear of it, never part of the layout: as a
            // bottom safe-area inset (or stacked under the list) the card made the split view taller
            // than the window on macOS 26, pushing both lists under the title bar and the card off
            // the window.
            List(selection: selection) { rows }
                .listStyle(.sidebar)
                .contentMargins(.bottom, offerHeight, for: .scrollContent)
                .overlay(alignment: .bottom) {
                    VStack(spacing: 0) { ExtensionOfferCard() }
                        .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { offerHeight = $0 }
                }
            #else
            List(selection: selection) { rows }
                .listStyle(.sidebar)
            #endif
        } else {
            List { rows }
                .listStyle(.platformGrouped)
        }
    }

    @ViewBuilder private var rows: some View {
        Section(L10n.nav.vaults) {
            row(.list(.all), L10n.scopes.all, "square.grid.2x2", count: directory.counts["all"])
            ForEach(ListScope.quickLists, id: \.self) { scope in
                if scope == .pinned { row(.nearby, L10n.scopes.nearby, "location") }
                // Pinned and Favourites are filters, with counts; the others keep an order of their own.
                row(.list(scope), scope.title(vaults: directory.vaults), scope.icon,
                    count: scope == .pinned || scope == .favorites ? directory.counts[scope.countKey] ?? 0 : nil)
            }
            ForEach(directory.vaults, id: \.id) { vault in
                row(.list(.vault(vault.id)), vault.name, vault.icon, count: directory.counts["v-\(vault.id)"] ?? 0,
                    badge: vault.badge, warn: vault.untrusted)
            }
            if !model.isLocal {
                Button {
                    creatingVault = true
                } label: {
                    Label(L10n.nav.newSharedVault, systemImage: "plus")
                }
                .accessibilityIdentifier("new-shared-vault")
            }
        }
        Section(L10n.nav.categories) {
            ForEach(ListScope.categories, id: \.self) { scope in
                row(.list(scope), scope.title(vaults: directory.vaults), scope.icon, count: directory.counts[scope.countKey] ?? 0)
            }
        }
        // On the iPhone, Safes and Health are tabs of their own.
        Section(L10n.nav.tools) {
            row(.generator, L10n.nav.generator, "wand.and.stars")
            if !compact {
                row(.health, L10n.nav.health, "checkmark.shield", score: health.report.map { Int($0.score) })
            }
            row(.maskedEmail, L10n.nav.maskedEmail, "envelope.badge.shield.half.filled")
            row(.tools, L10n.nav.devTools, "chevron.left.forwardslash.chevron.right")
            if !compact { row(.safes, L10n.fileTools.safesTitle, "lock.doc") }
            row(.sharing, L10n.nav.sharing, "person.2")
            row(.organisation, L10n.nav.organisation, "building.2")
            row(.emergency, L10n.nav.emergency, "lifepreserver")
            row(.list(.trash), L10n.scopes.trash, "trash", count: directory.counts["trash"])
            // The Mac's Settings are a window of their own (Octa Pass ▸ Settings…, Cmd+,).
            #if os(iOS)
            if !compact { row(.settings, L10n.nav.settings, "gearshape") }
            #endif
        }
        if let email = model.session.email {
            Section {
                Text(email)
                    .font(.footnote)
                    .foregroundStyle(Color.mist)
                    // A local vault shows its name here, in any language.
                    .environment(\.layoutDirection, model.isLocal ? model.layoutDirection : .leftToRight)
            }
        }
    }

    @ViewBuilder
    private func row(_ route: Route, _ title: String, _ icon: String, count: UInt32? = nil, badge: String? = nil, warn: Bool = false, score: Int? = nil) -> some View {
        let label = HStack {
            Label {
                HStack(spacing: 6) {
                    Text(title).lineLimit(1)
                    if let badge {
                        Text(badge)
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(warn ? Color.warnText : Color.mist)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background((warn ? Color.warn : Color.mist).opacity(0.12), in: Capsule())
                    }
                }
            } icon: {
                Image(systemName: icon)
            }
            Spacer()
            if let count {
                Text(count.formatted(.number.locale(L10n.formatLocale)))
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(Color.mist)
            }
            if let score { SidebarScore(score: score) }
        }
        .accessibilityElement(children: .combine)
        if selection != nil {
            label.tag(route)
                .accessibilityIdentifier("sidebar-\(identifier(route))")
        } else {
            NavigationLink(value: route) { label }
                .accessibilityIdentifier("sidebar-\(identifier(route))")
        }
    }

    private func identifier(_ route: Route) -> String {
        switch route {
        case let .list(scope):
            if case let .vault(id) = scope { return "vault-\(id)" }
            return scope.view
        case .item: return "item"
        case .generator: return "generator"
        case .health: return "health"
        case .settings: return "settings"
        case .sharing: return "sharing"
        case .organisation: return "organisation"
        case .orgSection: return "organisation-section"
        case .maskedEmail: return "masked-email"
        case .tools: return "tools"
        case .safes: return "safes"
        case .emergency: return "emergency"
        case .vaultMembers: return "members"
        case .nearby: return "nearby"
        case .editor: return "editor"
        case .newSafe: return "new-safe"
        case .safeFolder: return "safe-folder"
        case let .healthCheck(check): return "health-\(check.rawValue)"
        case .recoveryMap: return "recovery-map"
        case .reusedPasswords: return "reused-passwords"
        }
    }
}

/// The health score at the end of the sidebar's Health row: a small ring in the score's tone and
/// the number, where other rows show their count. The web vault's tones: 80 and up is good, 50 and
/// up needs attention, below that is at risk.
private struct SidebarScore: View {
    let score: Int

    private var tone: Color { score >= 80 ? .free : score >= 50 ? .warn : .danger }
    private var toneText: Color { score >= 80 ? .freeText : score >= 50 ? .warnText : .dangerText }

    var body: some View {
        HStack(spacing: 5) {
            ZStack {
                Circle().stroke(Color.line, lineWidth: 2.5)
                Circle()
                    .trim(from: 0, to: CGFloat(min(max(score, 0), 100)) / 100)
                    .stroke(tone, style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                    .rotationEffect(.degrees(-90))
            }
            .frame(width: 13, height: 13)
            Text(score.formatted(.number.locale(L10n.formatLocale)))
                .font(.callout.weight(.semibold).monospacedDigit())
                .foregroundStyle(toneText)
        }
        .accessibilityLabel("\(score) \(L10n.health.outOf)")
    }
}
