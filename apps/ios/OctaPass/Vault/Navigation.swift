import OctaPassResources
import OctaPassVault
import SwiftUI

/// The list a screen shows, as the web vault's `/items/:scope` (`lib/scope.ts`).
enum ListScope: Hashable {
    case all, favorites, pinned, passkeys, codes, trash
    /// Recently created, Frequently used, Recently used or Recently modified: every item in an
    /// order of its own (`smartList`), not a filter.
    case smart(SmartList)
    case vault(String)
    case type(ItemType)

    /// The lists above the vaults in the sidebar, in the web vault's order. Nearby, which comes
    /// second, isn't built yet: the sidebar shows it as coming soon.
    static let quickLists: [ListScope] = [.smart(.created), .pinned, .favorites, .smart(.frequent), .smart(.used), .smart(.changed)]

    /// The types a new item can be, in the web vault's order (`ITEM_TYPES`).
    static let itemTypes: [ItemType] = [.login, .password, .card, .identity, .secureNote, .wifi, .sshKey, .document, .environment, .bankAccount, .idDocument, .cryptoWallet, .apiCredential, .database, .softwareLicense, .custom, .customTemplate]

    /// The sidebar's categories, as the web vault lists them.
    static let categories: [ListScope] = [
        .type(.login), .passkeys, .codes, .type(.card), .type(.identity), .type(.secureNote),
        .type(.password), .type(.wifi), .type(.environment), .type(.sshKey), .type(.document),
        .type(.bankAccount), .type(.idDocument), .type(.cryptoWallet), .type(.apiCredential),
        .type(.database), .type(.softwareLicense), .type(.custom), .type(.customTemplate),
    ]

    var filter: ItemFilter {
        var filter = ItemFilter(vaultId: nil, itemType: nil, query: nil, trash: false, favorites: false, passkeys: false, totp: false)
        switch self {
        case .all, .smart: break
        case .favorites: filter.favorites = true
        case .pinned: filter.pinned = true
        case .passkeys: filter.passkeys = true
        case .codes: filter.totp = true
        case .trash: filter.trash = true
        case let .vault(id): filter.vaultId = id
        case let .type(type): filter.itemType = type
        }
        return filter
    }

    /// The key its sort and grouping are remembered under, and its count in `itemCounts`.
    var view: String {
        switch self {
        case .all: "all"
        case .favorites: "favorites"
        case .pinned: "pinned"
        case let .smart(list): smartListName(list: list)
        case .passkeys: "passkeys"
        case .codes: "codes"
        case .trash: "trash"
        case .vault: "vault"
        case let .type(type): type.name
        }
    }

    var countKey: String {
        if case let .vault(id) = self { return "v-\(id)" }
        return view
    }

    func title(vaults: [Vault]) -> String {
        switch self {
        case .all: L10n.scopes.all
        case .favorites: L10n.scopes.favorites
        case .pinned: L10n.scopes.pinned
        case .smart(.created): L10n.scopes.created
        case .smart(.frequent): L10n.scopes.frequent
        case .smart(.used): L10n.scopes.used
        case .smart(.changed): L10n.scopes.changed
        case .passkeys: L10n.categories.passkeys
        case .codes: L10n.categories.codes
        case .trash: L10n.scopes.trash
        case let .vault(id): vaults.first { $0.id == id }?.name ?? L10n.scopes.vault
        case let .type(type): type.categoryName
        }
    }

    var icon: String {
        switch self {
        case .all: "square.grid.2x2"
        case .favorites: "star"
        case .pinned: "pin"
        case .smart(.created): "sparkles"
        case .smart(.frequent): "chart.line.uptrend.xyaxis"
        case .smart(.used): "clock.arrow.circlepath"
        case .smart(.changed): "pencil"
        case .passkeys: "person.badge.key"
        case .codes: "clock"
        case .trash: "trash"
        case .vault: "lock.rectangle.stack"
        case let .type(type): type.icon
        }
    }

    /// The type a new item starts as here.
    var newItemType: ItemType {
        if case let .type(type) = self { return type }
        return .login
    }
}

extension ItemType {
    /// The web vault's name for the type: `login`, `secureNote`, …
    var name: String {
        switch self {
        case .login: "login"
        case .password: "password"
        case .secureNote: "secureNote"
        case .card: "card"
        case .identity: "identity"
        case .document: "document"
        case .wifi: "wifi"
        case .sshKey: "sshKey"
        case .environment: "environment"
        case .maskedEmailProvider: "maskedEmailProvider"
        case .bankAccount: "bankAccount"
        case .apiCredential: "apiCredential"
        case .softwareLicense: "softwareLicense"
        case .idDocument: "idDocument"
        case .cryptoWallet: "cryptoWallet"
        case .database: "database"
        case .custom: "custom"
        case .customTemplate: "customTemplate"
        case let .other(name): name
        }
    }

    /// One of a kind ("Login"), for the new item menu and the editor.
    var typeName: String {
        L10n.text(forKey: "types.\(name)") ?? L10n.list.otherType
    }

    /// The list of a kind ("Logins").
    var categoryName: String {
        L10n.text(forKey: "categories.\(name)") ?? typeName
    }

    var icon: String {
        switch self {
        case .login: "person.crop.circle"
        case .password: "key"
        case .secureNote: "note.text"
        case .card: "creditcard"
        case .identity: "person.text.rectangle"
        case .document: "doc"
        case .wifi: "wifi"
        case .sshKey: "key.horizontal"
        case .environment: "server.rack"
        case .maskedEmailProvider: "envelope"
        case .bankAccount: "building.columns"
        case .apiCredential: "key.horizontal"
        case .softwareLicense: "app.badge.checkmark"
        case .idDocument: "person.text.rectangle"
        case .cryptoWallet: "bitcoinsign.circle"
        case .database: "server.rack"
        case .custom: "square.grid.2x2"
        case .customTemplate: "square.dashed.inset.filled"
        case .other: "square.dashed"
        }
    }
}

extension Vault {
    var icon: String {
        switch vaultType {
        case .personal: "person"
        case .family: "house"
        case .shared: "person.2"
        }
    }

    /// "Shared", "Family" or the untrusted warning, after the name.
    var badge: String? {
        if untrusted { return L10n.vault.untrusted }
        switch vaultType {
        case .shared: return L10n.vault.shared
        case .family: return L10n.vault.family
        case .personal: return nil
        }
    }

    var canWrite: Bool { role != .read && !untrusted }
}

/// Where the vault's screens go: lists, items, the editor and the tools.
enum Route: Hashable {
    case list(ListScope)
    case item(String)
    case generator, health, settings, sharing, maskedEmail, emergency, tools, safes
    case vaultMembers(String)
    /// The Mac's item editor in the detail column (`DetailEditor`), by its session.
    case editor(UUID)
    /// The Mac's new-Safe form in the detail column.
    case newSafe
    /// A folder of a Safe (`SafeBrowserView`): the Safe's top, or a folder in it.
    case safeFolder(SafeFolder)
    /// One Health check's list, the recovery map, and the logins sharing an item's password. Routes
    /// rather than view links, so the Mac's detail column drops them with the rest of its stack.
    case healthCheck(HealthCheck)
    case recoveryMap
    case reusedPasswords(String)
}

/// A link from a list in the middle column to a page beside it. On the Mac the page starts the
/// detail column's stack over (`DetailEditor`): a link there doesn't reach that stack, and a page
/// pushed outside it stays when the sidebar moves on. Elsewhere it's a plain value link.
struct RouteLink<Label: View>: View {
    @Environment(\.detailEditor) private var detailEditor
    let route: Route
    @ViewBuilder let label: () -> Label

    var body: some View {
        if let detailEditor {
            let open = detailEditor.path.first == route
            Button { detailEditor.navigate([route]) } label: {
                label().contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .listRowBackground(open ? RoundedRectangle(cornerRadius: 8).fill(Color.trust.opacity(0.18)).padding(.horizontal, 6) : nil)
            .accessibilityAddTraits(open ? .isSelected : [])
        } else {
            NavigationLink(value: route, label: label)
        }
    }
}
