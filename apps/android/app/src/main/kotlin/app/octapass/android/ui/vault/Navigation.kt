package app.octap.android.ui.vault

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import app.octap.resources.R
import app.octap.vault.ItemFilter
import app.octap.vault.ItemType
import app.octap.vault.SmartList
import app.octap.vault.smartListName

/** The list a screen shows (`lib/scope.ts`): all items, favourites, one vault, one type, the trash… */
sealed interface Scope {
    data object All : Scope
    data object Favorites : Scope
    data object Pinned : Scope
    /** Recently created, Frequently used, Recently used or Recently modified: every item in an order of its own (`smartList`). */
    data class Smart(val list: SmartList) : Scope
    data object Passkeys : Scope
    data object Codes : Scope
    data object Trash : Scope
    data class InVault(val vaultId: String) : Scope
    data class OfType(val type: ItemType) : Scope

    /** The list's name for remembering its arrangement: each kind of list has its own, vaults share one. */
    val view: String
        get() = when (this) {
            All -> "all"
            Favorites -> "favorites"
            Pinned -> "pinned"
            is Smart -> smartListName(list)
            Passkeys -> "passkeys"
            Codes -> "codes"
            Trash -> "trash"
            is InVault -> "vault"
            is OfType -> typeKey(type)
        }

    /** The key the item counts use (`itemCounts`). */
    val countKey: String
        get() = when (this) {
            is InVault -> "v-$vaultId"
            else -> view
        }

    fun filter(query: String?): ItemFilter = ItemFilter(
        vaultId = (this as? InVault)?.vaultId,
        itemType = (this as? OfType)?.type,
        query = query?.takeIf { it.isNotBlank() },
        trash = this == Trash,
        favorites = this == Favorites,
        passkeys = this == Passkeys,
        totp = this == Codes,
        project = null,
        stage = null,
        pinned = this == Pinned,
    )
}

/** The item types people can add, in the web vault's order (`ITEM_TYPES`). */
val ITEM_TYPES: List<ItemType> = listOf(ItemType.Login, ItemType.Password, ItemType.Card, ItemType.Identity, ItemType.SecureNote, ItemType.Wifi, ItemType.SshKey, ItemType.Document, ItemType.Environment, ItemType.BankAccount, ItemType.IdDocument, ItemType.CryptoWallet, ItemType.ApiCredential, ItemType.Database, ItemType.SoftwareLicense, ItemType.Custom, ItemType.CustomTemplate)

fun typeKey(type: ItemType): String = when (type) {
    ItemType.Login -> "login"
    ItemType.Password -> "password"
    ItemType.Card -> "card"
    ItemType.Identity -> "identity"
    ItemType.SecureNote -> "secureNote"
    ItemType.Document -> "document"
    ItemType.Wifi -> "wifi"
    ItemType.SshKey -> "sshKey"
    ItemType.Environment -> "environment"
    ItemType.BankAccount -> "bankAccount"
    ItemType.IdDocument -> "idDocument"
    ItemType.CryptoWallet -> "cryptoWallet"
    ItemType.ApiCredential -> "apiCredential"
    ItemType.Database -> "database"
    ItemType.SoftwareLicense -> "softwareLicense"
    ItemType.Custom -> "custom"
    ItemType.CustomTemplate -> "customTemplate"
    ItemType.MaskedEmailProvider -> "maskedEmailProvider"
    is ItemType.Other -> type.name
}

fun typeOf(key: String): ItemType? = (ITEM_TYPES + ItemType.MaskedEmailProvider).firstOrNull { typeKey(it) == key }

/** "Logins", "Cards": the type's list. */
fun categoryRes(type: ItemType): Int = when (type) {
    ItemType.Login -> R.string.categories_login
    ItemType.Password -> R.string.categories_password
    ItemType.Card -> R.string.categories_card
    ItemType.Identity -> R.string.categories_identity
    ItemType.SecureNote -> R.string.categories_secureNote
    ItemType.Document -> R.string.categories_document
    ItemType.Wifi -> R.string.categories_wifi
    ItemType.SshKey -> R.string.categories_sshKey
    ItemType.Environment -> R.string.categories_environment
    ItemType.BankAccount -> R.string.categories_bankAccount
    ItemType.IdDocument -> R.string.categories_idDocument
    ItemType.CryptoWallet -> R.string.categories_cryptoWallet
    ItemType.ApiCredential -> R.string.categories_apiCredential
    ItemType.Database -> R.string.categories_database
    ItemType.SoftwareLicense -> R.string.categories_softwareLicense
    ItemType.Custom -> R.string.categories_custom
    ItemType.CustomTemplate -> R.string.categories_customTemplate
    ItemType.MaskedEmailProvider -> R.string.types_maskedEmailProvider
    is ItemType.Other -> R.string.list_otherType
}

/** "Login", "Card": one item of the type. */
fun typeRes(type: ItemType): Int = when (type) {
    ItemType.Login -> R.string.types_login
    ItemType.Password -> R.string.types_password
    ItemType.Card -> R.string.types_card
    ItemType.Identity -> R.string.types_identity
    ItemType.SecureNote -> R.string.types_secureNote
    ItemType.Document -> R.string.types_document
    ItemType.Wifi -> R.string.types_wifi
    ItemType.SshKey -> R.string.types_sshKey
    ItemType.Environment -> R.string.types_environment
    ItemType.BankAccount -> R.string.types_bankAccount
    ItemType.IdDocument -> R.string.types_idDocument
    ItemType.CryptoWallet -> R.string.types_cryptoWallet
    ItemType.ApiCredential -> R.string.types_apiCredential
    ItemType.Database -> R.string.types_database
    ItemType.SoftwareLicense -> R.string.types_softwareLicense
    ItemType.Custom -> R.string.types_custom
    ItemType.CustomTemplate -> R.string.types_customTemplate
    ItemType.MaskedEmailProvider -> R.string.types_maskedEmailProvider
    is ItemType.Other -> R.string.list_otherType
}

/** A place in the unlocked vault (the web vault's routes). */
sealed interface Route {
    data class Items(val scope: Scope) : Route
    data class Item(val id: String) : Route
    /** A new item when [id] is null, of [type] in [vaultId]. */
    data class Edit(val id: String?, val type: ItemType = ItemType.Login, val vaultId: String? = null) : Route
    data object Generator : Route
    data object DeveloperTools : Route
    data object Health : Route
    /** One check's list, opened from its tile on Health. */
    data class HealthCheck(val check: app.octap.android.ui.tools.HealthCheck) : Route
    data object RecoveryMap : Route
    data object MaskedEmail : Route
    data object Safes : Route
    data object Settings : Route
    data object ChangePassword : Route
    data object RotateSecretKey : Route
    data object VaultKeys : Route
    data object SecurityLog : Route
    data object Import : Route
    data object Sharing : Route
    data class VaultMembers(val vaultId: String) : Route
    data object Emergency : Route
    data class EmergencyVault(val contactId: String) : Route
    data class Takeover(val contactId: String, val email: String) : Route
    data object Scan : Route
    /** Add a one-time code to this login, from a QR code, an image, or its link or key. */
    data class AddCode(val itemId: String) : Route
    /** One-time codes to review ([VaultNavigator.pendingCodes]); [fromLink] when a link opened the app. */
    data class ScanCodes(val fromLink: Boolean) : Route
}

/** The four places the bottom bar (or the rail) switches between. */
enum class Tab { Items, Safes, Health, Settings }

/**
 * The vault's back stack, kept while the vault is locked so unlocking comes back to the same
 * screen. On wide screens an item opens in the pane beside the list ([detail]) instead of on top
 * of it.
 */
class VaultNavigator {
    val stack = mutableStateListOf<Route>(Route.Items(Scope.All))
    var detail by mutableStateOf<Route?>(null)

    /**
     * A new item to start from ("Save this network?", a scan): kept here in memory, never in the
     * route, as it can hold a password. The editor takes it once.
     */
    var pendingDraft: app.octap.vault.ItemDraft? = null

    /** Scanned or opened one-time code links for the review, in memory for the same reason. */
    var pendingCodes: List<String> = emptyList()

    /** Website rows that are open, by host; they stay open while the vault is unlocked. */
    val openSites = mutableStateMapOf<String, Boolean>()

    val top: Route get() = stack.last()

    /** The scope of the list at the bottom of the Items tab. */
    val scope: Scope get() = (stack.firstOrNull() as? Route.Items)?.scope ?: Scope.All

    val tab: Tab
        get() = when (stack.first()) {
            Route.Safes -> Tab.Safes
            Route.Health -> Tab.Health
            Route.Settings -> Tab.Settings
            else -> Tab.Items
        }

    fun push(route: Route) {
        if (stack.last() != route) stack.add(route)
    }

    fun pop(): Boolean {
        if (stack.size <= 1) return false
        stack.removeAt(stack.lastIndex)
        return true
    }

    /** Replaces the top of the stack (an editor that saved becomes the item). */
    fun replace(route: Route) {
        stack[stack.lastIndex] = route
    }

    fun reset(root: Route) {
        stack.clear()
        stack.add(root)
        detail = null
    }

    fun select(tab: Tab) = reset(
        when (tab) {
            Tab.Items -> Route.Items(scope)
            Tab.Safes -> Route.Safes
            Tab.Health -> Route.Health
            Tab.Settings -> Route.Settings
        },
    )

    fun showScope(scope: Scope) = reset(Route.Items(scope))

    /** An item or editor: beside the list on wide screens, on top of it otherwise. */
    fun open(route: Route, twoPane: Boolean) {
        if (twoPane && stack.size == 1 && stack[0] is Route.Items) detail = route else push(route)
    }

    /** Back from the item or editor showing, in either layout. */
    fun close(twoPane: Boolean) {
        if (twoPane && detail != null && stack.size == 1) detail = null else pop()
    }
}
