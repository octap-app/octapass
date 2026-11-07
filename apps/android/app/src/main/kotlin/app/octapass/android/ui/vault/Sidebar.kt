package app.octap.android.ui.vault

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.outlined.Login
import androidx.compose.material.icons.automirrored.outlined.StickyNote2
import androidx.compose.material.icons.automirrored.outlined.TrendingUp
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.AutoAwesome
import androidx.compose.material.icons.outlined.AutoFixHigh
import androidx.compose.material.icons.outlined.Badge
import androidx.compose.material.icons.outlined.CreditCard
import androidx.compose.material.icons.outlined.Code
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.LocationOn
import androidx.compose.material.icons.outlined.PushPin
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.GridView
import androidx.compose.material.icons.outlined.Groups
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Inventory2
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Mail
import androidx.compose.material.icons.outlined.CurrencyBitcoin
import androidx.compose.material.icons.outlined.DashboardCustomize
import androidx.compose.material.icons.outlined.AccountBalance
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material.icons.outlined.Verified
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.Password
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material.icons.outlined.StarOutline
import androidx.compose.material.icons.outlined.Support
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.NavigationDrawerItemDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.octap.android.model.isLocal
import app.octap.android.ui.components.Logo
import app.octap.android.ui.sharing.CreateVaultDialog
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.util.rememberLive
import app.octap.resources.R
import app.octap.vault.ItemType
import app.octap.vault.SmartList
import app.octap.vault.Vault
import app.octap.vault.VaultType

/** A vault with the default name for its type shows that name in the reader's language (`displayVault`). */
@Composable
fun vaultName(vault: Vault): String = when {
    vault.vaultType == VaultType.PERSONAL && vault.name == "Personal" -> stringResource(R.string.vault_names_personal)
    vault.vaultType == VaultType.SHARED && vault.name == "Shared vault" -> stringResource(R.string.vault_names_shared)
    vault.vaultType == VaultType.FAMILY && vault.name == "Family" -> stringResource(R.string.vault_names_family)
    else -> vault.name
}

fun vaultIcon(vault: Vault): ImageVector = when (vault.vaultType) {
    VaultType.PERSONAL -> Icons.Outlined.Inventory2
    VaultType.SHARED -> Icons.Outlined.Groups
    VaultType.FAMILY -> Icons.Outlined.Home
}

fun typeIcon(type: ItemType): ImageVector = when (type) {
    ItemType.Login -> Icons.AutoMirrored.Outlined.Login
    ItemType.Password -> Icons.Outlined.Password
    ItemType.Card -> Icons.Outlined.CreditCard
    ItemType.Identity -> Icons.Outlined.Badge
    ItemType.SecureNote -> Icons.AutoMirrored.Outlined.StickyNote2
    ItemType.Document -> Icons.Outlined.Description
    ItemType.Wifi -> Icons.Outlined.Wifi
    ItemType.SshKey -> Icons.Outlined.VpnKey
    ItemType.Environment -> Icons.Outlined.Dns
    ItemType.BankAccount -> Icons.Outlined.AccountBalance
    ItemType.IdDocument -> Icons.Outlined.Badge
    ItemType.CryptoWallet -> Icons.Outlined.CurrencyBitcoin
    ItemType.ApiCredential -> Icons.Outlined.VpnKey
    ItemType.Database -> Icons.Outlined.Storage
    ItemType.SoftwareLicense -> Icons.Outlined.Verified
    ItemType.Custom -> Icons.Outlined.Dashboard
    ItemType.CustomTemplate -> Icons.Outlined.DashboardCustomize
    ItemType.MaskedEmailProvider -> Icons.Outlined.Mail
    is ItemType.Other -> Icons.Outlined.Description
}

private data class Category(val scope: Scope, val icon: ImageVector, val label: Int)

/**
 * The lists above the vaults, in the web vault's order. Nearby comes second and isn't built yet
 * (it needs places saved with items), so the sidebar shows it as coming soon. Pinned and
 * Favourites are filters, with counts; the others keep an order of their own (`smartList`).
 */
private val QUICK_LISTS = listOf(
    Category(Scope.Smart(SmartList.CREATED), Icons.Outlined.AutoAwesome, R.string.scopes_created),
    Category(Scope.Pinned, Icons.Outlined.PushPin, R.string.scopes_pinned),
    Category(Scope.Favorites, Icons.Outlined.StarOutline, R.string.scopes_favorites),
    Category(Scope.Smart(SmartList.FREQUENT), Icons.AutoMirrored.Outlined.TrendingUp, R.string.scopes_frequent),
    Category(Scope.Smart(SmartList.USED), Icons.Outlined.History, R.string.scopes_used),
    Category(Scope.Smart(SmartList.CHANGED), Icons.Outlined.Edit, R.string.scopes_changed),
)

private val CATEGORIES = listOf(
    Category(Scope.OfType(ItemType.Login), Icons.AutoMirrored.Outlined.Login, R.string.categories_login),
    Category(Scope.Passkeys, Icons.Outlined.Key, R.string.categories_passkeys),
    Category(Scope.Codes, Icons.Outlined.Schedule, R.string.categories_codes),
    Category(Scope.OfType(ItemType.Card), Icons.Outlined.CreditCard, R.string.categories_card),
    Category(Scope.OfType(ItemType.Identity), Icons.Outlined.Badge, R.string.categories_identity),
    Category(Scope.OfType(ItemType.SecureNote), Icons.AutoMirrored.Outlined.StickyNote2, R.string.categories_secureNote),
    Category(Scope.OfType(ItemType.Password), Icons.Outlined.Password, R.string.categories_password),
    Category(Scope.OfType(ItemType.Wifi), Icons.Outlined.Wifi, R.string.categories_wifi),
    Category(Scope.OfType(ItemType.Environment), Icons.Outlined.Dns, R.string.categories_environment),
    Category(Scope.OfType(ItemType.SshKey), Icons.Outlined.VpnKey, R.string.categories_sshKey),
    Category(Scope.OfType(ItemType.Document), Icons.Outlined.Description, R.string.categories_document),
    Category(Scope.OfType(ItemType.BankAccount), Icons.Outlined.AccountBalance, R.string.categories_bankAccount),
    Category(Scope.OfType(ItemType.IdDocument), Icons.Outlined.Badge, R.string.categories_idDocument),
    Category(Scope.OfType(ItemType.CryptoWallet), Icons.Outlined.CurrencyBitcoin, R.string.categories_cryptoWallet),
    Category(Scope.OfType(ItemType.ApiCredential), Icons.Outlined.VpnKey, R.string.categories_apiCredential),
    Category(Scope.OfType(ItemType.Database), Icons.Outlined.Storage, R.string.categories_database),
    Category(Scope.OfType(ItemType.SoftwareLicense), Icons.Outlined.Verified, R.string.categories_softwareLicense),
    Category(Scope.OfType(ItemType.Custom), Icons.Outlined.Dashboard, R.string.categories_custom),
    Category(Scope.OfType(ItemType.CustomTemplate), Icons.Outlined.DashboardCustomize, R.string.categories_customTemplate),
)

/**
 * The vaults, categories and tools (`Sidebar`): a drawer on phones, always beside the list on large
 * tablets. Counts come from the vault (`itemCounts`).
 */
@Composable
fun Sidebar(onNavigate: () -> Unit) {
    val vault = LocalVault.current
    val model = vault.model
    val nav = vault.nav
    val session by model.session.collectAsState()
    val counts = rememberLive(model) { model.vault.itemCounts() }.data
    val vaults = rememberLive(model, sharing = true) { model.vault.listVaults() }.data
    val report = rememberLive(model) { model.vault.healthReport() }.data
    var creating by remember { mutableStateOf(false) }
    val current = nav.stack.first()

    fun go(route: Route) {
        nav.reset(route)
        onNavigate()
    }

    @Composable
    fun row(label: String, icon: ImageVector, route: Route, count: UInt? = null, badge: String? = null, warn: Boolean = false, tag: String) {
        NavigationDrawerItem(
            label = {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                    if (badge != null) Text(badge, style = MaterialTheme.typography.labelSmall, color = if (warn) Brand.colors.warnText else MaterialTheme.colorScheme.onSurfaceVariant)
                }
            },
            icon = { Icon(icon, contentDescription = null) },
            badge = count?.let { { Text(it.toString(), style = MaterialTheme.typography.labelMedium) } },
            selected = current == route,
            onClick = { go(route) },
            modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding).testTag(tag),
        )
    }

    /** A list that isn't built yet: shown, marked as coming soon, and not something to open. */
    @Composable
    fun soonRow(label: String, icon: ImageVector, tag: String) {
        val soon = stringResource(R.string.nav_soon)
        val dim = MaterialTheme.colorScheme.onSurfaceVariant
        Row(
            Modifier
                .padding(NavigationDrawerItemDefaults.ItemPadding)
                .fillMaxWidth()
                .heightIn(min = 56.dp)
                .padding(start = 16.dp, end = 24.dp)
                .semantics(mergeDescendants = true) {}
                .testTag(tag),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(icon, contentDescription = null, tint = dim)
            Text(label, color = dim, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
            Text(soon, style = MaterialTheme.typography.labelSmall, color = dim)
        }
    }

    @Composable
    fun heading(text: Int) {
        Text(
            stringResource(text),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 28.dp, end = 28.dp, top = 16.dp, bottom = 6.dp).semantics { heading() },
        )
    }

    Column(Modifier.fillMaxHeight()) {
        Row(Modifier.fillMaxWidth().padding(start = 24.dp, end = 12.dp, top = 16.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Logo(28.dp)
            Spacer(Modifier.width(10.dp))
            Text("Open", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Light)
            Text("Pass", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            IconButton(onClick = { model.vault.lock() }, modifier = Modifier.testTag("nav.lock")) {
                Icon(Icons.Outlined.Lock, contentDescription = stringResource(R.string.nav_lockNow))
            }
        }
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            heading(R.string.nav_vaults)
            row(stringResource(R.string.scopes_all), Icons.Outlined.GridView, Route.Items(Scope.All), counts?.get("all"), tag = "nav.all")
            for (list in QUICK_LISTS) {
                if (list.scope == Scope.Pinned) soonRow(stringResource(R.string.scopes_nearby), Icons.Outlined.LocationOn, tag = "nav.nearby")
                val counted = list.scope == Scope.Pinned || list.scope == Scope.Favorites
                row(stringResource(list.label), list.icon, Route.Items(list.scope), if (counted) counts?.get(list.scope.countKey) ?: 0u else null, tag = "nav.${list.scope.view}")
            }
            for (v in vaults.orEmpty()) {
                val badge = when {
                    v.untrusted -> stringResource(R.string.vault_untrusted)
                    v.vaultType == VaultType.SHARED -> stringResource(R.string.vault_shared)
                    v.vaultType == VaultType.FAMILY -> stringResource(R.string.vault_family)
                    else -> null
                }
                row(vaultName(v), vaultIcon(v), Route.Items(Scope.InVault(v.id)), counts?.get("v-${v.id}") ?: 0u, badge, v.untrusted, tag = "nav.vault.${v.id}")
            }
            if (!session.isLocal) {
                NavigationDrawerItem(
                    label = { Text(stringResource(R.string.nav_newSharedVault)) },
                    icon = { Icon(Icons.Outlined.Add, contentDescription = null) },
                    selected = false,
                    onClick = { creating = true },
                    modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding).testTag("nav.newVault"),
                )
            }

            heading(R.string.nav_categories)
            for (category in CATEGORIES) {
                // A document is its file, and a local vault keeps no files.
                if (session.isLocal && category.scope == Scope.OfType(ItemType.Document)) continue
                val count = counts?.get(category.scope.countKey) ?: 0u
                // Documents need file storage, which every Octa Pass server has; still hidden when empty elsewhere.
                row(stringResource(category.label), category.icon, Route.Items(category.scope), count, tag = "nav.${category.scope.view}")
            }

            heading(R.string.nav_tools)
            row(stringResource(R.string.nav_generator), Icons.Outlined.AutoFixHigh, Route.Generator, tag = "nav.generator")
            row(stringResource(R.string.nav_maskedEmail), Icons.Outlined.Mail, Route.MaskedEmail, tag = "nav.maskedEmail")
            row(stringResource(R.string.nav_devTools), Icons.Outlined.Code, Route.DeveloperTools, tag = "nav.tools")
            row(stringResource(R.string.fileTools_safesTitle), Icons.Outlined.Folder, Route.Safes, tag = "nav.safes")
            row(stringResource(R.string.nav_sharing), Icons.Outlined.Share, Route.Sharing, tag = "nav.sharing")
            row(stringResource(R.string.nav_emergency), Icons.Outlined.Support, Route.Emergency, tag = "nav.emergency")
            row(stringResource(R.string.scopes_trash), Icons.Outlined.Delete, Route.Items(Scope.Trash), counts?.get("trash"), tag = "nav.trash")
            row(stringResource(R.string.nav_settings), Icons.Outlined.Settings, Route.Settings, tag = "nav.settings")
        }
        NavigationDrawerItem(
            label = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(report?.score?.toString() ?: "–", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.nav_health), modifier = Modifier.weight(1f))
                    Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, contentDescription = null)
                }
            },
            icon = {
                CircularProgressIndicator(
                    progress = { (report?.score?.toFloat() ?: 0f) / 100f },
                    modifier = Modifier.size(28.dp),
                    strokeWidth = 4.dp,
                    color = healthTone(report?.score?.toInt()),
                    trackColor = MaterialTheme.colorScheme.outlineVariant,
                )
            },
            selected = current == Route.Health,
            onClick = { go(Route.Health) },
            modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding).testTag("nav.health"),
        )
        Text(
            session.email.orEmpty(),
            // An email reads left to right; a local vault's name is whatever it was called.
            style = MaterialTheme.typography.bodySmall.copy(textDirection = if (session.isLocal) TextDirection.Content else TextDirection.Ltr),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = 28.dp, vertical = 12.dp),
        )
    }
    if (creating) CreateVaultDialog(onDismiss = { creating = false })
}

/** The colour of a health score (`scoreTone`): green from 80, amber from 50, red below. */
@Composable
fun healthTone(score: Int?) = when {
    score == null || score >= 80 -> Brand.colors.free
    score >= 50 -> Brand.colors.warn
    else -> Brand.colors.danger
}
