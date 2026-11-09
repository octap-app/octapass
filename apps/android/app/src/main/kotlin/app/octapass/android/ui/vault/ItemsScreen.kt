package app.octap.android.ui.vault

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsBottomHeight
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Sort
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Clear
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.ExpandLess
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.FileUpload
import androidx.compose.material.icons.outlined.Groups
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Menu
import androidx.compose.material.icons.outlined.PushPin
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Star
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.automirrored.outlined.TrendingUp
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.VerticalDivider
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.ItemIcon
import app.octap.android.ui.components.Logo
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.SecondaryButton
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.theme.monoStyle
import app.octap.android.ui.util.Formats
import app.octap.android.ui.util.rememberLive
import app.octap.resources.R
import app.octap.vault.ItemDetails
import app.octap.vault.ItemSummary
import app.octap.vault.ItemType
import app.octap.vault.ListArrangement
import app.octap.vault.ListEntry
import app.octap.vault.ListGrouping
import app.octap.vault.environmentChoices
import app.octap.vault.ListSection
import app.octap.vault.ListSort
import app.octap.vault.SmartList
import app.octap.vault.Vault
import app.octap.vault.VaultRole
import app.octap.vault.isHotp
import app.octap.vault.listGroupings
import app.octap.vault.offersSiteRows
import app.octap.vault.totpCode
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.time.Instant

private const val TRASH_DAYS = 30

fun daysLeft(deletedAt: String): Int {
    val deleted = Formats.parse(deletedAt) ?: return TRASH_DAYS
    val elapsed = (Instant.now().toEpochMilli() - deleted.toEpochMilli()) / 86_400_000.0
    return maxOf(0, kotlin.math.ceil(TRASH_DAYS - elapsed).toInt())
}

@Composable
fun scopeTitle(scope: Scope, vaults: List<Vault>?): String = when (scope) {
    Scope.All -> stringResource(R.string.scopes_all)
    Scope.Favorites -> stringResource(R.string.scopes_favorites)
    Scope.Pinned -> stringResource(R.string.scopes_pinned)
    Scope.Nearby -> stringResource(R.string.scopes_nearby)
    is Scope.Smart -> stringResource(
        when (scope.list) {
            SmartList.CREATED -> R.string.scopes_created
            SmartList.FREQUENT -> R.string.scopes_frequent
            SmartList.USED -> R.string.scopes_used
            SmartList.CHANGED -> R.string.scopes_changed
        },
    )
    Scope.Passkeys -> stringResource(R.string.scopes_passkeys)
    Scope.Codes -> stringResource(R.string.scopes_codes)
    Scope.Trash -> stringResource(R.string.scopes_trash)
    is Scope.InVault -> vaults?.firstOrNull { it.id == scope.vaultId }?.let { vaultName(it) } ?: stringResource(R.string.scopes_vault)
    is Scope.OfType -> stringResource(categoryRes(scope.type))
}

/** The list (`ItemsPage`), with the item beside it on wide screens. */
@Composable
fun ItemsScreen(scope: Scope) {
    val vault = LocalVault.current
    val nav = vault.nav
    if (vault.twoPane) {
        Row(Modifier.fillMaxSize()) {
            Box(Modifier.width(400.dp).fillMaxHeight()) { if (scope == Scope.Nearby) NearbyList() else ItemList(scope) }
            VerticalDivider()
            Box(Modifier.weight(1f).fillMaxHeight()) {
                when (val detail = nav.detail) {
                    is Route.Item -> ItemScreen(detail.id)
                    is Route.Edit -> EditorScreen(detail)
                    else -> NoSelection()
                }
            }
        }
    } else if (scope == Scope.Nearby) {
        NearbyList()
    } else {
        ItemList(scope)
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
private fun ItemList(scope: Scope) {
    val vault = LocalVault.current
    val model = vault.model
    val nav = vault.nav
    val settings by model.settings.collectAsState()
    var query by rememberSaveable(scope) { mutableStateOf("") }
    var searched by remember(scope) { mutableStateOf("") }
    LaunchedEffect(query) {
        delay(150)
        searched = query.trim()
    }
    val vaults = rememberLive(model, sharing = true) { model.vault.listVaults() }.data
    val vaultCount = (vaults?.size ?: 1).toUInt()
    val view = scope.view
    var arrangement by remember(view, vaultCount) { mutableStateOf(model.vault.listArrangement(view, vaultCount)) }
    val groupings = remember(view, vaultCount) { listGroupings(view, vaultCount) }
    val isTrash = scope == Scope.Trash
    // Recently created, Frequently used, Recently used, Recently modified: their own order.
    val smart = (scope as? Scope.Smart)?.list
    val offerSites = offersSiteRows(view)
    val combine = offerSites && settings.combineSites
    // Search results and the trash keep the order they come in (by name, newest deletion first),
    // and so do the smart lists.
    val plain = searched.isNotEmpty() || isTrash || smart != null
    val isEnvironment = scope == Scope.OfType(ItemType.Environment)
    var projectFilter by rememberSaveable(scope) { mutableStateOf<String?>(null) }
    var stageFilter by rememberSaveable(scope) { mutableStateOf<String?>(null) }
    val environments = if (isEnvironment) rememberLive(model) { environmentChoices(model.vault.listItems(scope.filter(null))) }.data else null
    val sections = rememberLive(model, scope, searched, arrangement, combine, plain, projectFilter, stageFilter) {
        val filter = scope.filter(searched).copy(project = projectFilter, stage = stageFilter)
        if (smart != null) listOf(ListSection("", model.vault.smartList(smart, searched.ifEmpty { null }), emptyList()))
        else if (plain) listOf(ListSection("", model.vault.listItems(filter), emptyList()))
        else model.vault.arrangeItems(filter, arrangement.sort, arrangement.grouping, combine)
    }
    val count = sections.data?.sumOf { it.items.size }
    val inVault = (scope as? Scope.InVault)?.let { s -> vaults?.firstOrNull { it.id == s.vaultId } }
    val canAdd = !isTrash && inVault?.role != VaultRole.READ && inVault?.untrusted != true
    val title = scopeTitle(scope, vaults)
    val bar = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())

    fun newItem(type: ItemType) = vault.open(Route.Edit(null, type, inVault?.id))

    Scaffold(
        modifier = Modifier.nestedScroll(bar.nestedScrollConnection),
        contentWindowInsets = WindowInsets(0),
        topBar = {
            Column(Modifier.background(MaterialTheme.colorScheme.surface)) {
                TopAppBar(
                    title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.semantics { heading() }.testTag("list.title")) },
                    navigationIcon = {
                        vault.openDrawer?.let { open ->
                            IconButton(onClick = open, modifier = Modifier.testTag("list.menu")) { Icon(Icons.Outlined.Menu, contentDescription = stringResource(R.string.nav_openMenu)) }
                        }
                    },
                    actions = {
                        if (inVault != null && inVault.vaultType != app.octap.vault.VaultType.PERSONAL) {
                            IconButton(onClick = { nav.push(Route.VaultMembers(inVault.id)) }) { Icon(Icons.Outlined.Groups, contentDescription = stringResource(R.string.vault_members)) }
                        }
                        if (scope == Scope.OfType(ItemType.Wifi)) WifiListTools()
                        if (canAdd) {
                            IconButton(onClick = { nav.push(Route.Scan) }, modifier = Modifier.testTag("list.scan")) {
                                Icon(Icons.Outlined.QrCodeScanner, contentDescription = stringResource(R.string.phone_scan))
                            }
                        }
                        if (!isTrash && smart == null) {
                            SortMenu(
                                value = arrangement,
                                groupings = groupings,
                                onChange = {
                                    arrangement = it
                                    model.vault.setListArrangement(view, it)
                                },
                                combineSites = if (offerSites) settings.combineSites else null,
                                onCombineSites = { on -> model.updateSettings { s -> s.copy(combineSites = on) } },
                            )
                        }
                    },
                    windowInsets = TopAppBarDefaults.windowInsets,
                    scrollBehavior = bar,
                )
                SearchField(query, { query = it }, if (count != null && searched.isEmpty()) pluralStringResource(R.plurals.list_searchPlaceholder, count, count) else stringResource(R.string.list_search))
                if (searched.isNotEmpty() && count != null) {
                    // Screen readers hear how many matched; nothing shows.
                    val results = pluralStringResource(R.plurals.list_results, count, count)
                    Spacer(Modifier.size(0.dp).semantics { contentDescription = results; liveRegion = LiveRegionMode.Polite })
                }
                if (isTrash && (count ?: 0) > 0) Note(stringResource(R.string.trash_note, TRASH_DAYS))
                if (searched.isNotEmpty() && !isTrash && smart == null && (arrangement.grouping != ListGrouping.NONE || arrangement.sort != ListSort.NAME) && (count ?: 0) > 0) {
                    Note(stringResource(R.string.list_searchNote))
                }
                if (inVault?.untrusted == true) {
                    Alert(stringResource(R.string.vault_untrustedBody, vaultName(inVault)), AlertTone.Warn, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
                }
                if (scope == Scope.OfType(ItemType.Wifi)) WifiPermissionNote()
                app.octap.android.ui.local.BackupReminder()
                if (environments != null && (environments.projects.isNotEmpty() || environments.stages.isNotEmpty())) {
                    EnvironmentFilters(environments, projectFilter, stageFilter, { projectFilter = it }, { stageFilter = it })
                }
                if (scope == Scope.All) app.octap.android.ui.settings.AutoFillPrompt()
            }
        },
        floatingActionButton = {
            if (canAdd) AddButton(::newItem)
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            val data = sections.data
            when {
                sections.error != null && data == null -> Empty(Icons.Outlined.ErrorOutline, stringResource(R.string.list_loadFailed), null) {
                    SecondaryButton(stringResource(R.string.common_tryAgain), sections::retry)
                }
                data == null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                count == 0 && (projectFilter != null || stageFilter != null) -> Empty(Icons.Outlined.Search, stringResource(R.string.env_noMatches), null) {
                    SecondaryButton(stringResource(R.string.env_clearFilters), { projectFilter = null; stageFilter = null })
                }
                count == 0 -> ListEmpty(scope, searched, onClear = { query = "" }, onAdd = { newItem((scope as? Scope.OfType)?.type ?: ItemType.Login) }, onImport = { nav.push(Route.Import) })
                else -> {
                    // Any list with a network marks it; the Wi-Fi list also puts those in range first.
                    val isWifi = scope == Scope.OfType(ItemType.Wifi)
                    val wifi = if (data.any { section -> section.items.any { it.itemType == ItemType.Wifi } } && !isTrash) rememberWifiRadar() else null
                    LazyColumn(Modifier.fillMaxSize().testTag("list.items"), contentPadding = PaddingValues(bottom = 96.dp)) {
                        val grouped = !plain && arrangement.grouping != ListGrouping.NONE
                        val shown = if (wifi != null && isWifi && !plain) nearbyFirst(data, wifi) else data
                        for (section in shown) {
                            if (grouped || section.key == IN_RANGE) {
                                stickyHeader(key = "h:${section.key}") { SectionHeader(sectionLabel(arrangement.grouping, section.key, vaults), section.items.size) }
                            }
                            entries(section, scope, vaults, wifi)
                        }
                        item { Spacer(Modifier.windowInsetsBottomHeight(WindowInsets.navigationBars)) }
                    }
                }
            }
        }
    }
}

/** The Wi-Fi list's first section: the networks the phone is on or sees. */
const val IN_RANGE = "inRange"

@Composable
fun sectionLabel(grouping: ListGrouping, key: String, vaults: List<Vault>?): String {
    if (key == IN_RANGE) return stringResource(R.string.list_inRange)
    return when (grouping) {
        ListGrouping.TYPE -> typeOf(key)?.let { stringResource(categoryRes(it)) } ?: stringResource(R.string.list_otherType)
        ListGrouping.VAULT -> vaults?.firstOrNull { it.id == key }?.let { vaultName(it) } ?: stringResource(R.string.scopes_vault)
        ListGrouping.PROJECT -> key.ifEmpty { stringResource(R.string.env_noProject) }
        else -> key
    }
}

private fun LazyListScope.entries(section: ListSection, scope: Scope, vaults: List<Vault>?, wifi: WifiRadar?) {
    val rows = section.entries.ifEmpty { section.items.map { ListEntry.Item(it) } }
    for (entry in rows) {
        when (entry) {
            is ListEntry.Item -> item(key = "${section.key}:${entry.item.id}") { ItemRow(entry.item, scope, vaults, wifi) }
            is ListEntry.Site -> item(key = "${section.key}:site:${entry.host}") { SiteRow(entry, scope, vaults) }
        }
    }
}

@Composable
private fun SectionHeader(label: String, count: Int) {
    val spoken = pluralStringResource(R.plurals.list_sectionCount, count, count)
    Row(
        Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .semantics(mergeDescendants = true) {
                heading()
                contentDescription = "$label, $spoken"
            },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
        Text(Formats.number(count.toLong(), java.util.Locale.getDefault()), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** A list row (`ItemRow`). In the one-time codes list it also shows the current code, which copies when tapped. */
@Composable
fun ItemRow(item: ItemSummary, scope: Scope, vaults: List<Vault>?, wifi: WifiRadar? = null, indent: Boolean = false) {
    val vault = LocalVault.current
    val selected = vault.twoPane && (vault.nav.detail as? Route.Item)?.id == item.id
    val trash = scope == Scope.Trash
    val codes = scope == Scope.Codes
    val inVault = vaults?.firstOrNull { it.id == item.vaultId }
    val untitled = stringResource(R.string.detail_untitled)
    val subtitle = if (trash && item.deletedAt != null) {
        val left = daysLeft(item.deletedAt!!)
        pluralStringResource(R.plurals.trash_daysLeft, left, left)
    } else {
        item.subtitle
    }
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .background(if (selected) Brand.colors.selected else MaterialTheme.colorScheme.surface)
            .clickable(role = Role.Button) { vault.open(Route.Item(item.id)) }
            .padding(start = if (indent) 40.dp else 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp)
            .testTag("row.${item.id}"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        ItemIcon(vault.model, item.title, item.iconDomain)
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(item.title.ifEmpty { untitled }, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                if (item.favorite) {
                    Spacer(Modifier.width(4.dp))
                    Icon(Icons.Outlined.Star, contentDescription = stringResource(R.string.list_favorite), tint = Brand.colors.warn, modifier = Modifier.size(14.dp))
                }
                if (item.pinned) {
                    Spacer(Modifier.width(4.dp))
                    Icon(Icons.Outlined.PushPin, contentDescription = stringResource(R.string.list_pinned), tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(14.dp))
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                if (!subtitle.isNullOrEmpty()) {
                    Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                }
                if (item.itemType == ItemType.Environment && !trash) item.stage?.let { StageChip(it) }
                if (inVault?.vaultType == app.octap.vault.VaultType.SHARED && scope != Scope.InVault(inVault.id)) {
                    Text(
                        vaultName(inVault),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.background(MaterialTheme.colorScheme.surfaceContainer, CircleShape).padding(horizontal = 6.dp, vertical = 1.dp),
                    )
                }
            }
        }
        if (!trash && item.itemType == ItemType.Wifi && wifi != null) WifiMark(item.subtitle, wifi)
        if (item.hasPasskey) Icon(Icons.Outlined.Key, contentDescription = stringResource(R.string.list_hasPasskey), tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(16.dp))
        if (item.hasTotp && !codes) Icon(Icons.Outlined.Schedule, contentDescription = stringResource(R.string.list_hasTotp), tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(16.dp))
        if (codes) LiveCode(item, writable = !trash && inVault?.role != VaultRole.READ && inVault?.untrusted != true)
    }
}

/** Two or more logins for one website as one row that opens in place (`SiteGroup`). */
@Composable
private fun SiteRow(site: ListEntry.Site, scope: Scope, vaults: List<Vault>?) {
    val vault = LocalVault.current
    val nav = vault.nav
    val holdsActive = site.items.any { it.id == (nav.detail as? Route.Item)?.id }
    LaunchedEffect(holdsActive) { if (holdsActive) nav.openSites[site.host] = true }
    val open = nav.openSites[site.host] == true
    val accounts = pluralStringResource(R.plurals.list_siteAccounts, site.items.size, site.items.size)
    val state = stringResource(if (open) R.string.phone_native_expanded else R.string.phone_native_collapsed)
    Column {
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 64.dp)
                .clickable(role = Role.Button) { nav.openSites[site.host] = !open }
                .semantics { stateDescription = state }
                .padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 8.dp)
                .testTag("site.${site.host}"),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            ItemIcon(vault.model, site.host, site.items.firstOrNull()?.iconDomain)
            Column(Modifier.weight(1f)) {
                Text(site.host, style = MaterialTheme.typography.bodyLarge.copy(textDirection = androidx.compose.ui.text.style.TextDirection.Ltr), maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(accounts, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Icon(if (open) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore, contentDescription = null)
        }
        AnimatedVisibility(open) {
            Column { for (item in site.items) ItemRow(item, scope, vaults, indent = true) }
        }
    }
}

/** The row's current one-time code with its countdown; tapping copies it (`LiveCode`). A counter-based code gets Next code where it can move. */
@Composable
private fun LiveCode(item: ItemSummary, writable: Boolean) {
    val vault = LocalVault.current
    val model = vault.model
    val secret = rememberLive(model, item.id, item.updatedAt) {
        when (val details = model.vault.getItem(item.id).details) {
            is ItemDetails.Login -> details.login.totp
            is ItemDetails.Password -> details.login.totp
            else -> null
        }
    }.data
    val hotp = remember(secret) { secret != null && isHotp(secret) }
    val code = rememberTotp(if (hotp) null else secret)
    if (hotp) {
        if (writable) NextCode(item)
        return
    }
    val copiedLabel = stringResource(R.string.fields_totp)
    val label = stringResource(R.string.list_copyCode, item.title.ifEmpty { stringResource(R.string.detail_untitled) })
    if (code == TotpState.Invalid) {
        Text(stringResource(R.string.list_codeInvalid), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        return
    }
    val current = (code as? TotpState.Code)?.code
    TextButton(
        onClick = { current?.let { copy(model, it.code, copiedLabel, secret = true, item = item.id) } },
        enabled = current != null,
        modifier = Modifier.semantics { contentDescription = label }.testTag("code.${item.id}"),
    ) {
        Text(current?.let { formatCode(it.code) } ?: "––– –––", style = monoStyle)
        if (current != null) {
            Spacer(Modifier.width(8.dp))
            CountdownRing(current.remaining, current.period)
        }
        Spacer(Modifier.width(6.dp))
        Icon(Icons.Outlined.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
    }
}

/** A counter-based code has no current code to show: each press uses up one and copies it (`NextCode`). */
@Composable
private fun NextCode(item: ItemSummary) {
    val model = LocalVault.current.model
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    val copiedLabel = stringResource(R.string.fields_totp)
    val label = stringResource(R.string.list_nextCode, item.title.ifEmpty { stringResource(R.string.detail_untitled) })
    TextButton(
        onClick = {
            busy = true
            scope.launch {
                try {
                    copy(model, model.vault.nextHotpCode(item.id).code, copiedLabel, secret = true, item = item.id)
                } catch (error: Exception) {
                    model.toastError(error)
                } finally {
                    busy = false
                }
            }
        },
        enabled = !busy,
        modifier = Modifier.semantics { contentDescription = label }.testTag("nextCode.${item.id}"),
    ) {
        if (busy) CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp) else Text(stringResource(R.string.detail_hotpNext))
    }
}

@Composable
private fun SearchField(value: String, onChange: (String) -> Unit, placeholder: String) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        placeholder = { Text(placeholder) },
        leadingIcon = { Icon(Icons.Outlined.Search, contentDescription = null) },
        trailingIcon = {
            if (value.isNotEmpty()) IconButton(onClick = { onChange("") }) { Icon(Icons.Outlined.Clear, contentDescription = stringResource(R.string.empty_clearSearch)) }
        },
        singleLine = true,
        shape = CircleShape,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp)
            .semantics { contentDescription = placeholder }
            .testTag("list.search"),
    )
}

@Composable
private fun Note(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(horizontal = 20.dp, vertical = 6.dp))
}

/** New item: the floating button and the type menu (`list.newItemMenu`). */
@Composable
private fun AddButton(onNew: (ItemType) -> Unit) {
    var open by remember { mutableStateOf(false) }
    // A document is its file, and a local vault keeps no files.
    val types = if (LocalVault.current.model.isLocal) ITEM_TYPES - ItemType.Document else ITEM_TYPES
    Box {
        FloatingActionButton(onClick = { open = true }, modifier = Modifier.testTag("list.add")) {
            Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.list_newItem))
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            Text(stringResource(R.string.list_newItemMenu), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
            for (type in types) {
                DropdownMenuItem(
                    text = { Text(stringResource(typeRes(type))) },
                    leadingIcon = { Icon(typeIcon(type), contentDescription = null) },
                    onClick = {
                        open = false
                        onNew(type)
                    },
                    modifier = Modifier.testTag("new.${typeKey(type)}"),
                )
            }
        }
    }
}

/** The list's "Sort and group" menu (`SortMenu`), with "Combine accounts for the same website" when the list has logins. */
@Composable
private fun SortMenu(value: ListArrangement, groupings: List<ListGrouping>, onChange: (ListArrangement) -> Unit, combineSites: Boolean?, onCombineSites: (Boolean) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        IconButton(onClick = { open = true }, modifier = Modifier.testTag("list.arrange")) {
            Icon(Icons.AutoMirrored.Outlined.Sort, contentDescription = stringResource(R.string.list_arrange))
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            @Composable
            fun label(text: Int) = Text(stringResource(text), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp).semantics { heading() })

            @Composable
            fun option(text: Int, checked: Boolean, tag: String, onClick: () -> Unit) = DropdownMenuItem(
                text = { Text(stringResource(text)) },
                leadingIcon = { if (checked) Icon(Icons.Outlined.Check, contentDescription = null) else Spacer(Modifier.size(24.dp)) },
                onClick = {
                    open = false
                    onClick()
                },
                modifier = Modifier.semantics { stateDescription = if (checked) "✓" else "" }.testTag(tag),
            )

            label(R.string.list_sortBy)
            for (sort in ListSort.entries) option(sortRes(sort), value.sort == sort, "sort.${sort.name.lowercase()}") { onChange(value.copy(sort = sort)) }
            if (groupings.size > 1) {
                HorizontalDivider()
                label(R.string.list_groupBy)
                for (grouping in groupings) option(groupingRes(grouping), value.grouping == grouping, "group.${grouping.name.lowercase()}") { onChange(value.copy(grouping = grouping)) }
            }
            if (combineSites != null) {
                HorizontalDivider()
                option(R.string.list_combineSites, combineSites, "list.combineSites") { onCombineSites(!combineSites) }
            }
        }
    }
}

fun sortRes(sort: ListSort) = when (sort) {
    ListSort.NAME -> R.string.list_sorts_name
    ListSort.NAME_DESC -> R.string.list_sorts_nameDesc
    ListSort.NEWEST -> R.string.list_sorts_newest
    ListSort.OLDEST -> R.string.list_sorts_oldest
    ListSort.CHANGED -> R.string.list_sorts_changed
}

fun groupingRes(grouping: ListGrouping) = when (grouping) {
    ListGrouping.TYPE -> R.string.list_groupings_type
    ListGrouping.LETTER -> R.string.list_groupings_letter
    ListGrouping.VAULT -> R.string.list_groupings_vault
    ListGrouping.PROJECT -> R.string.list_groupings_project
    ListGrouping.NONE -> R.string.list_groupings_none
}

@Composable
fun Empty(icon: androidx.compose.ui.graphics.vector.ImageVector, title: String, body: String?, action: (@Composable () -> Unit)? = null) {
    Column(
        Modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(40.dp))
        Spacer(Modifier.size(12.dp))
        Text(title, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center, modifier = Modifier.semantics { heading() })
        if (body != null) {
            Spacer(Modifier.size(6.dp))
            Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
        }
        if (action != null) {
            Spacer(Modifier.size(16.dp))
            Column(Modifier.width(280.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { action() }
        }
    }
}

@Composable
private fun ListEmpty(scope: Scope, query: String, onClear: () -> Unit, onAdd: () -> Unit, onImport: () -> Unit) {
    if (query.isNotEmpty()) {
        return Empty(Icons.Outlined.Search, stringResource(R.string.empty_searchTitle, query), stringResource(R.string.empty_searchBody)) {
            SecondaryButton(stringResource(R.string.empty_clearSearch), onClear)
        }
    }
    when (scope) {
        Scope.Trash -> Empty(Icons.Outlined.Clear, stringResource(R.string.empty_trashTitle), stringResource(R.string.empty_trashBody))
        Scope.Favorites -> Empty(Icons.Outlined.Star, stringResource(R.string.empty_favoritesTitle), stringResource(R.string.empty_favoritesBody))
        Scope.Pinned -> Empty(Icons.Outlined.PushPin, stringResource(R.string.empty_pinnedTitle), stringResource(R.string.empty_pinnedBody))
        Scope.Smart(SmartList.FREQUENT) -> Empty(Icons.AutoMirrored.Outlined.TrendingUp, stringResource(R.string.empty_usedTitle), stringResource(R.string.empty_frequentBody))
        Scope.Smart(SmartList.USED) -> Empty(Icons.Outlined.History, stringResource(R.string.empty_usedTitle), stringResource(R.string.empty_usedBody))
        Scope.Passkeys -> Empty(Icons.Outlined.Key, stringResource(R.string.empty_passkeysTitle), stringResource(R.string.empty_passkeysBody))
        Scope.Codes -> Empty(Icons.Outlined.Schedule, stringResource(R.string.empty_codesTitle), stringResource(R.string.empty_codesBody))
        else -> Empty(Icons.Outlined.Search, stringResource(R.string.empty_vaultTitle), stringResource(R.string.empty_vaultBody)) {
            PrimaryButton(stringResource(R.string.empty_addItem), onAdd, icon = Icons.Outlined.Add, modifier = Modifier.testTag("empty.add"))
            SecondaryButton(stringResource(R.string.empty_import), onImport, icon = Icons.Outlined.FileUpload)
        }
    }
}

/** The pane beside the list before anything is chosen (`NoSelection`). */
@Composable
private fun NoSelection() {
    Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        Logo(56.dp)
        Spacer(Modifier.size(12.dp))
        Text(stringResource(R.string.detail_noSelection), style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
