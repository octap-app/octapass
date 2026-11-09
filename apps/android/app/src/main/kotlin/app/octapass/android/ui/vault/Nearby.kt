package app.octap.android.ui.vault

import android.Manifest
import android.content.Context
import android.icu.text.MeasureFormat
import android.icu.util.Measure
import android.icu.util.MeasureUnit
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.RequestMultiplePermissions
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.LocationOn
import androidx.compose.material.icons.outlined.Menu
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.platform.DeviceLocation
import app.octap.android.platform.WifiReading
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.tools.SettingsRow
import app.octap.android.ui.tools.SettingsSection
import app.octap.android.ui.util.rememberLive
import app.octap.resources.R
import app.octap.vault.Here
import app.octap.vault.HereBy
import app.octap.vault.Item
import app.octap.vault.NearbyPlace
import app.octap.vault.Place
import app.octap.vault.PlaceDraft
import app.octap.vault.Vault
import app.octap.vault.VaultRole
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import kotlinx.coroutines.launch
import java.util.Locale

// ---------- Device-only settings and state ----------

/** Nearby's per-phone settings and the items already asked about, outside the vault like the UI's other choices. */
object NearbyPrefs {
    private const val SUGGEST = "nearby.suggest"
    private const val ASKED = "nearby.asked"

    private fun prefs(context: Context) = context.getSharedPreferences("octapass.ui", Context.MODE_PRIVATE)

    /** "Suggest a place when saving": on unless turned off. */
    fun suggest(context: Context): Boolean = prefs(context).getBoolean(SUGGEST, true)

    fun setSuggest(context: Context, on: Boolean) = prefs(context).edit().putBoolean(SUGGEST, on).apply()

    fun asked(context: Context): Set<String> = prefs(context).getStringSet(ASKED, emptySet()).orEmpty()

    /** Remembers that [id] was asked about, keeping the last 200. */
    fun markAsked(context: Context, id: String) {
        val next = (asked(context) - id).toList().takeLast(199) + id
        prefs(context).edit().putStringSet(ASKED, next.toSet()).apply()
    }
}

/**
 * Items just made in the editor, which may be offered the place the phone is at. In memory only:
 * the question is asked right after saving, or not at all.
 */
object FreshItems {
    private val ids = mutableSetOf<String>()

    fun add(id: String) = synchronized(ids) { ids.add(id) }

    fun take(id: String): Boolean = synchronized(ids) { ids.remove(id) }
}

/** The rough distance, in the phone's language ("870 m", "1.2 km"). */
fun distanceText(metres: Double, locale: Locale = Locale.getDefault()): String {
    val d = NearbyLogic.distance(metres)
    val format = MeasureFormat.getInstance(locale, MeasureFormat.FormatWidth.SHORT, android.icu.text.NumberFormat.getInstance(locale).apply {
        maximumFractionDigits = d.decimals
        minimumFractionDigits = 0
    })
    return format.format(Measure(d.value, if (d.kilometres) MeasureUnit.KILOMETER else MeasureUnit.METER))
}

// ---------- Where the phone is ----------

/** Where the phone is, read once each time the screen comes to the front. */
class HereState(val here: Here, val network: String?, val location: NearbyLogic.LocationState, val checking: Boolean, val refresh: () -> Unit)

/**
 * The network the phone is on and one location reading, while [active] and the app is in front.
 * Asks for location the first time (Android shows network names only with it too). Never in the
 * background: a reading is taken on resume and dropped when the screen goes.
 */
@Composable
fun rememberHere(active: Boolean = true, ask: Boolean = true): HereState {
    val context = LocalContext.current
    val radar = rememberWifiRadar()
    var reading by remember { mutableStateOf<NearbyLogic.Reading?>(null) }
    var location by remember { mutableStateOf(NearbyLogic.LocationState.READING) }
    var tick by remember { mutableIntStateOf(0) }
    val permission = rememberLauncherForActivityResult(RequestMultiplePermissions()) {
        radar.asked = true
        radar.refresh(false)
        tick++
    }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle, active) {
        val observer = LifecycleEventObserver { _, event -> if (event == Lifecycle.Event.ON_RESUME && active) tick++ }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    LaunchedEffect(tick, active) {
        if (!active || tick == 0) return@LaunchedEffect
        when {
            !DeviceLocation.enabled(context) && DeviceLocation.source === DeviceLocation.systemSource -> location = NearbyLogic.LocationState.OFF
            !DeviceLocation.granted(context) && DeviceLocation.source === DeviceLocation.systemSource -> {
                if (ask && !radar.asked) {
                    radar.asked = true
                    permission.launch(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION))
                }
                location = NearbyLogic.LocationState.DENIED
            }
            else -> {
                location = NearbyLogic.LocationState.READING
                reading = DeviceLocation.current(context)
                location = if (reading != null) NearbyLogic.LocationState.OK else NearbyLogic.LocationState.UNAVAILABLE
            }
        }
    }
    val network = radar.connected.takeIf { radar.permission == WifiReading.Permission.GRANTED }
    val here = remember(network, reading) { NearbyLogic.here(network, reading) }
    return HereState(here, network, location, location == NearbyLogic.LocationState.READING && active, refresh = { radar.refresh(false); tick++ })
}

// ---------- The list ----------

/** Nearby (`NearbyPage`): the place the phone is at first, its items by type, then the other places. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NearbyList() {
    val vault = LocalVault.current
    val model = vault.model
    val state = rememberHere()
    val vaults = rememberLive(model, sharing = true) { model.vault.listVaults() }.data
    val list = rememberLive(model, state.here) { model.vault.nearby(state.here) }
    var managing by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf<Place?>(null) }
    var creating by remember { mutableStateOf(false) }
    val places = list.data
    val anyHere = places?.any { it.here != null } == true

    Scaffold(
        contentWindowInsets = WindowInsets(0),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.scopes_nearby), modifier = Modifier.semantics { heading() }.testTag("list.title")) },
                navigationIcon = {
                    vault.openDrawer?.let { open ->
                        IconButton(onClick = open, modifier = Modifier.testTag("list.menu")) { Icon(Icons.Outlined.Menu, contentDescription = stringResource(R.string.nav_openMenu)) }
                    }
                },
                actions = {
                    IconButton(onClick = { managing = true }, modifier = Modifier.testTag("nearby.places")) { Icon(Icons.Outlined.Settings, contentDescription = stringResource(R.string.nearby_places)) }
                    IconButton(onClick = { creating = true }, modifier = Modifier.testTag("nearby.new")) { Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.nearby_newPlace)) }
                },
            )
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when {
                places == null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                places.isEmpty() -> Empty(Icons.Outlined.LocationOn, stringResource(R.string.nearby_emptyTitle), stringResource(R.string.nearby_emptyBody)) {
                    Button(onClick = { creating = true }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.nearby_newPlace)) }
                }
                else -> LazyColumn(Modifier.fillMaxSize().testTag("nearby.list")) {
                    if (state.checking) item { Status(stringResource(R.string.nearby_checking)) }
                    else if (!anyHere) item { Status(reasonText(NearbyLogic.reason(state.here, state.location))) }
                    var others = false
                    for (entry in places) {
                        if (entry.here == null && anyHere && !others) {
                            others = true
                            item(key = "others") {
                                Text(stringResource(R.string.nearby_otherPlaces), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp).semantics { heading() })
                            }
                        }
                        item(key = "place.${entry.place.id}") {
                            PlaceHeader(entry, vaults, onEdit = { editing = entry.place }, onAdd = { addHere(vault, entry.place, vaults) })
                        }
                        if (entry.sections.all { it.items.isEmpty() }) {
                            item(key = "empty.${entry.place.id}") {
                                Text(stringResource(R.string.nearby_noItems), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(start = 56.dp, end = 16.dp, bottom = 12.dp))
                            }
                        }
                        for (section in entry.sections.filter { it.items.isNotEmpty() }) {
                            item(key = "section.${entry.place.id}.${typeKey(section.itemType)}") {
                                Text(stringResource(categoryRes(section.itemType)), style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 6.dp, bottom = 2.dp).semantics { heading() })
                            }
                            items(section.items, key = { "row.${entry.place.id}.${it.id}" }) { ItemRow(it, Scope.Nearby, vaults) }
                        }
                        item(key = "divider.${entry.place.id}") { HorizontalDivider(Modifier.padding(top = 8.dp)) }
                    }
                }
            }
        }
    }
    if (managing) PlacesManager(vaults, onDismiss = { managing = false }, onEdit = { managing = false; editing = it }, onNew = { managing = false; creating = true })
    if (creating || editing != null) PlaceEditor(editing, vaults, state.network, onDismiss = { creating = false; editing = null })
}

/** "Add an item here": a new login that starts at the place, in the personal vault unless the place's vault is the only writable one. */
private fun addHere(vault: VaultContext, place: Place, vaults: List<Vault>?) {
    val writable = vaults.orEmpty().filter { it.role != VaultRole.READ && !it.untrusted }
    val vaultId = writable.firstOrNull { it.vaultType == VaultType.PERSONAL }?.id ?: writable.firstOrNull()?.id ?: return
    vault.nav.pendingDraft = newItemDraft(app.octap.vault.ItemType.Login, vaultId).also { it.places = listOf(place.id) }
    vault.open(Route.Edit(null, app.octap.vault.ItemType.Login, vaultId))
}

@Composable
private fun reasonText(reason: NearbyLogic.Reason): String = when (reason) {
    NearbyLogic.Reason.NO_MATCH -> stringResource(R.string.nearby_reasonNoMatch)
    NearbyLogic.Reason.LOCATION_OFF -> stringResource(R.string.nearby_reasonLocationUnavailable)
    NearbyLogic.Reason.LOCATION_DENIED -> stringResource(R.string.nearby_reasonLocationDenied)
    NearbyLogic.Reason.LOCATION_UNAVAILABLE -> stringResource(R.string.nearby_reasonLocationUnavailable)
}

@Composable
private fun Status(text: String) {
    Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp).testTag("nearby.status"))
}

@Composable
private fun PlaceHeader(entry: NearbyPlace, vaults: List<Vault>?, onEdit: () -> Unit, onAdd: () -> Unit) {
    val inVault = vaults?.firstOrNull { it.id == entry.place.vaultId }
    val canEdit = inVault?.role != VaultRole.READ && inVault?.untrusted != true
    val how = when (entry.here) {
        HereBy.WIFI -> stringResource(R.string.nearby_byWifi)
        HereBy.LOCATION -> stringResource(R.string.nearby_byLocation)
        null -> entry.distance?.let { stringResource(R.string.nearby_away, distanceText(it)) }
    }
    Row(
        Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 12.dp, bottom = 4.dp).testTag("place.${entry.place.id}"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(Icons.Outlined.LocationOn, contentDescription = null, tint = if (entry.here != null) Brand.colors.trustText else MaterialTheme.colorScheme.onSurfaceVariant)
        Column(Modifier.weight(1f)) {
            val name = if (entry.here != null) stringResource(R.string.nearby_nowNearby, entry.place.name) else entry.place.name
            Text(name, style = MaterialTheme.typography.titleMedium, maxLines = 2, overflow = TextOverflow.Ellipsis, modifier = Modifier.semantics { heading() }.testTag("place.name"))
            val sub = listOfNotNull(how, inVault?.takeIf { it.vaultType != VaultType.PERSONAL }?.let { vaultName(it) }).joinToString(" · ")
            if (sub.isNotEmpty()) Text(sub, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (canEdit) IconButton(onClick = onEdit) { Icon(Icons.Outlined.Edit, contentDescription = stringResource(R.string.nearby_editPlace)) }
        IconButton(onClick = onAdd, modifier = Modifier.testTag("place.add")) { Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.nearby_addItemHere)) }
    }
}

// ---------- The Places manager and the editor ----------

@Composable
private fun placeSummary(place: Place): String {
    val parts = buildList {
        if (place.latitude != null && place.longitude != null) add(stringResource(R.string.nearby_summaryPoint, distanceText(place.radius)))
        if (place.networks.isNotEmpty()) add(pluralStringResource(R.plurals.nearby_summaryNetworks, place.networks.size, place.networks.size))
    }
    return parts.joinToString(" · ").ifEmpty { stringResource(R.string.nearby_summaryNothing) }
}

@Composable
private fun PlacesManager(vaults: List<Vault>?, onDismiss: () -> Unit, onEdit: (Place) -> Unit, onNew: () -> Unit) {
    val model = LocalVault.current.model
    val places = rememberLive(model) { model.vault.places() }.data.orEmpty()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.nearby_managerTitle)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.nearby_managerBody), style = MaterialTheme.typography.bodyMedium)
                for (place in places) {
                    val inVault = vaults?.firstOrNull { it.id == place.vaultId }
                    val canEdit = inVault?.role != VaultRole.READ && inVault?.untrusted != true
                    Row(
                        Modifier.fillMaxWidth().clickable(enabled = canEdit) { onEdit(place) }.padding(vertical = 8.dp).testTag("places.${place.id}"),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Icon(Icons.Outlined.LocationOn, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
                        Column(Modifier.weight(1f)) {
                            Text(place.name, style = MaterialTheme.typography.bodyLarge)
                            Text(placeSummary(place), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        if (canEdit) Icon(Icons.Outlined.Edit, contentDescription = stringResource(R.string.nearby_editPlace))
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onNew) { Text(stringResource(R.string.nearby_newPlace)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_close)) } },
    )
}

/** New place or Edit place, full screen. */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun PlaceEditor(place: Place?, vaults: List<Vault>?, network: String?, onDismiss: () -> Unit) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val writable = vaults.orEmpty().filter { it.role != VaultRole.READ && !it.untrusted }
    var name by remember { mutableStateOf(place?.name.orEmpty()) }
    var vaultId by remember { mutableStateOf(place?.vaultId ?: writable.firstOrNull { it.vaultType == VaultType.PERSONAL }?.id ?: writable.firstOrNull()?.id.orEmpty()) }
    var latitude by remember { mutableStateOf(place?.latitude?.toString().orEmpty()) }
    var longitude by remember { mutableStateOf(place?.longitude?.toString().orEmpty()) }
    var radius by remember { mutableStateOf(place?.radius?.toLong()?.toString() ?: "150") }
    var networks by remember { mutableStateOf(place?.networks.orEmpty()) }
    var newNetwork by remember { mutableStateOf("") }
    var notes by remember { mutableStateOf(place?.notes.orEmpty()) }
    var nameError by remember { mutableStateOf<String?>(null) }
    var pointError by remember { mutableStateOf<String?>(null) }
    var locateError by remember { mutableStateOf<String?>(null) }
    var formError by remember { mutableStateOf<String?>(null) }
    var locating by remember { mutableStateOf(false) }
    var saving by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf(false) }
    var choosingVault by remember { mutableStateOf(false) }
    val inVault = vaults?.firstOrNull { it.id == vaultId }
    val hasPoint = latitude.isNotBlank() || longitude.isNotBlank()
    val permission = rememberLauncherForActivityResult(RequestMultiplePermissions()) { granted ->
        if (granted.values.none { it }) locateError = context.getString(R.string.nearby_locationFailed)
    }

    fun addNetwork(ssid: String) {
        if (ssid.isNotBlank() && ssid !in networks) networks = networks + ssid
        newNetwork = ""
    }

    fun useCurrent() {
        if (!DeviceLocation.granted(context) && DeviceLocation.source === DeviceLocation.systemSource) {
            permission.launch(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION))
            return
        }
        locating = true
        locateError = null
        scope.launch {
            val reading = DeviceLocation.current(context)
            locating = false
            if (reading == null) {
                locateError = context.getString(R.string.nearby_locationFailed)
            } else {
                latitude = String.format(Locale.ROOT, "%.6f", reading.latitude)
                longitude = String.format(Locale.ROOT, "%.6f", reading.longitude)
                pointError = null
            }
        }
    }

    fun save() {
        val point = NearbyLogic.point(latitude, longitude)
        nameError = if (name.isBlank()) context.getString(R.string.nearby_nameRequired) else null
        pointError = if (point.isFailure) context.getString(R.string.nearby_invalidPoint) else null
        if (nameError != null || pointError != null || vaultId.isEmpty()) return
        saving = true
        formError = null
        scope.launch {
            try {
                val pair = point.getOrNull()
                val saved = model.vault.savePlace(
                    PlaceDraft(
                        id = place?.id,
                        vaultId = vaultId,
                        revision = place?.revision,
                        name = name.trim(),
                        latitude = pair?.first,
                        longitude = pair?.second,
                        radius = radius.trim().toDoubleOrNull(),
                        networks = networks,
                        notes = notes.trim().ifEmpty { null },
                    ),
                )
                model.toast(context.getString(R.string.nearby_saved, saved.name), Toast.Tone.Success)
                onDismiss()
            } catch (error: Exception) {
                formError = errorMessage(context, error)
                saving = false
            }
        }
    }

    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            Scaffold(
                contentWindowInsets = WindowInsets(0),
                topBar = {
                    TopAppBar(
                        title = { Text(stringResource(if (place == null) R.string.nearby_newPlace else R.string.nearby_editPlace)) },
                        navigationIcon = { IconButton(onClick = onDismiss) { Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.common_cancel)) } },
                        actions = { TextButton(onClick = { save() }, enabled = !saving, modifier = Modifier.testTag("place.save")) { Text(stringResource(R.string.common_save)) } },
                    )
                },
            ) { padding ->
                Column(
                    Modifier.padding(padding).fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(16.dp).widthIn(max = 640.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    formError?.let { Alert(it) }
                    OutlinedTextField(name, { name = it }, label = { Text(stringResource(R.string.nearby_name)) }, placeholder = { Text(stringResource(R.string.nearby_namePlaceholder)) }, isError = nameError != null, supportingText = nameError?.let { { Text(it) } }, singleLine = true, modifier = Modifier.fillMaxWidth().testTag("place.name.field"))
                    if (place == null && writable.size > 1) {
                        Box {
                            OutlinedButton(onClick = { choosingVault = true }, modifier = Modifier.fillMaxWidth()) { Text("${stringResource(R.string.nearby_vault)}: ${inVault?.let { vaultName(it) }.orEmpty()}") }
                            DropdownMenu(expanded = choosingVault, onDismissRequest = { choosingVault = false }) {
                                for (v in writable) DropdownMenuItem(text = { Text(vaultName(v)) }, onClick = { vaultId = v.id; choosingVault = false })
                            }
                        }
                    }

                    Text(stringResource(R.string.nearby_networks), style = MaterialTheme.typography.titleSmall)
                    Text(stringResource(R.string.nearby_networksHint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        for (ssid in networks) {
                            Row(Modifier.clip(CircleShape).background(MaterialTheme.colorScheme.surfaceContainer).padding(start = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Outlined.Wifi, contentDescription = null, modifier = Modifier.size(14.dp))
                                Spacer(Modifier.size(4.dp))
                                Text(ssid, style = MaterialTheme.typography.labelLarge)
                                IconButton(onClick = { networks = networks - ssid }) { Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.nearby_removeNetwork, ssid), modifier = Modifier.size(16.dp)) }
                            }
                        }
                    }
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(newNetwork, { if (it.toByteArray().size <= 32) newNetwork = it }, label = { Text(stringResource(R.string.nearby_networkPlaceholder)) }, singleLine = true, modifier = Modifier.weight(1f).testTag("place.network.field"))
                        OutlinedButton(onClick = { addNetwork(newNetwork) }, enabled = newNetwork.isNotBlank()) { Text(stringResource(R.string.nearby_addNetwork)) }
                    }
                    if (network != null && network !in networks) {
                        TextButton(onClick = { addNetwork(network) }) { Text(stringResource(R.string.nearby_addConnected, network)) }
                    }

                    Text(stringResource(R.string.nearby_location), style = MaterialTheme.typography.titleSmall)
                    Text(stringResource(R.string.nearby_locationHint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(latitude, { latitude = it }, label = { Text(stringResource(R.string.nearby_latitude)) }, isError = pointError != null, singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal), modifier = Modifier.weight(1f).testTag("place.latitude"))
                        OutlinedTextField(longitude, { longitude = it }, label = { Text(stringResource(R.string.nearby_longitude)) }, isError = pointError != null, singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal), modifier = Modifier.weight(1f).testTag("place.longitude"))
                    }
                    pointError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { useCurrent() }, enabled = !locating, modifier = Modifier.testTag("place.useCurrent")) {
                            Text(stringResource(if (locating) R.string.nearby_locating else R.string.nearby_useCurrent))
                        }
                        if (hasPoint) TextButton(onClick = { latitude = ""; longitude = "" }) { Text(stringResource(R.string.nearby_clearLocation)) }
                    }
                    locateError?.let { Alert(it, AlertTone.Warn) }
                    OutlinedTextField(radius, { radius = it.filter { c -> c.isDigit() } }, label = { Text(stringResource(R.string.nearby_radius)) }, supportingText = { Text(stringResource(R.string.nearby_radiusHint)) }, singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth())
                    if (hasPoint && inVault != null && inVault.vaultType != VaultType.PERSONAL) {
                        Alert(stringResource(R.string.nearby_sharedWarning, vaultName(inVault)), AlertTone.Warn, Modifier.testTag("place.sharedWarning"))
                    }
                    if (!hasPoint && networks.isEmpty()) Text(stringResource(R.string.nearby_noWay), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    OutlinedTextField(notes, { notes = it }, label = { Text(stringResource(R.string.nearby_notes)) }, minLines = 3, modifier = Modifier.fillMaxWidth())
                    if (place != null) {
                        TextButton(onClick = { deleting = true }) { Text(stringResource(R.string.nearby_deletePlace), color = MaterialTheme.colorScheme.error) }
                    }
                }
            }
        }
    }
    if (deleting && place != null) {
        AlertDialog(
            onDismissRequest = { deleting = false },
            title = { Text(stringResource(R.string.nearby_deletePlace)) },
            text = { Text(stringResource(R.string.nearby_deleteConfirm, place.name)) },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch {
                        try {
                            model.vault.deletePlace(place.id)
                            model.toast(context.getString(R.string.nearby_deleted, place.name), Toast.Tone.Success)
                            deleting = false
                            onDismiss()
                        } catch (error: Exception) {
                            deleting = false
                            formError = errorMessage(context, error)
                        }
                    }
                }) { Text(stringResource(R.string.nearby_deletePlace), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { deleting = false }) { Text(stringResource(R.string.common_cancel)) } },
        )
    }
}

// ---------- On an item ----------

/** The item's places, with Add to a place and a way off each (`ItemPlaces`). Hidden when there's nothing to show. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ItemPlaces(item: Item, editable: Boolean) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val places = rememberLive(model) { model.vault.places() }.data ?: return
    val linked = places.filter { it.id in item.places }
    val others = places.filter { it.id !in item.places }
    if (linked.isEmpty() && (!editable || places.isEmpty())) return
    var menu by remember { mutableStateOf(false) }

    fun change(place: Place, on: Boolean) = scope.launch {
        try {
            model.vault.setItemPlace(item.id, place.id, on)
            model.toast(context.getString(if (on) R.string.nearby_addedTo else R.string.nearby_removedFrom, place.name), Toast.Tone.Success)
        } catch (error: Exception) {
            model.toastError(error)
        }
    }

    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp).testTag("item.places"), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(stringResource(R.string.nearby_itemPlaces), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.semantics { heading() })
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            for (place in linked) {
                Row(Modifier.clip(CircleShape).background(MaterialTheme.colorScheme.surfaceContainer).padding(start = 10.dp, end = if (editable) 0.dp else 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.LocationOn, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.size(4.dp))
                    Text(place.name, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(vertical = if (editable) 0.dp else 6.dp))
                    if (editable) IconButton(onClick = { change(place, false) }, modifier = Modifier.testTag("item.places.remove.${place.id}")) { Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.nearby_removeFromPlace, place.name), modifier = Modifier.size(16.dp)) }
                }
            }
            if (editable && others.isNotEmpty()) {
                Box {
                    TextButton(onClick = { menu = true }, modifier = Modifier.testTag("item.places.add")) {
                        Icon(Icons.Outlined.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.size(4.dp))
                        Text(stringResource(R.string.nearby_addToPlace))
                    }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        for (place in others) DropdownMenuItem(text = { Text(place.name) }, onClick = { menu = false; change(place, true) }, modifier = Modifier.testTag("item.places.option.${place.id}"))
                    }
                }
            }
        }
    }
}

/**
 * "You're at Office. Add this item to it?", right after a new item is saved, when the phone is at
 * a place everyone who sees the item can see (`suggestedPlace`). Asked once per item; Settings →
 * Nearby turns it off.
 */
@Composable
fun PlaceSuggestion(item: Item) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val fresh = remember(item.id) { FreshItems.take(item.id) }
    val active = remember(item.id) { fresh && NearbyPrefs.suggest(context) && item.id !in NearbyPrefs.asked(context) }
    // Nothing to ask: don't look at Wi-Fi or the location at all.
    if (!active) return
    val state = rememberHere(active = true, ask = false)
    var offered by remember(item.id) { mutableStateOf<Place?>(null) }
    var answered by remember(item.id) { mutableStateOf(false) }
    LaunchedEffect(item.id, state.here, state.checking, active) {
        if (answered || offered != null || state.checking) return@LaunchedEffect
        if (!NearbyLogic.shouldAsk(item.id, active, NearbyPrefs.suggest(context), NearbyPrefs.asked(context), state.here)) return@LaunchedEffect
        val place = runCatching { model.vault.suggestedPlace(item.id, state.here) }.getOrNull() ?: return@LaunchedEffect
        NearbyPrefs.markAsked(context, item.id)
        offered = place
    }
    val place = offered ?: return
    if (answered) return
    Alert(stringResource(R.string.nearby_suggest, place.name), AlertTone.Info, Modifier.padding(horizontal = 16.dp, vertical = 4.dp).testTag("item.suggestPlace")) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = {
                answered = true
                scope.launch {
                    try {
                        model.vault.setItemPlace(item.id, place.id, true)
                        model.toast(context.getString(R.string.nearby_addedTo, place.name), Toast.Tone.Success)
                    } catch (error: Exception) {
                        model.toastError(error)
                    }
                }
            }, modifier = Modifier.testTag("item.suggestPlace.add")) { Text(stringResource(R.string.nearby_suggestAdd)) }
            TextButton(onClick = { answered = true }, modifier = Modifier.testTag("item.suggestPlace.notNow")) { Text(stringResource(R.string.nearby_suggestNotNow)) }
        }
    }
}

// ---------- Settings ----------

/** Settings → Nearby: the place suggestion, a choice for this phone only. */
@Composable
fun NearbySettingsSection() {
    val context = LocalContext.current
    var suggest by remember { mutableStateOf(NearbyPrefs.suggest(context)) }
    SettingsSection(stringResource(R.string.nearby_settingsTitle), tag = "settings.nearby") {
        SettingsRow(
            stringResource(R.string.nearby_suggestSetting),
            stringResource(R.string.nearby_suggestSettingHint),
            onClick = {
                suggest = !suggest
                NearbyPrefs.setSuggest(context, suggest)
            },
            modifier = Modifier.testTag("settings.nearbySuggest"),
        ) { Switch(suggest, null) }
    }
}
