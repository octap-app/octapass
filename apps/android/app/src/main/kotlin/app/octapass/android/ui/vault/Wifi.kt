package app.octap.android.ui.vault

import android.Manifest
import android.content.Context
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.RequestPermission
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import app.octap.android.platform.WifiReading
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.theme.Brand
import app.octap.resources.R
import app.octap.vault.ItemSummary
import app.octap.vault.ItemType
import app.octap.vault.ListEntry
import app.octap.vault.ListSection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The connected and in-range networks (`useWifiRadar`): one poller for the app, running only while
 * a Wi-Fi screen is open and the app is in front, every 15 seconds.
 */
class WifiRadar(private val context: Context) {
    var permission by mutableStateOf(WifiReading.Permission.PROMPT)
        private set
    var connected by mutableStateOf<String?>(null)
        private set
    var sightings by mutableStateOf<Map<String, Int>>(emptyMap())
        private set
    var scanning by mutableStateOf(false)
        private set

    /** Asked once this run: a refusal after that reads as "denied", as the system won't ask again. */
    var asked = false

    private var users = 0
    private var poller: Job? = null
    private val scope = MainScope()

    fun acquire() {
        if (users++ == 0) start()
    }

    fun release() {
        if (--users == 0) stop()
    }

    fun refresh(rescan: Boolean) {
        scope.launch {
            scanning = rescan
            permission = WifiReading.permission(context, asked)
            if (permission != WifiReading.Permission.GRANTED) {
                connected = null
                sightings = emptyMap()
                scanning = false
                return@launch
            }
            val (current, nearby) = withContext(Dispatchers.Default) {
                runCatching { WifiReading.current(context) }.getOrNull() to runCatching { WifiReading.nearby(context, rescan) }.getOrDefault(emptyList())
            }
            connected = current
            sightings = nearby.associate { it.ssid to it.signal }
            scanning = false
        }
    }

    private fun start() {
        poller?.cancel()
        poller = scope.launch {
            refresh(true)
            while (isActive) {
                delay(15_000)
                refresh(false)
            }
        }
    }

    private fun stop() {
        poller?.cancel()
        poller = null
    }

    companion object {
        private var shared: WifiRadar? = null

        fun get(context: Context): WifiRadar = shared ?: WifiRadar(context.applicationContext).also { shared = it }
    }
}

/** The radar while this screen is on screen and the app is in front. */
@Composable
fun rememberWifiRadar(): WifiRadar {
    val context = LocalContext.current
    val radar = remember { WifiRadar.get(context) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle) {
        var holding = false
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME && !holding) {
                radar.acquire()
                holding = true
            } else if (event == Lifecycle.Event.ON_PAUSE && holding) {
                radar.release()
                holding = false
            }
        }
        lifecycle.addObserver(observer)
        onDispose {
            lifecycle.removeObserver(observer)
            if (holding) radar.release()
        }
    }
    return radar
}

/** A Wi-Fi item's network name: its list subtitle. */
fun wifiSsid(item: ItemSummary): String? = item.subtitle?.takeIf { item.itemType == ItemType.Wifi && it.isNotEmpty() }

/** Networks the phone is on or sees first, connected then strongest, in their own section (`nearbyFirst`). */
fun nearbyFirst(sections: List<ListSection>, radar: WifiRadar): List<ListSection> {
    fun rank(item: ItemSummary): Int {
        val ssid = wifiSsid(item) ?: return -1
        if (ssid == radar.connected) return 101
        return radar.sightings[ssid] ?: -1
    }
    val all = sections.flatMap { it.items }
    val near = all.filter { rank(it) >= 0 }.sortedByDescending(::rank)
    if (near.isEmpty()) return sections
    val nearIds = near.map { it.id }.toSet()
    val rest = sections.mapNotNull { section ->
        val items = section.items.filter { it.id !in nearIds }
        val entries = section.entries.mapNotNull { entry -> if (entry is ListEntry.Item && entry.item.id in nearIds) null else entry }
        if (items.isEmpty()) null else ListSection(section.key, items, entries)
    }
    return listOf(ListSection(IN_RANGE, near, near.map { ListEntry.Item(it) })) + rest
}

/** Four bars, the way the system draws them. */
@Composable
fun SignalBars(signal: Int) {
    val bars = WifiReading.bars(signal)
    val label = stringResource(R.string.wifi_signal, bars.toString())
    val on = MaterialTheme.colorScheme.onSurface
    val off = MaterialTheme.colorScheme.outlineVariant
    Canvas(Modifier.size(16.dp, 12.dp).semantics { contentDescription = label }) {
        val unit = size.width / 16f
        for (i in 0 until 4) {
            val height = (3 + i * 3) * unit
            drawRoundRect(if (i < bars) on else off, Offset(i * 4 * unit, size.height - height), Size(3 * unit, height), CornerRadius(0.75f * unit))
        }
    }
}

/** "Connected", or "In range" with the signal (`WifiMark`). */
@Composable
fun WifiMark(ssid: String?, radar: WifiRadar) {
    ssid ?: return
    if (radar.connected == ssid) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            Icon(Icons.Outlined.Wifi, contentDescription = null, tint = Brand.colors.freeText, modifier = Modifier.size(14.dp))
            Text(stringResource(R.string.wifi_connected), style = MaterialTheme.typography.labelSmall, color = Brand.colors.freeText)
        }
        return
    }
    val signal = radar.sightings[ssid] ?: return
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        SignalBars(signal)
        Text(stringResource(R.string.wifi_inRange), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** Asks for location access or says it's off: Android tells apps network names only with it (`WifiPermissionNote`). */
@Composable
fun WifiPermissionNote() {
    val radar = rememberWifiRadar()
    val ask = rememberLauncherForActivityResult(RequestPermission()) {
        radar.asked = true
        radar.refresh(true)
    }
    when (radar.permission) {
        WifiReading.Permission.PROMPT -> Alert(stringResource(R.string.wifi_permissionTitle), AlertTone.Info, Modifier.padding(horizontal = 16.dp, vertical = 4.dp)) {
            Text(stringResource(R.string.wifi_permissionBody), style = MaterialTheme.typography.bodySmall, color = Brand.colors.trustText)
            TextButton(onClick = { ask.launch(Manifest.permission.ACCESS_FINE_LOCATION) }) { Text(stringResource(R.string.wifi_permissionAllow)) }
        }
        WifiReading.Permission.DENIED -> Alert(stringResource(R.string.wifi_permissionDenied), AlertTone.Warn, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
        WifiReading.Permission.GRANTED -> Unit
    }
}

/** The Wi-Fi list's buttons: look again, and how to bring networks in from this phone (`WifiListTools`). */
@Composable
fun WifiListTools() {
    val radar = rememberWifiRadar()
    var importing by remember { mutableStateOf(false) }
    if (radar.permission == WifiReading.Permission.GRANTED) {
        IconButton(onClick = { radar.refresh(true) }, enabled = !radar.scanning) { Icon(Icons.Outlined.Refresh, contentDescription = stringResource(R.string.wifi_refresh)) }
    }
    IconButton(onClick = { importing = true }) { Icon(Icons.Outlined.Download, contentDescription = stringResource(R.string.wifi_importAction)) }
    if (importing) {
        // Android doesn't let apps read saved networks: say how to bring one in instead.
        AlertDialog(
            onDismissRequest = { importing = false },
            title = { Text(stringResource(R.string.wifi_phoneImportTitle)) },
            text = { Text(stringResource(R.string.wifi_androidImport)) },
            confirmButton = { TextButton(onClick = { importing = false }) { Text(stringResource(R.string.common_close)) } },
        )
    }
}

/**
 * "Save “Home” in Octa Pass?" (`WifiSaveOffer`): when the phone is on a network the vault doesn't
 * have, checked when the app comes back. Asked once per network; Never stops it for good.
 */
@Composable
fun WifiSaveOffer() {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val settings by model.settings.collectAsState()
    // Checked when the app opens or comes back, not polled: the offer is about where the phone is now.
    var current by remember { mutableStateOf<String?>(null) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle, settings.wifiOffers) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME && settings.wifiOffers && WifiReading.permission(context, asked = false) == WifiReading.Permission.GRANTED) {
                current = runCatching { WifiReading.current(context) }.getOrNull()
            }
        }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    val saved = app.octap.android.ui.util.rememberLive(model) {
        model.vault.listItems(app.octap.vault.ItemFilter(null, ItemType.Wifi, null, false, false, false, false, null, null)).mapNotNull(::wifiSsid).toSet()
    }.data
    var dismissed by remember { mutableStateOf<String?>(null) }
    val ssid = current
    val offers = app.octap.android.ui.settings.WifiOffers.load(context)
    val show = settings.wifiOffers && ssid != null && saved != null && ssid !in saved && ssid !in offers.asked && ssid !in offers.never && dismissed != ssid
    if (!show) return

    fun done(never: Boolean) {
        val current = app.octap.android.ui.settings.WifiOffers.load(context)
        app.octap.android.ui.settings.WifiOffers.save(
            context,
            current.copy(asked = (current.asked + ssid!!).distinct(), never = if (never) (current.never + ssid).distinct() else current.never),
        )
        dismissed = ssid
    }

    AlertDialog(
        onDismissRequest = { done(false) },
        icon = { Icon(Icons.Outlined.Wifi, contentDescription = null) },
        title = { Text(stringResource(R.string.wifi_offerTitle, ssid!!)) },
        text = { Text(stringResource(R.string.wifi_offerPhone)) },
        dismissButton = {
            Row {
                TextButton(onClick = { done(true) }) { Text(stringResource(R.string.wifi_offerNever)) }
                TextButton(onClick = { done(false) }) { Text(stringResource(R.string.wifi_offerNotNow)) }
            }
        },
        confirmButton = {
            TextButton(
                modifier = androidx.compose.ui.Modifier.testTag("wifiOffer.save"),
                onClick = {
                    done(false)
                    model.launch {
                        val vaults = model.vault.listVaults().filter { it.role != app.octap.vault.VaultRole.READ && !it.untrusted }
                        val target = vaults.firstOrNull { it.vaultType == app.octap.vault.VaultType.PERSONAL } ?: vaults.firstOrNull() ?: return@launch
                        val draft = app.octap.vault.newItemDraft(ItemType.Wifi, target.id)
                        val details = (draft.details as app.octap.vault.ItemDetails.Wifi).wifi.copy(ssid = ssid!!)
                        vault.nav.pendingDraft = draft.copy(details = app.octap.vault.ItemDetails.Wifi(details))
                        vault.open(Route.Edit(null, ItemType.Wifi, target.id))
                    }
                },
            ) { Text(stringResource(R.string.wifi_offerSave)) }
        },
    )
}
