package app.octap.android.ui.settings

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.platform.AutofillSettings
import app.octap.android.ui.auth.deviceMethodName
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.Field
import app.octap.android.ui.local.LocalSection
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.theme.monoStyle
import app.octap.android.ui.tools.SettingsRow
import app.octap.android.ui.tools.SettingsSection
import app.octap.android.ui.tools.VaultPage
import app.octap.android.ui.util.formatBytes
import app.octap.android.ui.util.rememberLive
import app.octap.android.ui.vault.Choice
import app.octap.android.ui.vault.Confirm
import app.octap.android.ui.vault.LocalVault
import app.octap.android.ui.vault.Route
import app.octap.android.ui.vault.copy
import app.octap.android.ui.components.forgetIcons
import app.octap.resources.R
import app.octap.vault.EquivalentDomains
import app.octap.vault.ErrorCode
import app.octap.vault.LanguagePreference
import app.octap.vault.StayUnlockedStatus
import app.octap.vault.ThemePreference
import app.octap.vault.UnlockMethods
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The auto-lock choices the vault accepts (`AUTO_LOCK_CHOICES`). */
private val AUTO_LOCK = listOf(1, 5, 15, 30, 60, 240, 0)

/**
 * Settings (`SettingsPage`), with the phone's own sections after Security. A local vault opens with
 * its own section and has none of what belongs to an account.
 */
@Composable
fun SettingsScreen() {
    val vault = LocalVault.current
    val model = vault.model
    val settings by model.settings.collectAsState()
    var exporting by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf(false) }
    val local = model.isLocal
    val stayUnlocked = rememberStayUnlocked()
    // While the vault stays unlocked, the lock timer, locking in the background and the app-open
    // gate don't apply: shown, greyed out (plan 18).
    val stays = settings.stayUnlocked && stayUnlocked.status?.available != false

    VaultPage(stringResource(R.string.settings_title), tag = "settings.title") {
        if (local) LocalSection()
        SettingsSection(stringResource(R.string.settings_appearance), tag = "settings.appearance") {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.settings_theme), style = MaterialTheme.typography.bodyLarge)
                Segments(
                    listOf(ThemePreference.SYSTEM to R.string.settings_themeSystem, ThemePreference.LIGHT to R.string.settings_themeLight, ThemePreference.DARK to R.string.settings_themeDark),
                    settings.theme,
                    "settings.theme",
                ) { theme -> model.updateSettings { it.copy(theme = theme) } }
                Text(stringResource(R.string.settings_language), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(top = 8.dp))
                Text(stringResource(R.string.settings_languageHelp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                // Each language named in itself, so anyone can find their own.
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    val options = listOf(LanguagePreference.SYSTEM to stringResource(R.string.settings_languageSystem), LanguagePreference.EN to "English", LanguagePreference.AR to "العربية")
                    options.forEachIndexed { i, (language, label) ->
                        SegmentedButton(
                            selected = settings.language == language,
                            onClick = { model.updateSettings { it.copy(language = language) } },
                            shape = SegmentedButtonDefaults.itemShape(i, options.size),
                            modifier = Modifier.testTag("settings.language.${language.name.lowercase()}"),
                        ) { Text(label) }
                    }
                }
            }
            SettingsRow(
                stringResource(R.string.settings_siteIcons),
                stringResource(R.string.settings_siteIconsHelp),
                onClick = {
                    // Icons already shown go too when they're turned off.
                    if (settings.showSiteIcons) forgetIcons()
                    model.updateSettings { it.copy(showSiteIcons = !it.showSiteIcons) }
                },
                modifier = Modifier.testTag("settings.siteIcons"),
            ) { Switch(settings.showSiteIcons, null) }
        }

        SettingsSection(stringResource(R.string.settings_security), tag = "settings.security") {
            StayUnlockedRow(stayUnlocked)
            Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                Choice(
                    stringResource(R.string.settings_autoLock),
                    AUTO_LOCK.map { minutes ->
                        minutes.toString() to when {
                            minutes == 0 -> stringResource(R.string.settings_autoLockNever)
                            minutes >= 60 -> pluralStringResource(R.plurals.settings_hours, minutes / 60, minutes / 60)
                            else -> pluralStringResource(R.plurals.settings_minutes, minutes, minutes)
                        }
                    },
                    settings.autoLockMinutes.toString(),
                    enabled = !stays,
                    tag = "settings.autoLock",
                ) { value -> model.updateSettings { it.copy(autoLockMinutes = (value ?: "15").toUInt()) } }
                Text(stringResource(R.string.settings_autoLockHelp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))
            }
            SettingsRow(
                stringResource(R.string.settings_lockOnHide),
                stringResource(R.string.settings_lockOnHideHelp),
                onClick = if (stays) null else ({ model.updateSettings { it.copy(lockOnBackground = !it.lockOnBackground) } }),
                modifier = Modifier.testTag("settings.lockOnHide"),
            ) { Switch(settings.lockOnBackground, null, enabled = !stays) }
            if (stays) StayUnlockedGates()
            DeviceUnlockRow()
            WatchCodesRow()
            SettingsRow(stringResource(R.string.settings_lockNow), stringResource(R.string.settings_lockNowHelp)) {
                OutlinedButton(onClick = { model.vault.lock() }, modifier = Modifier.testTag("settings.lockNow")) { Text(stringResource(R.string.settings_lockNow)) }
            }
            if (!local) SecretKeyRow()
            SettingsRow(
                stringResource(R.string.fields_masterPassword),
                if (local) null else stringResource(R.string.changePassword_rowHelp),
                onClick = { vault.nav.push(Route.ChangePassword) },
                modifier = Modifier.testTag("settings.changePassword"),
            )
            if (!local) SettingsRow(
                stringResource(R.string.rotateSecretKey_row),
                stringResource(R.string.rotateSecretKey_rowHelp),
                onClick = { vault.nav.push(Route.RotateSecretKey) },
                modifier = Modifier.testTag("settings.rotateSecretKey"),
            )
            if (!local) SettingsRow(
                stringResource(R.string.vaultKeys_row),
                stringResource(R.string.vaultKeys_rowHelp),
                onClick = { vault.nav.push(Route.VaultKeys) },
                modifier = Modifier.testTag("settings.vaultKeys"),
            )
            if (!local) SettingsRow(stringResource(R.string.settings_securityLog), stringResource(R.string.settings_securityLogHelp), onClick = { vault.nav.push(Route.SecurityLog) }, modifier = Modifier.testTag("settings.securityLog"))
        }

        // Next to Security: its gates follow the stay-unlocked switch there.
        DeviceAuthSection(stays)
        AutoFillSection()
        TransferSection()
        EquivalentDomainsSection()
        WifiSection()
        if (!local) {
            TwoStepSection()
            DevicesSection()
        }

        SettingsSection(stringResource(R.string.settings_export), stringResource(R.string.settings_exportHelp)) {
            SettingsRow(stringResource(R.string.settings_exportVault), stringResource(R.string.export_rowHelp)) {
                OutlinedButton(onClick = { exporting = true }, modifier = Modifier.testTag("settings.export")) { Text(stringResource(R.string.settings_exportAction)) }
            }
        }
        SettingsSection(stringResource(R.string.settings_import), stringResource(R.string.settings_importHelp)) {
            SettingsRow(stringResource(R.string.empty_import), onClick = { vault.nav.push(Route.Import) }, modifier = Modifier.testTag("settings.import"))
        }
        if (!local) AccountSection(onDelete = { deleting = true })
        Text(stringResource(R.string.settings_about), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 8.dp))
    }
    if (exporting) ExportDialog { exporting = false }
    if (deleting) DeleteAccountDialog { deleting = false }
}

/**
 * Codes on a Wear OS watch: off until asked for, and turning it on is a reveal, so it confirms
 * it's the owner first. This phone's choice, never synced.
 */
@Composable
private fun WatchCodesRow() {
    val model = LocalVault.current.model
    val settings by model.settings.collectAsState()
    var confirming by remember { mutableStateOf(false) }
    SettingsRow(
        stringResource(R.string.phone_native_wearCodes),
        stringResource(R.string.phone_native_wearCodesHelp),
        onClick = {
            if (settings.showCodesOnWatch) model.updateSettings { it.copy(showCodesOnWatch = false) } else confirming = true
        },
        modifier = Modifier.testTag("settings.watchCodes"),
    ) { Switch(settings.showCodesOnWatch, null) }
    if (confirming) {
        Dialog(onDismissRequest = { confirming = false }) {
            Surface(shape = MaterialTheme.shapes.large) {
                Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    Confirm(stringResource(R.string.phone_native_watchConfirmBody)) {
                        confirming = false
                        model.updateSettings { it.copy(showCodesOnWatch = true) }
                    }
                }
            }
        }
    }
}

@Composable
private fun <T> Segments(options: List<Pair<T, Int>>, selected: T, tag: String, onSelect: (T) -> Unit) {
    SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
        options.forEachIndexed { i, (value, label) ->
            SegmentedButton(selected = selected == value, onClick = { onSelect(value) }, shape = SegmentedButtonDefaults.itemShape(i, options.size), modifier = Modifier.testTag("$tag.$i")) { Text(stringResource(label)) }
        }
    }
}

/** Unlock with the fingerprint, face or screen lock (`DeviceUnlockRow`). */
@Composable
private fun DeviceUnlockRow() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var methods by remember { mutableStateOf<UnlockMethods?>(null) }
    var busy by remember { mutableStateOf(false) }
    androidx.compose.runtime.LaunchedEffect(Unit) { methods = runCatching { model.vault.unlockMethods() }.getOrNull() }
    val current = methods ?: return
    val method = deviceMethodName()
    SettingsRow(
        stringResource(R.string.unlock_settingTitle, method),
        if (current.deviceUnlockEnabled) stringResource(R.string.unlock_onHelp) else stringResource(R.string.unlock_help_android),
        onClick = if (busy || (!current.deviceUnlockSupported && !current.deviceUnlockEnabled)) null else ({
            busy = true
            val on = !current.deviceUnlockEnabled
            scope.launch {
                try {
                    if (on) model.vault.enableDeviceUnlock() else model.vault.disableDeviceUnlock()
                    methods = model.vault.unlockMethods()
                    model.toast(context.getString(if (on) R.string.phone_native_unlockEnabled else R.string.unlock_disabled, method), Toast.Tone.Success)
                } catch (error: Exception) {
                    if (!error.isCode(ErrorCode.DEVICE_UNLOCK_CANCELLED)) model.toastError(error)
                } finally {
                    busy = false
                }
            }
        }),
        modifier = Modifier.testTag("settings.deviceUnlock"),
    ) { Switch(current.deviceUnlockEnabled, null, enabled = current.deviceUnlockSupported || current.deviceUnlockEnabled) }
    if (!current.deviceUnlockSupported && !current.deviceUnlockEnabled) {
        Alert(stringResource(R.string.phone_native_unlockUnsupported), AlertTone.Info, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
    }
}

/** What Settings knows about stay unlocked, read off the main thread (it reads the Keystore). */
private class StayUnlockedState {
    var status by mutableStateOf<StayUnlockedStatus?>(null)
    var busy by mutableStateOf(false)
}

/** Read again when the switch changes and when the app comes back (a screen lock set or removed). */
@Composable
private fun rememberStayUnlocked(): StayUnlockedState {
    val model = LocalVault.current.model
    val settings by model.settings.collectAsState()
    val state = remember { StayUnlockedState() }
    val resumed = rememberOnResume { System.nanoTime() }
    LaunchedEffect(settings.stayUnlocked, resumed) {
        state.status = withContext(Dispatchers.IO) { runCatching { model.vault.stayUnlockedStatus() }.getOrNull() }
    }
    return state
}

/**
 * "Stay unlocked while you're logged in to this device" (plan 18, this phone only, on by default):
 * the vault opens and fills with no prompt while the phone is unlocked. Needs a screen lock; it
 * says so when there's none. Turning it on keeps a key for this account in the Keystore, which may
 * take a moment, so it runs off the main thread.
 */
@Composable
private fun StayUnlockedRow(state: StayUnlockedState) {
    val model = LocalVault.current.model
    val settings by model.settings.collectAsState()
    val scope = rememberCoroutineScope()
    val status = state.status
    val available = status?.available != false
    val on = settings.stayUnlocked && available
    // What "Confirm it's you" asks for: the device lock where device unlock is on, the master password otherwise.
    val methods = rememberLive(model) { runCatching { model.vault.unlockMethods() }.getOrNull() }.data
    val method = if (methods?.deviceUnlockEnabled == false) stringResource(R.string.deviceAuth_stayUnlockedPassword) else deviceMethodName()
    SettingsRow(
        stringResource(R.string.deviceAuth_stayUnlocked),
        if (on) stringResource(R.string.deviceAuth_stayUnlockedOn, method) else null,
        onClick = if (state.busy || !available) null else ({
            state.busy = true
            scope.launch {
                try {
                    withContext(Dispatchers.IO) { model.updateSettings { it.copy(stayUnlocked = !it.stayUnlocked) } }
                } catch (error: Exception) {
                    model.toastError(error)
                } finally {
                    state.status = withContext(Dispatchers.IO) { runCatching { model.vault.stayUnlockedStatus() }.getOrNull() }
                    state.busy = false
                }
            }
        }),
        modifier = Modifier.testTag("settings.stayUnlocked"),
    ) { Switch(on, null, enabled = available && !state.busy) }
    when {
        !available -> Alert(stringResource(R.string.deviceAuth_stayUnlockedNoScreenLock), AlertTone.Info, Modifier.padding(horizontal = 16.dp, vertical = 4.dp).testTag("settings.stayUnlockedNoScreenLock"))
        on && status?.passwordRequired == true -> Alert(stringResource(R.string.deviceAuth_stayUnlockedPasswordDue), AlertTone.Info, Modifier.padding(horizontal = 16.dp, vertical = 4.dp).testTag("settings.stayUnlockedPasswordDue"))
    }
}

/** Under the settings stay unlocked replaces, while it's on. */
@Composable
private fun StayUnlockedGates() {
    Text(
        stringResource(R.string.deviceAuth_stayUnlockedGates),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp).testTag("settings.stayUnlockedGates"),
    )
}

/**
 * The two gates (plan 03, this phone only): asking when the app opens, and asking on every fill
 * (the Autofill and Credential Manager services), with its warning while it's off. With no lock
 * Octa Pass can use there's nothing to ask with: opening and filling don't ask while the vault
 * stays unlocked, and this says so. While "Stay unlocked" is on ([stays]) the gates don't apply:
 * shown, greyed out (plan 18).
 */
@Composable
private fun DeviceAuthSection(stays: Boolean) {
    val model = LocalVault.current.model
    val settings by model.settings.collectAsState()
    val methods = rememberLive(model) { runCatching { model.vault.unlockMethods() }.getOrNull() }.data
    val lockless = methods != null && !methods.deviceUnlockEnabled
    val enabled = !lockless && !stays
    val scope = rememberCoroutineScope()
    SettingsSection(stringResource(R.string.deviceAuth_title), tag = "settings.deviceAuth") {
        if (stays) StayUnlockedGates()
        SettingsRow(
            stringResource(R.string.deviceAuth_appOpen),
            stringResource(R.string.deviceAuth_appOpenHelp),
            onClick = if (enabled) ({ model.updateSettings { it.copy(deviceAuthOnOpen = !it.deviceAuthOnOpen) } }) else null,
            modifier = Modifier.testTag("settings.deviceAuthOpen"),
        ) { Switch(settings.deviceAuthOnOpen, null, enabled = enabled) }
        SettingsRow(
            stringResource(R.string.deviceAuth_autofill),
            stringResource(R.string.deviceAuth_autofillHelp),
            // Off: the app keeps the services' fill key in the Keystore, which can take a moment.
            onClick = if (enabled) ({ scope.launch(Dispatchers.IO) { model.updateSettings { it.copy(deviceAuthOnAutofill = !it.deviceAuthOnAutofill) } } }) else null,
            modifier = Modifier.testTag("settings.deviceAuthAutofill"),
        ) { Switch(settings.deviceAuthOnAutofill, null, enabled = enabled) }
        if (!stays && !settings.deviceAuthOnAutofill) {
            Alert(stringResource(R.string.deviceAuth_autofillOff), AlertTone.Warn, Modifier.padding(horizontal = 16.dp, vertical = 4.dp).testTag("settings.deviceAuthAutofillOff"))
        }
        SettingsRow(stringResource(R.string.deviceAuth_revealHelp), null)
        if (lockless && !stays) Alert(stringResource(R.string.deviceAuth_lockless), AlertTone.Info, Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
    }
}

/** The Secret Key, shown on request (`SecretKeyRow`). */
@Composable
private fun SecretKeyRow() {
    val model = LocalVault.current.model
    val scope = rememberCoroutineScope()
    var secretKey by remember { mutableStateOf<String?>(null) }
    // A key shown before it was replaced no longer works.
    val newKit by model.newKit.collectAsState()
    androidx.compose.runtime.LaunchedEffect(newKit) { secretKey = null }
    val what = stringResource(R.string.fields_secretKey)
    val shown = secretKey
    SettingsRow(what, if (shown == null) stringResource(R.string.settings_secretKeyHelp) else null) {
        if (shown == null) {
            OutlinedButton(onClick = {
                scope.launch {
                    if (model.confirmIdentity()) runCatching { model.vault.secretKey() }.onSuccess { secretKey = it }.onFailure(model::toastError)
                }
            }, modifier = Modifier.testTag("settings.showSecretKey")) {
                Text(stringResource(R.string.common_show))
            }
        } else {
            IconButton(onClick = { scope.launch { if (model.confirmIdentity()) copy(model, shown, what, secret = true) } }) { Icon(Icons.Outlined.ContentCopy, contentDescription = stringResource(R.string.copy_action, what)) }
            IconButton(onClick = { secretKey = null }) { Icon(Icons.Outlined.VisibilityOff, contentDescription = stringResource(R.string.common_hideWhat, what)) }
        }
    }
    if (shown != null) Text(shown, style = monoStyle.copy(textDirection = TextDirection.Ltr), modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 12.dp).testTag("settings.secretKey"))
}

/** Re-reads [read] whenever the app comes back to the front (from the system's settings). */
@Composable
private fun <T> rememberOnResume(read: () -> T): T {
    var value by remember { mutableStateOf(read()) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event -> if (event == Lifecycle.Event.ON_RESUME) value = read() }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    return value
}

/** Settings → AutoFill (`AutoFillSection`): Octa Pass as the Autofill service and in Credential Manager. */
@Composable
private fun AutoFillSection() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val autofill = remember { AutofillSettings(context) }
    val enabled = rememberOnResume { autofill.autofillEnabled() }
    val passkeys = rememberOnResume { autofill.passkeysEnabled() }
    val open = rememberLauncherForActivityResult(StartActivityForResult()) { model.inSystemUi = false }
    fun launch(intent: android.content.Intent) {
        model.inSystemUi = true
        try {
            open.launch(intent)
        } catch (error: android.content.ActivityNotFoundException) {
            model.inSystemUi = false
            model.toast(R.string.phone_connectUnsupported, Toast.Tone.Danger)
        }
    }
    SettingsSection(stringResource(R.string.phone_autoFill), stringResource(R.string.phone_autoFillHelp), tag = "settings.autofill") {
        SettingsRow(stringResource(R.string.phone_autoFill), stringResource(if (enabled) R.string.phone_autoFillOn else R.string.phone_autoFillOff)) {
            if (!enabled) OutlinedButton(onClick = { launch(autofill.requestAutofill()) }, modifier = Modifier.testTag("settings.autofillOn")) { Text(stringResource(R.string.phone_autoFillTurnOn)) }
        }
        if (passkeys != null) {
            SettingsRow(stringResource(R.string.phone_autoFillPasskeys), stringResource(if (passkeys) R.string.phone_autoFillPasskeysOn else R.string.phone_autoFillPasskeysOff)) {
                if (!passkeys) OutlinedButton(onClick = { launch(autofill.passkeySettings()) }) { Text(stringResource(R.string.phone_autoFillTurnOn)) }
            }
        }
    }
}

/**
 * Sites that share one sign-in (`EquivalentDomainsSection`). The list is an encrypted vault item,
 * so it follows the account; what a domain may be is decided by the core when saving.
 */
@Composable
private fun EquivalentDomainsSection() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var list by remember { mutableStateOf<EquivalentDomains?>(null) }
    var rows by remember { mutableStateOf(emptyList<String>()) }
    var rejected by remember { mutableStateOf(emptyList<String>()) }
    var busy by remember { mutableStateOf(false) }

    fun show(next: EquivalentDomains) {
        list = next
        rows = next.groups.map { it.joinToString(", ") }
    }

    LaunchedEffect(Unit) { runCatching { model.vault.equivalentDomains() }.onSuccess(::show) }
    val current = list ?: return

    fun save(excluded: List<String>) {
        busy = true
        scope.launch {
            try {
                val saved = model.vault.saveEquivalentDomains(rows.map { row -> row.split(Regex("[\\s,]+")).filter { it.isNotEmpty() } }, excluded)
                show(saved)
                rejected = saved.rejected
                model.toast(context.getString(R.string.equivalent_saved), Toast.Tone.Success)
            } catch (error: Exception) {
                model.toastError(error)
            } finally {
                busy = false
            }
        }
    }

    SettingsSection(stringResource(R.string.equivalent_title), stringResource(R.string.equivalent_help), tag = "settings.equivalent") {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            rows.forEachIndexed { i, row ->
                Field(
                    value = row,
                    onValueChange = { text -> rows = rows.mapIndexed { at, one -> if (at == i) text else one } },
                    label = stringResource(R.string.equivalent_group, i + 1),
                    placeholder = "example.com, example.org",
                    mono = true,
                    modifier = Modifier.testTag("equivalent.group.$i"),
                    trailing = {
                        IconButton(onClick = { rows = rows.filterIndexed { at, _ -> at != i } }) {
                            Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.equivalent_removeGroup, i + 1))
                        }
                    },
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { rows = rows + "" }, modifier = Modifier.testTag("equivalent.add")) {
                    Icon(Icons.Outlined.Add, null, Modifier.size(18.dp))
                    Text(stringResource(R.string.equivalent_addGroup), Modifier.padding(start = 6.dp))
                }
                OutlinedButton(onClick = { save(current.excludedDefaults) }, enabled = !busy, modifier = Modifier.testTag("equivalent.save")) { Text(stringResource(R.string.common_save)) }
            }
            if (rejected.isNotEmpty()) Alert(stringResource(R.string.equivalent_rejected, rejected.joinToString(", ")), modifier = Modifier.testTag("equivalent.rejected"))
        }
        // Each built-in group goes by its first domain, and saves straight away.
        for (group in current.defaults) {
            val name = group.firstOrNull() ?: continue
            val on = name !in current.excludedDefaults
            SettingsRow(
                group.take(3).joinToString(", ") + if (group.size > 3) " …" else "",
                onClick = if (busy) null else ({ save(if (on) current.excludedDefaults + name else current.excludedDefaults - name) }),
                modifier = Modifier.testTag("equivalent.default.$name"),
            ) { Switch(on, null, enabled = !busy) }
        }
    }
}

/** Settings → Wi-Fi: the "Save this network?" offers (`WifiSection`). */
@Composable
private fun WifiSection() {
    val model = LocalVault.current.model
    val settings by model.settings.collectAsState()
    val context = LocalContext.current
    var never by remember { mutableIntStateOf(WifiOffers.load(context).never.size) }
    SettingsSection(stringResource(R.string.wifi_settings), stringResource(R.string.wifi_settingsHelp)) {
        SettingsRow(stringResource(R.string.wifi_offerSetting), stringResource(R.string.wifi_offerSettingHelp), onClick = { model.updateSettings { it.copy(wifiOffers = !it.wifiOffers) } }) {
            Switch(settings.wifiOffers, null)
        }
        if (never > 0) {
            SettingsRow(pluralStringResource(R.plurals.wifi_forgetNever, never, never)) {
                OutlinedButton(onClick = {
                    WifiOffers.save(context, WifiOffers.load(context).copy(never = emptyList()))
                    never = 0
                }) { Text(stringResource(R.string.wifi_forgetNeverAction)) }
            }
        }
    }
}

/** Settings → Devices (`DevicesSection`): where the account is signed in; rename this one, sign others out. */
@Composable
private fun DevicesSection() {
    val model = LocalVault.current.model
    val devices = rememberLive(model, sharing = true) { model.vault.listDevices() }
    var signingOut by remember { mutableStateOf<app.octap.vault.Device?>(null) }
    var renaming by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current
    SettingsSection(stringResource(R.string.devices_title), stringResource(R.string.devices_help), tag = "settings.devices") {
        val list = devices.data
        if (list == null) {
            CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
            return@SettingsSection
        }
        for (device in list) {
            val platform = stringResource(devicePlatformRes(device.platform))
            val seen = stringResource(R.string.devices_lastSeen, app.octap.android.ui.util.Formats.relative(device.lastSeenAt))
            SettingsRow(device.name, listOfNotNull(if (device.current) stringResource(R.string.devices_current) else null, platform, seen).joinToString(" · ")) {
                if (device.current) {
                    OutlinedButton(onClick = { renaming = device.name }, modifier = Modifier.testTag("devices.rename")) { Text(stringResource(R.string.common_rename)) }
                } else {
                    OutlinedButton(onClick = { signingOut = device }) { Text(stringResource(R.string.devices_signOut)) }
                }
            }
        }
    }
    renaming?.let { name ->
        TextPrompt(
            title = stringResource(R.string.devices_rename),
            label = stringResource(R.string.devices_rename),
            initial = name,
            confirm = stringResource(R.string.common_save),
            onDismiss = { renaming = null },
        ) { next ->
            model.launch {
                model.vault.renameDevice(next.trim())
                model.toast(context.getString(R.string.devices_renamed), Toast.Tone.Success)
                devices.retry()
            }
            renaming = null
        }
    }
    signingOut?.let { device ->
        Confirm(
            title = stringResource(R.string.devices_signOutTitle, device.name),
            body = stringResource(R.string.devices_signOutBody),
            confirm = stringResource(R.string.devices_signOut),
            onDismiss = { signingOut = null },
        ) {
            signingOut = null
            model.launch {
                model.vault.signOutDevice(device.id)
                model.toast(context.getString(R.string.devices_signedOut, device.name), Toast.Tone.Success)
                devices.retry()
            }
        }
    }
}

fun devicePlatformRes(platform: String) = when (platform) {
    "web" -> R.string.devices_platforms_web
    "extension" -> R.string.devices_platforms_extension
    "ios" -> R.string.devices_platforms_ios
    "android" -> R.string.devices_platforms_android
    "mac" -> R.string.devices_platforms_mac
    "windows" -> R.string.devices_platforms_windows
    "linux" -> R.string.devices_platforms_linux
    "desktop" -> R.string.devices_platforms_desktop
    else -> R.string.devices_platforms_other
}

/** Settings → Account: email, server, storage, sign out and delete. */
@Composable
private fun AccountSection(onDelete: () -> Unit) {
    val model = LocalVault.current.model
    val session by model.session.collectAsState()
    val server = rememberLive(model, session.serverUrl) { session.serverUrl?.let { model.vault.serverInfo(it) } }
    val storage = rememberLive(model) { model.vault.storageUsage() }
    val usage = storage.data
    SettingsSection(stringResource(R.string.settings_account)) {
        SettingsRow(stringResource(R.string.fields_email), session.email)
        SettingsRow(
            stringResource(R.string.settings_server),
            server.data?.let { stringResource(R.string.settings_serverInfo, it.name, session.serverUrl.orEmpty(), it.version) }
                ?: if (server.error != null) stringResource(R.string.settings_serverUnreachable, session.serverUrl.orEmpty()) else session.serverUrl,
        )
        if (usage == null && storage.error != null) SettingsRow(stringResource(R.string.settings_storage), stringResource(R.string.settings_storageFailed))
        if (usage != null) {
            SettingsRow(
                stringResource(R.string.settings_storage),
                "${stringResource(R.string.settings_storageUsed, formatBytes(usage.attachmentBytes.toLong()), formatBytes(usage.maxAttachmentBytes.toLong()))}. ${stringResource(R.string.settings_storageFileLimit, formatBytes(usage.maxFileBytes.toLong()))} ${stringResource(R.string.settings_storageHelp)}",
            ) {
                val share = if (usage.maxAttachmentBytes > 0uL) usage.attachmentBytes.toFloat() / usage.maxAttachmentBytes.toFloat() else 0f
                CircularProgressIndicator(progress = { share }, modifier = Modifier.size(32.dp), color = when { share > 0.9f -> Brand.colors.danger; share > 0.75f -> Brand.colors.warn; else -> Brand.colors.trust }, trackColor = MaterialTheme.colorScheme.outlineVariant)
            }
        }
        SettingsRow(stringResource(R.string.settings_signOut), stringResource(R.string.settings_signOutHelp)) {
            OutlinedButton(onClick = { model.launch { model.vault.signOut() } }, modifier = Modifier.testTag("settings.signOut")) { Text(stringResource(R.string.settings_signOut)) }
        }
        SettingsRow(stringResource(R.string.settings_deleteAccount), stringResource(R.string.settings_deleteAccountHelp)) {
            OutlinedButton(onClick = onDelete, modifier = Modifier.testTag("settings.deleteAccount")) { Text(stringResource(R.string.settings_deleteAccount), color = Brand.colors.dangerText) }
        }
    }
}

/** On the list until AutoFill is on or the user says Not now, remembered on this phone (`AutoFillPrompt`). */
@Composable
fun AutoFillPrompt() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val autofill = remember { AutofillSettings(context) }
    val prefs = remember { context.getSharedPreferences("octapass.ui", android.content.Context.MODE_PRIVATE) }
    var dismissed by remember { mutableStateOf(prefs.getBoolean("autofillPromptDismissed", false)) }
    val enabled = rememberOnResume { autofill.autofillEnabled() }
    val open = rememberLauncherForActivityResult(StartActivityForResult()) { model.inSystemUi = false }
    if (enabled || dismissed) return
    Alert(stringResource(R.string.phone_autoFillPrompt), AlertTone.Info, Modifier.padding(horizontal = 16.dp, vertical = 4.dp).testTag("autofill.prompt")) {
        androidx.compose.foundation.layout.Row {
            androidx.compose.material3.TextButton(onClick = {
                model.inSystemUi = true
                runCatching { open.launch(autofill.requestAutofill()) }.onFailure { model.inSystemUi = false }
            }) { Text(stringResource(R.string.phone_autoFillTurnOn)) }
            androidx.compose.material3.TextButton(onClick = {
                prefs.edit().putBoolean("autofillPromptDismissed", true).apply()
                dismissed = true
            }, modifier = Modifier.testTag("autofill.dismiss")) { Text(stringResource(R.string.phone_autoFillDismiss)) }
        }
    }
}
