package app.octap.android.ui.auth

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.octap.android.model.AppModel
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.model.isLocal
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.AuthLayout
import app.octap.android.ui.components.LinkButton
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.SecondaryButton
import app.octap.android.ui.local.LocalVaultList
import app.octap.android.ui.local.localPasswordError
import app.octap.android.ui.local.rememberLocalVaults
import app.octap.android.ui.util.haptic
import app.octap.resources.R
import app.octap.vault.ErrorCode
import app.octap.vault.UnlockMethods
import kotlinx.coroutines.launch

private enum class Mode { Loading, Device, Password }

/** The phone's lock in the catalog's words: "your fingerprint, face or screen lock". */
@Composable
fun deviceMethodName(): String = stringResource(R.string.unlockOffer_android)

/**
 * The locked vault (`Lock`): nothing at all while "Stay unlocked" can open it (plan 18), otherwise
 * the device prompt straight away when it's on, the master password one tap away. A local vault
 * has nothing to sign out of and no email to reset from; it offers the other vaults here and the
 * first screen instead.
 */
@Composable
fun LockScreen(model: AppModel, onForgotPassword: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val session by model.session.collectAsState()
    var methods by remember { mutableStateOf<UnlockMethods?>(null) }
    var mode by remember { mutableStateOf(Mode.Loading) }
    var prompting by remember { mutableStateOf(false) }
    var deviceError by remember { mutableStateOf<String?>(null) }
    val method = deviceMethodName()
    val local = session.isLocal
    val others = rememberLocalVaults(model).filterNot { it.current }

    fun unlockWithDevice() {
        if (prompting) return
        prompting = true
        deviceError = null
        scope.launch {
            try {
                model.confirmedUnlock { model.vault.unlockWithDevice() }
            } catch (error: Exception) {
                when {
                    error.isCode(ErrorCode.PASSWORD_REQUIRED) -> {
                        methods = methods?.copy(passwordRequired = true)
                        mode = Mode.Password
                    }
                    error.isCode(ErrorCode.DEVICE_UNLOCK_FAILED) -> {
                        methods = methods?.copy(deviceUnlockEnabled = false)
                        deviceError = errorMessage(context, error)
                        mode = Mode.Password
                    }
                    // Cancelling the prompt leaves the button there to try again.
                    error.isCode(ErrorCode.DEVICE_UNLOCK_CANCELLED) -> Unit
                    else -> deviceError = errorMessage(context, error)
                }
            } finally {
                prompting = false
            }
        }
    }

    LaunchedEffect(Unit) {
        // Stay unlocked (plan 18): the vault opens with no prompt and this screen goes away. Only
        // when it can't (Lock now, the 14-day check, no key) does anything below ask.
        if (model.unlockStayingUnlocked()) return@LaunchedEffect
        val next = runCatching { model.vault.unlockMethods() }.getOrNull()
        methods = next
        // The app-open gate is its own per-device switch: off means the master password here. It
        // doesn't apply while the vault stays unlocked.
        val gate = model.settings.value.deviceAuthOnOpen || model.staysUnlocked
        val useDevice = next != null && next.deviceUnlockEnabled && !next.passwordRequired && gate
        mode = if (useDevice) Mode.Device else Mode.Password
        if (useDevice) unlockWithDevice()
    }

    val canUseDevice = methods?.let { it.deviceUnlockEnabled && !it.passwordRequired } == true

    AuthLayout(
        title = stringResource(R.string.lock_title),
        subtitle = if (local) "${session.email.orEmpty()}\n${stringResource(R.string.localVault_lockedSubtitle)}" else session.email,
        footer = {
            if (local) {
                LinkButton(stringResource(R.string.localVault_addVault), { model.launch { model.vault.leaveLocalVault() } }, Modifier.testTag("lock.addVault"))
            } else {
                LinkButton(stringResource(R.string.lock_signOut), { model.launch { model.vault.signOut() } }, Modifier.testTag("lock.signOut"))
            }
        },
    ) {
        when (mode) {
            Mode.Loading -> Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) { CircularProgressIndicator(Modifier.size(28.dp)) }
            Mode.Device -> Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
                val label = stringResource(R.string.lock_unlockWith, method)
                FilledTonalIconButton(
                    onClick = ::unlockWithDevice,
                    enabled = !prompting,
                    shape = CircleShape,
                    colors = IconButtonDefaults.filledTonalIconButtonColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
                    modifier = Modifier.size(88.dp).testTag("lock.device"),
                ) {
                    Icon(Icons.Outlined.Fingerprint, contentDescription = label, modifier = Modifier.size(44.dp), tint = MaterialTheme.colorScheme.primary)
                }
                Text(label, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
                Text(
                    if (prompting) stringResource(R.string.lock_waiting, method) else deviceError.orEmpty(),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                Spacer(Modifier.height(8.dp))
                SecondaryButton(stringResource(R.string.lock_usePassword), { mode = Mode.Password }, modifier = Modifier.testTag("lock.usePassword"))
            }
            Mode.Password -> PasswordForm(
                model = model,
                notice = if (methods?.passwordRequired == true) stringResource(R.string.lock_passwordRequired) else deviceError,
                onUseDevice = if (canUseDevice) ({ mode = Mode.Device }) else null,
                onForgot = if (local) null else onForgotPassword,
                method = method,
            )
        }
        if (others.isNotEmpty()) LocalVaultList(model, others, stringResource(R.string.localVault_switchVault))
    }
}

@Composable
private fun PasswordForm(model: AppModel, notice: String?, onUseDevice: (() -> Unit)?, onForgot: (() -> Unit)?, method: String) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun submit() {
        if (busy) return
        if (password.isEmpty()) {
            error = context.getString(R.string.validation_passwordRequired)
            return
        }
        busy = true
        error = null
        scope.launch {
            try {
                model.confirmedUnlock { model.vault.unlock(password) }
            } catch (e: Exception) {
                error = if (model.isLocal) localPasswordError(context, e) else errorMessage(context, e)
                password = ""
                haptic(context, Toast.Tone.Danger)
            } finally {
                busy = false
            }
        }
    }

    notice?.let { Alert(it, AlertTone.Info) }
    PasswordField(
        value = password,
        onValueChange = { password = it },
        label = stringResource(R.string.fields_masterPassword),
        error = error,
        onImeAction = ::submit,
        modifier = Modifier.testTag("lock.password"),
    )
    PrimaryButton(stringResource(R.string.lock_unlock), ::submit, busy = busy, icon = Icons.Outlined.Lock, modifier = Modifier.testTag("lock.unlock"))
    if (onUseDevice != null) {
        LinkButton(stringResource(R.string.lock_unlockWith, method), onUseDevice, Modifier.fillMaxWidth().testTag("lock.useDevice"))
    }
    if (onForgot != null) {
        LinkButton(stringResource(R.string.signIn_forgotPassword), onForgot, Modifier.fillMaxWidth().testTag("lock.forgotPassword"))
    }
}

/**
 * Right after sign-in or sign-up (`DeviceUnlockOffer`): "Use your fingerprint, face or screen lock
 * to unlock Octa Pass?". Not now asks once more at a later unlock, then never again.
 */
@Composable
fun DeviceUnlockOffer(model: AppModel) {
    val session by model.session.collectAsState()
    // A local vault's name can change, and two can share one.
    val account = (if (session.isLocal) session.serverUrl else session.email) ?: return
    val prefs = remember { model.app.getSharedPreferences("octapass.ui", android.content.Context.MODE_PRIVATE) }
    val key = "deviceUnlockOffer:$account"
    var offer by remember(account) { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    val method = deviceMethodName()
    val context = LocalContext.current

    LaunchedEffect(account) {
        val state = prefs.getString(key, null)
        // Once per unlock: a recreated window (a language change) isn't another unlock.
        if (state == "done" || !model.offeredDeviceUnlock.add(account)) return@LaunchedEffect
        val methods = runCatching { model.vault.unlockMethods() }.getOrNull() ?: return@LaunchedEffect
        if (!methods.deviceUnlockSupported || methods.deviceUnlockEnabled) return@LaunchedEffect
        // The reminder is the last time.
        if (state == "declined") prefs.edit().putString(key, "done").apply()
        offer = true
    }
    if (!offer) return

    fun notNow() {
        if (prefs.getString(key, null) != "done") prefs.edit().putString(key, "declined").apply()
        offer = false
    }

    AlertDialog(
        onDismissRequest = { if (!busy) notNow() },
        title = { Text(stringResource(R.string.unlockOffer_title, method)) },
        text = { Text(stringResource(R.string.unlockOffer_body, method)) },
        dismissButton = { TextButton(onClick = ::notNow, enabled = !busy, modifier = Modifier.testTag("offer.notNow")) { Text(stringResource(R.string.unlockOffer_notNow)) } },
        confirmButton = {
            TextButton(
                enabled = !busy,
                modifier = Modifier.testTag("offer.turnOn"),
                onClick = {
                    busy = true
                    model.scope.launch {
                        try {
                            model.vault.enableDeviceUnlock()
                            prefs.edit().putString(key, "done").apply()
                            offer = false
                            model.toast(context.getString(R.string.unlockOffer_enabled, method), Toast.Tone.Success)
                        } catch (error: Exception) {
                            if (error.isCode(ErrorCode.DEVICE_UNLOCK_CANCELLED)) notNow() else model.toastError(error)
                        } finally {
                            busy = false
                        }
                    }
                },
            ) { Text(stringResource(R.string.unlockOffer_turnOn)) }
        },
        modifier = Modifier.padding(8.dp),
    )
}
