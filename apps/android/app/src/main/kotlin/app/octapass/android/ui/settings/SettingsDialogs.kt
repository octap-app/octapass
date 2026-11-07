package app.octap.android.ui.settings

import android.content.ActivityNotFoundException
import android.content.Context
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Mail
import androidx.compose.material.icons.outlined.Smartphone
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import app.octap.android.autofill.CredentialTransfer
import app.octap.android.model.AppModel
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.platform.Files
import app.octap.android.ui.auth.normalizeEmail
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.QrImage
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.theme.monoStyle
import app.octap.android.ui.tools.SettingsRow
import app.octap.android.ui.tools.SettingsSection
import app.octap.android.ui.tools.VaultPage
import app.octap.android.ui.util.formatDate
import app.octap.android.ui.util.rememberLive
import app.octap.android.ui.vault.LocalVault
import app.octap.android.ui.vault.categoryRes
import app.octap.android.ui.vault.copy
import app.octap.android.ui.vault.typeOf
import app.octap.resources.R
import app.octap.vault.ErrorCode
import app.octap.vault.ExportFormat
import app.octap.vault.ReceivedPreview
import app.octap.vault.SecurityEvent
import app.octap.vault.SecurityKeyInfo
import app.octap.vault.TotpSetup
import app.octap.vault.TwoStepStatus
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Networks already offered and the ones the user said never to (`loadOffers`). Device-only, like settings. */
data class WifiOffers(val asked: List<String> = emptyList(), val never: List<String> = emptyList()) {
    companion object {
        private const val KEY = "wifiOffers"

        private fun prefs(context: Context) = context.getSharedPreferences("octapass.ui", Context.MODE_PRIVATE)

        fun load(context: Context): WifiOffers {
            val json = prefs(context).getString(KEY, null)?.let { runCatching { JSONObject(it) }.getOrNull() } ?: return WifiOffers()
            fun list(name: String) = json.optJSONArray(name)?.let { array -> (0 until array.length()).map { array.getString(it) } }.orEmpty()
            return WifiOffers(list("asked"), list("never"))
        }

        fun save(context: Context, offers: WifiOffers) {
            prefs(context).edit().putString(KEY, JSONObject().put("asked", JSONArray(offers.asked)).put("never", JSONArray(offers.never)).toString()).apply()
        }
    }
}

@Composable
fun Confirm(title: String, body: String, confirm: String, danger: Boolean = true, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(body) },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = {
            TextButton(onClick = onConfirm, modifier = Modifier.testTag("confirm.ok")) { Text(confirm, color = if (danger) Brand.colors.dangerText else MaterialTheme.colorScheme.primary) }
        },
    )
}

@Composable
fun TextPrompt(title: String, label: String, initial: String, confirm: String, onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var value by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Field(value, { value = it.take(64) }, label, modifier = Modifier.testTag("prompt.value")) },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = { TextButton(onClick = { onConfirm(value) }, enabled = value.isNotBlank(), modifier = Modifier.testTag("prompt.ok")) { Text(confirm) } },
    )
}

/** Hands a file the vault wrote (an export) to the share sheet, and deletes it when the sheet closes. */
@Composable
fun rememberShareFile(model: AppModel): (path: String, type: String) -> Unit {
    val context = LocalContext.current
    val files = remember { Files(context) }
    var shared by remember { mutableStateOf<File?>(null) }
    val sheet = rememberLauncherForActivityResult(StartActivityForResult()) {
        model.inSystemUi = false
        shared?.delete()
        shared = null
    }
    return { path, type ->
        val file = File(path)
        shared = file
        model.inSystemUi = true
        try {
            sheet.launch(files.shareIntent(file, file.name, type))
        } catch (error: ActivityNotFoundException) {
            model.inSystemUi = false
            file.delete()
            model.toast(R.string.errors_noFileViewer, Toast.Tone.Danger)
        }
    }
}

/** The encrypted export's password: anyone with the file can try guesses offline. */
const val MIN_EXPORT_PASSWORD = 10

private val FORMATS = listOf(
    Triple(ExportFormat.ENCRYPTED, R.string.export_formatEncrypted, R.string.export_encryptedHelp),
    Triple(ExportFormat.JSON, R.string.settings_formatJson, R.string.settings_jsonHelp),
    Triple(ExportFormat.CSV, R.string.settings_formatCsv, R.string.settings_csvHelp),
    Triple(ExportFormat.CXF, R.string.export_formatCxf, R.string.export_cxfHelp),
)

/** Settings → Export (`ExportDialog`): a format, the master password, and for the encrypted export a password for the file. */
@Composable
fun ExportDialog(onClose: () -> Unit) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val share = rememberShareFile(model)
    var format by remember { mutableStateOf(ExportFormat.ENCRYPTED) }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val encrypted = format == ExportFormat.ENCRYPTED

    fun submit() {
        error = when {
            encrypted && password.length < MIN_EXPORT_PASSWORD -> context.resources.getQuantityString(R.plurals.export_passwordTooShort, MIN_EXPORT_PASSWORD, MIN_EXPORT_PASSWORD)
            encrypted && password != confirm -> context.getString(R.string.export_passwordMismatch)
            else -> null
        }
        if (error != null) return
        scope.launch {
            // The device lock, or the master password without one (plan 03).
            if (!model.confirmIdentity()) return@launch
            busy = true
            try {
                val path = model.vault.exportVault(format, if (encrypted) password else null, null)
                share(path, if (format == ExportFormat.CSV) "text/csv" else "application/json")
                onClose()
            } catch (e: Exception) {
                error = errorMessage(context, e)
            } finally {
                busy = false
            }
        }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        title = { Text(stringResource(R.string.settings_exportTitle)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                for ((value, label, _) in FORMATS) {
                    Row(Modifier.fillMaxWidth().toggleable(format == value, role = Role.RadioButton) { format = value }.testTag("export.${value.name.lowercase()}"), verticalAlignment = Alignment.CenterVertically) {
                        androidx.compose.material3.RadioButton(format == value, null)
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(label))
                    }
                }
                Text(stringResource(FORMATS.first { it.first == format }.third), style = MaterialTheme.typography.bodySmall)
                if (encrypted) {
                    PasswordField(password, { password = it }, stringResource(R.string.export_password), contentType = null, modifier = Modifier.testTag("export.password"))
                    PasswordField(confirm, { confirm = it }, stringResource(R.string.export_confirmPassword), contentType = null, modifier = Modifier.testTag("export.confirm"))
                    Alert(stringResource(R.string.export_encryptedNote), AlertTone.Info)
                } else {
                    Alert(stringResource(R.string.settings_exportWarning), AlertTone.Warn)
                }
                error?.let { Alert(it) }
            }
        },
        dismissButton = { TextButton(onClick = onClose, enabled = !busy) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = {
            TextButton(onClick = ::submit, enabled = !busy, modifier = Modifier.testTag("export.go")) {
                if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) else Text(stringResource(R.string.settings_exportAction))
            }
        },
    )
}

/**
 * Settings → Account → Delete account (`DeleteAccount`, plan 11): what goes, an export first, then
 * the account email and a fresh master password check.
 */
@Composable
fun DeleteAccountDialog(onClose: () -> Unit) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val share = rememberShareFile(model)
    val summary = rememberLive(model) { model.vault.accountSummary() }
    var confirming by remember { mutableStateOf(false) }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val account = summary.data
    val matches = account != null && normalizeEmail(email) == account.email

    fun exportFirst(format: ExportFormat) = scope.launch {
        if (!model.confirmIdentity()) return@launch
        runCatching { model.vault.exportVault(format, null, null) }.onSuccess { share(it, if (format == ExportFormat.CSV) "text/csv" else "application/json") }.onFailure(model::toastError)
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        title = { Text(stringResource(R.string.deleteAccount_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                when {
                    account == null -> summary.error?.let { Alert(errorMessage(context, it)) } ?: CircularProgressIndicator(Modifier.size(24.dp))
                    !confirming -> {
                        Text(stringResource(R.string.deleteAccount_intro))
                        Fact(Icons.Outlined.Key, "${pluralStringResource(R.plurals.deleteAccount_items, account.itemCount.toInt(), account.itemCount.toInt())} ${pluralStringResource(R.plurals.deleteAccount_vaults, account.vaultCount.toInt(), account.vaultCount.toInt())}")
                        Fact(Icons.Outlined.Smartphone, pluralStringResource(R.plurals.deleteAccount_devices, account.deviceCount.toInt(), account.deviceCount.toInt()))
                        Fact(Icons.Outlined.Mail, stringResource(R.string.deleteAccount_emailFreed, account.email))
                        if (account.sharedVaultsOwned.isNotEmpty()) {
                            Alert(pluralStringResource(R.plurals.deleteAccount_sharedVaults, account.sharedVaultsOwned.size, account.sharedVaultsOwned.joinToString(", ")), AlertTone.Warn)
                        }
                        Alert(stringResource(R.string.deleteAccount_permanent))
                        Text(stringResource(R.string.deleteAccount_exportFirst), style = MaterialTheme.typography.bodySmall)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = { exportFirst(ExportFormat.JSON) }) { Text(stringResource(R.string.settings_formatJson)) }
                            OutlinedButton(onClick = { exportFirst(ExportFormat.CSV) }) { Text(stringResource(R.string.settings_formatCsv)) }
                        }
                    }
                    else -> {
                        Text(stringResource(R.string.deleteAccount_confirmIntro))
                        error?.let { Alert(it) }
                        Field(
                            email,
                            { email = it },
                            stringResource(R.string.deleteAccount_typeEmail, account.email),
                            keyboardType = KeyboardType.Email,
                            error = if (email.isNotEmpty() && !matches && normalizeEmail(email).length >= account.email.length) stringResource(R.string.errors_emailMismatch) else null,
                            modifier = Modifier.testTag("delete.email"),
                        )
                        PasswordField(password, { password = it }, stringResource(R.string.fields_masterPassword), modifier = Modifier.testTag("delete.password"))
                    }
                }
            }
        },
        dismissButton = {
            TextButton(onClick = { if (confirming) confirming = false else onClose() }, enabled = !busy) {
                Text(stringResource(if (confirming) R.string.common_back else R.string.deleteAccount_keep))
            }
        },
        confirmButton = {
            if (!confirming) {
                TextButton(onClick = { confirming = true }, enabled = account != null, modifier = Modifier.testTag("delete.continue")) { Text(stringResource(R.string.deleteAccount_continue)) }
            } else {
                TextButton(
                    enabled = matches && password.isNotEmpty() && !busy,
                    modifier = Modifier.testTag("delete.confirm"),
                    onClick = {
                        busy = true
                        error = null
                        scope.launch {
                            try {
                                model.vault.deleteAccount(email, password)
                                // Signed out: the goodbye, then the start, as on the web.
                                model.accountDeleted.value = true
                                context.getSharedPreferences("octapass.ui", Context.MODE_PRIVATE).edit().clear().apply()
                            } catch (e: Exception) {
                                error = errorMessage(context, e)
                                password = ""
                                busy = false
                            }
                        }
                    },
                ) {
                    Icon(Icons.Outlined.Delete, null, Modifier.size(18.dp), tint = Brand.colors.dangerText)
                    Text(stringResource(R.string.deleteAccount_confirm), color = Brand.colors.dangerText, modifier = Modifier.padding(start = 6.dp))
                }
            }
        },
    )
}

@Composable
private fun Fact(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Icon(icon, null, Modifier.size(18.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}

private enum class TwoStepFlow { ENABLE, CHANGE, REMOVE_KEY, RENEW, DISABLE }

/** Settings → Two-step sign-in (`TwoStepSection`): on with an authenticator app, recovery codes, off again. */
@Composable
fun TwoStepSection() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val status = rememberLive(model) { model.vault.twoStepStatus() }
    var flow by remember { mutableStateOf<TwoStepFlow?>(null) }
    var removing by remember { mutableStateOf<SecurityKeyInfo?>(null) }
    SettingsSection(stringResource(R.string.settings_twoStep), stringResource(R.string.settings_twoStepHelp), tag = "settings.twoStep") {
        val current: TwoStepStatus? = status.data
        when {
            current == null -> status.error?.let { Text(errorMessage(context, it), Modifier.padding(16.dp)) } ?: CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
            !current.enabled -> SettingsRow(stringResource(R.string.twoStepSettings_status), stringResource(R.string.twoStepSettings_off)) {
                OutlinedButton(onClick = { flow = TwoStepFlow.ENABLE }, modifier = Modifier.testTag("twoStep.turnOn")) { Text(stringResource(R.string.twoStepSettings_turnOn)) }
            }
            else -> {
                SettingsRow(stringResource(R.string.twoStepSettings_authenticator), stringResource(R.string.twoStepSettings_authenticatorOn)) {
                    OutlinedButton(onClick = { flow = TwoStepFlow.CHANGE }) { Text(stringResource(R.string.twoStepSettings_change)) }
                }
                // Security keys need the web vault's relying party, which the phone apps don't have yet.
                SettingsRow(stringResource(R.string.twoStepSettings_securityKeys), stringResource(R.string.twoStepSettings_securityKeysUnsupported))
                for (key in current.securityKeys) {
                    SettingsRow(key.name, listOfNotNull(stringResource(R.string.twoStepSettings_keyAdded, formatDate(key.createdAt)), key.lastUsedAt?.let { stringResource(R.string.twoStepSettings_keyUsed, formatDate(it)) }).joinToString(" · ")) {
                        TextButton(onClick = { removing = key; flow = TwoStepFlow.REMOVE_KEY }) { Text(stringResource(R.string.common_remove)) }
                    }
                }
                SettingsRow(stringResource(R.string.twoStepSettings_recoveryCodes), pluralStringResource(R.plurals.twoStepSettings_recoveryCodesLeft, current.recoveryCodesLeft.toInt(), current.recoveryCodesLeft.toInt())) {
                    OutlinedButton(onClick = { flow = TwoStepFlow.RENEW }) { Text(stringResource(R.string.twoStepSettings_newCodes)) }
                }
                SettingsRow(stringResource(R.string.twoStepSettings_otherDevices), stringResource(R.string.twoStepSettings_otherDevicesHelp)) {
                    OutlinedButton(onClick = {
                        model.launch {
                            model.vault.forgetTrustedDevices()
                            model.toast(context.getString(R.string.twoStepSettings_devicesForgotten), Toast.Tone.Success)
                        }
                    }) { Text(stringResource(R.string.twoStepSettings_forgetDevices)) }
                }
                SettingsRow(stringResource(R.string.twoStepSettings_turnOff), stringResource(R.string.twoStepSettings_turnOffHelp)) {
                    OutlinedButton(onClick = { flow = TwoStepFlow.DISABLE }, modifier = Modifier.testTag("twoStep.turnOff")) { Text(stringResource(R.string.twoStepSettings_turnOff), color = Brand.colors.dangerText) }
                }
            }
        }
    }
    flow?.let { current -> TwoStepDialog(current, removing, onClose = { flow = null; removing = null }, onChanged = status::retry) }
}

@Composable
private fun TwoStepDialog(flow: TwoStepFlow, key: SecurityKeyInfo?, onClose: () -> Unit, onChanged: () -> Unit) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var step by remember { mutableStateOf("password") }
    var password by remember { mutableStateOf("") }
    var setup by remember { mutableStateOf<TotpSetup?>(null) }
    var code by remember { mutableStateOf("") }
    var codes by remember { mutableStateOf<List<String>>(emptyList()) }
    var saved by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val titles = mapOf(
        TwoStepFlow.ENABLE to R.string.twoStepSettings_titles_enable,
        TwoStepFlow.CHANGE to R.string.twoStepSettings_titles_change,
        TwoStepFlow.REMOVE_KEY to R.string.twoStepSettings_titles_removeKey,
        TwoStepFlow.RENEW to R.string.twoStepSettings_titles_renew,
        TwoStepFlow.DISABLE to R.string.twoStepSettings_titles_disable,
    )
    val intros = mapOf(
        TwoStepFlow.ENABLE to R.string.twoStepSettings_passwordIntro_enable,
        TwoStepFlow.CHANGE to R.string.twoStepSettings_passwordIntro_change,
        TwoStepFlow.REMOVE_KEY to R.string.twoStepSettings_passwordIntro_removeKey,
        TwoStepFlow.RENEW to R.string.twoStepSettings_passwordIntro_renew,
        TwoStepFlow.DISABLE to R.string.twoStepSettings_passwordIntro_disable,
    )

    fun finished(message: String) {
        model.toast(message, Toast.Tone.Success)
        onChanged()
        onClose()
    }

    fun run(action: suspend () -> Unit) {
        busy = true
        error = null
        scope.launch {
            try {
                action()
            } catch (e: Exception) {
                when {
                    e.isCode(ErrorCode.INVALID_TWO_STEP_CODE) -> {
                        error = errorMessage(context, e)
                        code = ""
                    }
                    e.isCode(ErrorCode.TWO_STEP_EXPIRED) -> {
                        step = "password"
                        error = context.getString(R.string.twoStepSettings_setupExpired)
                    }
                    else -> error = errorMessage(context, e)
                }
            } finally {
                password = ""
                busy = false
            }
        }
    }

    fun submitPassword() {
        if (password.isEmpty()) {
            error = context.getString(R.string.validation_passwordRequired)
            return
        }
        val typed = password
        run {
            when (flow) {
                TwoStepFlow.ENABLE, TwoStepFlow.CHANGE -> {
                    setup = model.vault.startTotpSetup(typed)
                    step = "scan"
                }
                TwoStepFlow.RENEW -> {
                    codes = model.vault.renewRecoveryCodes(typed)
                    step = "codes"
                    onChanged()
                }
                TwoStepFlow.REMOVE_KEY -> {
                    model.vault.removeSecurityKey(key!!.id, typed)
                    finished(context.getString(R.string.twoStepSettings_keyRemoved, key.name))
                }
                TwoStepFlow.DISABLE -> {
                    model.vault.disableTwoStep(typed)
                    finished(context.getString(R.string.twoStepSettings_turnedOff))
                }
            }
        }
    }

    fun confirmCode() {
        val typed = code.replace(" ", "")
        if (!Regex("^\\d{6}$").matches(typed)) {
            error = context.getString(R.string.twoStep_codeRequired)
            return
        }
        run {
            val recovery = model.vault.confirmTotpSetup(typed)
            if (recovery != null) {
                onChanged()
                codes = recovery
                step = "codes"
            } else {
                finished(context.getString(R.string.twoStepSettings_changed))
            }
        }
    }

    // Recovery codes are shown once: closing waits until they're saved.
    val closable = !busy && (step != "codes" || saved)
    val codesWhat = stringResource(R.string.twoStepSettings_codesLabel)
    val keyWhat = stringResource(R.string.twoStepSettings_setupKey)
    AlertDialog(
        onDismissRequest = { if (closable) onClose() },
        title = { Text(stringResource(titles.getValue(flow))) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                when (step) {
                    "password" -> {
                        Text(stringResource(intros.getValue(flow), key?.name.orEmpty()))
                        error?.let { Alert(it) }
                        PasswordField(password, { password = it }, stringResource(R.string.fields_masterPassword), onImeAction = ::submitPassword, modifier = Modifier.testTag("twoStepSettings.password"))
                    }
                    "scan" -> setup?.let { current ->
                        Text(stringResource(R.string.twoStepSettings_scan))
                        QrImage(current.otpauthUri, 176.dp, stringResource(R.string.twoStepSettings_qrLabel), Modifier.align(Alignment.CenterHorizontally))
                        Text(stringResource(R.string.twoStepSettings_typeInstead), style = MaterialTheme.typography.bodySmall)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(current.secret.chunked(4).joinToString(" "), style = monoStyle.copy(textDirection = TextDirection.Ltr), modifier = Modifier.weight(1f).testTag("twoStepSettings.secret"))
                            androidx.compose.material3.IconButton(onClick = { copy(model, current.secret, keyWhat, secret = true) }) { Icon(Icons.Outlined.ContentCopy, stringResource(R.string.copy_action, keyWhat)) }
                        }
                        Text(stringResource(R.string.twoStepSettings_confirmCode))
                        error?.let { Alert(it) }
                        Field(code, { code = it.filter { c -> c.isDigit() || c == ' ' }.take(7) }, stringResource(R.string.twoStep_codeLabel), mono = true, keyboardType = KeyboardType.NumberPassword, onImeAction = ::confirmCode, modifier = Modifier.testTag("twoStepSettings.code"))
                    }
                    else -> {
                        Text(stringResource(R.string.twoStepSettings_saveCodes))
                        OutlinedCard(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(12.dp).testTag("twoStepSettings.codes")) { for (c in codes) Text(c, style = monoStyle.copy(textDirection = TextDirection.Ltr)) }
                        }
                        TextButton(onClick = { copy(model, codes.joinToString("\n"), codesWhat, secret = true) }) { Text(stringResource(R.string.twoStepSettings_copyCodes)) }
                        Row(Modifier.toggleable(saved, role = Role.Checkbox) { saved = it }.testTag("twoStepSettings.saved"), verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(saved, null)
                            Text(stringResource(R.string.twoStepSettings_saved))
                        }
                    }
                }
            }
        },
        dismissButton = { if (step != "codes") TextButton(onClick = onClose, enabled = !busy) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = {
            val danger = flow == TwoStepFlow.DISABLE || flow == TwoStepFlow.REMOVE_KEY
            when (step) {
                "password" -> TextButton(onClick = ::submitPassword, enabled = !busy, modifier = Modifier.testTag("twoStepSettings.continue")) {
                    Text(
                        stringResource(
                            when (flow) {
                                TwoStepFlow.REMOVE_KEY -> R.string.common_remove
                                TwoStepFlow.RENEW -> R.string.twoStepSettings_newCodes
                                TwoStepFlow.DISABLE -> R.string.twoStepSettings_turnOff
                                else -> R.string.twoStepSettings_continue
                            },
                        ),
                        color = if (danger) Brand.colors.dangerText else MaterialTheme.colorScheme.primary,
                    )
                }
                "scan" -> TextButton(onClick = ::confirmCode, enabled = !busy, modifier = Modifier.testTag("twoStepSettings.confirm")) {
                    Text(stringResource(if (flow == TwoStepFlow.ENABLE) R.string.twoStepSettings_confirm else R.string.twoStepSettings_confirmChange))
                }
                else -> TextButton(
                    onClick = {
                        if (flow == TwoStepFlow.ENABLE) model.toast(context.getString(R.string.twoStepSettings_turnedOn), Toast.Tone.Success)
                        onClose()
                    },
                    enabled = saved,
                    modifier = Modifier.testTag("twoStepSettings.done"),
                ) { Text(stringResource(R.string.twoStepSettings_done)) }
            }
        },
    )
}

/** In the order the item list shows them. */
private val RECEIVED_ORDER = listOf("login", "password", "wifi", "card", "identity", "secureNote", "sshKey", "document", "environment")

/**
 * Settings → Other password managers (`TransferSection`, Android): imports from another app on the
 * phone through Credential Manager, after a look at what it sent; exporting starts in the other app.
 */
@Composable
fun TransferSection() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    if (!remember { CredentialTransfer.available(context) }) return
    var busy by remember { mutableStateOf(false) }
    var preview by remember { mutableStateOf<ReceivedPreview?>(null) }
    val activity = context as? android.app.Activity ?: (context as? android.content.ContextWrapper)?.baseContext as? android.app.Activity

    fun receive() {
        val host = activity ?: return
        busy = true
        model.inSystemUi = true
        CredentialTransfer.receive(host) { result ->
            model.inSystemUi = false
            result.fold(
                { received ->
                    if (received == null) {
                        busy = false
                        return@fold
                    }
                    scope.launch {
                        try {
                            val next = model.vault.previewReceived(received.json, received.from)
                            if (next.items.isEmpty() && next.codes == 0u) {
                                model.vault.discardReceived()
                                model.toast(context.getString(R.string.phone_receivedNothing, next.from), Toast.Tone.Danger)
                            } else {
                                preview = next
                            }
                        } catch (error: Exception) {
                            model.toastError(error)
                        } finally {
                            busy = false
                        }
                    }
                },
                { error ->
                    busy = false
                    model.toast(error.message ?: context.getString(R.string.phone_native_unexpected), Toast.Tone.Danger)
                },
            )
        }
    }

    SettingsSection(stringResource(R.string.phone_transfer), stringResource(R.string.phone_transferHelp), tag = "settings.transfer") {
        SettingsRow(stringResource(R.string.phone_transferImport), stringResource(R.string.phone_transferImportHelp)) {
            OutlinedButton(onClick = ::receive, enabled = !busy) { Text(stringResource(R.string.phone_transferImportAction)) }
        }
        SettingsRow(stringResource(R.string.phone_transferExport), stringResource(R.string.phone_transferExportHelp))
    }
    preview?.let { received ->
        AlertDialog(
            onDismissRequest = {
                if (!busy) {
                    model.vault.discardReceived()
                    preview = null
                }
            },
            title = { Text(stringResource(R.string.phone_receivedTitle, received.from)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(stringResource(R.string.phone_receivedBody))
                    for (type in RECEIVED_ORDER) {
                        val count = received.items.firstOrNull { it.itemType == type }?.count ?: continue
                        Row { Text(typeOf(type)?.let { stringResource(categoryRes(it)) } ?: type, Modifier.weight(1f)); Text(count.toString()) }
                    }
                    if (received.passkeys > 0u) Row { Text(stringResource(R.string.categories_passkeys), Modifier.weight(1f)); Text(received.passkeys.toString()) }
                    if (received.updated > 0u || received.unchanged > 0u) Text(stringResource(R.string.phone_receivedAgain, received.updated.toString(), received.unchanged.toString()), style = MaterialTheme.typography.bodySmall)
                    if (received.codes > 0u) Text(pluralStringResource(R.plurals.phone_receivedCodes, received.codes.toInt(), received.codes.toInt()), style = MaterialTheme.typography.bodySmall)
                    if (received.skipped > 0u) Text(pluralStringResource(R.plurals.phone_receivedSkipped, received.skipped.toInt(), received.skipped.toInt()), style = MaterialTheme.typography.bodySmall)
                    for (warning in received.warnings) Text(warning, style = MaterialTheme.typography.bodySmall)
                }
            },
            dismissButton = {
                TextButton(onClick = { model.vault.discardReceived(); preview = null }, enabled = !busy) { Text(stringResource(R.string.phone_receivedCancel)) }
            },
            confirmButton = {
                TextButton(enabled = !busy, onClick = {
                    busy = true
                    scope.launch {
                        try {
                            val result = model.vault.importReceived()
                            model.toast(importSummaryText(context, result), Toast.Tone.Success)
                            preview = null
                        } catch (error: Exception) {
                            model.toastError(error)
                        } finally {
                            busy = false
                        }
                    }
                }) { Text(stringResource(R.string.phone_receivedImport)) }
            },
        )
    }
}

/** Settings → Security log (`SecurityLogPage`): the account's own events, newest first. */
@Composable
fun SecurityLogScreen() {
    val model = LocalVault.current.model
    val events = rememberLive(model, sharing = true) { model.vault.securityLog() }
    VaultPage(stringResource(R.string.securityLog_title), stringResource(R.string.securityLog_subtitle), tag = "securityLog.title") {
        val list = events.data
        OutlinedCard(Modifier.fillMaxWidth()) {
            when {
                list == null -> CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
                list.isEmpty() -> Text(stringResource(R.string.securityLog_empty), Modifier.padding(16.dp))
                else -> Column {
                    for (event in list) {
                        val id = securityEventRes(event.eventType)
                        // An export names the device; the others the other account.
                        val who = if (event.eventType == "vault-exported") event.deviceName ?: stringResource(R.string.securityLog_unknownDevice)
                        else event.otherAccountEmail ?: stringResource(R.string.securityLog_someone)
                        val details = exportDetailsRes(event)?.let { stringResource(it) }
                        SettingsRow(if (id != 0) stringResource(id, who) else event.eventType, listOfNotNull(details, formatDate(event.createdAt, long = true)).joinToString(" · "))
                    }
                }
            }
        }
    }
}

private fun securityEventRes(type: String) = when (type) {
    "emergency-contact-added" -> R.string.securityLog_events_emergency_contact_added
    "emergency-contact-removed" -> R.string.securityLog_events_emergency_contact_removed
    "emergency-access-requested" -> R.string.securityLog_events_emergency_access_requested
    "emergency-access-denied" -> R.string.securityLog_events_emergency_access_denied
    "emergency-access-approved" -> R.string.securityLog_events_emergency_access_approved
    "emergency-access-released" -> R.string.securityLog_events_emergency_access_released
    "two-step-enabled" -> R.string.securityLog_events_two_step_enabled
    "two-step-disabled" -> R.string.securityLog_events_two_step_disabled
    "authenticator-changed" -> R.string.securityLog_events_authenticator_changed
    "security-key-added" -> R.string.securityLog_events_security_key_added
    "security-key-removed" -> R.string.securityLog_events_security_key_removed
    "recovery-codes-renewed" -> R.string.securityLog_events_recovery_codes_renewed
    "recovery-code-used" -> R.string.securityLog_events_recovery_code_used
    "two-step-locked" -> R.string.securityLog_events_two_step_locked
    "trusted-devices-forgotten" -> R.string.securityLog_events_trusted_devices_forgotten
    "vault-exported" -> R.string.securityLog_events_vault_exported
    "password-changed" -> R.string.securityLog_events_password_changed
    "password-reset" -> R.string.securityLog_events_password_reset
    "secret-key-rotated" -> R.string.securityLog_events_secret_key_rotated
    "vault-key-rotated" -> R.string.securityLog_events_vault_key_rotated
    "emergency-takeover" -> R.string.securityLog_events_emergency_takeover
    "organiser-recovery-enabled" -> R.string.securityLog_events_organiser_recovery_enabled
    "organiser-recovery-disabled" -> R.string.securityLog_events_organiser_recovery_disabled
    else -> 0
}

/** An export's format, and whether the file held the attachments. */
private fun exportDetailsRes(event: SecurityEvent) = when (event.exportFormat) {
    ExportFormat.JSON -> R.string.securityLog_exportDetails_json
    ExportFormat.CSV -> R.string.securityLog_exportDetails_csv
    ExportFormat.CXF -> R.string.securityLog_exportDetails_cxf
    ExportFormat.ENCRYPTED -> if (event.exportAttachments == true) R.string.securityLog_exportDetails_encryptedFiles else R.string.securityLog_exportDetails_encrypted
    null -> null
}
