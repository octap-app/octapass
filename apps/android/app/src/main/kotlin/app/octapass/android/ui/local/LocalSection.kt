package app.octap.android.ui.local

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.octap.android.model.AppModel
import app.octap.android.model.LocalFlow
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.settings.TextPrompt
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.tools.SettingsRow
import app.octap.android.ui.tools.SettingsSection
import app.octap.android.ui.util.formatDate
import app.octap.android.ui.vault.LocalVault
import app.octap.resources.R
import app.octap.vault.ErrorCode
import app.octap.vault.UnlockMethods
import kotlinx.coroutines.launch

/** A wrong master password, in words for a vault that has no email or Secret Key. */
fun localPasswordError(context: Context, error: Throwable): String =
    if (error.isCode(ErrorCode.INVALID_CREDENTIALS)) context.getString(R.string.identityGate_wrongPassword) else errorMessage(context, error)

/** Settings for a vault on this device only (`LocalSection`): backups, its recovery code, Turn on sync, other vaults. */
@Composable
fun LocalSection() {
    val context = LocalContext.current
    val model = LocalVault.current.model
    val session by model.session.collectAsState()
    val vaults = rememberLocalVaults(model)
    val current = vaults.firstOrNull { it.current }
    val others = vaults.filterNot { it.current }
    val backups = rememberBackupActions(model)
    var code by remember { mutableStateOf<String?>(null) }
    var renaming by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf(false) }
    // What waits for "Confirm it's you".
    var gated by remember { mutableStateOf<(() -> Unit)?>(null) }
    val folder = current?.backupFolderName
    val name = session.email.orEmpty()

    SettingsSection(stringResource(R.string.localVault_sectionTitle), stringResource(R.string.localVault_sectionHelp), tag = "settings.local") {
        SettingsRow(stringResource(R.string.localVault_nameLabel), name) {
            OutlinedButton(onClick = { renaming = true }, modifier = Modifier.testTag("local.rename")) { Text(stringResource(R.string.localVault_rename)) }
        }
        val lastBackup = current?.lastBackupAt
        SettingsRow(
            stringResource(R.string.localVault_backUp),
            if (lastBackup != null) stringResource(R.string.localVault_lastBackup, formatDate(lastBackup)) else stringResource(R.string.localVault_neverBackedUp),
        ) {
            OutlinedButton(onClick = { gated = backups.save }, enabled = !backups.busy, modifier = Modifier.testTag("local.backUp")) {
                Text(stringResource(R.string.localVault_backUp))
            }
        }
        SettingsRow(
            stringResource(R.string.localVault_folder),
            if (folder != null) stringResource(R.string.localVault_folderOn, folder) else stringResource(R.string.localVault_folderOff),
        )
        Row(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = backups.chooseFolder, enabled = !backups.busy, modifier = Modifier.testTag("local.chooseFolder")) {
                Text(stringResource(if (folder != null) R.string.localVault_changeFolder else R.string.localVault_chooseFolder))
            }
            if (folder != null) {
                TextButton(
                    onClick = {
                        model.launch {
                            val before = model.vault.localVaults().firstOrNull { it.current }?.backupFolder
                            model.vault.setBackupFolder(null, null)
                            before?.let { releaseFolder(context, it) }
                            model.localChanged()
                        }
                    },
                    modifier = Modifier.testTag("local.stopFolder"),
                ) { Text(stringResource(R.string.localVault_stopFolder)) }
            }
        }
        val what = stringResource(R.string.localVault_recoveryCode)
        val shown = code
        SettingsRow(what, if (shown == null) stringResource(R.string.localVault_showCodeHelp) else null) {
            if (shown == null) {
                OutlinedButton(
                    onClick = { gated = { model.launch { code = model.vault.localRecoveryCode() } } },
                    modifier = Modifier.testTag("local.showCode"),
                ) { Text(stringResource(R.string.localVault_showCode)) }
            } else {
                IconButton(onClick = { code = null }) { Icon(Icons.Outlined.VisibilityOff, contentDescription = stringResource(R.string.common_hideWhat, what)) }
            }
        }
        if (shown != null) {
            Column(Modifier.padding(start = 16.dp, end = 8.dp, bottom = 8.dp)) { RecoveryCode(model, shown, Modifier.testTag("local.code")) }
        }
        if (current != null) {
            SettingsRow(stringResource(R.string.settings_security), stringResource(if (current.chipBound) R.string.localVault_chipOn else R.string.localVault_chipOff))
        }
        SettingsRow(stringResource(R.string.localVault_turnOnSync), stringResource(R.string.localVault_turnOnSyncHelp)) {
            Button(onClick = { model.localFlow.value = LocalFlow.TurnOnSync }, modifier = Modifier.testTag("local.turnOnSync")) { Text(stringResource(R.string.localVault_turnOnSync)) }
        }
        if (others.isNotEmpty()) {
            SettingsRow(stringResource(R.string.localVault_otherVaults), stringResource(R.string.localVault_otherVaultsHelp))
            for (vault in others) LocalVaultRow(model, vault)
        }
        SettingsRow(stringResource(R.string.localVault_addVault), stringResource(R.string.localVault_addVaultHelp)) {
            OutlinedButton(onClick = { model.launch { model.vault.leaveLocalVault() } }, modifier = Modifier.testTag("local.addVault")) { Text(stringResource(R.string.localVault_addVault)) }
        }
        SettingsRow(stringResource(R.string.localVault_deleteVault), stringResource(R.string.localVault_deleteVaultHelp)) {
            OutlinedButton(onClick = { deleting = true }, modifier = Modifier.testTag("local.delete")) { Text(stringResource(R.string.localVault_deleteVault), color = Brand.colors.dangerText) }
        }
    }

    if (renaming) {
        TextPrompt(
            title = stringResource(R.string.localVault_renameTitle),
            label = stringResource(R.string.localVault_nameLabel),
            initial = name,
            confirm = stringResource(R.string.common_save),
            onDismiss = { renaming = false },
        ) { next ->
            renaming = false
            model.launch { model.vault.renameLocalVault(next.trim()) }
        }
    }
    if (deleting) DeleteDialog(model, name) { deleting = false }
    gated?.let { action ->
        ConfirmIdentityDialog(model, onDismiss = { gated = null }) {
            gated = null
            action()
        }
    }
}

/** "Confirm it's you" (`ConfirmIdentityDialog`): device unlock where it's on, otherwise the master password. */
@Composable
private fun ConfirmIdentityDialog(model: AppModel, onDismiss: () -> Unit, onConfirmed: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var methods by remember { mutableStateOf<UnlockMethods?>(null) }
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { methods = runCatching { model.vault.unlockMethods() }.getOrNull() }
    val device = methods?.let { it.deviceUnlockEnabled && !it.passwordRequired } == true

    fun confirm(withPassword: String?) {
        if (busy) return
        busy = true
        error = null
        scope.launch {
            try {
                model.vault.confirmUser(withPassword)
                onConfirmed()
            } catch (e: Exception) {
                if (!e.isCode(ErrorCode.DEVICE_UNLOCK_CANCELLED)) error = localPasswordError(context, e)
            } finally {
                busy = false
            }
        }
    }

    fun submit() {
        if (password.isEmpty()) error = context.getString(R.string.validation_passwordRequired) else confirm(password)
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(stringResource(R.string.identityGate_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.identityGate_body), style = MaterialTheme.typography.bodyMedium)
                if (device) {
                    OutlinedButton(onClick = { confirm(null) }, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("identity.device")) { Text(stringResource(R.string.identityGate_useDevice)) }
                }
                PasswordField(
                    value = password,
                    onValueChange = { password = it },
                    label = stringResource(if (device) R.string.identityGate_passwordOrDevice else R.string.fields_masterPassword),
                    onImeAction = ::submit,
                    modifier = Modifier.testTag("identity.password"),
                )
                error?.let { Alert(it) }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = {
            TextButton(onClick = ::submit, enabled = !busy, modifier = Modifier.testTag("identity.ok")) {
                if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) else Text(stringResource(R.string.identityGate_confirm))
            }
        },
    )
}

@Composable
private fun DeleteDialog(model: AppModel, name: String, onClose: () -> Unit) {
    val context = LocalContext.current
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
        // This dialog goes with the vault, before the call returns: the app's scope sees it through.
        model.scope.launch {
            try {
                model.vault.deleteLocalVault(password)
                model.toast(R.string.localVault_deleted, Toast.Tone.Success)
            } catch (e: Exception) {
                error = localPasswordError(context, e)
                busy = false
            }
        }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        title = { Text(stringResource(R.string.localVault_deleteTitle, name)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.localVault_deleteBody), style = MaterialTheme.typography.bodyMedium)
                PasswordField(
                    value = password,
                    onValueChange = { password = it },
                    label = stringResource(R.string.fields_masterPassword),
                    onImeAction = ::submit,
                    modifier = Modifier.testTag("local.deletePassword"),
                )
                error?.let { Alert(it) }
            }
        },
        dismissButton = { TextButton(onClick = onClose, enabled = !busy) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = {
            TextButton(onClick = ::submit, enabled = !busy, modifier = Modifier.testTag("local.deleteConfirm")) {
                if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) else Text(stringResource(R.string.localVault_deleteAction), color = Brand.colors.dangerText)
            }
        },
    )
}
