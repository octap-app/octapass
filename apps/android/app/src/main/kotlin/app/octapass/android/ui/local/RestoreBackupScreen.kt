package app.octap.android.ui.local

import android.content.ActivityNotFoundException
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.OpenDocument
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AttachFile
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.autofill.ContentType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import app.octap.android.model.AppModel
import app.octap.android.model.errorMessage
import app.octap.android.platform.Files
import app.octap.android.platform.PickedFile
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AuthLayout
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.LinkButton
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.SecondaryButton
import app.octap.android.ui.components.StrengthHint
import app.octap.resources.R
import app.octap.vault.BackupKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private enum class Secret { Password, Code }

/** Opens a `.octapass-backup` file as a new vault here (`RestoreBackup`), with its password or the recovery code. */
@Composable
fun RestoreBackupScreen(model: AppModel, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val files = remember { Files(context) }
    val capabilities = remember { model.vault.localCapabilities() }
    var file by remember { mutableStateOf<PickedFile?>(null) }
    var secret by rememberSaveable { mutableStateOf(Secret.Password) }
    var password by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var newPassword by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var passwordError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val estimate = remember(newPassword) { model.vault.estimateStrength(newPassword) }
    BackHandler(enabled = !busy, onBack = onClose)

    // The copy lasts as long as this screen, or until another file is picked.
    DisposableEffect(file) {
        val copy = file
        onDispose { copy?.file?.parentFile?.deleteRecursively() }
    }

    val pick = rememberLauncherForActivityResult(OpenDocument()) { uri ->
        model.inSystemUi = false
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            try {
                file = withContext(Dispatchers.IO) { files.copy(listOf(uri)) }.first()
                error = null
            } catch (e: Exception) {
                error = errorMessage(context, e)
            }
        }
    }

    fun openPicker() {
        model.inSystemUi = true
        try {
            // Backups have no media type of their own.
            pick.launch(arrayOf("*/*"))
        } catch (e: ActivityNotFoundException) {
            model.inSystemUi = false
            error = context.getString(R.string.errors_noFileViewer)
        }
    }

    fun submit() {
        if (busy) return
        val picked = file
        val withPassword = secret == Secret.Password
        passwordError = null
        if (picked == null || (if (withPassword) password.isEmpty() else code.isBlank() || newPassword.isEmpty())) {
            error = context.getString(R.string.localVault_restoreFailed)
            return
        }
        if (!withPassword && estimate.score.toInt() < capabilities.minScore.toInt()) {
            passwordError = context.getString(R.string.localVault_weak)
            return
        }
        busy = true
        error = null
        scope.launch {
            try {
                val key = if (withPassword) BackupKey.Password(password) else BackupKey.RecoveryCode(code.trim(), newPassword)
                model.confirmedUnlock { model.vault.restoreLocalVault(picked.file.path, key) }
                onClose()
            } catch (e: Exception) {
                error = errorMessage(context, e)
            } finally {
                busy = false
            }
        }
    }

    AuthLayout(
        title = stringResource(R.string.localVault_restoreTitle),
        subtitle = stringResource(R.string.localVault_restoreSubtitle),
        footer = { LinkButton(stringResource(R.string.common_back), onClose, enabled = !busy, modifier = Modifier.testTag("restore.back")) },
    ) {
        error?.let { Alert(it, modifier = Modifier.testTag("restore.error")) }
        SecondaryButton(
            file?.name ?: stringResource(R.string.localVault_backupFile),
            ::openPicker,
            enabled = !busy,
            icon = Icons.Outlined.AttachFile,
            modifier = Modifier.testTag("restore.file"),
        )
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            val options = listOf(Secret.Password to R.string.localVault_withPassword, Secret.Code to R.string.localVault_withCode)
            options.forEachIndexed { i, (value, label) ->
                SegmentedButton(
                    selected = secret == value,
                    onClick = { secret = value },
                    shape = SegmentedButtonDefaults.itemShape(i, options.size),
                    modifier = Modifier.testTag("restore.${value.name.lowercase()}"),
                ) { Text(stringResource(label)) }
            }
        }
        if (secret == Secret.Password) {
            PasswordField(
                value = password,
                onValueChange = { password = it },
                label = stringResource(R.string.localVault_backupPassword),
                onImeAction = ::submit,
                modifier = Modifier.testTag("restore.password"),
            )
        } else {
            Field(
                value = code,
                onValueChange = { code = it },
                label = stringResource(R.string.localVault_recoveryCode),
                mono = true,
                capitalization = KeyboardCapitalization.Characters,
                keyboardType = KeyboardType.Ascii,
                modifier = Modifier.testTag("restore.code"),
            )
            Column {
                PasswordField(
                    value = newPassword,
                    onValueChange = { newPassword = it },
                    label = stringResource(R.string.localVault_newPassword),
                    error = passwordError,
                    imeAction = ImeAction.Done,
                    contentType = ContentType.NewPassword,
                    onImeAction = ::submit,
                    modifier = Modifier.testTag("restore.newPassword"),
                )
                StrengthHint(estimate, empty = newPassword.isEmpty())
            }
        }
        PrimaryButton(stringResource(R.string.localVault_restore), ::submit, busy = busy, modifier = Modifier.testTag("restore.submit"))
    }
}
