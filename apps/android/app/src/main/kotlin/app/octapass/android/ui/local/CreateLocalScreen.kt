package app.octap.android.ui.local

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.SaveAlt
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
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
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.octap.android.model.AppModel
import app.octap.android.model.errorMessage
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AuthLayout
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.LinkButton
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.SecondaryButton
import app.octap.android.ui.components.StrengthHint
import app.octap.resources.R
import app.octap.vault.SessionStatus
import kotlinx.coroutines.launch

private enum class Step { Password, Code, FirstBackup }

/**
 * "Use on this device only" (`CreateLocal`): a name and a master password, the recovery code, then
 * a first backup. Creating unlocks the new vault, so [AppRoot][app.octap.android.ui.AppRoot]
 * keeps this up until [onClose].
 */
@Composable
fun CreateLocalScreen(model: AppModel, onClose: () -> Unit) {
    val session by model.session.collectAsState()
    var step by remember { mutableStateOf(Step.Password) }
    var code by remember { mutableStateOf("") }

    // A recreated window loses the steps, and with the vault open there's nothing left to create.
    LaunchedEffect(Unit) { if (model.session.value.status != SessionStatus.SIGNED_OUT) onClose() }
    // A locked app shows no secrets. Nothing is lost: Settings shows the code again, after a check.
    LaunchedEffect(step, session.status) { if (step != Step.Password && session.status != SessionStatus.UNLOCKED) onClose() }

    when (step) {
        Step.Password -> PasswordStep(model, onClose) {
            code = it
            step = Step.Code
        }
        Step.Code -> CodeStep(model, code) {
            code = ""
            step = Step.FirstBackup
        }
        Step.FirstBackup -> FirstBackup(model, onClose)
    }
}

@Composable
private fun PasswordStep(model: AppModel, onBack: () -> Unit, onCreated: (String) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val capabilities = remember { model.vault.localCapabilities() }
    val defaultName = stringResource(R.string.localVault_defaultName)
    var name by rememberSaveable { mutableStateOf(defaultName) }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var nameError by remember { mutableStateOf<String?>(null) }
    var passwordError by remember { mutableStateOf<String?>(null) }
    var confirmError by remember { mutableStateOf<String?>(null) }
    var formError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val estimate = remember(password) { model.vault.estimateStrength(password) }
    BackHandler(enabled = !busy, onBack = onBack)

    fun submit() {
        if (busy) return
        nameError = if (name.isBlank()) context.getString(R.string.errors_invalidName) else null
        passwordError = when {
            password.isEmpty() -> context.getString(R.string.validation_passwordRequired)
            estimate.score.toInt() < capabilities.minScore.toInt() -> context.getString(R.string.localVault_weak)
            else -> null
        }
        confirmError = if (confirm != password) context.getString(R.string.validation_passwordsDontMatch) else null
        formError = null
        if (nameError != null || passwordError != null || confirmError != null) return
        busy = true
        scope.launch {
            try {
                onCreated(model.confirmedUnlock { model.vault.createLocalVault(name, password) })
            } catch (error: Exception) {
                formError = errorMessage(context, error)
            } finally {
                busy = false
            }
        }
    }

    AuthLayout(
        title = stringResource(R.string.localVault_createTitle),
        subtitle = stringResource(R.string.localVault_createSubtitle),
        footer = { LinkButton(stringResource(R.string.common_back), onBack, enabled = !busy, modifier = Modifier.testTag("local.createBack")) },
    ) {
        formError?.let { Alert(it, modifier = Modifier.testTag("local.error")) }
        Field(
            value = name,
            onValueChange = { name = it.take(64) },
            label = stringResource(R.string.localVault_nameLabel),
            hint = stringResource(R.string.localVault_nameHint),
            error = nameError,
            capitalization = KeyboardCapitalization.Sentences,
            modifier = Modifier.testTag("local.name"),
        )
        Column {
            PasswordField(
                value = password,
                onValueChange = { password = it },
                label = stringResource(R.string.fields_masterPassword),
                error = passwordError,
                imeAction = ImeAction.Next,
                contentType = ContentType.NewPassword,
                modifier = Modifier.testTag("local.password"),
            )
            StrengthHint(estimate, empty = password.isEmpty())
        }
        PasswordField(
            value = confirm,
            onValueChange = { confirm = it },
            label = stringResource(R.string.fields_confirmPassword),
            error = confirmError,
            contentType = ContentType.NewPassword,
            onImeAction = ::submit,
            modifier = Modifier.testTag("local.confirm"),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Icon(Icons.Outlined.Info, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
            val guidance = stringResource(R.string.localVault_guidance)
            val chip = if (capabilities.chip) " ${stringResource(R.string.localVault_guidanceChip)}" else ""
            Text(guidance + chip, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        PrimaryButton(stringResource(R.string.localVault_create), ::submit, busy = busy, modifier = Modifier.testTag("local.create"))
        if (busy) {
            Text(
                stringResource(R.string.localVault_creating),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite },
            )
        }
    }
}

@Composable
private fun CodeStep(model: AppModel, code: String, onDone: () -> Unit) {
    var saved by rememberSaveable { mutableStateOf(false) }
    // Only Continue leaves: this is the moment to write it down.
    BackHandler {}

    AuthLayout(
        title = stringResource(R.string.localVault_kitTitle),
        subtitle = stringResource(R.string.localVault_kitSubtitle),
    ) {
        RecoveryCode(model, code, Modifier.testTag("local.code"))
        ConfirmRow(stringResource(R.string.localVault_kitConfirm), saved, { saved = it }, Modifier.testTag("local.kitConfirm"))
        PrimaryButton(stringResource(R.string.localVault_kitContinue), onDone, enabled = saved, modifier = Modifier.testTag("local.kitContinue"))
    }
}

/** Prompted on first setup (plan 01): a file now, a folder for automatic backups, or later. */
@Composable
private fun FirstBackup(model: AppModel, onDone: () -> Unit) {
    val backups = rememberBackupActions(model, onDone)
    BackHandler(enabled = !backups.busy, onBack = onDone)

    AuthLayout(
        title = stringResource(R.string.localVault_firstBackupTitle),
        subtitle = stringResource(R.string.localVault_firstBackupSubtitle),
    ) {
        PrimaryButton(stringResource(R.string.localVault_backUp), backups.save, busy = backups.busy, icon = Icons.Outlined.SaveAlt, modifier = Modifier.testTag("local.firstBackup"))
        SecondaryButton(stringResource(R.string.localVault_chooseFolder), backups.chooseFolder, enabled = !backups.busy, modifier = Modifier.testTag("local.firstFolder"))
        LinkButton(stringResource(R.string.localVault_firstBackupLater), onDone, Modifier.fillMaxWidth().testTag("local.firstBackupLater"), enabled = !backups.busy)
    }
}
