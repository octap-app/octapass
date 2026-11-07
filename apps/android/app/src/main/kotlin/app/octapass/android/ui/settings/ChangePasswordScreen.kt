package app.octap.android.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.StrengthHint
import app.octap.android.ui.auth.MIN_SCORE
import app.octap.android.ui.tools.VaultPage
import app.octap.android.ui.util.haptic
import app.octap.android.ui.vault.LocalVault
import app.octap.resources.R
import app.octap.vault.ErrorCode
import kotlinx.coroutines.launch

/** Settings → Master password (`ChangePassword`): the current password, then a new one. */
@Composable
fun ChangePasswordScreen() {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var current by remember { mutableStateOf("") }
    var new by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var currentError by remember { mutableStateOf<String?>(null) }
    var newError by remember { mutableStateOf<String?>(null) }
    var confirmError by remember { mutableStateOf<String?>(null) }
    var formError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val estimate = remember(new) { model.vault.estimateStrength(new) }
    val local = model.isLocal
    val minScore = remember { if (local) model.vault.localCapabilities().minScore.toInt() else MIN_SCORE }

    fun submit() {
        if (busy) return
        currentError = if (current.isEmpty()) context.getString(R.string.validation_passwordRequired) else null
        newError = when {
            new.isEmpty() -> context.getString(R.string.changePassword_newRequired)
            estimate.score.toInt() < minScore -> context.getString(R.string.validation_passwordTooWeak)
            new == current -> context.getString(R.string.changePassword_same)
            else -> null
        }
        confirmError = if (confirm != new) context.getString(R.string.validation_passwordsDontMatch) else null
        formError = null
        if (currentError != null || newError != null || confirmError != null) {
            haptic(context, Toast.Tone.Danger)
            return
        }
        busy = true
        scope.launch {
            try {
                model.vault.changeMasterPassword(current, new)
                model.toast(R.string.changePassword_done, Toast.Tone.Success)
                vault.nav.pop()
            } catch (error: Exception) {
                haptic(context, Toast.Tone.Danger)
                if (error.isCode(ErrorCode.INVALID_CREDENTIALS)) currentError = context.getString(R.string.changePassword_wrongCurrent) else formError = errorMessage(context, error)
            } finally {
                busy = false
            }
        }
    }

    VaultPage(stringResource(R.string.changePassword_title), tag = "changePassword.title") {
        // The account's words: a local vault has no Secret Key and no other devices.
        if (!local) Text(stringResource(R.string.changePassword_intro), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        formError?.let { Alert(it, modifier = Modifier.testTag("changePassword.error")) }
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            PasswordField(
                value = current,
                onValueChange = { current = it },
                label = stringResource(R.string.changePassword_current),
                error = currentError,
                imeAction = ImeAction.Next,
                modifier = Modifier.fillMaxWidth().testTag("changePassword.current"),
            )
            Column {
                PasswordField(
                    value = new,
                    onValueChange = { new = it },
                    label = stringResource(R.string.fields_masterPassword),
                    error = newError,
                    imeAction = ImeAction.Next,
                    modifier = Modifier.fillMaxWidth().testTag("changePassword.new"),
                )
                StrengthHint(estimate, empty = new.isEmpty())
            }
            PasswordField(
                value = confirm,
                onValueChange = { confirm = it },
                label = stringResource(R.string.fields_confirmPassword),
                error = confirmError,
                onImeAction = ::submit,
                modifier = Modifier.fillMaxWidth().testTag("changePassword.confirm"),
            )
        }
        PrimaryButton(stringResource(R.string.changePassword_submit), ::submit, busy = busy, modifier = Modifier.testTag("changePassword.submit"))
        if (!local) Text(stringResource(R.string.changePassword_signsOut), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
