package app.octap.android.ui.vault

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.octap.android.model.AppModel
import app.octap.android.model.code
import app.octap.android.model.errorMessage
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.PasswordField
import app.octap.resources.R
import app.octap.vault.ErrorCode
import kotlinx.coroutines.launch

/**
 * The master password half of "Confirm it's you" (`AppModel.confirmIdentity`, plan 03): the
 * device lock is tried there first, and this shows when it can't be used. One per vault, so any
 * screen, list row or dialog can ask.
 */
@Composable
fun IdentityGateDialog(model: AppModel) {
    val request by model.identityRequest.collectAsState()
    val answer = request ?: return
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember(answer) { mutableStateOf("") }
    var error by remember(answer) { mutableStateOf<String?>(null) }
    var busy by remember(answer) { mutableStateOf(false) }
    val session by model.session.collectAsState()
    // Locking leaves nothing to confirm against.
    LaunchedEffect(session.status) {
        if (session.status != app.octap.vault.SessionStatus.UNLOCKED) answer.complete(false)
    }

    fun confirm() {
        if (password.isEmpty() || busy) return
        busy = true
        error = null
        scope.launch {
            try {
                model.vault.confirmUser(password)
                answer.complete(true)
            } catch (failure: Exception) {
                error = if (failure.code == ErrorCode.INVALID_CREDENTIALS) context.getString(R.string.identityGate_wrongPassword) else errorMessage(context, failure)
            } finally {
                busy = false
            }
        }
    }

    AlertDialog(
        onDismissRequest = { answer.complete(false) },
        title = { Text(stringResource(R.string.identityGate_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.identityGate_body), style = MaterialTheme.typography.bodyMedium)
                error?.let { Alert(it, modifier = Modifier.testTag("gate.error")) }
                PasswordField(password, { password = it }, stringResource(R.string.fields_masterPassword), onImeAction = ::confirm, modifier = Modifier.testTag("gate.password"))
            }
        },
        dismissButton = { TextButton(onClick = { answer.complete(false) }, modifier = Modifier.testTag("gate.cancel")) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = { TextButton(onClick = ::confirm, enabled = password.isNotEmpty() && !busy, modifier = Modifier.testTag("gate.confirm")) { Text(stringResource(R.string.identityGate_confirm)) } },
    )
}
