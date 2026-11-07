package app.octap.android.ui.settings

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import app.octap.android.model.PendingKit
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.tools.SettingsRow
import app.octap.android.ui.tools.SettingsSection
import app.octap.android.ui.tools.VaultPage
import app.octap.android.ui.util.haptic
import app.octap.android.ui.util.rememberLive
import app.octap.android.ui.vault.LocalVault
import app.octap.android.ui.vault.Route
import app.octap.android.ui.vault.vaultName
import app.octap.resources.R
import app.octap.vault.ErrorCode
import app.octap.vault.Vault
import app.octap.vault.VaultRole
import kotlinx.coroutines.launch

/**
 * Settings → Replace Secret Key (`RotateSecretKey`): the master password, then the new Recovery
 * Kit, which covers the app until it's saved. The call runs in the model's scope, not this
 * screen's: leaving must not cancel it after the server took the new key, or the only copy of
 * the kit would be lost.
 */
@Composable
fun RotateSecretKeyScreen() {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    var password by remember { mutableStateOf("") }
    var newRecoveryCode by remember { mutableStateOf(false) }
    var passwordError by remember { mutableStateOf<String?>(null) }
    var formError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    BackHandler(enabled = busy) {}

    fun submit() {
        if (busy) return
        formError = null
        passwordError = if (password.isEmpty()) context.getString(R.string.validation_passwordRequired) else null
        if (passwordError != null) {
            haptic(context, Toast.Tone.Danger)
            return
        }
        busy = true
        val title = context.getString(R.string.rotateSecretKey_kitTitle)
        val body = context.getString(R.string.rotateSecretKey_kitBody)
        val done = context.getString(R.string.rotateSecretKey_done)
        model.scope.launch {
            try {
                val kit = model.vault.rotateSecretKey(password, newRecoveryCode)
                model.newKit.value = PendingKit(kit, title, body, done)
                if (vault.nav.top == Route.RotateSecretKey) vault.nav.pop()
            } catch (error: Exception) {
                haptic(context, Toast.Tone.Danger)
                if (error.isCode(ErrorCode.INVALID_CREDENTIALS)) passwordError = context.getString(R.string.changePassword_wrongCurrent) else formError = errorMessage(context, error)
            } finally {
                password = ""
                busy = false
            }
        }
    }

    VaultPage(stringResource(R.string.rotateSecretKey_title), tag = "rotate.title") {
        Text(stringResource(R.string.rotateSecretKey_intro), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        formError?.let { Alert(it, modifier = Modifier.testTag("rotate.error")) }
        PasswordField(
            value = password,
            onValueChange = { password = it },
            label = stringResource(R.string.fields_masterPassword),
            error = passwordError,
            onImeAction = ::submit,
            modifier = Modifier.fillMaxWidth().testTag("rotate.password"),
        )
        Row(
            Modifier
                .fillMaxWidth()
                .toggleable(value = newRecoveryCode, role = Role.Checkbox, onValueChange = { newRecoveryCode = it })
                .padding(vertical = 4.dp)
                .testTag("rotate.recoveryCode"),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(checked = newRecoveryCode, onCheckedChange = null)
            Spacer(Modifier.width(12.dp))
            Text(stringResource(R.string.rotateSecretKey_newRecoveryCode), style = MaterialTheme.typography.bodyLarge)
        }
        Alert(stringResource(R.string.rotateSecretKey_signsOut), AlertTone.Info)
        PrimaryButton(stringResource(R.string.rotateSecretKey_submit), ::submit, busy = busy, modifier = Modifier.testTag("rotate.submit"))
    }
}

/** Settings → Vault keys (`VaultKeysRow`): a new key for a vault this account owns or manages. */
@Composable
fun VaultKeysScreen() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val vaults = rememberLive(model, sharing = true) { model.vault.listVaults() }.data
    var confirming by remember { mutableStateOf<Vault?>(null) }
    var rotating by remember { mutableStateOf<String?>(null) }

    VaultPage(stringResource(R.string.vaultKeys_title), tag = "vaultKeys.title") {
        Text(stringResource(R.string.vaultKeys_intro), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Alert(stringResource(R.string.vaultKeys_limits), AlertTone.Info)
        SettingsSection(stringResource(R.string.vaultKeys_row), tag = "vaultKeys.list") {
            val rotatable = vaults?.filter { (it.role == VaultRole.OWNER || it.role == VaultRole.MANAGE) && !it.untrusted }
            if (rotatable == null) {
                CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
            } else {
                for (v in rotatable) {
                    SettingsRow(vaultName(v)) {
                        if (rotating == v.id) {
                            CircularProgressIndicator(Modifier.size(24.dp))
                        } else {
                            OutlinedButton(onClick = { confirming = v }, enabled = rotating == null, modifier = Modifier.testTag("vaultKeys.rotate.${v.id}")) { Text(stringResource(R.string.vaultKeys_rotate)) }
                        }
                    }
                }
            }
        }
    }
    confirming?.let { v ->
        val name = vaultName(v)
        Confirm(stringResource(R.string.vaultKeys_confirmTitle, name), stringResource(R.string.vaultKeys_confirmBody), stringResource(R.string.vaultKeys_rotate), danger = false, onDismiss = { confirming = null }) {
            confirming = null
            rotating = v.id
            model.launch {
                try {
                    model.vault.rotateVaultKey(v.id)
                    model.toast(context.getString(R.string.vaultKeys_done, name), Toast.Tone.Success)
                } finally {
                    rotating = null
                }
            }
        }
    }
}
