package app.octap.android.ui.local

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import app.octap.android.model.AppModel
import app.octap.android.ui.components.LinkButton
import app.octap.android.ui.components.SecondaryButton
import app.octap.android.ui.theme.monoStyle
import app.octap.android.ui.tools.SettingsRow
import app.octap.android.ui.tools.SettingsSection
import app.octap.android.ui.util.Formats
import app.octap.android.ui.vault.copy
import app.octap.resources.R
import app.octap.vault.LocalVaultInfo

/** Every vault on this phone only (`useLocalVaults`), read again when the session or a backup changes. */
@Composable
fun rememberLocalVaults(model: AppModel): List<LocalVaultInfo> {
    val session by model.session.collectAsState()
    val backups by model.localVersion.collectAsState()
    return remember(session, backups) { model.vault.localVaults() }
}

/** Whole days since an ISO time. */
fun daysSince(iso: String, now: Long = System.currentTimeMillis()): Int {
    val then = Formats.parse(iso)?.toEpochMilli() ?: return 0
    return ((now - then) / 86_400_000L).toInt()
}

/** On the first screen, under signing in (`LocalChoices`): the vaults here, a new one, or a backup. */
@Composable
fun LocalChoices(model: AppModel, onUseLocal: () -> Unit, onRestore: () -> Unit) {
    val vaults = rememberLocalVaults(model)
    HorizontalDivider()
    if (vaults.isNotEmpty()) LocalVaultList(model, vaults, stringResource(R.string.localVault_onThisDevice))
    SecondaryButton(stringResource(R.string.localVault_useOnThisDevice), onUseLocal, icon = Icons.Outlined.Lock, modifier = Modifier.testTag("local.use"))
    Text(
        stringResource(R.string.localVault_useOnThisDeviceHelp),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
        modifier = Modifier.fillMaxWidth(),
    )
    LinkButton(stringResource(R.string.localVault_restoreBackup), onRestore, Modifier.fillMaxWidth().testTag("local.restore"))
}

/** A row for each vault, opening it locked. The whole row is the button, so TalkBack reads its name with Open. */
@Composable
fun LocalVaultList(model: AppModel, vaults: List<LocalVaultInfo>, heading: String) {
    SettingsSection(heading, tag = "local.vaults") {
        for (vault in vaults) LocalVaultRow(model, vault)
    }
}

@Composable
fun LocalVaultRow(model: AppModel, vault: LocalVaultInfo) {
    SettingsRow(
        vault.name,
        onClick = { model.launch { model.vault.switchLocalVault(vault.tag) } },
        modifier = Modifier.testTag("local.open.${vault.tag}"),
    ) { Text(stringResource(R.string.localVault_open), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary) }
}

/** The backup recovery code (`RecoveryCode`), left to right in Arabic too, and easy to copy out. */
@Composable
fun RecoveryCode(model: AppModel, code: String, modifier: Modifier = Modifier) {
    val what = stringResource(R.string.localVault_recoveryCode)
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(code, style = monoStyle.copy(textDirection = TextDirection.Ltr), modifier = modifier.weight(1f).padding(vertical = 4.dp))
        IconButton(onClick = { copy(model, code, what, secret = true) }, modifier = Modifier.testTag("local.copyCode")) {
            Icon(Icons.Outlined.ContentCopy, contentDescription = stringResource(R.string.copy_action, what))
        }
    }
}

/** "I've written it down": what the Continue under a code or a kit waits for. */
@Composable
internal fun ConfirmRow(text: String, checked: Boolean, onChange: (Boolean) -> Unit, modifier: Modifier = Modifier) {
    Row(
        modifier
            .fillMaxWidth()
            .toggleable(value = checked, role = Role.Checkbox, onValueChange = onChange)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = checked, onCheckedChange = null)
        Spacer(Modifier.width(12.dp))
        Text(text, style = MaterialTheme.typography.bodyLarge)
    }
}
