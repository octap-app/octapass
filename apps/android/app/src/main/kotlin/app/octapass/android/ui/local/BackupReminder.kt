package app.octap.android.ui.local

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.util.formatDate
import app.octap.android.ui.vault.LocalVault
import app.octap.android.ui.vault.Tab
import app.octap.resources.R

/**
 * Every 30 days (plan 01), and when a backup folder has stopped working: the vault keeps `backupDue`
 * off only while a folder keeps up. It goes away with the next backup.
 */
@Composable
fun BackupReminder() {
    val vault = LocalVault.current
    val model = vault.model
    if (!model.isLocal) return
    val current = rememberLocalVaults(model).firstOrNull { it.current } ?: return
    if (!current.backupDue) return
    val last = current.lastBackupAt
    val text = if (last != null) {
        val days = daysSince(last)
        pluralStringResource(R.plurals.localVault_reminder, days, days)
    } else {
        stringResource(R.string.localVault_reminderNever)
    }
    Alert(text, AlertTone.Warn, Modifier.padding(horizontal = 16.dp, vertical = 4.dp).testTag("local.reminder")) {
        TextButton(onClick = { vault.nav.select(Tab.Settings) }, modifier = Modifier.testTag("local.reminderBackUp")) {
            Text(stringResource(R.string.localVault_backUp))
        }
    }
}

/** A local vault's health includes its backups (plan 05). */
@Composable
fun LocalBackupLine() {
    val model = LocalVault.current.model
    if (!model.isLocal) return
    val current = rememberLocalVaults(model).firstOrNull { it.current } ?: return
    val last = current.lastBackupAt
    val line = if (last != null) stringResource(R.string.localVault_lastBackupHealth, formatDate(last)) else stringResource(R.string.localVault_neverBackedUp)
    Alert(line, if (current.backupDue) AlertTone.Warn else AlertTone.Info, Modifier.testTag("health.lastBackup"))
}
