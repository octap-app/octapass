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

/**
 * Plan 05: Health says "Last backup 34 days ago" for a vault on this phone only, warns when one is
 * due, and goes to Settings, where the backup is. Read on the phone; nothing is sent.
 */
@Composable
fun LocalBackupLine() {
    val vault = LocalVault.current
    val model = vault.model
    if (!model.isLocal) return
    val current = rememberLocalVaults(model).firstOrNull { it.current } ?: return
    val last = current.lastBackupAt
    val days = last?.let(::daysSince)
    val parts = buildList {
        add(
            when {
                days == null -> stringResource(R.string.health_backup_never)
                days <= 0 -> stringResource(R.string.health_backup_today)
                else -> pluralStringResource(R.plurals.health_backup_daysAgo, days, days)
            },
        )
        current.backupFolderName?.let { add(stringResource(R.string.health_backup_automatic, it)) }
    }
    val line = parts.joinToString(" · ") + if (current.backupDue) " ${stringResource(R.string.health_backup_due)}" else ""
    Alert(line, if (current.backupDue) AlertTone.Warn else AlertTone.Info, Modifier.testTag("health.lastBackup")) {
        TextButton(onClick = { vault.nav.select(Tab.Settings) }, modifier = Modifier.testTag("health.lastBackup.backUp")) {
            Text(stringResource(R.string.health_backup_action))
        }
    }
}
