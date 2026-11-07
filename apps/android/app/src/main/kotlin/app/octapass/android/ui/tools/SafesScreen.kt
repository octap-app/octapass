package app.octap.android.ui.tools

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.octap.android.model.Toast
import app.octap.android.platform.OpenSafe
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.util.Formats
import app.octap.android.ui.util.isolate
import app.octap.android.ui.util.rememberLive
import app.octap.android.ui.util.shownLocale
import app.octap.android.ui.vault.LocalVault
import app.octap.resources.R
import app.octap.vault.SafeItem
import app.octap.vault.SafeWarning
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** The Safes in this account, with making one. Their files are in the system's Files app. */
@Composable
fun SafesScreen() {
    val model = LocalVault.current.model
    val safes = rememberLive(model) { model.vault.listSafes(model.safes.folder.path) }.data
    val open by model.safes.open.collectAsState()
    val settings by model.settings.collectAsState()
    VaultPage(stringResource(R.string.fileTools_safesTitle), stringResource(R.string.fileTools_safesHelp), tag = "safes.title") {
        Alert(stringResource(R.string.phone_native_safesInFiles), AlertTone.Info, Modifier.testTag("safes.inFiles"))
        if (settings.lockOnBackground) Alert(stringResource(R.string.phone_native_safesLockInBackground), AlertTone.Warn, Modifier.testTag("safes.lockInBackground"))
        NewSafeSection()
        SettingsSection(stringResource(R.string.fileTools_safesTitle), tag = "safes.list") {
            if (safes?.isEmpty() == true) SettingsRow(stringResource(R.string.fileTools_noSafes), stringResource(R.string.fileTools_noSafesHelp))
            for (safe in safes.orEmpty()) SafeRow(safe, open[safe.itemId])
        }
    }
}

@Composable
private fun NewSafeSection() {
    val model = LocalVault.current.model
    var name by remember { mutableStateOf("") }
    var sync by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    SettingsSection(stringResource(R.string.fileTools_newSafe), tag = "safes.new") {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Field(name, { name = it }, stringResource(R.string.fileTools_safeName), modifier = Modifier.testTag("safes.name"))
        }
        SettingsRow(
            stringResource(R.string.fileTools_safeSync),
            stringResource(R.string.fileTools_safeSyncHelp),
            modifier = Modifier.testTag("safes.sync"),
            onClick = { sync = !sync },
        ) { Switch(sync, null) }
        Column(Modifier.padding(16.dp)) {
            PrimaryButton(
                stringResource(R.string.fileTools_createSafe),
                onClick = {
                    busy = true
                    model.launch {
                        try {
                            // The item change opens it, through AppModel.
                            model.vault.createSafe(name.trim(), sync)
                            name = ""
                            sync = false
                        } finally {
                            busy = false
                        }
                    }
                },
                busy = busy,
                enabled = name.isNotBlank(),
                modifier = Modifier.fillMaxWidth().testTag("safes.create"),
            )
        }
    }
}

@Composable
private fun SafeRow(safe: SafeItem, open: OpenSafe?) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    var busy by remember { mutableStateOf(false) }
    var syncs by remember { mutableIntStateOf(0) }
    var deleting by remember { mutableStateOf(false) }
    val locale = shownLocale()
    val warnings = rememberLive(model, open, syncs) {
        // It can wait for a file being sealed, so not on the main thread.
        withContext(Dispatchers.IO) { open?.drive?.warnings().orEmpty() }
    }.data
    SettingsRow(
        safe.name,
        stringResource(if (safe.sync) R.string.fileTools_synced else R.string.fileTools_thisDevice),
        modifier = Modifier.testTag("safes.row"),
    ) {
        if (safe.sync && open != null) {
            OutlinedButton(
                enabled = !busy,
                onClick = {
                    busy = true
                    model.launch {
                        try {
                            val summary = model.safes.sync(open)
                            summary.conflicts.forEach { model.toast(context.getString(R.string.fileTools_conflict, Formats.isolate(it, locale))) }
                            summary.tooBig.forEach { model.toast(context.getString(R.string.fileTools_tooBig, Formats.isolate(it, locale)), Toast.Tone.Danger) }
                            model.toast(R.string.fileTools_syncDone, Toast.Tone.Success)
                        } finally {
                            busy = false
                            syncs++
                        }
                    }
                },
                modifier = Modifier.testTag("safes.syncNow"),
            ) { Text(stringResource(R.string.fileTools_syncNow), style = MaterialTheme.typography.labelLarge) }
        }
        TextButton(
            enabled = !busy,
            onClick = { deleting = true },
            modifier = Modifier.testTag("safes.delete"),
        ) { Text(stringResource(R.string.fileTools_deleteSafe), style = MaterialTheme.typography.labelLarge) }
    }
    if (deleting) {
        var typed by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { deleting = false },
            title = { Text(stringResource(R.string.fileTools_deleteSafe)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.fileTools_deleteSafeConfirm, Formats.isolate(safe.name, locale)))
                    Field(typed, { typed = it }, stringResource(R.string.fileTools_typeSafeName, Formats.isolate(safe.name, locale)), modifier = Modifier.testTag("safes.deleteName"))
                }
            },
            confirmButton = {
                TextButton(
                    enabled = typed == safe.name && !busy,
                    onClick = {
                        busy = true
                        model.launch {
                            try {
                                model.safes.delete(safe)
                                model.toast(context.getString(R.string.fileTools_safeDeleted, Formats.isolate(safe.name, locale)), Toast.Tone.Success)
                                deleting = false
                                model.safes.refresh()
                            } finally {
                                busy = false
                            }
                        }
                    },
                    modifier = Modifier.testTag("safes.deleteConfirm"),
                ) { Text(stringResource(R.string.fileTools_deleteSafe)) }
            },
            dismissButton = { TextButton(onClick = { deleting = false }) { Text(stringResource(R.string.common_cancel)) } },
        )
    }
    for (warning in warnings.orEmpty()) {
        Alert(warningText(warning), AlertTone.Warn, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
    }
}

@Composable
private fun warningText(warning: SafeWarning): String = when (warning) {
    SafeWarning.Damaged -> stringResource(R.string.fileTools_warnings_damagedBlob)
    SafeWarning.RolledBack -> stringResource(R.string.fileTools_warnings_rolledBack)
    SafeWarning.Missing -> stringResource(R.string.fileTools_warnings_missing)
    is SafeWarning.Orphaned -> stringResource(R.string.fileTools_warnings_orphaned, isolate(warning.name))
}
