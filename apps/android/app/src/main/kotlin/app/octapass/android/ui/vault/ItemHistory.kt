package app.octap.android.ui.vault

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.ui.components.Alert
import app.octap.android.ui.settings.Confirm
import app.octap.android.ui.util.formatDateTime
import app.octap.android.ui.util.rememberLive
import app.octap.resources.R
import app.octap.vault.Item
import app.octap.vault.ItemVersion
import kotlinx.coroutines.launch

/**
 * An item's past versions (`ItemHistory`): the last 10, read from the server only when this opens.
 * A version shows the same fields as the item, so its secrets stay hidden until revealed, but none
 * of the live actions. Restoring is an ordinary edit, so it can be undone from the same list.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ItemHistorySheet(item: Item, editable: Boolean, onClose: () -> Unit) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val versions = rememberLive(model, item.id) { model.vault.itemVersions(item.id) }
    var shown by remember { mutableStateOf<ULong?>(null) }
    var restoring by remember { mutableStateOf<ItemVersion?>(null) }
    var busy by remember { mutableStateOf(false) }
    var restoreError by remember { mutableStateOf<String?>(null) }
    val list = versions.data
    val failed = versions.error

    ModalBottomSheet(onDismissRequest = onClose, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(Modifier.padding(bottom = 24.dp).verticalScroll(rememberScrollState()).testTag("history.sheet"), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.history_title), style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
                Text(stringResource(R.string.history_help), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (failed != null) Alert(errorMessage(context, failed))
                restoreError?.let { Alert(it) }
                if (list == null && failed == null) CircularProgressIndicator(Modifier.size(24.dp))
                if (list?.isEmpty() == true) Text(stringResource(R.string.history_empty), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("history.empty"))
            }
            for (version in list.orEmpty()) {
                key(version.revision) {
                    val open = shown == version.revision
                    Row(Modifier.fillMaxWidth().padding(start = 20.dp, end = 12.dp).testTag("history.version.${version.revision}"), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(formatDateTime(version.updatedAt), style = MaterialTheme.typography.bodyLarge)
                            Text(version.item.title.ifEmpty { stringResource(R.string.detail_untitled) }, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                        TextButton(onClick = { shown = if (open) null else version.revision }, modifier = Modifier.testTag("history.show.${version.revision}")) {
                            Text(stringResource(if (open) R.string.common_hide else R.string.common_show))
                        }
                        if (editable) {
                            TextButton(onClick = { restoring = version }, enabled = !busy, modifier = Modifier.testTag("history.restore.${version.revision}")) {
                                Text(stringResource(R.string.history_restore))
                            }
                        }
                    }
                    if (open) TypeFields(version.item, pastVersion = true)
                }
            }
        }
    }

    restoring?.let { version ->
        Confirm(
            title = stringResource(R.string.history_confirmTitle),
            body = stringResource(R.string.history_confirmBody, formatDateTime(version.updatedAt)),
            confirm = stringResource(R.string.history_restore),
            danger = false,
            onDismiss = { restoring = null },
        ) {
            restoring = null
            busy = true
            restoreError = null
            scope.launch {
                try {
                    model.vault.restoreItemVersion(item.id, version.revision)
                    model.toast(context.getString(R.string.history_restored), Toast.Tone.Success)
                    onClose()
                } catch (error: Exception) {
                    // On the sheet: a toast would sit behind it.
                    restoreError = errorMessage(context, error)
                } finally {
                    busy = false
                }
            }
        }
    }
}
