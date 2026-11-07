package app.octap.android.ui.vault

import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.Ndef
import android.nfc.tech.NdefFormatable
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Nfc
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.SecondaryButton
import app.octap.android.ui.util.findActivity
import app.octap.resources.R
import app.octap.vault.WifiDetails
import app.octap.vault.wifiTagMimeType
import app.octap.vault.wifiTagPayload
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

private const val READER_FLAGS = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_NFC_F or NfcAdapter.FLAG_READER_NFC_V

private enum class TagResult(@StringRes val message: Int, val tone: AlertTone, val retry: Boolean) {
    WRITTEN(R.string.phone_native_nfcDone, AlertTone.Info, false),
    TOO_SMALL(R.string.phone_native_nfcTooSmall, AlertTone.Danger, true),
    READ_ONLY(R.string.phone_native_nfcReadOnly, AlertTone.Danger, true),
    FAILED(R.string.phone_native_nfcFailed, AlertTone.Danger, true),
}

private fun writeNdef(ndef: Ndef, message: NdefMessage): TagResult = try {
    ndef.connect()
    when {
        !ndef.isWritable -> TagResult.READ_ONLY
        ndef.maxSize < message.byteArrayLength -> TagResult.TOO_SMALL
        else -> {
            ndef.writeNdefMessage(message)
            TagResult.WRITTEN
        }
    }
} catch (e: Exception) {
    TagResult.FAILED
} finally {
    runCatching { ndef.close() }
}

private fun formatTag(tag: NdefFormatable, message: NdefMessage): TagResult = try {
    tag.connect()
    tag.format(message)
    TagResult.WRITTEN
} catch (e: Exception) {
    TagResult.FAILED
} finally {
    runCatching { tag.close() }
}

/** Blocks on the tag: a new tag has no NDEF yet and is formatted with the message. */
private fun writeTag(tag: Tag, message: NdefMessage): TagResult {
    Ndef.get(tag)?.let { return writeNdef(it, message) }
    NdefFormatable.get(tag)?.let { return formatTag(it, message) }
    return TagResult.FAILED
}

private sealed interface NfcStep {
    data object Warning : NfcStep
    class Reading(val message: NdefMessage) : NfcStep
    data class Finished(@StringRes val message: Int, val tone: AlertTone, val retry: Boolean) : NfcStep
}

/**
 * The activity reads tags for as long as this is composed. Android restarts discovery when reader
 * mode ends, which loses the tag, so this stays up until the write has finished. Only the first
 * tag counts.
 */
@Composable
private fun ReaderMode(adapter: NfcAdapter, onTag: (Tag) -> Unit) {
    val activity = LocalContext.current.findActivity() ?: return
    val latest by rememberUpdatedState(onTag)
    DisposableEffect(adapter, activity) {
        val taken = AtomicBoolean(false)
        adapter.enableReaderMode(activity, { tag -> if (taken.compareAndSet(false, true)) latest(tag) }, READER_FLAGS, null)
        onDispose { adapter.disableReaderMode(activity) }
    }
}

/** Write to NFC tag: only on phones with an NFC adapter. */
@Composable
fun NfcTagButton(details: WifiDetails) {
    val context = LocalContext.current
    val adapter = remember { NfcAdapter.getDefaultAdapter(context) } ?: return
    var open by remember { mutableStateOf(false) }
    SecondaryButton(stringResource(R.string.phone_native_nfcWrite), { open = true }, icon = Icons.Outlined.Nfc, modifier = Modifier.testTag("wifi.nfc"))
    if (open) NfcTagDialog(adapter, details) { open = false }
}

/**
 * Puts the network on a tag so a phone joins by tapping it. A tag isn't encrypted, so the warning
 * comes first; the payload is made only after the user accepts it, and lives in this dialog.
 */
@Composable
private fun NfcTagDialog(adapter: NfcAdapter, details: WifiDetails, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    var step by remember { mutableStateOf<NfcStep>(NfcStep.Warning) }
    var writing by remember { mutableStateOf(false) }

    fun start() {
        val payload = wifiTagPayload(details.ssid, details.security, details.password)
        step = when {
            payload == null -> NfcStep.Finished(R.string.phone_native_nfcUnsupported, AlertTone.Danger, retry = false)
            !adapter.isEnabled -> NfcStep.Finished(R.string.phone_native_nfcOff, AlertTone.Warn, retry = true)
            else -> NfcStep.Reading(NdefMessage(NdefRecord.createMime(wifiTagMimeType(), payload)))
        }
    }

    val current = step
    if (current is NfcStep.Reading) {
        ReaderMode(adapter) { tag ->
            // Called on a binder thread. The write runs in the background, the state changes on the main thread.
            scope.launch {
                writing = true
                val result = withContext(Dispatchers.IO) { writeTag(tag, current.message) }
                writing = false
                step = NfcStep.Finished(result.message, result.tone, result.retry)
            }
        }
    }

    AlertDialog(
        // A write in progress finishes first: leaving now would lose the tag halfway through it.
        onDismissRequest = { if (!writing) onClose() },
        title = { Text(stringResource(R.string.phone_native_nfcTitle)) },
        text = {
            Column(Modifier.fillMaxWidth().testTag("nfc.dialog"), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
                when (current) {
                    NfcStep.Warning -> Alert(stringResource(R.string.phone_native_nfcWarning), AlertTone.Warn)
                    is NfcStep.Reading -> {
                        Alert(stringResource(R.string.phone_native_nfcHold), AlertTone.Info, Modifier.testTag("nfc.hold"))
                        CircularProgressIndicator(Modifier.size(24.dp))
                    }
                    is NfcStep.Finished -> Alert(stringResource(current.message), current.tone, Modifier.testTag("nfc.result"))
                }
            }
        },
        dismissButton = {
            if (current == NfcStep.Warning) TextButton(onClick = onClose, modifier = Modifier.testTag("nfc.cancel")) { Text(stringResource(R.string.common_cancel)) }
            if (current is NfcStep.Finished && current.retry) TextButton(onClick = { start() }, modifier = Modifier.testTag("nfc.retry")) { Text(stringResource(R.string.common_tryAgain)) }
        },
        confirmButton = {
            when (current) {
                NfcStep.Warning -> TextButton(onClick = { start() }, modifier = Modifier.testTag("nfc.confirm")) { Text(stringResource(R.string.phone_native_nfcWrite)) }
                is NfcStep.Reading -> TextButton(onClick = onClose, enabled = !writing, modifier = Modifier.testTag("nfc.cancel")) { Text(stringResource(R.string.common_cancel)) }
                is NfcStep.Finished -> TextButton(onClick = onClose, modifier = Modifier.testTag("nfc.close")) { Text(stringResource(R.string.common_close)) }
            }
        },
    )
}
