package app.octap.android.ui.vault

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.OpenDocument
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.FileUpload
import androidx.compose.material.icons.outlined.IosShare
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import app.octap.android.model.Toast
import app.octap.android.model.code
import app.octap.android.model.errorMessage
import app.octap.android.platform.Files
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.Field as InputField
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.SecondaryButton
import app.octap.android.ui.settings.rememberShareFile
import app.octap.android.ui.theme.monoStyle
import app.octap.android.ui.tools.Toggle
import app.octap.resources.R
import app.octap.vault.ErrorCode
import app.octap.vault.Item
import app.octap.vault.SshKeyDetails
import app.octap.vault.SshKeyKind
import app.octap.vault.SshKeyMaterial
import app.octap.vault.authorizedKeysLine
import app.octap.vault.isUsableSshKey
import app.octap.vault.sshKeyFileName
import app.octap.vault.sshKeyKinds
import app.octap.vault.sshKeyTypeLabel
import app.octap.vault.withSshKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Key files are a few kilobytes; anything much bigger isn't one. */
private const val MAX_KEY_FILE = 64 * 1024L

/** The editor's SSH key part (`SshKeySection`): generate or read the key, then its comment and passphrase. */
@Composable
fun SshKeySection(details: SshKeyDetails, error: String?, set: (SshKeyDetails) -> Unit) {
    var replacing by remember { mutableStateOf(false) }
    Section(stringResource(R.string.sshKey_key)) {
        if (details.privateKey != null && !replacing) {
            Text(stringResource(R.string.sshKey_type) + ": " + (sshKeyTypeLabel(details) ?: "—"), style = MaterialTheme.typography.bodyMedium)
            Text(details.fingerprint ?: "—", style = monoStyle.copy(textDirection = TextDirection.Ltr), modifier = Modifier.testTag("ssh.fingerprint"))
            SecondaryButton(stringResource(R.string.sshKey_replace), { replacing = true }, icon = Icons.Outlined.Refresh, modifier = Modifier.testTag("ssh.replace"))
        } else {
            if (replacing) Alert(stringResource(R.string.sshKey_replaceConfirm), AlertTone.Warn)
            KeySource(details.comment.orEmpty(), error) { key, passphrase ->
                set(withSshKey(details, key, passphrase))
                replacing = false
            }
            if (replacing) TextButton(onClick = { replacing = false }) { Text(stringResource(R.string.common_cancel)) }
        }
        InputField(details.comment.orEmpty(), { set(details.copy(comment = it)) }, stringResource(R.string.sshKey_comment), hint = stringResource(R.string.sshKey_commentHint), modifier = Modifier.testTag("ssh.comment"))
        PasswordField(details.passphrase.orEmpty(), { set(details.copy(passphrase = it)) }, stringResource(R.string.sshKey_passphrase), hint = stringResource(R.string.sshKey_passphraseHint), contentType = null, modifier = Modifier.testTag("ssh.passphrase"))
    }
}

/** Generate a key, choose a key file or paste one. Asks for the passphrase when the key has one. */
@Composable
private fun KeySource(comment: String, error: String?, onKey: (SshKeyMaterial, String?) -> Unit) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val files = remember { Files(context) }
    val kinds = remember { sshKeyKinds() }
    var kind by remember { mutableStateOf(SshKeyKind.ED25519) }
    var pasted by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var locked by remember { mutableStateOf<String?>(null) }

    fun read(text: String) {
        busy = true
        scope.launch {
            try {
                onKey(model.vault.readSshKey(text, null), null)
                pasted = ""
            } catch (failure: Exception) {
                if (failure.code == ErrorCode.SSH_PASSPHRASE_REQUIRED) locked = text else model.toastError(failure)
            } finally {
                busy = false
            }
        }
    }

    val pick = rememberLauncherForActivityResult(OpenDocument()) { uri: Uri? ->
        model.inSystemUi = false
        if (uri != null) {
            scope.launch {
                runCatching {
                    withContext(Dispatchers.IO) {
                        val file = files.copy(listOf(uri)).first()
                        try {
                            if (file.file.length() > MAX_KEY_FILE) null else file.file.readText()
                        } finally {
                            file.file.parentFile?.deleteRecursively()
                        }
                    }
                }.onSuccess { text -> if (text != null) read(text) else model.toast(R.string.errors_invalidSshKey, Toast.Tone.Danger) }
                    .onFailure(model::toastError)
            }
        }
    }

    Choice(
        label = stringResource(R.string.sshKey_kind),
        options = kinds.map { it.name to messageFor(context, "sshKey.kinds.${it.name}") },
        selected = kinds.first { it.kind == kind }.name,
        tag = "ssh.kind",
    ) { name -> kind = kinds.first { it.name == name }.kind }
    Text(stringResource(R.string.sshKey_kindHint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    PrimaryButton(
        stringResource(if (busy) R.string.sshKey_generating else R.string.sshKey_generateAction),
        {
            busy = true
            scope.launch {
                try {
                    onKey(model.vault.generateSshKey(kind, comment), null)
                } catch (failure: Exception) {
                    model.toastError(failure)
                } finally {
                    busy = false
                }
            }
        },
        busy = busy,
        icon = Icons.Outlined.Key,
        modifier = Modifier.testTag("ssh.generate"),
    )
    SecondaryButton(stringResource(R.string.sshKey_importFile), { model.inSystemUi = true; pick.launch(arrayOf("*/*")) }, enabled = !busy, icon = Icons.Outlined.FileUpload, modifier = Modifier.testTag("ssh.importFile"))
    Text(stringResource(R.string.sshKey_importFileHint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    InputField(pasted, { pasted = it }, stringResource(R.string.sshKey_paste), error = error, placeholder = "-----BEGIN OPENSSH PRIVATE KEY-----", mono = true, singleLine = false, minLines = 4, modifier = Modifier.testTag("ssh.paste"))
    if (pasted.isNotBlank()) SecondaryButton(stringResource(R.string.sshKey_pasteAction), { read(pasted) }, enabled = !busy, modifier = Modifier.testTag("ssh.pasteAction"))

    locked?.let { text ->
        PassphraseDialog(text, onClose = { locked = null }) { key, passphrase ->
            locked = null
            pasted = ""
            onKey(key, passphrase)
        }
    }
}

@Composable
private fun PassphraseDialog(text: String, onClose: () -> Unit, onKey: (SshKeyMaterial, String?) -> Unit) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var passphrase by remember { mutableStateOf("") }
    var keep by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun submit() {
        busy = true
        scope.launch {
            try {
                onKey(model.vault.readSshKey(text, passphrase), if (keep) passphrase else null)
            } catch (failure: Exception) {
                error = if (failure.code == ErrorCode.WRONG_PASSPHRASE) context.getString(R.string.sshKey_wrongPassphrase) else errorMessage(context, failure)
            } finally {
                busy = false
            }
        }
    }

    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(stringResource(R.string.sshKey_passphraseTitle)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.sshKey_passphraseBody), style = MaterialTheme.typography.bodyMedium)
                PasswordField(passphrase, { passphrase = it }, stringResource(R.string.sshKey_passphrase), error = error, contentType = null, onImeAction = { if (passphrase.isNotEmpty()) submit() }, modifier = Modifier.testTag("ssh.readPassphrase"))
                Toggle(stringResource(R.string.sshKey_keepPassphrase), keep, tag = "ssh.keepPassphrase") { keep = it }
            }
        },
        dismissButton = { TextButton(onClick = onClose) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = { TextButton(onClick = ::submit, enabled = passphrase.isNotEmpty() && !busy, modifier = Modifier.testTag("ssh.readAction")) { Text(stringResource(R.string.sshKey_readAction)) } },
    )
}

/**
 * An SSH key's fields (`SshKeyFields`). The private key is shown, copied or saved only after
 * confirming it's the owner (plan 16 §6); confirming covers this item while it's open, and a
 * confirmed unlock covers showing and copying it (plan 03 History, 2026-11-05).
 */
@Composable
fun SshKeyFields(item: Item, details: SshKeyDetails) {
    val model = LocalVault.current.model
    val scope = rememberCoroutineScope()
    val share = rememberShareFile(model)
    val line = remember(details) { authorizedKeysLine(details) }
    val typeLabel = remember(details) { sshKeyTypeLabel(details) }
    val fileName = remember(item.title, details) { sshKeyFileName(item.title, details) }
    var confirmed by remember(item.id) { mutableStateOf(false) }
    var shown by remember(item.id) { mutableStateOf(false) }
    var exporting by remember(item.id) { mutableStateOf(false) }

    /** Saving the private key to a file is an export: "Confirm it's you" every time, once for this item while it's open. */
    fun gated(action: () -> Unit) {
        if (confirmed) return action()
        scope.launch {
            if (model.confirmIdentity()) {
                confirmed = true
                action()
            }
        }
    }

    /** Showing it doesn't ask again when the user answered this unlock ([AppModel.confirmReveal]). */
    fun reveal() {
        if (confirmed) {
            shown = true
            return
        }
        scope.launch {
            if (model.unlockCoversReveal()) {
                shown = true
            } else if (model.confirmIdentity()) {
                model.revealAnswered()
                confirmed = true
                shown = true
            }
        }
    }

    FieldList {
        Field(stringResource(R.string.sshKey_publicKey), line.ifEmpty { null }, model, mono = true, tag = "ssh.publicKey")
        Field(stringResource(R.string.sshKey_fingerprint), details.fingerprint, model, mono = true, tag = "ssh.fingerprint")
        Field(stringResource(R.string.sshKey_type), typeLabel, model, copy = false)
        Field(stringResource(R.string.sshKey_comment), details.comment, model, ltr = true)
        details.privateKey?.let { privateKey ->
            val label = stringResource(R.string.sshKey_privateKey)
            Field(
                label,
                "",
                model,
                copy = false,
                actions = {
                    if (shown) {
                        IconButton(onClick = { shown = false }) { Icon(Icons.Outlined.VisibilityOff, contentDescription = stringResource(R.string.sshKey_hidePrivate)) }
                        IconButton(onClick = { copy(model, privateKey, label, secret = true, item = item.id) }, modifier = Modifier.testTag("ssh.copyPrivate")) {
                            Icon(Icons.Outlined.ContentCopy, contentDescription = stringResource(R.string.copy_action, label))
                        }
                    } else {
                        OutlinedButton(onClick = { reveal() }, modifier = Modifier.padding(end = 8.dp).testTag("ssh.showPrivate")) { Text(stringResource(R.string.sshKey_showPrivate)) }
                    }
                },
            ) {
                if (shown) Text(privateKey, style = monoStyle.copy(textDirection = TextDirection.Ltr), modifier = Modifier.testTag("ssh.privateKey"))
                else Text("•".repeat(16), style = monoStyle)
            }
        }
        SecretField(stringResource(R.string.sshKey_passphrase), details.passphrase, model)
    }
    if (typeLabel != null && details.keyType != null && !isUsableSshKey(details)) {
        Alert(stringResource(R.string.sshKey_notUsable, typeLabel), AlertTone.Info, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
    }
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (details.privateKey != null) {
            SecondaryButton(stringResource(R.string.sshKey_exportPrivate), { gated { exporting = true } }, icon = Icons.Outlined.IosShare, modifier = Modifier.testTag("ssh.exportPrivate"))
        }
        if (line.isNotEmpty()) {
            SecondaryButton(stringResource(R.string.sshKey_exportPublic), {
                scope.launch {
                    runCatching { model.vault.writeShareFile("$fileName.pub", "$line\n") }.onSuccess { share(it, "text/plain") }.onFailure(model::toastError)
                }
            }, icon = Icons.Outlined.IosShare, modifier = Modifier.testTag("ssh.exportPublic"))
        }
    }
    if (details.customFields.isNotEmpty()) {
        FieldList(stringResource(R.string.detail_moreFields)) {
            for (field in details.customFields) if (field.hidden) SecretField(field.label, field.value, model) else Field(field.label, field.value, model)
        }
    }
    details.notes?.takeIf { it.isNotEmpty() }?.let { notes ->
        FieldList(stringResource(R.string.fields_notes)) { Field(stringResource(R.string.fields_notes), notes, model, secret = true) }
    }
    if (exporting) ExportDialog(details, fileName, share) { exporting = false }
}

/** The private key as a file: with a passphrase for the copy, offered from the item's own. */
@Composable
private fun ExportDialog(details: SshKeyDetails, fileName: String, share: (String, String) -> Unit, onClose: () -> Unit) {
    val model = LocalVault.current.model
    val scope = rememberCoroutineScope()
    var passphrase by remember { mutableStateOf(details.passphrase.orEmpty()) }
    var busy by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(stringResource(R.string.sshKey_exportTitle)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.sshKey_exportBody), style = MaterialTheme.typography.bodyMedium)
                PasswordField(passphrase, { passphrase = it }, stringResource(R.string.sshKey_exportPassphrase), hint = stringResource(R.string.sshKey_exportPassphraseHint), contentType = null, modifier = Modifier.testTag("ssh.exportPassphrase"))
            }
        },
        dismissButton = { TextButton(onClick = onClose) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = {
            TextButton(
                onClick = {
                    busy = true
                    scope.launch {
                        try {
                            share(model.vault.exportSshKey(details, fileName, passphrase.ifEmpty { null }), "application/x-pem-file")
                            onClose()
                        } catch (failure: Exception) {
                            model.toastError(failure)
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !busy,
                modifier = Modifier.testTag("ssh.exportAction"),
            ) { Text(stringResource(R.string.sshKey_exportAction)) }
        },
    )
}
