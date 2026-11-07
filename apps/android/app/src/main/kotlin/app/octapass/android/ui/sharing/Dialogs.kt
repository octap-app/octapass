package app.octap.android.ui.sharing

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.util.formatDate
import app.octap.android.ui.util.rememberLive
import app.octap.android.ui.vault.Choice
import app.octap.android.ui.vault.LocalVault
import app.octap.android.ui.vault.Route
import app.octap.android.ui.vault.Scope
import app.octap.android.ui.vault.copy
import app.octap.android.ui.vault.vaultIcon
import app.octap.android.ui.vault.vaultName
import app.octap.resources.R
import app.octap.vault.CreatedShareLink
import app.octap.vault.Item
import app.octap.vault.ShareLinkOptions
import app.octap.vault.VaultRole
import kotlinx.coroutines.launch

private val EXPIRY_HOURS = listOf(1, 24, 72, 168, 720)

@Composable
private fun expiryLabel(hours: Int) = if (hours < 24) pluralStringResource(R.plurals.shareLink_hours, hours, hours) else pluralStringResource(R.plurals.shareLink_days, hours / 24, hours / 24)

/** Item → Share a copy (`ShareLinkDialog`): a one-time link with an expiry, a view limit and an optional passphrase. */
@Composable
fun ShareLinkDialog(item: Item, onClose: () -> Unit) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var hours by remember { mutableStateOf(24) }
    var views by remember { mutableStateOf("1") }
    var passphrase by remember { mutableStateOf("") }
    var created by remember { mutableStateOf<Pair<CreatedShareLink, Boolean>?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val maxViews = views.toIntOrNull()
    val valid = maxViews != null && maxViews in 1..100
    val linkWhat = stringResource(R.string.shareLink_linkWhat)

    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        title = { Text(if (created != null) stringResource(R.string.shareLink_ready) else stringResource(R.string.shareLink_title, item.title.ifEmpty { stringResource(R.string.detail_untitled) })) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                val done = created
                if (done != null) {
                    Text(stringResource(R.string.shareLink_readyBody, formatDate(done.first.expiresAt, long = true)))
                    Field(done.first.url, {}, stringResource(R.string.shareLink_link), mono = true, readOnly = true, singleLine = false, modifier = Modifier.testTag("shareLink.url"))
                    TextButton(onClick = { copy(model, done.first.url, linkWhat, secret = true) }, modifier = Modifier.testTag("shareLink.copy")) {
                        Icon(Icons.Outlined.ContentCopy, null, Modifier.size(18.dp))
                        Text(stringResource(R.string.shareLink_copyLink), Modifier.padding(start = 6.dp))
                    }
                    if (done.second) Alert(stringResource(R.string.shareLink_sendPassphrase), AlertTone.Info)
                    TextButton(onClick = { onClose(); vault.nav.reset(Route.Sharing) }) { Text(stringResource(R.string.shareLink_manage)) }
                } else {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Outlined.Lock, null, Modifier.size(18.dp))
                        Text(stringResource(R.string.shareLink_intro), style = MaterialTheme.typography.bodySmall)
                    }
                    Choice(stringResource(R.string.shareLink_expires), EXPIRY_HOURS.map { it.toString() to expiryLabel(it) }, hours.toString(), tag = "shareLink.expires") { hours = it?.toInt() ?: 24 }
                    Field(
                        views,
                        { views = it.filter(Char::isDigit).take(3) },
                        stringResource(R.string.shareLink_views),
                        hint = stringResource(R.string.shareLink_viewsHint),
                        error = if (views.isNotEmpty() && !valid) stringResource(R.string.shareLink_viewsHint) else null,
                        keyboardType = KeyboardType.Number,
                        modifier = Modifier.testTag("shareLink.views"),
                    )
                    PasswordField(passphrase, { passphrase = it }, stringResource(R.string.shareLink_passphrase), hint = stringResource(R.string.shareLink_passphraseHint), contentType = null)
                    error?.let { Alert(it) }
                }
            }
        },
        dismissButton = {
            if (created == null) TextButton(onClick = onClose, enabled = !busy) { Text(stringResource(R.string.common_cancel)) }
        },
        confirmButton = {
            if (created != null) {
                TextButton(onClick = onClose, modifier = Modifier.testTag("shareLink.done")) { Text(stringResource(R.string.common_done)) }
            } else {
                TextButton(
                    enabled = valid && !busy,
                    modifier = Modifier.testTag("shareLink.create"),
                    onClick = {
                        busy = true
                        error = null
                        scope.launch {
                            try {
                                val link = model.vault.createShareLink(item.id, ShareLinkOptions(hours.toUInt(), maxViews!!.toUInt(), passphrase.ifEmpty { null }))
                                created = link to passphrase.isNotEmpty()
                                passphrase = ""
                            } catch (e: Exception) {
                                error = errorMessage(context, e)
                            } finally {
                                busy = false
                            }
                        }
                    },
                ) { if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) else Text(stringResource(R.string.shareLink_create)) }
            }
        },
    )
}

/** Item → Move to… / Copy to… (`MoveCopyDialog`): any other vault the user can add items to. */
@Composable
fun MoveCopyDialog(item: Item, move: Boolean, onClose: () -> Unit) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val targets = rememberLive(model, sharing = true) { model.vault.listVaults() }.data.orEmpty().filter { it.id != item.vaultId && it.role != VaultRole.READ && !it.untrusted }
    var target by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val chosen = targets.firstOrNull { it.id == (target ?: targets.firstOrNull()?.id) }
    val title = item.title.ifEmpty { stringResource(R.string.detail_untitled) }
    val chosenName = chosen?.let { vaultName(it) }

    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        title = { Text(stringResource(if (move) R.string.moveCopy_moveTitle else R.string.moveCopy_copyTitle, title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(if (move) R.string.moveCopy_moveIntro else R.string.moveCopy_copyIntro))
                if (targets.isEmpty()) {
                    Text(stringResource(R.string.moveCopy_noTargets))
                } else {
                    Column(Modifier.selectableGroup()) {
                        for (v in targets) {
                            Row(
                                Modifier.fillMaxWidth().selectable(chosen?.id == v.id, role = Role.RadioButton) { target = v.id }.padding(vertical = 8.dp).testTag("moveCopy.${v.id}"),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RadioButton(chosen?.id == v.id, null)
                                Spacer(Modifier.width(8.dp))
                                Icon(vaultIcon(v), null, Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(vaultName(v))
                            }
                        }
                    }
                }
                error?.let { Alert(it) }
            }
        },
        dismissButton = { TextButton(onClick = onClose, enabled = !busy) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = {
            TextButton(
                enabled = chosen != null && !busy,
                modifier = Modifier.testTag("moveCopy.confirm"),
                onClick = {
                    val to = chosen ?: return@TextButton
                    busy = true
                    error = null
                    scope.launch {
                        try {
                            val result = if (move) model.vault.moveItem(item.id, to.id) else model.vault.copyItem(item.id, to.id)
                            model.toast(context.getString(if (move) R.string.moveCopy_moved else R.string.moveCopy_copied, chosenName), Toast.Tone.Success)
                            onClose()
                            vault.nav.showScope(Scope.InVault(to.id))
                            vault.open(Route.Item(result.id))
                        } catch (e: Exception) {
                            error = errorMessage(context, e)
                        } finally {
                            busy = false
                        }
                    }
                },
            ) { Text(stringResource(if (move) R.string.moveCopy_moveAction else R.string.moveCopy_copyAction)) }
        },
    )
}

/** Names a new shared vault, creates it, and opens its members to invite people (`CreateVaultDialog`). */
@Composable
fun CreateVaultDialog(onDismiss: () -> Unit) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(stringResource(R.string.sharing_newVaultTitle)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.sharing_newVaultHelp))
                Field(name, { name = it.take(80) }, stringResource(R.string.sharing_vaultName), placeholder = stringResource(R.string.sharing_vaultNamePlaceholder), modifier = Modifier.testTag("newVault.name"))
                error?.let { Alert(it) }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = {
            TextButton(
                enabled = name.isNotBlank() && !busy,
                modifier = Modifier.testTag("newVault.create"),
                onClick = {
                    busy = true
                    scope.launch {
                        try {
                            val created = model.vault.createVault(name.trim())
                            onDismiss()
                            vault.nav.reset(Route.Sharing)
                            vault.nav.push(Route.VaultMembers(created.id))
                        } catch (e: Exception) {
                            error = errorMessage(context, e)
                        } finally {
                            busy = false
                        }
                    }
                },
            ) { Text(stringResource(R.string.sharing_create)) }
        },
    )
}
