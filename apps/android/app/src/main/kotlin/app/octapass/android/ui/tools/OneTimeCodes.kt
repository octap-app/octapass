package app.octap.android.ui.tools

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.unit.dp
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.Avatar
import app.octap.android.ui.util.rememberLive
import app.octap.android.ui.vault.LocalVault
import app.octap.android.ui.vault.Route
import app.octap.android.ui.vault.hostOf
import app.octap.resources.R
import app.octap.vault.Item
import app.octap.vault.ItemDetails
import app.octap.vault.ItemFilter
import app.octap.vault.ItemSummary
import app.octap.vault.ItemType
import app.octap.vault.VaultRole
import kotlinx.coroutines.launch

private const val SHOWN = 8

/** A login that only holds a one-time code: what an authenticator import or a scan makes (`isCodeOnly`). */
fun isCodeOnly(item: Item): Boolean {
    val login = when (val details = item.details) {
        is ItemDetails.Login -> details.login
        is ItemDetails.Password -> details.login
        else -> return false
    }
    return !login.totp.isNullOrEmpty() && login.password.isNullOrEmpty() && item.urls.isEmpty() && login.passkeys.isEmpty()
}

/** "GitHub (octo@example.com)", or whichever of the two there is (`codeLabel`). */
@Composable
fun codeLabel(issuer: String?, account: String?, title: String? = null): String {
    val name = issuer?.takeIf { it.isNotEmpty() } ?: title?.takeIf { it.isNotEmpty() }
    return when {
        name != null && !account.isNullOrEmpty() -> "$name ($account)"
        else -> name ?: account?.takeIf { it.isNotEmpty() } ?: stringResource(R.string.otp_untitled)
    }
}

/** The logins a one-time code can join: in vaults the user can change (`useLogins`). */
@Composable
fun rememberLogins(): List<ItemSummary>? {
    val model = LocalVault.current.model
    return rememberLive(model) {
        val writable = model.vault.listVaults().filter { it.role != VaultRole.READ && !it.untrusted }.map { it.id }.toSet()
        model.vault.listItems(ItemFilter(null, null, null, false, false, false, false, null, null))
            .filter { (it.itemType == ItemType.Login || it.itemType == ItemType.Password) && it.vaultId in writable }
    }.data
}

/** Title, username and website, each word anywhere (`matchesLogin`). */
fun matchesLogin(item: ItemSummary, query: String): Boolean {
    val haystack = (listOf(item.title, item.subtitle.orEmpty()) + item.urls.map { hostOf(it) ?: it }).joinToString(" ").lowercase()
    return query.lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }.all { haystack.contains(it) }
}

/** A searchable list of logins; logins that already have a code can't be picked (`LoginPicker`). */
@Composable
fun LoginPicker(
    logins: List<ItemSummary>,
    value: String?,
    onChange: (String?) -> Unit,
    label: String,
    taken: Set<String> = emptySet(),
    allowSeparate: Boolean = true,
    exclude: String? = null,
) {
    var query by remember { mutableStateOf("") }
    val candidates = logins.filter { it.id != exclude && (query.isBlank() || matchesLogin(it, query.trim())) }
    val chosen = logins.firstOrNull { it.id == value }
    val shown = candidates.take(SHOWN).let { if (chosen != null && chosen !in it) listOf(chosen) + it else it }
    val untitled = stringResource(R.string.detail_untitled)
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            placeholder = { Text(stringResource(R.string.otp_searchLogins)) },
            leadingIcon = { Icon(Icons.Outlined.Search, contentDescription = null) },
            singleLine = true,
            label = { Text(label) },
            modifier = Modifier.fillMaxWidth().testTag("picker.search"),
        )
        Column(Modifier.selectableGroup()) {
            if (allowSeparate) {
                Row(Modifier.fillMaxWidth().selectable(value == null, role = Role.RadioButton) { onChange(null) }.padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(value == null, null)
                    Icon(Icons.Outlined.Add, null, Modifier.padding(horizontal = 8.dp).size(18.dp))
                    Text(stringResource(R.string.otp_separate))
                }
            }
            for (login in shown) {
                val unavailable = login.id != value && (login.hasTotp || login.id in taken)
                Row(
                    Modifier.fillMaxWidth().selectable(value == login.id, enabled = !unavailable, role = Role.RadioButton) { onChange(login.id) }.padding(vertical = 6.dp).testTag("picker.${login.id}"),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(value == login.id, null, enabled = !unavailable)
                    Avatar(login.title, 28.dp, Modifier.padding(horizontal = 8.dp))
                    Column {
                        Text(login.title.ifEmpty { untitled }, style = MaterialTheme.typography.bodyLarge)
                        Text(
                            if (unavailable) stringResource(if (login.hasTotp) R.string.otp_hasCode else R.string.otp_takenByOther)
                            else listOfNotNull(login.subtitle, login.urls.firstOrNull()?.let { hostOf(it) ?: it }).joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
            if (candidates.isEmpty()) Text(stringResource(R.string.otp_noLogins), style = MaterialTheme.typography.bodySmall)
            if (candidates.size > SHOWN) Text(pluralStringResource(R.plurals.otp_moreLogins, candidates.size - SHOWN, candidates.size - SHOWN), style = MaterialTheme.typography.bodySmall)
        }
    }
}

/**
 * A one-time code on an item of its own → Move this code to a login (`LinkToLoginDialog`): the
 * code moves into the chosen login, with all its settings, and this item goes to the trash.
 */
@Composable
fun LinkToLoginDialog(item: Item, onClose: () -> Unit) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val logins = rememberLogins()
    var target by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        title = { Text(stringResource(R.string.otp_linkTitle)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.otp_linkHelp), style = MaterialTheme.typography.bodySmall)
                if (logins == null) CircularProgressIndicator(Modifier.size(24.dp))
                else LoginPicker(logins, target, { target = it }, stringResource(R.string.otp_linkPicker), allowSeparate = false, exclude = item.id)
                error?.let { Alert(it) }
            }
        },
        dismissButton = { TextButton(onClick = onClose, enabled = !busy) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = {
            TextButton(
                enabled = target != null && !busy,
                modifier = Modifier.testTag("link.confirm"),
                onClick = {
                    val loginId = target ?: return@TextButton
                    busy = true
                    error = null
                    scope.launch {
                        try {
                            val login = model.vault.getItem(loginId)
                            val totp = (item.details as? ItemDetails.Login)?.login?.totp ?: (item.details as? ItemDetails.Password)?.login?.totp
                            val draft = app.octap.vault.itemDraft(login)
                            val details = when (val d = draft.details) {
                                is ItemDetails.Login -> ItemDetails.Login(d.login.copy(totp = totp))
                                is ItemDetails.Password -> ItemDetails.Password(d.login.copy(totp = totp))
                                else -> d
                            }
                            model.vault.saveItem(draft.copy(details = details))
                            model.vault.deleteItem(item.id)
                            model.toast(context.getString(R.string.otp_linked, login.title), Toast.Tone.Success)
                            onClose()
                            vault.close()
                            vault.open(Route.Item(login.id))
                        } catch (e: Exception) {
                            error = errorMessage(context, e)
                        } finally {
                            busy = false
                        }
                    }
                },
            ) { Text(stringResource(R.string.otp_linkAction)) }
        },
    )
}
