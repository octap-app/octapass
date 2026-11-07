package app.octap.android.ui.tools

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Mail
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
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
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.Avatar
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.theme.monoStyle
import app.octap.android.ui.util.rememberLive
import app.octap.android.ui.vault.Choice
import app.octap.android.ui.vault.LocalVault
import app.octap.android.ui.vault.Route
import app.octap.android.ui.vault.copy
import app.octap.android.ui.vault.providerName
import app.octap.resources.R
import app.octap.vault.MaskedAlias
import app.octap.vault.RecoveryContact
import app.octap.vault.canManageAlias
import app.octap.vault.MaskedEmailConnection
import app.octap.vault.maskedEmailProviders
import kotlinx.coroutines.launch

/** A titled card of rows, as the settings pages lay them out (`Section`). */
@Composable
fun SettingsSection(title: String, description: String? = null, tag: String? = null, content: @Composable () -> Unit) {
    Column(Modifier.padding(top = 8.dp).let { if (tag != null) it.testTag(tag) else it }, verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
        if (description != null) Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        OutlinedCard(Modifier.fillMaxWidth()) { Column(Modifier.padding(vertical = 4.dp)) { content() } }
    }
}

/** One row in a settings card: a label, an optional description and its control. */
@Composable
fun SettingsRow(label: String, description: String? = null, modifier: Modifier = Modifier, onClick: (() -> Unit)? = null, control: (@Composable () -> Unit)? = null) {
    Row(
        modifier.fillMaxWidth().heightIn(min = 56.dp).let { if (onClick != null) it.clickable(onClick = onClick) else it }.padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge)
            if (description != null) Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        control?.invoke()
    }
}

/** Masked email (`MaskedEmailPage`): providers, a new alias for a site, and the aliases logins use. */
@Composable
fun MaskedEmailScreen() {
    VaultPage(stringResource(R.string.maskedEmail_title), stringResource(R.string.maskedEmail_subtitle), tag = "maskedEmail.title") {
        ProvidersSection()
        AliasMakerSection()
        AliasesSection()
    }
}

@Composable
private fun ProvidersSection() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val connections = rememberLive(model, sharing = true) { model.vault.maskedEmailConnections() }.data
    var leaving by remember { mutableStateOf<MaskedEmailConnection?>(null) }
    SettingsSection(stringResource(R.string.maskedEmail_providers), stringResource(R.string.maskedEmail_providersHelp), tag = "maskedEmail.providers") {
        if (connections?.isEmpty() == true) SettingsRow(stringResource(R.string.maskedEmail_none))
        for (connection in connections.orEmpty()) {
            val details = listOfNotNull(connection.domain, connection.baseUrl?.let { Uri.parse(it).host }).joinToString(" · ").ifEmpty { null }
            Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Avatar(providerName(connection.provider), 32.dp)
                Column(Modifier.weight(1f)) {
                    Text(providerName(connection.provider), style = MaterialTheme.typography.bodyLarge)
                    details?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                }
                OutlinedButton(onClick = { leaving = connection }) { Text(stringResource(R.string.maskedEmail_disconnect)) }
            }
        }
        HorizontalDivider()
        ConnectForm()
    }
    leaving?.let { connection ->
        val name = providerName(connection.provider)
        AlertDialog(
            onDismissRequest = { leaving = null },
            title = { Text(stringResource(R.string.maskedEmail_disconnectTitle, name)) },
            text = { Text(stringResource(R.string.maskedEmail_disconnectBody, name)) },
            dismissButton = { TextButton(onClick = { leaving = null }) { Text(stringResource(R.string.common_cancel)) } },
            confirmButton = {
                TextButton(onClick = {
                    leaving = null
                    model.launch {
                        model.vault.disconnectMaskedEmail(connection.itemId)
                        model.toast(context.getString(R.string.maskedEmail_disconnected, name), Toast.Tone.Success)
                    }
                }) { Text(stringResource(R.string.maskedEmail_disconnect)) }
            },
        )
    }
}

@Composable
private fun ConnectForm() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val providers = remember { maskedEmailProviders() }
    var provider by remember { mutableStateOf(providers.firstOrNull()?.id ?: "simplelogin") }
    var token by remember { mutableStateOf("") }
    var domain by remember { mutableStateOf("") }
    var baseUrl by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val info = providers.firstOrNull { it.id == provider }
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(R.string.maskedEmail_connect), style = MaterialTheme.typography.titleSmall)
        Choice(stringResource(R.string.maskedEmail_provider), providers.map { it.id to it.name }, provider, tag = "maskedEmail.provider") { provider = it ?: provider }
        PasswordField(token, { token = it }, stringResource(R.string.maskedEmail_token), hint = stringResource(R.string.maskedEmail_tokenHint, info?.name.orEmpty()), contentType = null, modifier = Modifier.testTag("maskedEmail.token"))
        if (info != null) {
            TextButton(onClick = {
                try {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(info.tokenUrl)))
                } catch (ignored: ActivityNotFoundException) {
                }
            }) { Text(stringResource(R.string.maskedEmail_getToken)) }
        }
        if (info?.needsDomain == true) Field(domain, { domain = it }, stringResource(R.string.maskedEmail_domain), hint = stringResource(R.string.maskedEmail_domainHint), keyboardType = KeyboardType.Uri)
        info?.defaultBaseUrl?.let { default ->
            Field(baseUrl, { baseUrl = it }, stringResource(R.string.maskedEmail_selfHosted), placeholder = default, hint = stringResource(R.string.maskedEmail_selfHostedHint, info.name), keyboardType = KeyboardType.Uri)
        }
        error?.let { Alert(it) }
        OutlinedButton(
            enabled = token.isNotBlank() && !busy,
            modifier = Modifier.testTag("maskedEmail.connectButton"),
            onClick = {
                busy = true
                error = null
                scope.launch {
                    try {
                        model.vault.connectMaskedEmail(provider, token, baseUrl.trim().ifEmpty { null }, domain.trim().ifEmpty { null })
                        model.toast(context.getString(R.string.maskedEmail_connected, info?.name.orEmpty()), Toast.Tone.Success)
                        token = ""
                        domain = ""
                        baseUrl = ""
                    } catch (e: Exception) {
                        error = errorMessage(context, e)
                    } finally {
                        busy = false
                    }
                }
            },
        ) {
            Icon(Icons.Outlined.Add, null, Modifier.size(18.dp))
            Text(stringResource(R.string.maskedEmail_connectButton), Modifier.padding(start = 6.dp))
        }
    }
}

/** "Use a masked email" for a site the user types (`AliasMaker`): the generator's counterpart for email addresses. */
@Composable
fun AliasMakerSection() {
    val vault = LocalVault.current
    val model = vault.model
    val scope = rememberCoroutineScope()
    val connections = rememberLive(model, sharing = true) { runCatching { model.vault.maskedEmailConnections() }.getOrNull() }.data ?: return
    var site by remember { mutableStateOf("") }
    var connectionId by remember { mutableStateOf<String?>(null) }
    var alias by remember { mutableStateOf<MaskedAlias?>(null) }
    var busy by remember { mutableStateOf(false) }
    val emailWhat = stringResource(R.string.fields_email)
    SettingsSection(stringResource(R.string.maskedEmail_make), tag = "maskedEmail.make") {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            if (connections.isEmpty()) {
                Text(stringResource(R.string.errors_maskedEmailNotSetUp), style = MaterialTheme.typography.bodyMedium)
                TextButton(onClick = { vault.nav.push(Route.MaskedEmail) }) { Text(stringResource(R.string.maskedEmail_connect)) }
                return@Column
            }
            Field(site, { site = it }, stringResource(R.string.maskedEmail_site), placeholder = stringResource(R.string.maskedEmail_sitePlaceholder), keyboardType = KeyboardType.Uri, modifier = Modifier.testTag("maskedEmail.site"))
            if (connections.size > 1) {
                Choice(
                    stringResource(R.string.maskedEmail_useWith),
                    listOf<Pair<String?, String>>(null to providerName(connections.first().provider)) + connections.map { it.itemId to listOfNotNull(providerName(it.provider), it.domain).joinToString(" · ") },
                    connectionId,
                ) { connectionId = it }
            }
            OutlinedButton(
                enabled = site.isNotBlank() && !busy,
                modifier = Modifier.testTag("maskedEmail.makeButton"),
                onClick = {
                    busy = true
                    scope.launch {
                        try {
                            alias = model.vault.createAlias(site.trim(), connectionId)
                        } catch (e: Exception) {
                            model.toastError(e)
                        } finally {
                            busy = false
                        }
                    }
                },
            ) {
                Icon(Icons.Outlined.Mail, null, Modifier.size(18.dp))
                Text(stringResource(R.string.editor_useMaskedEmail), Modifier.padding(start = 6.dp))
            }
            alias?.let { made ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.maskedEmail_created), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(made.email, style = monoStyle.copy(textDirection = TextDirection.Ltr), modifier = Modifier.testTag("maskedEmail.alias"))
                    }
                    IconButton(onClick = { copy(model, made.email, emailWhat, secret = false) }) { Icon(Icons.Outlined.ContentCopy, contentDescription = stringResource(R.string.copy_action, emailWhat)) }
                }
            }
        }
    }
}

/** The aliases logins use, from the recovery map (`AliasesSection`). */
@Composable
private fun AliasesSection() {
    val vault = LocalVault.current
    val model = vault.model
    val report = rememberLive(model) { model.vault.healthReport() }.data
    val aliases = report?.recovery?.filter { it.aliasProvider != null }.orEmpty()
    val connections = rememberLive(model, sharing = true) { model.vault.maskedEmailConnections() }.data
    val context = LocalContext.current
    var busy by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf<RecoveryContact?>(null) }
    fun change(done: String, call: suspend () -> Unit) {
        busy = true
        model.launch {
            try {
                call()
                model.toast(done, Toast.Tone.Success)
            } finally {
                busy = false
            }
        }
    }
    SettingsSection(stringResource(R.string.maskedEmail_aliases), stringResource(R.string.maskedEmail_aliasesHelp)) {
        if (report != null && aliases.isEmpty()) SettingsRow(stringResource(R.string.maskedEmail_noAliases))
        for (alias in aliases) {
            Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                Text(alias.value, style = MaterialTheme.typography.bodyLarge.copy(textDirection = TextDirection.Ltr))
                Text("${providerName(alias.aliasProvider)} · ${pluralStringResource(R.plurals.maskedEmail_usedBy, alias.logins.size, alias.logins.size)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                for (login in alias.logins) {
                    TextButton(onClick = { vault.nav.push(Route.Item(login.itemId)) }) { Text(login.title) }
                }
                val provider = alias.aliasProvider.orEmpty()
                val aliasId = alias.aliasId ?: alias.value
                // The list comes from the vault, not the provider, so it doesn't know whether an
                // alias is on right now: both switches are offered, and repeating one does nothing.
                when {
                    !canManageAlias(provider, aliasId, alias.value) -> Text(stringResource(R.string.maskedEmail_manageThere, providerName(provider)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    connections?.any { it.provider == provider } != true -> Text(stringResource(R.string.maskedEmail_connectToManage, providerName(provider)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    else -> Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(enabled = !busy, modifier = Modifier.testTag("maskedEmail.turnOff"), onClick = {
                            change(context.getString(R.string.maskedEmail_turnedOff)) { model.vault.setAliasEnabled(provider, aliasId, alias.value, false) }
                        }) { Text(stringResource(R.string.maskedEmail_turnOff)) }
                        OutlinedButton(enabled = !busy, modifier = Modifier.testTag("maskedEmail.turnOn"), onClick = {
                            change(context.getString(R.string.maskedEmail_turnedOn)) { model.vault.setAliasEnabled(provider, aliasId, alias.value, true) }
                        }) { Text(stringResource(R.string.maskedEmail_turnOn)) }
                        TextButton(enabled = !busy, modifier = Modifier.testTag("maskedEmail.delete"), onClick = { deleting = alias }) { Text(stringResource(R.string.maskedEmail_delete)) }
                    }
                }
            }
        }
    }
    deleting?.let { alias ->
        val provider = alias.aliasProvider.orEmpty()
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text(stringResource(R.string.maskedEmail_deleteTitle)) },
            text = { Text(stringResource(R.string.maskedEmail_deleteBody, providerName(provider), alias.value)) },
            dismissButton = { TextButton(onClick = { deleting = null }) { Text(stringResource(R.string.common_cancel)) } },
            confirmButton = {
                TextButton(modifier = Modifier.testTag("maskedEmail.confirmDelete"), onClick = {
                    deleting = null
                    change(context.getString(R.string.maskedEmail_deleted)) {
                        model.vault.deleteAlias(provider, alias.aliasId ?: alias.value, alias.value, alias.logins.map { it.itemId })
                    }
                }) { Text(stringResource(R.string.maskedEmail_delete)) }
            },
        )
    }
}
