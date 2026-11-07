package app.octap.android.ui.sharing

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import app.octap.android.model.PendingKit
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.ui.auth.MIN_SCORE
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.StrengthHint
import app.octap.android.ui.settings.Confirm
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.tools.SettingsRow
import app.octap.android.ui.tools.SettingsSection
import app.octap.android.ui.tools.VaultPage
import app.octap.android.ui.util.Formats
import app.octap.android.ui.util.formatDate
import app.octap.android.ui.util.haptic
import app.octap.android.ui.util.rememberLive
import app.octap.android.ui.util.shownLocale
import app.octap.android.ui.vault.Choice
import app.octap.android.ui.vault.FieldList
import app.octap.android.ui.vault.LocalVault
import app.octap.android.ui.vault.Route
import app.octap.android.ui.vault.TypeFields
import app.octap.android.ui.vault.vaultName
import app.octap.resources.R
import app.octap.vault.EmergencyAccessLevel
import app.octap.vault.EmergencyContact
import app.octap.vault.EmergencyScope
import app.octap.vault.EmergencyStatus
import app.octap.vault.ErrorCode
import app.octap.vault.Item
import app.octap.vault.Vault
import app.octap.vault.VaultRole
import kotlinx.coroutines.launch

private val WAIT_DAYS = listOf(1, 2, 3, 7, 14, 30)

private sealed interface EmergencyConfirm {
    val contact: EmergencyContact

    data class Remove(override val contact: EmergencyContact) : EmergencyConfirm
    data class Request(override val contact: EmergencyContact) : EmergencyConfirm
    data class StepDown(override val contact: EmergencyContact) : EmergencyConfirm
}

@Composable
private fun scopeLabel(contact: EmergencyContact, vaults: List<Vault>?): String = when (val scope = contact.scope) {
    EmergencyScope.Account -> stringResource(R.string.emergency_scopeAccount)
    is EmergencyScope.Vault -> stringResource(R.string.emergency_scopeVault, vaults?.firstOrNull { it.id == scope.vaultId }?.let { vaultName(it) } ?: stringResource(R.string.scopes_vault))
}

/** Emergency access (`EmergencyPage`, plan 06): trusted contacts both ways, and the request, deny and release timeline. */
@Composable
fun EmergencyScreen() {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val vaults = rememberLive(model, sharing = true) { model.vault.listVaults() }.data
    val contacts = rememberLive(model, sharing = true) { model.vault.listEmergencyContacts() }.data
    var confirm by remember { mutableStateOf<EmergencyConfirm?>(null) }
    var renewing by remember { mutableStateOf<EmergencyContact?>(null) }
    var waitDays by remember { mutableStateOf(7) }
    var accessLevel by remember { mutableStateOf(EmergencyAccessLevel.VIEW) }
    var scope by remember { mutableStateOf<String?>(null) }
    val locale = shownLocale()

    fun act(message: String, action: suspend () -> Unit) = model.launch {
        action()
        model.toast(message, Toast.Tone.Success)
    }

    VaultPage(stringResource(R.string.emergency_title), stringResource(R.string.emergency_subtitle), tag = "emergency.title") {
        Alert(stringResource(R.string.emergency_how), AlertTone.Info)
        SettingsSection(stringResource(R.string.emergency_contacts), tag = "emergency.contacts") {
            when {
                contacts == null -> CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
                contacts.granted.isEmpty() -> SettingsRow(stringResource(R.string.emergency_noContacts))
                else -> for (contact in contacts.granted) {
                    Column {
                        SettingsRow(
                            contact.contactEmail,
                            listOf(
                                scopeLabel(contact, vaults),
                                stringResource(
                                    when {
                                        contact.organiserRecovery -> R.string.emergency_organiserRecovery
                                        contact.accessLevel == EmergencyAccessLevel.VIEW -> R.string.emergency_view
                                        else -> R.string.emergency_takeover
                                    },
                                ),
                                pluralStringResource(R.plurals.emergency_days, contact.waitDays.toInt(), contact.waitDays.toInt()),
                            ).joinToString(" · "),
                        ) {
                            IconButton(onClick = { confirm = EmergencyConfirm.Remove(contact) }) {
                                Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.emergency_remove, contact.contactEmail))
                            }
                        }
                        if (contact.keyStale) {
                            Alert(stringResource(R.string.emergency_keyStale), AlertTone.Warn, Modifier.padding(horizontal = 16.dp, vertical = 4.dp).testTag("emergency.keyStale")) {
                                TextButton(onClick = { renewing = contact }, modifier = Modifier.testTag("emergency.renew")) { Text(stringResource(R.string.emergency_renew)) }
                            }
                        }
                        when (contact.status) {
                            EmergencyStatus.IDLE -> Text(stringResource(R.string.emergency_statusIdle), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 16.dp, bottom = 8.dp))
                            EmergencyStatus.REQUESTED -> Alert(stringResource(R.string.emergency_statusRequested, formatDate(contact.requestedAt.orEmpty()), formatDate(contact.releasesAt.orEmpty(), long = true)), AlertTone.Warn, Modifier.padding(horizontal = 16.dp, vertical = 4.dp)) {
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    TextButton(onClick = { act(context.getString(R.string.emergency_denied)) { model.vault.denyEmergencyAccess(contact.id) } }) { Text(stringResource(R.string.emergency_deny)) }
                                    TextButton(onClick = { act(context.getString(R.string.emergency_approved, contact.contactEmail)) { model.vault.approveEmergencyAccess(contact.id) } }) { Text(stringResource(R.string.emergency_approve)) }
                                }
                            }
                            EmergencyStatus.RELEASED -> Alert(stringResource(R.string.emergency_statusReleased, formatDate(contact.releasedAt.orEmpty(), long = true)), AlertTone.Info, Modifier.padding(horizontal = 16.dp, vertical = 4.dp)) {
                                TextButton(onClick = { act(context.getString(R.string.emergency_denied)) { model.vault.denyEmergencyAccess(contact.id) } }) { Text(stringResource(R.string.emergency_denyReleased)) }
                            }
                        }
                    }
                }
            }
        }
        SettingsSection(stringResource(R.string.emergency_add), tag = "emergency.add") {
            val owned = vaults.orEmpty().filter { it.role == VaultRole.OWNER && !it.untrusted }
            AccountFinder(
                stringResource(R.string.emergency_addAction),
                options = {
                    Choice(stringResource(R.string.emergency_waitDays), WAIT_DAYS.map { it.toString() to pluralStringResource(R.plurals.emergency_days, it, it) }, waitDays.toString()) { waitDays = it?.toInt() ?: 7 }
                    Choice(
                        stringResource(R.string.emergency_scope),
                        listOf<Pair<String?, String>>(null to stringResource(R.string.emergency_scopeAccount)) + owned.map { it.id to stringResource(R.string.emergency_scopeVault, vaultName(it)) },
                        scope,
                    ) {
                        scope = it
                        // Takeover needs the whole account: the server refuses it for one vault.
                        if (it != null) accessLevel = EmergencyAccessLevel.VIEW
                    }
                    Text(stringResource(R.string.emergency_accessLevel), style = MaterialTheme.typography.labelLarge)
                    SingleChoiceSegmentedButtonRow {
                        listOf(EmergencyAccessLevel.VIEW to R.string.emergency_view, EmergencyAccessLevel.TAKEOVER to R.string.emergency_takeover).forEachIndexed { i, (level, label) ->
                            SegmentedButton(selected = accessLevel == level, onClick = {
                                accessLevel = level
                                if (level == EmergencyAccessLevel.TAKEOVER) scope = null
                            }, shape = SegmentedButtonDefaults.itemShape(i, 2)) { Text(stringResource(label)) }
                        }
                    }
                    Text(stringResource(if (accessLevel == EmergencyAccessLevel.VIEW) R.string.emergency_viewHelp else R.string.emergency_takeoverHelp), style = MaterialTheme.typography.bodySmall)
                    if (accessLevel == EmergencyAccessLevel.TAKEOVER) Alert(stringResource(R.string.emergency_takeoverWarning), AlertTone.Warn)
                },
            ) { account ->
                model.vault.addEmergencyContact(account, waitDays.toUInt(), accessLevel, scope?.let { EmergencyScope.Vault(it) } ?: EmergencyScope.Account)
                model.toast(context.getString(R.string.emergency_added, account.email), Toast.Tone.Success)
            }
        }
        SettingsSection(stringResource(R.string.emergency_received), tag = "emergency.received") {
            when {
                contacts == null -> CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
                contacts.received.isEmpty() -> SettingsRow(stringResource(R.string.emergency_noReceived))
                else -> for (contact in contacts.received) {
                    val email = contact.grantorEmail
                    val status = when (contact.status) {
                        EmergencyStatus.IDLE -> stringResource(R.string.emergency_receivedIdle, email, pluralStringResource(R.plurals.emergency_days, contact.waitDays.toInt(), contact.waitDays.toInt()))
                        EmergencyStatus.REQUESTED -> stringResource(R.string.emergency_receivedRequested, email, formatDate(contact.releasesAt.orEmpty(), long = true), email)
                        EmergencyStatus.RELEASED -> stringResource(
                            if (contact.organiserRecovery) R.string.emergency_organiserReleased else R.string.emergency_receivedReleased,
                            formatDate(contact.releasedAt.orEmpty(), long = true),
                        )
                    }
                    SettingsRow(email, status)
                    if (contact.keyStale && contact.status == EmergencyStatus.RELEASED) {
                        Text(stringResource(R.string.emergency_receivedStale, email), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(horizontal = 16.dp))
                    }
                    Row(Modifier.padding(start = 8.dp, bottom = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = { confirm = EmergencyConfirm.StepDown(contact) }) { Text(stringResource(R.string.emergency_stepDown)) }
                        if (contact.status == EmergencyStatus.IDLE) OutlinedButton(onClick = { confirm = EmergencyConfirm.Request(contact) }) { Text(stringResource(R.string.emergency_request)) }
                        // The organiser can reset an account, never read it.
                        if (contact.status == EmergencyStatus.RELEASED && !contact.organiserRecovery) OutlinedButton(onClick = { vault.nav.push(Route.EmergencyVault(contact.id)) }, modifier = Modifier.testTag("emergency.open")) { Text(stringResource(R.string.emergency_open)) }
                    }
                    // Released, and for the whole account: a vault's key can't open an account.
                    if (contact.status == EmergencyStatus.RELEASED && contact.accessLevel == EmergencyAccessLevel.TAKEOVER && contact.scope == EmergencyScope.Account) {
                        OutlinedButton(onClick = { vault.nav.push(Route.Takeover(contact.id, email)) }, modifier = Modifier.padding(start = 16.dp, bottom = 8.dp).testTag("emergency.takeover")) {
                            Text(stringResource(R.string.takeover_action), color = Brand.colors.dangerText)
                        }
                    }
                }
            }
        }
    }
    renewing?.let { RenewDialog(it) { renewing = null } }
    confirm?.let { current ->
        val contact = current.contact
        when (current) {
            is EmergencyConfirm.Remove -> Confirm(stringResource(R.string.emergency_removeTitle, contact.contactEmail), stringResource(R.string.emergency_removeBody), stringResource(R.string.common_remove), onDismiss = { confirm = null }) {
                confirm = null
                act(context.getString(R.string.emergency_removed, contact.contactEmail)) { model.vault.removeEmergencyContact(contact.id) }
            }
            is EmergencyConfirm.Request -> Confirm(stringResource(R.string.emergency_requestTitle, contact.grantorEmail), stringResource(R.string.emergency_requestBody, contact.grantorEmail), stringResource(R.string.emergency_request), danger = false, onDismiss = { confirm = null }) {
                confirm = null
                model.launch {
                    model.vault.requestEmergencyAccess(contact.id)
                    val updated = model.vault.listEmergencyContacts().received.firstOrNull { it.id == contact.id }
                    model.toast(context.getString(R.string.emergency_requested, Formats.date(updated?.releasesAt.orEmpty(), locale, long = true)), Toast.Tone.Success)
                }
            }
            is EmergencyConfirm.StepDown -> Confirm(stringResource(R.string.emergency_stepDownTitle, contact.grantorEmail), stringResource(R.string.emergency_stepDownBody, contact.grantorEmail), stringResource(R.string.emergency_stepDown), onDismiss = { confirm = null }) {
                confirm = null
                act(context.getString(R.string.emergency_steppedDown, contact.grantorEmail)) { model.vault.removeEmergencyContact(contact.id) }
            }
        }
    }
}

/** A rotated vault's key, sealed to the contact again once the user has seen their fingerprint (`RenewDialog`). */
@Composable
private fun RenewDialog(contact: EmergencyContact, onClose: () -> Unit) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(stringResource(R.string.emergency_renewTitle, contact.contactEmail)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(stringResource(R.string.emergency_renewBody))
                // The fingerprint comes first: the action only shows once it's on screen.
                AccountFinder(stringResource(R.string.emergency_renew), fixedEmail = contact.contactEmail, findAtOnce = true) { account ->
                    model.vault.renewEmergencyKey(contact.id, account)
                    model.toast(context.getString(R.string.emergency_renewed, contact.contactEmail), Toast.Tone.Success)
                    onClose()
                }
            }
        },
        confirmButton = { TextButton(onClick = onClose) { Text(stringResource(R.string.common_cancel)) } },
    )
}

/**
 * As the contact of a released takeover record (`TakeoverDialog`): this account's own master
 * password, a new one for the grantor, then the new Recovery Kit. The call runs in the model's
 * scope, not this screen's: leaving must not cancel it after the server took the new keys, or
 * the only copy of the kit would be lost.
 */
@Composable
fun TakeoverScreen(contactId: String, email: String) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    var own by remember { mutableStateOf("") }
    var new by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var ownError by remember { mutableStateOf<String?>(null) }
    var newError by remember { mutableStateOf<String?>(null) }
    var confirmError by remember { mutableStateOf<String?>(null) }
    var formError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val estimate = remember(new) { model.vault.estimateStrength(new) }
    BackHandler(enabled = busy) {}

    fun submit() {
        if (busy) return
        ownError = if (own.isEmpty()) context.getString(R.string.validation_passwordRequired) else null
        newError = when {
            new.isEmpty() -> context.getString(R.string.changePassword_newRequired)
            estimate.score.toInt() < MIN_SCORE -> context.getString(R.string.validation_passwordTooWeak)
            else -> null
        }
        confirmError = if (confirm != new) context.getString(R.string.validation_passwordsDontMatch) else null
        formError = null
        if (ownError != null || newError != null || confirmError != null) {
            haptic(context, Toast.Tone.Danger)
            return
        }
        busy = true
        val title = context.getString(R.string.takeover_kitTitle)
        val body = context.getString(R.string.takeover_kitBody, email)
        model.scope.launch {
            try {
                val kit = model.vault.takeOverAccount(contactId, own, new)
                model.newKit.value = PendingKit(kit, title, body)
                own = ""
                new = ""
                confirm = ""
                if (vault.nav.top is Route.Takeover) vault.nav.pop()
            } catch (error: Exception) {
                haptic(context, Toast.Tone.Danger)
                own = ""
                if (error.isCode(ErrorCode.INVALID_CREDENTIALS)) ownError = context.getString(R.string.takeover_wrongOwn) else formError = errorMessage(context, error)
            } finally {
                busy = false
            }
        }
    }

    VaultPage(stringResource(R.string.takeover_title, email), tag = "takeover.title") {
        Alert(stringResource(R.string.takeover_warning, email), modifier = Modifier.testTag("takeover.warning"))
        formError?.let { Alert(it, modifier = Modifier.testTag("takeover.error")) }
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            PasswordField(
                value = own,
                onValueChange = { own = it },
                label = stringResource(R.string.takeover_ownPassword),
                error = ownError,
                imeAction = ImeAction.Next,
                modifier = Modifier.fillMaxWidth().testTag("takeover.own"),
            )
            Column {
                PasswordField(
                    value = new,
                    onValueChange = { new = it },
                    label = stringResource(R.string.takeover_newPassword, email),
                    error = newError,
                    imeAction = ImeAction.Next,
                    modifier = Modifier.fillMaxWidth().testTag("takeover.new"),
                )
                StrengthHint(estimate, empty = new.isEmpty())
            }
            PasswordField(
                value = confirm,
                onValueChange = { confirm = it },
                label = stringResource(R.string.fields_confirmPassword),
                error = confirmError,
                onImeAction = ::submit,
                modifier = Modifier.fillMaxWidth().testTag("takeover.confirm"),
            )
        }
        PrimaryButton(stringResource(R.string.takeover_submit), ::submit, busy = busy, modifier = Modifier.testTag("takeover.submit"))
    }
}

/** As a trusted contact, after release (`EmergencyVaultPage`): the grantor's vaults, read-only, decrypted on this phone. */
@Composable
fun EmergencyVaultScreen(contactId: String) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val view = rememberLive(model, contactId) { model.vault.openEmergencyAccess(contactId) }
    var selected by remember { mutableStateOf<Item?>(null) }
    val data = view.data
    VaultPage(data?.let { stringResource(R.string.emergency_vaultTitle, it.contact.grantorEmail) } ?: stringResource(R.string.emergency_title), tag = "emergencyVault.title") {
        when {
            view.error != null && data == null -> Alert(stringResource(R.string.emergency_vaultFailed) + " " + errorMessage(context, view.error!!))
            data == null -> CircularProgressIndicator()
            else -> {
                Alert(stringResource(R.string.emergency_vaultReadOnly), AlertTone.Warn)
                val shown = selected
                if (shown != null) {
                    TextButton(onClick = { selected = null }) { Text(stringResource(R.string.common_back)) }
                    Text(shown.title.ifEmpty { stringResource(R.string.detail_untitled) }, style = MaterialTheme.typography.headlineSmall)
                    TypeFields(shown)
                    EmergencyFiles(contactId, shown)
                } else if (data.items.isEmpty()) {
                    Text(stringResource(R.string.emergency_vaultEmpty))
                } else {
                    for (v in data.vaults) {
                        val items = data.items.filter { it.vaultId == v.id }.sortedBy { it.title.lowercase() }
                        if (items.isEmpty()) continue
                        FieldList(vaultName(v)) {
                            for (item in items) {
                                Row(
                                    Modifier.fillMaxWidth().clickable { selected = item }.padding(horizontal = 16.dp, vertical = 10.dp).testTag("emergencyVault.item.${item.id}"),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    app.octap.android.ui.components.Avatar(item.title, 36.dp)
                                    Column {
                                        Text(item.title.ifEmpty { stringResource(R.string.detail_untitled) })
                                        item.subtitle?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/** The grantor's files, read-only: each opens in the app the user picks, decrypted on this phone. */
@Composable
private fun EmergencyFiles(contactId: String, item: app.octap.vault.Item) {
    val model = LocalVault.current.model
    val open = app.octap.android.ui.vault.rememberAttachmentOpener(model) { attachment, itemId ->
        model.vault.openEmergencyAttachment(contactId, itemId, attachment.id)
    }
    if (item.attachments.isEmpty()) return
    FieldList(stringResource(R.string.files_title)) {
        for (attachment in item.attachments) {
            TextButton(onClick = { open(item.id, attachment) }, modifier = Modifier.padding(horizontal = 8.dp).testTag("emergencyVault.file.${attachment.id}")) { Text(attachment.name) }
        }
    }
}
