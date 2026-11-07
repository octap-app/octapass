package app.octap.android.ui.sharing

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.Avatar
import app.octap.android.ui.components.Field
import app.octap.android.ui.settings.Confirm
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.theme.monoStyle
import app.octap.android.ui.tools.SettingsRow
import app.octap.android.ui.tools.SettingsSection
import app.octap.android.ui.tools.VaultPage
import app.octap.android.ui.util.formatDate
import app.octap.android.ui.util.rememberLive
import app.octap.android.ui.vault.Choice
import app.octap.android.ui.vault.LocalVault
import app.octap.android.ui.vault.Route
import app.octap.android.ui.vault.Scope
import app.octap.android.ui.vault.vaultName
import app.octap.resources.R
import app.octap.vault.AccountLookup
import app.octap.vault.Family
import app.octap.vault.Fingerprint
import app.octap.vault.Vault
import app.octap.vault.VaultMember
import app.octap.vault.VaultRole
import app.octap.vault.VaultType
import kotlinx.coroutines.launch

fun roleRes(role: VaultRole) = when (role) {
    VaultRole.OWNER -> R.string.roles_owner
    VaultRole.MANAGE -> R.string.roles_manage
    VaultRole.WRITE -> R.string.roles_write
    VaultRole.READ -> R.string.roles_read
}

private fun roleHelpRes(role: VaultRole) = when (role) {
    VaultRole.OWNER -> R.string.roles_ownerHelp
    VaultRole.MANAGE -> R.string.roles_manageHelp
    VaultRole.WRITE -> R.string.roles_writeHelp
    VaultRole.READ -> R.string.roles_readHelp
}

/** Owners and managers change members; managers can't change owners (`roles.ts`). */
private fun canChangeMember(mine: VaultRole, theirs: VaultRole) = mine == VaultRole.OWNER || (mine == VaultRole.MANAGE && theirs != VaultRole.OWNER)

@Composable
private fun roleOptions(mine: VaultRole) = listOf(VaultRole.OWNER, VaultRole.MANAGE, VaultRole.WRITE, VaultRole.READ)
    .filter { mine == VaultRole.OWNER || it != VaultRole.OWNER }
    .map { it.name to "${stringResource(roleRes(it))}: ${stringResource(roleHelpRes(it))}" }

/** A key's fingerprint as digits and emoji, to read out to the other person (`KeyFingerprint`). */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun FingerprintView(fingerprint: Fingerprint, label: String) {
    val emojiLabel = stringResource(R.string.fingerprint_emoji)
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(fingerprint.digits, style = monoStyle.copy(textDirection = TextDirection.Ltr), modifier = Modifier.testTag("fingerprint.digits"))
        FlowRow(
            Modifier.semantics { contentDescription = "$emojiLabel: ${fingerprint.emoji.joinToString(", ") { it.name }}" },
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            for (emoji in fingerprint.emoji) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(emoji.emoji, fontSize = 26.sp)
                    Text(emoji.name, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

/**
 * Finds an account by email and shows its fingerprint to compare before anything is shared
 * (`AccountFinder`). Ticking "it matches" remembers the fingerprint on this phone.
 */
@Composable
fun AccountFinder(
    submitLabel: String,
    options: (@Composable () -> Unit)? = null,
    /** The one account this can be: the email can't be changed. */
    fixedEmail: String? = null,
    /** Looks [fixedEmail] up as soon as this shows, for a screen opened to do just that. */
    findAtOnce: Boolean = false,
    onSubmit: suspend (AccountLookup) -> Unit,
) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var email by remember { mutableStateOf(fixedEmail.orEmpty()) }
    var account by remember { mutableStateOf<AccountLookup?>(null) }
    var matches by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun run(action: suspend () -> Unit) {
        busy = true
        error = null
        scope.launch {
            try {
                action()
            } catch (e: Exception) {
                error = errorMessage(context, e)
            } finally {
                busy = false
            }
        }
    }

    if (findAtOnce && fixedEmail != null) {
        LaunchedEffect(fixedEmail) { run { account = model.vault.lookupAccount(fixedEmail); matches = false } }
    }

    val found = account
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (found == null) {
            Field(email, { email = it }, stringResource(R.string.people_email), error = error, keyboardType = KeyboardType.Email, readOnly = fixedEmail != null, modifier = Modifier.testTag("finder.email"))
            OutlinedButton(onClick = { run { account = model.vault.lookupAccount(email.trim()); matches = false } }, enabled = email.isNotBlank() && !busy, modifier = Modifier.testTag("finder.find")) {
                Text(stringResource(R.string.people_find))
            }
        } else {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Avatar(found.email, 36.dp)
                Column(Modifier.weight(1f)) {
                    Text(found.email, style = MaterialTheme.typography.bodyLarge)
                    Text(stringResource(R.string.people_found), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (fixedEmail == null) TextButton(onClick = { account = null }, enabled = !busy) { Text(stringResource(R.string.people_change)) }
            }
            FingerprintView(found.fingerprint, stringResource(R.string.fingerprint_title))
            Text(stringResource(R.string.fingerprint_compareHelp, found.email), style = MaterialTheme.typography.bodySmall)
            Row(Modifier.toggleable(matches, role = Role.Checkbox) { matches = it }.testTag("finder.matches"), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(matches, null)
                Text(stringResource(R.string.fingerprint_matches, found.email))
            }
            options?.invoke()
            error?.let { Alert(it) }
            OutlinedButton(
                enabled = !busy,
                modifier = Modifier.testTag("finder.submit"),
                onClick = {
                    run {
                        if (matches) model.vault.markVerified(found)
                        onSubmit(found)
                        account = null
                        email = fixedEmail.orEmpty()
                    }
                },
            ) { Text(submitLabel) }
        }
    }
}

/** Sharing (`SharingPage`, plan 06): your fingerprint, the vaults you share, your family and your share links. */
@Composable
fun SharingScreen() {
    val vault = LocalVault.current
    val model = vault.model
    var creating by remember { mutableStateOf(false) }
    val fingerprint = rememberLive(model) { model.vault.myFingerprint() }.data
    val vaults = rememberLive(model, sharing = true) { model.vault.listVaults() }.data
    VaultPage(
        stringResource(R.string.sharing_title),
        stringResource(R.string.sharing_subtitle),
        tag = "sharing.title",
        actions = { IconButton(onClick = { creating = true }, modifier = Modifier.testTag("sharing.newVault")) { Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.sharing_newVault)) } },
    ) {
        SettingsSection(stringResource(R.string.fingerprint_yours)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (fingerprint == null) CircularProgressIndicator(Modifier.size(24.dp)) else FingerprintView(fingerprint, stringResource(R.string.fingerprint_yours))
                Text(stringResource(R.string.fingerprint_yoursHelp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        SettingsSection(stringResource(R.string.sharing_vaults), stringResource(R.string.sharing_vaultsHelp), tag = "sharing.vaults") {
            val shared = vaults?.filter { it.vaultType == VaultType.SHARED }
            when {
                shared == null -> CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
                shared.isEmpty() -> SettingsRow(stringResource(R.string.sharing_noVaults))
                else -> for (v in shared) {
                    SettingsRow(
                        vaultName(v),
                        if (v.untrusted) stringResource(R.string.vault_untrusted) else stringResource(R.string.sharing_roleIn, stringResource(roleRes(v.role))),
                        onClick = { vault.nav.push(Route.VaultMembers(v.id)) },
                        modifier = Modifier.testTag("sharing.vault.${v.id}"),
                    )
                }
            }
        }
        SettingsSection(stringResource(R.string.family_title), tag = "sharing.family") { FamilyPanel() }
        SettingsSection(stringResource(R.string.sharing_links), stringResource(R.string.sharing_linksHelp), tag = "sharing.links") { ShareLinks() }
    }
    if (creating) CreateVaultDialog { creating = false }
}

@Composable
private fun ShareLinks() {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val links = rememberLive(model, sharing = true) { model.vault.listShareLinks() }.data
    when {
        links == null -> CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
        links.isEmpty() -> SettingsRow(stringResource(R.string.sharing_noLinks))
        else -> for (link in links) {
            val title = link.itemTitle ?: stringResource(R.string.sharing_linkItem)
            val meta = listOfNotNull(
                stringResource(R.string.sharing_linkExpires, formatDate(link.expiresAt, long = true)),
                pluralStringResource(R.plurals.sharing_linkViews, link.maxViews.toInt(), link.views.toInt(), link.maxViews.toInt()),
                if (link.passphraseRequired) stringResource(R.string.sharing_linkPassphrase) else null,
            ).joinToString(" · ")
            SettingsRow(title, meta, onClick = link.itemId?.let { id -> { vault.nav.push(Route.Item(id)) } }) {
                IconButton(onClick = {
                    model.launch {
                        model.vault.revokeShareLink(link.id)
                        model.toast(context.getString(R.string.sharing_revoked), Toast.Tone.Success)
                    }
                }) { Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.sharing_revokeLink, title), tint = Brand.colors.dangerText) }
            }
        }
    }
}

private sealed interface FamilyConfirm {
    data class Remove(val accountId: String, val email: String) : FamilyConfirm
    data object Leave : FamilyConfirm
    data object Delete : FamilyConfirm
}

/** Sharing → Family (`FamilyPanel`): create one, invite up to the limit, accept invitations, leave or remove. */
@Composable
private fun FamilyPanel() {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val state = rememberLive(model, sharing = true) { model.vault.getFamily() }.data
    var confirm by remember { mutableStateOf<FamilyConfirm?>(null) }

    fun act(message: Int, vararg args: Any, action: suspend () -> Unit) = model.launch {
        action()
        model.toast(context.getString(message, *args), Toast.Tone.Success)
    }

    if (state == null) {
        CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
        return
    }
    for (invite in state.invitations) {
        SettingsRow(stringResource(R.string.family_invitation, invite.organiserEmail), stringResource(R.string.family_invitedOn, formatDate(invite.invitedAt))) {
            TextButton(onClick = { act(R.string.family_declined) { model.vault.declineFamilyInvite(invite.familyId) } }) { Text(stringResource(R.string.family_decline)) }
            OutlinedButton(onClick = { act(R.string.family_joined) { model.vault.acceptFamilyInvite(invite.familyId) } }, modifier = Modifier.testTag("family.accept")) { Text(stringResource(R.string.family_accept)) }
        }
    }
    val family = state.family
    if (family == null) {
        SettingsRow(stringResource(R.string.family_help, 6)) {
            OutlinedButton(onClick = { act(R.string.family_created) { model.vault.createFamily() } }, modifier = Modifier.testTag("family.create")) { Text(stringResource(R.string.family_create)) }
        }
    } else {
        val used = family.members.size + family.invites.size
        val full = used.toUInt() >= family.maxMembers
        SettingsRow(stringResource(R.string.family_vault), stringResource(R.string.family_count, used, family.maxMembers.toInt())) {
            OutlinedButton(onClick = { vault.nav.showScope(Scope.InVault(family.vaultId)) }) { Text(stringResource(R.string.members_openVault)) }
        }
        for (member in family.members) {
            SettingsRow(
                if (member.isYou) stringResource(R.string.members_you, member.email) else member.email,
                stringResource(if (member.role == app.octap.vault.FamilyRole.ORGANISER) R.string.family_organiser else R.string.family_member),
            ) {
                if (family.isOrganiser && !member.isYou) {
                    IconButton(onClick = { confirm = FamilyConfirm.Remove(member.accountId, member.email) }) {
                        Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.family_remove, member.email), tint = Brand.colors.dangerText)
                    }
                }
            }
        }
        for (invite in family.invites) {
            SettingsRow(invite.email, "${stringResource(R.string.family_pending)} · ${stringResource(R.string.family_invitedOn, formatDate(invite.invitedAt))}") {
                IconButton(onClick = { act(R.string.family_cancelled) { model.vault.cancelFamilyInvite(invite.accountId) } }) {
                    Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.family_cancelInvite, invite.email))
                }
            }
        }
        if (family.isOrganiser) {
            Text(stringResource(R.string.family_invite), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(start = 16.dp, top = 8.dp))
            if (full) {
                Text(stringResource(R.string.family_full), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(16.dp))
            } else {
                AccountFinder(stringResource(R.string.family_inviteAction)) { account ->
                    model.vault.inviteToFamily(account)
                    model.toast(context.getString(R.string.family_invited, account.email), Toast.Tone.Success)
                }
            }
        }
        if (!family.isOrganiser) OrganiserRecovery(family)
        SettingsRow(
            stringResource(if (family.isOrganiser) R.string.family_delete else R.string.family_leave),
            stringResource(if (family.isOrganiser) R.string.family_deleteBody else R.string.family_leaveBody),
        ) {
            OutlinedButton(onClick = { confirm = if (family.isOrganiser) FamilyConfirm.Delete else FamilyConfirm.Leave }) {
                Text(stringResource(if (family.isOrganiser) R.string.family_delete else R.string.family_leave), color = Brand.colors.dangerText)
            }
        }
    }
    confirm?.let { current ->
        Confirm(
            title = when (current) {
                is FamilyConfirm.Remove -> stringResource(R.string.family_removeTitle, current.email)
                FamilyConfirm.Leave -> stringResource(R.string.family_leaveTitle)
                FamilyConfirm.Delete -> stringResource(R.string.family_deleteTitle)
            },
            body = stringResource(
                when (current) {
                    is FamilyConfirm.Remove -> R.string.family_removeBody
                    FamilyConfirm.Leave -> R.string.family_leaveBody
                    FamilyConfirm.Delete -> R.string.family_deleteBody
                },
            ),
            confirm = stringResource(
                when (current) {
                    is FamilyConfirm.Remove -> R.string.common_remove
                    FamilyConfirm.Leave -> R.string.family_leave
                    FamilyConfirm.Delete -> R.string.family_delete
                },
            ),
            onDismiss = { confirm = null },
        ) {
            confirm = null
            when (current) {
                is FamilyConfirm.Remove -> act(R.string.family_removed, current.email) { model.vault.removeFamilyMember(current.accountId) }
                FamilyConfirm.Leave -> act(R.string.family_left) { model.vault.leaveFamily() }
                FamilyConfirm.Delete -> act(R.string.family_deleted) { model.vault.deleteFamily() }
            }
        }
    }
}

private val RECOVERY_WAIT_DAYS = listOf(1, 2, 3, 7, 14, 30)

/** As a family member: the organiser helping recover this account (`OrganiserRecovery`). Off unless the member turns it on. */
@Composable
private fun OrganiserRecovery(family: Family) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val contacts = rememberLive(model, sharing = true) { model.vault.listEmergencyContacts() }.data
    var waitDays by remember { mutableStateOf(7) }
    var turningOff by remember { mutableStateOf(false) }
    val organiser = family.members.firstOrNull { it.accountId == family.organiserId } ?: return
    val record = contacts?.granted?.firstOrNull { it.organiserRecovery }

    Column(Modifier.padding(top = 8.dp).testTag("family.recovery")) {
        Text(stringResource(R.string.family_recovery_title), style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(horizontal = 16.dp))
        when {
            contacts == null -> CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
            record != null -> {
                val days = pluralStringResource(R.plurals.emergency_days, record.waitDays.toInt(), record.waitDays.toInt())
                SettingsRow(stringResource(R.string.family_recovery_on, record.contactEmail, days)) {
                    OutlinedButton(onClick = { turningOff = true }, modifier = Modifier.testTag("family.recovery.off")) { Text(stringResource(R.string.family_recovery_turnOff)) }
                }
            }
            else -> {
                Text(stringResource(R.string.family_recovery_help, organiser.email), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
                Alert(stringResource(R.string.family_recovery_warning), AlertTone.Warn, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
                // The organiser's fingerprint comes first: the action only shows once it's on screen.
                AccountFinder(
                    stringResource(R.string.family_recovery_turnOn),
                    options = {
                        Choice(stringResource(R.string.emergency_waitDays), RECOVERY_WAIT_DAYS.map { it.toString() to pluralStringResource(R.plurals.emergency_days, it, it) }, waitDays.toString(), tag = "family.recovery.wait") { waitDays = it?.toInt() ?: 7 }
                    },
                    fixedEmail = organiser.email,
                ) { account ->
                    model.vault.enableOrganiserRecovery(account, waitDays.toUInt())
                    model.toast(context.getString(R.string.family_recovery_turnedOn), Toast.Tone.Success)
                }
            }
        }
    }
    if (turningOff && record != null) {
        Confirm(stringResource(R.string.family_recovery_offTitle), stringResource(R.string.family_recovery_offBody), stringResource(R.string.family_recovery_turnOff), onDismiss = { turningOff = false }) {
            turningOff = false
            model.launch {
                model.vault.removeEmergencyContact(record.id)
                model.toast(context.getString(R.string.family_recovery_turnedOff), Toast.Tone.Success)
            }
        }
    }
}

/** Sharing → a vault (`VaultMembersPage`): who's in it, their roles and fingerprints, adding and removing people. */
@Composable
fun VaultMembersScreen(vaultId: String) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val vaults = rememberLive(model, sharing = true) { model.vault.listVaults() }.data
    val target: Vault? = vaults?.firstOrNull { it.id == vaultId }
    val members = rememberLive(model, vaultId, sharing = true) { model.vault.listMembers(vaultId) }
    var removing by remember { mutableStateOf<VaultMember?>(null) }
    var leaving by remember { mutableStateOf(false) }
    var inviteRole by remember { mutableStateOf(VaultRole.WRITE) }
    var name by remember(target?.name) { mutableStateOf(target?.name.orEmpty()) }
    if (target == null || target.vaultType == VaultType.PERSONAL) {
        VaultPage(stringResource(R.string.sharing_title)) {
            if (vaults == null) CircularProgressIndicator() else Text(stringResource(R.string.members_notFound))
        }
        return
    }
    val manager = (target.role == VaultRole.OWNER || target.role == VaultRole.MANAGE) && !target.untrusted
    val shared = target.vaultType == VaultType.SHARED
    val list = members.data
    val lastOwner = target.role == VaultRole.OWNER && (list?.count { it.role == VaultRole.OWNER } ?: 0) <= 1
    val unverified = list?.count { !it.verified } ?: 0
    val title = vaultName(target)
    VaultPage(title, stringResource(R.string.sharing_roleIn, stringResource(roleRes(target.role))), tag = "members.title") {
        OutlinedButton(onClick = { vault.nav.showScope(Scope.InVault(target.id)) }) { Text(stringResource(R.string.members_openVault)) }
        if (target.untrusted) Alert(stringResource(R.string.vault_untrustedBody, title), AlertTone.Warn)
        if (target.vaultType == VaultType.FAMILY) Alert(stringResource(R.string.members_familyVault), AlertTone.Info)
        if (shared && target.role != VaultRole.READ && !target.untrusted) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Field(name, { name = it.take(80) }, stringResource(R.string.members_rename), modifier = Modifier.weight(1f))
                OutlinedButton(
                    enabled = name.isNotBlank() && name.trim() != target.name,
                    onClick = {
                        model.launch {
                            model.vault.renameVault(target.id, name.trim())
                            model.toast(context.getString(R.string.members_renamed), Toast.Tone.Success)
                        }
                    },
                ) { Text(stringResource(R.string.common_rename)) }
            }
        }
        SettingsSection(stringResource(R.string.vault_members), if (unverified > 0) pluralStringResource(R.plurals.members_unverifiedCount, unverified, unverified) else null, tag = "members.list") {
            when {
                members.error != null && list == null -> Text(errorMessage(context, members.error!!), Modifier.padding(16.dp))
                list == null -> CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
                else -> for (member in list) MemberRow(target, member, shared && manager && !member.isYou && canChangeMember(target.role, member.role)) { removing = member }
            }
        }
        if (shared && manager) {
            SettingsSection(stringResource(R.string.members_invite), stringResource(R.string.members_inviteHelp), tag = "members.invite") {
                AccountFinder(
                    stringResource(R.string.members_inviteAction),
                    options = { Choice(stringResource(R.string.roles_label), roleOptions(target.role), inviteRole.name) { inviteRole = VaultRole.valueOf(it ?: "WRITE") } },
                ) { account ->
                    model.vault.addMember(target.id, account, inviteRole)
                    model.toast(context.getString(R.string.members_invited, account.email, title), Toast.Tone.Success)
                }
            }
        }
        if (shared) {
            SettingsSection(stringResource(R.string.members_leave)) {
                SettingsRow(stringResource(R.string.members_leave), stringResource(if (lastOwner) R.string.members_lastOwner else R.string.members_leaveHelp)) {
                    OutlinedButton(onClick = { leaving = true }, enabled = !lastOwner) { Text(stringResource(R.string.members_leave), color = Brand.colors.dangerText) }
                }
            }
        }
    }
    removing?.let { member ->
        Confirm(stringResource(R.string.members_removeTitle, member.email), stringResource(R.string.members_removeBody, title), stringResource(R.string.members_removeAction), onDismiss = { removing = null }) {
            removing = null
            model.launch {
                model.vault.removeMember(target.id, member.accountId)
                model.toast(context.getString(R.string.members_removed, member.email), Toast.Tone.Success)
            }
        }
    }
    if (leaving) {
        Confirm(stringResource(R.string.members_leaveTitle, title), stringResource(R.string.members_leaveBody), stringResource(R.string.members_leave), onDismiss = { leaving = false }) {
            leaving = false
            model.launch {
                model.vault.leaveVault(target.id)
                model.toast(context.getString(R.string.members_left, title), Toast.Tone.Success)
                vault.nav.reset(Route.Sharing)
            }
        }
    }
}

@Composable
private fun MemberRow(vault: Vault, member: VaultMember, editable: Boolean, onRemove: () -> Unit) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    var comparing by remember { mutableStateOf(false) }
    Column {
        SettingsRow(
            if (member.isYou) stringResource(R.string.members_you, member.email) else member.email,
            listOf(
                stringResource(if (member.verified) R.string.fingerprint_verified else R.string.fingerprint_unverified),
                stringResource(R.string.members_added, formatDate(member.addedAt)),
                if (!editable) stringResource(roleRes(member.role)) else "",
            ).filter { it.isNotEmpty() }.joinToString(" · "),
        ) {
            if (!member.isYou) TextButton(onClick = { comparing = !comparing }) { Text(stringResource(R.string.fingerprint_verify)) }
            if (editable) {
                IconButton(onClick = onRemove) { Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.members_remove, member.email), tint = Brand.colors.dangerText) }
            }
        }
        if (editable) {
            Column(Modifier.padding(horizontal = 16.dp)) {
                Choice(stringResource(R.string.roles_label), roleOptions(vault.role), member.role.name) { value ->
                    val role = VaultRole.valueOf(value ?: return@Choice)
                    model.launch {
                        model.vault.changeRole(vault.id, member.accountId, role)
                        model.toast(context.getString(R.string.members_roleChanged, member.email, context.getString(roleRes(role))), Toast.Tone.Success)
                    }
                }
            }
        }
        if (comparing) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                FingerprintView(member.fingerprint, stringResource(R.string.fingerprint_title))
                Text(stringResource(R.string.fingerprint_compareHelp, member.email), style = MaterialTheme.typography.bodySmall)
                if (!member.verified) {
                    OutlinedButton(onClick = {
                        model.launch {
                            model.vault.markVerified(AccountLookup(member.accountId, member.email, "", "", member.fingerprint))
                            model.toast(context.getString(R.string.fingerprint_markedVerified), Toast.Tone.Success)
                        }
                    }) {
                        Icon(Icons.Outlined.Check, null, Modifier.size(18.dp))
                        Text(stringResource(R.string.fingerprint_markVerified), Modifier.padding(start = 6.dp))
                    }
                }
            }
        }
    }
}
