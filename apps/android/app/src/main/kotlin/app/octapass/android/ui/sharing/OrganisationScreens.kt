package app.octap.android.ui.sharing

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.PasswordField
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
import app.octap.android.ui.vault.copy
import app.octap.resources.R
import app.octap.vault.ConfirmedGrant
import app.octap.vault.ErrorCode
import app.octap.vault.OidcSettings
import app.octap.vault.OrgAccessReview
import app.octap.vault.OrgInvitation
import app.octap.vault.OrgMember
import app.octap.vault.OrgPolicies
import app.octap.vault.OrgRole
import app.octap.vault.Organisation
import app.octap.vault.SamlSettings
import app.octap.vault.SsoProtocol
import app.octap.vault.VaultRole
import app.octap.vault.orgEventMessageKey

fun orgRoleRes(role: OrgRole) = when (role) {
    OrgRole.OWNER -> R.string.organisation_role_owner
    OrgRole.ADMIN -> R.string.organisation_role_admin
    OrgRole.MEMBER -> R.string.organisation_role_member
}

/** A shared vault's name is inside it: without the key, part of its id. */
@Composable
private fun orgVaultName(name: String?, shortId: String) = name ?: stringResource(R.string.organisation_vaultWithId, shortId)

/** The rules a policy set brings, in words (`policySummary`). */
@Composable
private fun policyRules(policies: OrgPolicies): List<String> = buildList {
    if (policies.requireSso) add(stringResource(R.string.organisation_policySso))
    if (policies.requireTwoStep) add(stringResource(R.string.organisation_policyTwoStep))
    if (policies.disableShareLinks) add(stringResource(R.string.organisation_policyShareLinks))
    if (policies.disableEmergencyAccess) add(stringResource(R.string.organisation_policyEmergency))
    if (policies.disableExport) add(stringResource(R.string.organisation_policyExport))
    policies.maxAutoLockMinutes?.takeIf { it > 0u }?.let { add(stringResource(R.string.organisation_policyAutoLock, it.toString())) }
    policies.minPasswordLength?.takeIf { it > 0u }?.let { add(stringResource(R.string.organisation_policyPassword, it.toString())) }
}

@Composable
private fun Rules(rules: List<String>) {
    if (rules.isEmpty()) return
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(R.string.organisation_joinRules), style = MaterialTheme.typography.titleSmall)
        for (rule in rules) Text("• $rule", style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * Organisation (`OrganisationPage`): invitations, or creating one; then the organisation, whose
 * sections depend on the member's role. The calls are the desktop app's, through `OctaPassVault`
 * (`crates/octapass-mobile/src/organisations.rs`). Only the access review seals a key, on this
 * phone, to people confirmed by their fingerprint.
 */
@Composable
fun OrganisationScreen() {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val live = rememberLive(model, sharing = true) { model.vault.getOrganisation() }
    val state = live.data
    val organisation = state?.organisation
    val reviews = rememberLive(model, organisation?.id, sharing = true) { if (organisation == null) emptyList() else model.vault.orgAccess() }.data.orEmpty()
    var name by remember { mutableStateOf("") }
    var leaving by remember { mutableStateOf(false) }
    var orphaning by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf(false) }

    VaultPage(organisation?.name ?: stringResource(R.string.organisation_title), stringResource(R.string.organisation_subtitle), tag = "org.title") {
        when {
            state == null && live.error != null -> Alert(errorMessage(context, live.error!!))
            state == null -> CircularProgressIndicator(Modifier.size(24.dp))
            else -> {
                for (invitation in state.invitations) Invitation(invitation, joined = organisation != null)
                if (organisation == null) {
                    SettingsSection(stringResource(R.string.organisation_create), stringResource(R.string.organisation_createHelp), tag = "org.create") {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Field(name, { name = it.take(64) }, stringResource(R.string.organisation_name), hint = stringResource(R.string.organisation_nameHint), modifier = Modifier.testTag("org.name"))
                            OutlinedButton(
                                enabled = name.isNotBlank(),
                                modifier = Modifier.testTag("org.createButton"),
                                onClick = {
                                    model.launch {
                                        model.vault.createOrganisation(name.trim())
                                        name = ""
                                        model.toast(context.getString(R.string.organisation_created), Toast.Tone.Success)
                                    }
                                },
                            ) { Text(stringResource(R.string.organisation_createAction)) }
                        }
                    }
                } else {
                    Member(organisation, reviews)
                    SettingsSection(stringResource(R.string.organisation_danger), tag = "org.danger") {
                        SettingsRow(stringResource(R.string.organisation_leave), stringResource(R.string.organisation_leaveBody)) {
                            OutlinedButton(onClick = { orphaning = false; leaving = true }, modifier = Modifier.testTag("org.leave")) {
                                Text(stringResource(R.string.organisation_leave), color = Brand.colors.dangerText)
                            }
                        }
                        if (organisation.role == OrgRole.OWNER) {
                            SettingsRow(stringResource(R.string.organisation_delete), stringResource(R.string.organisation_deleteBody)) {
                                OutlinedButton(onClick = { deleting = true }, modifier = Modifier.testTag("org.delete")) {
                                    Text(stringResource(R.string.organisation_delete), color = Brand.colors.dangerText)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (leaving && organisation != null) {
        Confirm(
            stringResource(R.string.organisation_leaveTitle, organisation.name),
            stringResource(if (orphaning) R.string.organisation_removeOrphans else R.string.organisation_leaveBody),
            stringResource(R.string.organisation_leave),
            onDismiss = { leaving = false },
        ) {
            leaving = false
            model.launch {
                try {
                    model.vault.leaveOrganisation(orphaning)
                    model.toast(context.getString(R.string.organisation_left), Toast.Tone.Success)
                } catch (error: Exception) {
                    if (error.isCode(ErrorCode.ORG_VAULT_ORPHANED)) {
                        orphaning = true
                        leaving = true
                    } else {
                        throw error
                    }
                }
            }
        }
    }
    if (deleting && organisation != null) DeleteOrganisationDialog(organisation) { deleting = false }
}

@Composable
private fun Invitation(invitation: OrgInvitation, joined: Boolean) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    SettingsSection(
        stringResource(R.string.organisation_invitation, invitation.orgName),
        invitation.invitedBy?.let { stringResource(R.string.organisation_invitedBy, it) },
        tag = "org.invitation",
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(stringResource(R.string.organisation_joinPrivacy), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.organisation_joinOwners), style = MaterialTheme.typography.bodySmall)
        }
        Rules(policyRules(invitation.policies))
        if (joined) Alert(stringResource(R.string.organisation_oneAtATime), AlertTone.Info, Modifier.padding(horizontal = 16.dp))
        Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = {
                model.launch {
                    model.vault.declineOrgInvite(invitation.orgId, invitation.id)
                    model.toast(context.getString(R.string.organisation_declined), Toast.Tone.Success)
                }
            }) { Text(stringResource(R.string.organisation_decline)) }
            OutlinedButton(
                enabled = !joined,
                modifier = Modifier.testTag("org.accept"),
                onClick = {
                    model.launch {
                        model.vault.acceptOrgInvite(invitation.orgId, invitation.id)
                        model.toast(context.getString(R.string.organisation_joined), Toast.Tone.Success)
                    }
                },
            ) { Text(stringResource(R.string.organisation_accept)) }
        }
    }
}

@Composable
private fun Member(organisation: Organisation, reviews: List<OrgAccessReview>) {
    val vault = LocalVault.current
    val admin = organisation.role != OrgRole.MEMBER
    val owner = organisation.role == OrgRole.OWNER
    if (organisation.accessWithheld) {
        Alert("${stringResource(R.string.organisation_withheldTitle)}. ${stringResource(R.string.organisation_withheldBody)}", AlertTone.Warn)
    }
    if (reviews.isNotEmpty()) {
        SettingsSection(stringResource(R.string.organisation_accessTitle), stringResource(R.string.organisation_accessHelp), tag = "org.access") {
            for (review in reviews) {
                val count = review.grants.size
                SettingsRow(
                    orgVaultName(review.vaultName, review.shortId),
                    if (review.canApply) pluralStringResource(R.plurals.organisation_accessApply, count, count) else pluralStringResource(R.plurals.organisation_accessWaiting, count, count),
                    onClick = { vault.nav.push(Route.OrgAccess(review.vaultId)) },
                    modifier = Modifier.testTag("org.review.${review.vaultId}"),
                )
            }
        }
    }
    SettingsSection(stringResource(R.string.organisation_about), tag = "org.about") {
        val count = organisation.memberCount.toInt()
        SettingsRow(
            stringResource(R.string.organisation_yourRole, stringResource(orgRoleRes(organisation.role))),
            pluralStringResource(R.plurals.organisation_since, count, formatDate(organisation.createdAt, long = true), count),
            modifier = Modifier.testTag("org.role"),
        )
        if (!owner) Rules(policyRules(organisation.policies))
    }
    if (admin) {
        SettingsSection(stringResource(R.string.organisation_sections), tag = "org.sections") {
            SettingsRow(stringResource(R.string.organisation_tabMembers), onClick = { vault.nav.push(Route.OrgMembers(owner)) }, modifier = Modifier.testTag("org.members"))
            SettingsRow(stringResource(R.string.organisation_tabGroups), onClick = { vault.nav.push(Route.OrgGroups) }, modifier = Modifier.testTag("org.groups"))
            SettingsRow(stringResource(R.string.organisation_tabVaults), onClick = { vault.nav.push(Route.OrgVaults) }, modifier = Modifier.testTag("org.vaults"))
            if (owner) {
                SettingsRow(stringResource(R.string.organisation_tabPolicies), onClick = { vault.nav.push(Route.OrgPolicies) }, modifier = Modifier.testTag("org.policies"))
                SettingsRow(stringResource(R.string.organisation_tabSso), onClick = { vault.nav.push(Route.OrgSso) })
                SettingsRow(stringResource(R.string.organisation_tabScim), onClick = { vault.nav.push(Route.OrgScim) })
            }
            SettingsRow(stringResource(R.string.organisation_tabActivity), onClick = { vault.nav.push(Route.OrgActivity) }, modifier = Modifier.testTag("org.activity"))
        }
    }
}

@Composable
private fun DeleteOrganisationDialog(organisation: Organisation, onDismiss: () -> Unit) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    var confirmName by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.organisation_deleteTitle, organisation.name)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.organisation_deleteBody))
                Field(confirmName, { confirmName = it }, stringResource(R.string.organisation_deleteConfirm, organisation.name))
                PasswordField(password, { password = it }, stringResource(R.string.organisation_masterPassword), error = error)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel)) } },
        confirmButton = {
            TextButton(
                enabled = !busy && confirmName == organisation.name && password.isNotEmpty(),
                onClick = {
                    busy = true
                    model.launch {
                        try {
                            model.vault.deleteOrganisation(password, confirmName)
                            model.toast(context.getString(R.string.organisation_deleted), Toast.Tone.Success)
                            onDismiss()
                        } catch (e: Exception) {
                            error = errorMessage(context, e)
                        } finally {
                            busy = false
                        }
                    }
                },
            ) { Text(stringResource(R.string.organisation_delete), color = Brand.colors.dangerText) }
        },
    )
}

/** One vault's waiting grants: each person's fingerprint, computed on this phone, ticked one by one. */
@Composable
fun OrgAccessScreen(vaultId: String) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val live = rememberLive(model, vaultId, sharing = true) { model.vault.orgAccess() }
    val reviews = live.data
    val review = reviews?.firstOrNull { it.vaultId == vaultId }
    var confirmed by remember { mutableStateOf(setOf<String>()) }
    VaultPage(review?.let { orgVaultName(it.vaultName, it.shortId) } ?: stringResource(R.string.organisation_accessTitle), stringResource(R.string.organisation_accessHelp), tag = "org.review") {
        when {
            reviews == null && live.error != null -> {
                Alert(errorMessage(context, live.error!!))
                OutlinedButton(onClick = { live.retry() }) { Text(stringResource(R.string.common_tryAgain)) }
                return@VaultPage
            }
            reviews == null -> {
                CircularProgressIndicator(Modifier.size(24.dp))
                return@VaultPage
            }
            // Given already, or nothing is waiting any more.
            review == null -> {
                Text(pluralStringResource(R.plurals.organisation_accessWaiting, 0, 0))
                return@VaultPage
            }
        }
        review!!
        for (grant in review.grants) {
            SettingsSection(grant.email) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        listOfNotNull(
                            stringResource(roleRes(grant.role)),
                            if (grant.upgrade) stringResource(R.string.organisation_accessUpgrade) else null,
                            if (grant.verified) stringResource(R.string.fingerprint_verified) else null,
                        ).joinToString(" · "),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    FingerprintView(grant.fingerprint, stringResource(R.string.fingerprint_title))
                    if (review.canApply) {
                        val on = grant.accountId in confirmed
                        Row(
                            Modifier.toggleable(on, enabled = !grant.keyChanged, role = Role.Checkbox) { confirmed = if (it) confirmed + grant.accountId else confirmed - grant.accountId }
                                .testTag("org.review.confirm"),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(on, null, enabled = !grant.keyChanged)
                            Text(stringResource(R.string.organisation_accessConfirm, grant.email))
                        }
                    }
                    if (grant.keyChanged) Alert(stringResource(R.string.organisation_accessKeyChanged), AlertTone.Warn)
                }
            }
        }
        if (review.canApply) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (review.grants.isNotEmpty()) {
                    OutlinedButton(
                        enabled = confirmed.isNotEmpty(),
                        modifier = Modifier.testTag("org.review.apply"),
                        onClick = {
                            val chosen = review.grants.filter { it.accountId in confirmed }.map { ConfirmedGrant(it.accountId, it.fingerprint.digits) }
                            model.launch {
                                model.vault.applyOrgAccess(vaultId, chosen)
                                confirmed = emptySet()
                                model.toast(context.getString(R.string.organisation_accessApplied), Toast.Tone.Success)
                                vault.nav.pop()
                            }
                        },
                    ) { Text(pluralStringResource(R.plurals.organisation_accessApply, confirmed.size, confirmed.size)) }
                }
                if (review.rotate) {
                    OutlinedButton(onClick = {
                        model.launch {
                            model.vault.rotateOrgVault(vaultId)
                            model.toast(context.getString(R.string.organisation_rotated), Toast.Tone.Success)
                        }
                    }) { Text(stringResource(R.string.organisation_rotate)) }
                }
            }
        } else {
            Text(pluralStringResource(R.plurals.organisation_accessWaiting, review.grants.size, review.grants.size))
        }
    }
}

/** Members and pending invites. Only owners change roles or remove an owner. */
@Composable
fun OrgMembersScreen(owner: Boolean) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val data = rememberLive(model, sharing = true) { model.vault.listOrgMembers() }.data
    var email by remember { mutableStateOf("") }
    var role by remember { mutableStateOf(OrgRole.MEMBER) }
    var removing by remember { mutableStateOf<OrgMember?>(null) }
    var orphaning by remember { mutableStateOf(false) }
    val roles = listOf(OrgRole.OWNER, OrgRole.ADMIN, OrgRole.MEMBER)
    VaultPage(stringResource(R.string.organisation_tabMembers), tag = "org.members.title") {
        SettingsSection(stringResource(R.string.organisation_tabMembers), tag = "org.members.list") {
            if (data == null) {
                CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
            } else {
                for (member in data.members) {
                    SettingsRow(
                        if (member.isYou) stringResource(R.string.members_you, member.email) else member.email,
                        listOfNotNull(
                            if (!owner) stringResource(orgRoleRes(member.role)) else null,
                            stringResource(if (member.twoStep) R.string.organisation_twoStepOn else R.string.organisation_twoStepOff),
                            if (member.ssoLinked) stringResource(R.string.organisation_ssoLinked) else null,
                        ).joinToString(" · "),
                    ) {
                        if (!member.isYou && (owner || member.role != OrgRole.OWNER)) {
                            IconButton(onClick = { orphaning = false; removing = member }) {
                                Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.organisation_remove, member.email), tint = Brand.colors.dangerText)
                            }
                        }
                    }
                    if (owner) {
                        Column(Modifier.padding(horizontal = 16.dp)) {
                            Choice(stringResource(R.string.organisation_roleOf, member.email), roles.map { it.name to context.getString(orgRoleRes(it)) }, member.role.name) { value ->
                                val next = OrgRole.valueOf(value ?: return@Choice)
                                model.launch {
                                    model.vault.setOrgMemberRole(member.accountId, next)
                                    model.toast(context.getString(R.string.organisation_roleChanged), Toast.Tone.Success)
                                }
                            }
                        }
                    }
                }
                for (invite in data.invites) {
                    SettingsRow(invite.email, "${stringResource(R.string.family_pending)} · ${stringResource(orgRoleRes(invite.role))} · ${stringResource(R.string.family_invitedOn, formatDate(invite.invitedAt))}") {
                        IconButton(onClick = {
                            model.launch {
                                model.vault.cancelOrgInvite(invite.id)
                                model.toast(context.getString(R.string.family_cancelled), Toast.Tone.Success)
                            }
                        }) { Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.family_cancelInvite, invite.email)) }
                    }
                }
            }
        }
        SettingsSection(stringResource(R.string.organisation_invite), tag = "org.invite") {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Field(email, { email = it }, stringResource(R.string.organisation_inviteEmail), keyboardType = KeyboardType.Email, modifier = Modifier.testTag("org.invite.email"))
                Choice(stringResource(R.string.roles_label), listOf(OrgRole.MEMBER, OrgRole.ADMIN).map { it.name to context.getString(orgRoleRes(it)) }, role.name, tag = "org.invite.role") { role = OrgRole.valueOf(it ?: "MEMBER") }
                OutlinedButton(
                    enabled = email.contains('@'),
                    modifier = Modifier.testTag("org.invite.send"),
                    onClick = {
                        val address = email.trim()
                        model.launch {
                            model.vault.inviteOrgMember(address, role)
                            email = ""
                            model.toast(context.getString(R.string.organisation_invited, address), Toast.Tone.Success)
                        }
                    },
                ) { Text(stringResource(R.string.organisation_inviteAction)) }
            }
        }
    }
    removing?.let { member ->
        Confirm(
            stringResource(R.string.organisation_removeTitle, member.email),
            stringResource(if (orphaning) R.string.organisation_removeOrphans else R.string.organisation_removeBody),
            stringResource(R.string.common_remove),
            onDismiss = { removing = null },
        ) {
            removing = null
            model.launch {
                try {
                    model.vault.removeOrgMember(member.accountId, orphaning)
                } catch (error: Exception) {
                    if (error.isCode(ErrorCode.ORG_VAULT_ORPHANED)) {
                        orphaning = true
                        removing = member
                    } else {
                        throw error
                    }
                }
            }
        }
    }
}

/** Groups: lists of people. Adding someone only asks a vault manager to give them the key. */
@Composable
fun OrgGroupsScreen() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val groups = rememberLive(model, sharing = true) { model.vault.listOrgGroups() }.data
    val people = rememberLive(model, sharing = true) { model.vault.listOrgMembers().members }.data.orEmpty()
    var name by remember { mutableStateOf("") }
    var deleting by remember { mutableStateOf<app.octap.vault.OrgGroup?>(null) }
    VaultPage(stringResource(R.string.organisation_tabGroups), stringResource(R.string.organisation_groupsHelp), tag = "org.groups.title") {
        when {
            groups == null -> CircularProgressIndicator(Modifier.size(24.dp))
            groups.isEmpty() -> Text(stringResource(R.string.organisation_noGroups))
            else -> for (group in groups) {
                SettingsSection(group.name, tag = "org.group.${group.id}") {
                    for (accountId in group.members) {
                        val email = people.firstOrNull { it.accountId == accountId }?.email ?: accountId
                        SettingsRow(email) {
                            IconButton(onClick = { model.launch { model.vault.removeOrgGroupMember(group.id, accountId) } }) {
                                Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.organisation_removeFromGroup, email, group.name))
                            }
                        }
                    }
                    val others = people.filter { it.accountId !in group.members }
                    if (others.isNotEmpty()) {
                        Column(Modifier.padding(horizontal = 16.dp)) {
                            Choice(stringResource(R.string.organisation_addToGroup, group.name), listOf(null to context.getString(R.string.organisation_chooseMember)) + others.map { it.accountId to it.email }, null, tag = "org.group.add") { accountId ->
                                if (accountId != null) model.launch { model.vault.addOrgGroupMember(group.id, accountId) }
                            }
                        }
                    }
                    SettingsRow(stringResource(R.string.organisation_deleteGroup)) {
                        IconButton(onClick = { deleting = group }) {
                            Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.organisation_deleteGroupNamed, group.name), tint = Brand.colors.dangerText)
                        }
                    }
                }
            }
        }
        SettingsSection(stringResource(R.string.organisation_newGroup), tag = "org.groups.new") {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Field(name, { name = it.take(64) }, stringResource(R.string.organisation_groupName), hint = stringResource(R.string.organisation_nameHint), modifier = Modifier.testTag("org.group.name"))
                OutlinedButton(
                    enabled = name.isNotBlank(),
                    modifier = Modifier.testTag("org.group.create"),
                    onClick = {
                        model.launch {
                            model.vault.createOrgGroup(name.trim())
                            name = ""
                            model.toast(context.getString(R.string.organisation_groupCreated), Toast.Tone.Success)
                        }
                    },
                ) { Text(stringResource(R.string.organisation_createGroup)) }
            }
        }
    }
    deleting?.let { group ->
        Confirm(stringResource(R.string.organisation_deleteGroupTitle, group.name), stringResource(R.string.organisation_deleteGroupBody), stringResource(R.string.organisation_deleteGroup), onDismiss = { deleting = null }) {
            deleting = null
            model.launch { model.vault.deleteOrgGroup(group.id) }
        }
    }
}

/** The organisation's vaults, named when this account can open them. */
@Composable
fun OrgVaultsScreen() {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val vaults = rememberLive(model, sharing = true) { model.vault.listOrgVaults() }.data
    var name by remember { mutableStateOf("") }
    VaultPage(stringResource(R.string.organisation_tabVaults), stringResource(R.string.organisation_vaultsHelp), tag = "org.vaults.title") {
        SettingsSection(stringResource(R.string.organisation_tabVaults), tag = "org.vaults.list") {
            when {
                vaults == null -> CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
                vaults.isEmpty() -> SettingsRow(stringResource(R.string.organisation_noVaults))
                else -> for (v in vaults) {
                    val count = v.memberCount.toInt()
                    SettingsRow(
                        orgVaultName(v.name, v.shortId),
                        listOfNotNull(
                            pluralStringResource(R.plurals.organisation_vaultMembers, count, count),
                            if (v.rotationPending) stringResource(R.string.organisation_rotationDue) else null,
                            if (v.managerCount == 0uL) stringResource(R.string.organisation_noManagers) else null,
                        ).joinToString(" · "),
                        onClick = { vault.nav.push(Route.OrgVault(v.id)) },
                        modifier = Modifier.testTag("org.vault.${v.id}"),
                    )
                }
            }
        }
        SettingsSection(stringResource(R.string.organisation_newVault), tag = "org.vaults.new") {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Field(name, { name = it.take(100) }, stringResource(R.string.organisation_vaultName), modifier = Modifier.testTag("org.vault.name"))
                OutlinedButton(
                    enabled = name.isNotBlank(),
                    modifier = Modifier.testTag("org.vault.create"),
                    onClick = {
                        model.launch {
                            model.vault.createOrgVault(name.trim())
                            name = ""
                            model.toast(context.getString(R.string.organisation_vaultCreated), Toast.Tone.Success)
                        }
                    },
                ) { Text(stringResource(R.string.organisation_createVault)) }
            }
        }
    }
}

private val GROUP_ROLES = listOf(VaultRole.READ, VaultRole.WRITE, VaultRole.MANAGE)

/** One organisation vault: the groups with access and their roles, linking another, deleting. */
@Composable
fun OrgVaultScreen(vaultId: String) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val target = rememberLive(model, vaultId, sharing = true) { model.vault.listOrgVaults().firstOrNull { it.id == vaultId } }.data
    val groups = rememberLive(model, sharing = true) { model.vault.listOrgGroups() }.data.orEmpty()
    var linking by remember { mutableStateOf<String?>(null) }
    var role by remember { mutableStateOf(VaultRole.READ) }
    var deleting by remember { mutableStateOf(false) }
    val roleOptions = GROUP_ROLES.map { it.name to context.getString(roleRes(it)) }
    if (target == null) {
        VaultPage(stringResource(R.string.organisation_tabVaults)) { CircularProgressIndicator(Modifier.size(24.dp)) }
        return
    }
    val title = orgVaultName(target.name, target.shortId)
    VaultPage(title, tag = "org.vault.title") {
        if (target.role != null) OutlinedButton(onClick = { vault.nav.showScope(Scope.InVault(target.id)) }) { Text(stringResource(R.string.members_openVault)) }
        SettingsSection(stringResource(R.string.organisation_vaultGroups, title), tag = "org.vault.groups") {
            for (link in target.groups) {
                val group = groups.firstOrNull { it.id == link.groupId }
                SettingsRow(group?.name ?: link.groupId) {
                    IconButton(onClick = { model.launch { model.vault.unlinkOrgVaultGroup(target.id, link.groupId) } }) {
                        Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.organisation_unlink, group?.name.orEmpty()))
                    }
                }
                Column(Modifier.padding(horizontal = 16.dp)) {
                    Choice(stringResource(R.string.organisation_groupRole, group?.name.orEmpty()), roleOptions, link.role.name) { value ->
                        val next = VaultRole.valueOf(value ?: return@Choice)
                        model.launch { model.vault.linkOrgVaultGroup(target.id, link.groupId, next) }
                    }
                }
            }
            val unlinked = groups.filter { group -> target.groups.none { it.groupId == group.id } }
            if (unlinked.isNotEmpty()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Choice(stringResource(R.string.organisation_linkGroup), listOf(null to context.getString(R.string.organisation_chooseGroup)) + unlinked.map { it.id to it.name }, linking, tag = "org.link.group") { linking = it }
                    Choice(stringResource(R.string.roles_label), roleOptions, role.name, tag = "org.link.role") { role = VaultRole.valueOf(it ?: "READ") }
                    OutlinedButton(
                        enabled = linking != null,
                        modifier = Modifier.testTag("org.link"),
                        onClick = {
                            val groupId = linking ?: return@OutlinedButton
                            model.launch {
                                model.vault.linkOrgVaultGroup(target.id, groupId, role)
                                linking = null
                                model.toast(context.getString(R.string.organisation_linked), Toast.Tone.Success)
                            }
                        },
                    ) { Text(stringResource(R.string.organisation_link)) }
                }
            }
        }
        SettingsSection(stringResource(R.string.organisation_deleteVault)) {
            SettingsRow(stringResource(R.string.organisation_deleteVault), stringResource(R.string.organisation_deleteVaultBody)) {
                OutlinedButton(onClick = { deleting = true }) { Text(stringResource(R.string.organisation_deleteVault), color = Brand.colors.dangerText) }
            }
        }
    }
    if (deleting) {
        var password by remember { mutableStateOf("") }
        var error by remember { mutableStateOf<String?>(null) }
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { deleting = false },
            title = { Text(stringResource(R.string.organisation_deleteVaultTitle, title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.organisation_deleteVaultBody))
                    PasswordField(password, { password = it }, stringResource(R.string.organisation_masterPassword), error = error)
                }
            },
            dismissButton = { TextButton(onClick = { deleting = false }) { Text(stringResource(R.string.common_cancel)) } },
            confirmButton = {
                TextButton(enabled = password.isNotEmpty(), onClick = {
                    model.launch {
                        try {
                            model.vault.deleteOrgVault(password, target.id)
                            deleting = false
                            model.toast(context.getString(R.string.organisation_vaultDeleted), Toast.Tone.Success)
                            vault.nav.pop()
                        } catch (e: Exception) {
                            error = errorMessage(context, e)
                        }
                    }
                }) { Text(stringResource(R.string.organisation_deleteVault), color = Brand.colors.dangerText) }
            },
        )
    }
}

/** Owner: the organisation's rules, the server's and the apps'. */
@Composable
fun OrgPoliciesScreen() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val current = rememberLive(model, sharing = true) { model.vault.getOrganisation().organisation?.policies }.data
    var draft by remember(current) { mutableStateOf(current) }
    var autoLock by remember(current) { mutableStateOf(current?.maxAutoLockMinutes?.toString().orEmpty()) }
    var minPassword by remember(current) { mutableStateOf(current?.minPasswordLength?.toString().orEmpty()) }
    VaultPage(stringResource(R.string.organisation_tabPolicies), tag = "org.policies.title") {
        val policies = draft
        if (policies == null) {
            CircularProgressIndicator(Modifier.size(24.dp))
            return@VaultPage
        }
        @Composable
        fun toggle(label: Int, help: Int, value: Boolean, tag: String, set: (Boolean) -> OrgPolicies) =
            SettingsRow(stringResource(label), stringResource(help)) { Switch(value, { draft = set(it) }, Modifier.testTag(tag)) }
        SettingsSection(stringResource(R.string.organisation_policiesServer), stringResource(R.string.organisation_policiesServerHelp)) {
            toggle(R.string.organisation_requireTwoStep, R.string.organisation_requireTwoStepHelp, policies.requireTwoStep, "org.policy.twoStep") { policies.copy(requireTwoStep = it) }
            toggle(R.string.organisation_requireSso, R.string.organisation_requireSsoHelp, policies.requireSso, "org.policy.sso") { policies.copy(requireSso = it) }
            toggle(R.string.organisation_disableShareLinks, R.string.organisation_disableShareLinksHelp, policies.disableShareLinks, "org.policy.links") { policies.copy(disableShareLinks = it) }
            toggle(R.string.organisation_disableEmergency, R.string.organisation_disableEmergencyHelp, policies.disableEmergencyAccess, "org.policy.emergency") { policies.copy(disableEmergencyAccess = it) }
            Column(Modifier.padding(16.dp)) {
                Field(policies.ssoMaxAgeHours.toString(), { value -> value.toUIntOrNull()?.let { draft = policies.copy(ssoMaxAgeHours = it.coerceAtMost(8760u)) } }, stringResource(R.string.organisation_ssoMaxAge), hint = stringResource(R.string.organisation_ssoMaxAgeHelp), keyboardType = KeyboardType.Number)
            }
        }
        SettingsSection(stringResource(R.string.organisation_policiesClient), stringResource(R.string.organisation_policiesClientHelp)) {
            toggle(R.string.organisation_disableExport, R.string.organisation_disableExportHelp, policies.disableExport, "org.policy.export") { policies.copy(disableExport = it) }
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Field(autoLock, { autoLock = it.filter(Char::isDigit) }, stringResource(R.string.organisation_maxAutoLock), hint = stringResource(R.string.organisation_maxAutoLockHelp), keyboardType = KeyboardType.Number, modifier = Modifier.testTag("org.policy.autoLock"))
                Field(minPassword, { minPassword = it.filter(Char::isDigit) }, stringResource(R.string.organisation_minPassword), hint = stringResource(R.string.organisation_minPasswordHelp), keyboardType = KeyboardType.Number)
            }
        }
        OutlinedButton(
            modifier = Modifier.testTag("org.policies.save"),
            onClick = {
                val next = policies.copy(
                    maxAutoLockMinutes = autoLock.toUIntOrNull()?.takeIf { it > 0u },
                    minPasswordLength = minPassword.toUIntOrNull()?.takeIf { it > 0u },
                )
                model.launch {
                    draft = model.vault.setOrgPolicies(next)
                    model.toast(context.getString(R.string.organisation_policiesSaved), Toast.Tone.Success)
                }
            },
        ) { Text(stringResource(R.string.organisation_savePolicies)) }
    }
}

/** Owner: single sign-on with OpenID Connect or SAML 2.0. Sign-in only: the provider can't open a vault. */
@Composable
fun OrgSsoScreen() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val sso = rememberLive(model, sharing = true) { model.vault.orgSso() }
    val locked = rememberLive(model, sharing = true) { model.vault.getOrganisation().organisation?.policies?.requireSso == true }.data == true
    val saved = sso.data
    var protocol by remember(saved?.protocol) { mutableStateOf(saved?.protocol ?: SsoProtocol.OIDC) }
    var issuer by remember(saved) { mutableStateOf(saved?.issuer.orEmpty()) }
    var clientId by remember(saved) { mutableStateOf(saved?.clientId.orEmpty()) }
    var clientSecret by remember { mutableStateOf("") }
    var metadata by remember { mutableStateOf("") }
    var entityId by remember { mutableStateOf("") }
    var ssoUrl by remember { mutableStateOf("") }
    var certificate by remember { mutableStateOf("") }
    VaultPage(stringResource(R.string.organisation_tabSso), stringResource(R.string.organisation_ssoHelp), tag = "org.sso.title") {
        if (saved == null) {
            CircularProgressIndicator(Modifier.size(24.dp))
            return@VaultPage
        }
        Alert(stringResource(R.string.organisation_ssoSignInOnlyHelp), AlertTone.Info)
        when {
            saved.testedAt != null -> Text(stringResource(R.string.organisation_ssoTested, formatDate(saved.testedAt!!, long = true)))
            saved.protocol != null -> Text(stringResource(R.string.organisation_ssoNotTested), color = Brand.colors.warnText)
        }
        saved.saml?.let { saml ->
            Text(stringResource(R.string.organisation_samlSaved, saml.entityId), style = MaterialTheme.typography.bodySmall)
            for (certificateRecord in saml.certificates) Text(stringResource(R.string.organisation_samlCertificate, certificateRecord.sha256), style = MaterialTheme.typography.labelSmall)
        }
        if (locked) Alert(stringResource(R.string.organisation_ssoLocked), AlertTone.Info)
        Choice(stringResource(R.string.organisation_ssoProtocol), listOf(SsoProtocol.OIDC.name to context.getString(R.string.organisation_ssoOidc), SsoProtocol.SAML.name to context.getString(R.string.organisation_ssoSaml)), protocol.name, enabled = !locked) { protocol = SsoProtocol.valueOf(it ?: "OIDC") }
        @Composable
        fun copyRow(label: String, value: String) = SettingsRow(label, value) {
            TextButton(onClick = { copy(model, value, label, secret = false) }) { Text(stringResource(R.string.organisation_scimCopy)) }
        }
        if (protocol == SsoProtocol.OIDC) {
            copyRow(stringResource(R.string.organisation_ssoRedirect), saved.callbackUrl)
            Field(issuer, { issuer = it }, stringResource(R.string.organisation_ssoIssuer), keyboardType = KeyboardType.Uri, enabled = !locked)
            Field(clientId, { clientId = it }, stringResource(R.string.organisation_ssoClientId), enabled = !locked)
            PasswordField(clientSecret, { clientSecret = it }, stringResource(R.string.organisation_ssoClientSecret), hint = stringResource(if (saved.hasClientSecret) R.string.organisation_ssoSecretKept else R.string.organisation_ssoSecretHelp))
        } else {
            copyRow(stringResource(R.string.organisation_samlSpEntity), saved.samlEntityId)
            copyRow(stringResource(R.string.organisation_samlAcs), saved.samlAcsUrl)
            Field(metadata, { metadata = it }, stringResource(R.string.organisation_samlMetadata), hint = stringResource(R.string.organisation_samlMetadataHelp), singleLine = false, minLines = 3, mono = true, enabled = !locked)
            Field(entityId, { entityId = it }, stringResource(R.string.organisation_samlEntityId), enabled = !locked)
            Field(ssoUrl, { ssoUrl = it }, stringResource(R.string.organisation_samlSsoUrl), keyboardType = KeyboardType.Uri, enabled = !locked)
            Field(certificate, { certificate = it }, stringResource(R.string.organisation_samlCertificateField), hint = stringResource(R.string.organisation_samlCertificateHelp), singleLine = false, minLines = 3, mono = true, enabled = !locked)
        }
        if (saved.protocol != null && saved.protocol != protocol) Text(stringResource(R.string.organisation_ssoReplaces), color = Brand.colors.warnText, style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(enabled = !locked, onClick = {
                model.launch {
                    if (protocol == SsoProtocol.OIDC) {
                        model.vault.saveOrgSso(OidcSettings(issuer, clientId, clientSecret.ifEmpty { null }))
                    } else {
                        model.vault.saveOrgSaml(SamlSettings(metadata.ifBlank { null }, entityId.ifBlank { null }, ssoUrl.ifBlank { null }, listOf(certificate).filter { it.isNotBlank() }))
                    }
                    clientSecret = ""
                    sso.retry()
                    model.toast(context.getString(R.string.organisation_ssoSaved), Toast.Tone.Success)
                }
            }) { Text(stringResource(R.string.organisation_ssoSave)) }
            if (saved.protocol != null) {
                OutlinedButton(onClick = {
                    model.launch {
                        val url = model.vault.testOrgSso()
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                    }
                }) { Text(stringResource(R.string.organisation_ssoTest)) }
            }
        }
        if (saved.protocol != null) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { sso.retry() }) { Text(stringResource(R.string.organisation_ssoRefresh)) }
                TextButton(enabled = !locked, onClick = {
                    model.launch {
                        model.vault.removeOrgSso()
                        sso.retry()
                        model.toast(context.getString(R.string.organisation_ssoRemoved), Toast.Tone.Success)
                    }
                }) { Text(stringResource(R.string.organisation_ssoRemove), color = Brand.colors.dangerText) }
            }
        }
    }
}

/** Owner: SCIM tokens for an identity provider. A new token's secret shows once. */
@Composable
fun OrgScimScreen() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val live = rememberLive(model, sharing = true) { model.vault.orgScim() }
    val scim = live.data
    var name by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf<String?>(null) }
    VaultPage(stringResource(R.string.organisation_tabScim), stringResource(R.string.organisation_scimHelp), tag = "org.scim.title") {
        Alert(stringResource(R.string.organisation_scimWhatItDoesHelp), AlertTone.Info)
        if (scim == null) {
            CircularProgressIndicator(Modifier.size(24.dp))
            return@VaultPage
        }
        SettingsSection(stringResource(R.string.organisation_scimBaseUrl)) {
            SettingsRow(scim.baseUrl) {
                TextButton(onClick = { copy(model, scim.baseUrl, context.getString(R.string.organisation_scimBaseUrl), secret = false) }) { Text(stringResource(R.string.organisation_scimCopy)) }
            }
        }
        secret?.let { value ->
            SettingsSection(stringResource(R.string.organisation_scimNewToken), stringResource(R.string.organisation_scimNewTokenHelp)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(value, style = monoStyle)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { copy(model, value, context.getString(R.string.organisation_scimNewToken), secret = true) }) { Text(stringResource(R.string.organisation_scimCopy)) }
                        TextButton(onClick = { secret = null }) { Text(stringResource(R.string.organisation_scimDone)) }
                    }
                }
            }
        }
        SettingsSection(stringResource(R.string.organisation_tabScim)) {
            if (scim.tokens.isEmpty()) SettingsRow(stringResource(R.string.organisation_scimNoTokens))
            for (token in scim.tokens) {
                SettingsRow(
                    token.name,
                    listOf(
                        stringResource(R.string.organisation_scimCreated, formatDate(token.createdAt)),
                        token.lastUsedAt?.let { stringResource(R.string.organisation_scimLastUsed, formatDate(it)) } ?: stringResource(R.string.organisation_scimNeverUsed),
                    ).joinToString(" · "),
                ) {
                    TextButton(onClick = {
                        model.launch {
                            model.vault.revokeOrgScimToken(token.id)
                            live.retry()
                            model.toast(context.getString(R.string.organisation_scimRevoked), Toast.Tone.Success)
                        }
                    }) { Text(stringResource(R.string.organisation_scimRevoke), color = Brand.colors.dangerText) }
                }
            }
        }
        Field(name, { name = it.take(64) }, stringResource(R.string.organisation_scimTokenName), hint = stringResource(R.string.organisation_scimTokenNameHelp))
        OutlinedButton(enabled = name.isNotBlank(), onClick = {
            model.launch {
                secret = model.vault.createOrgScimToken(name.trim()).secret
                name = ""
                live.retry()
            }
        }) { Text(stringResource(R.string.organisation_scimCreate)) }
    }
}

/** What members and admins did, newest first. Names and ids only, never vault contents. */
@Composable
fun OrgActivityScreen() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val events = rememberLive(model, sharing = true) { model.vault.orgEvents() }.data
    VaultPage(stringResource(R.string.organisation_tabActivity), stringResource(R.string.organisation_activityHelp), tag = "org.activity.title") {
        SettingsSection(stringResource(R.string.organisation_tabActivity)) {
            when {
                events == null -> CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
                events.isEmpty() -> SettingsRow(stringResource(R.string.organisation_noActivity))
                else -> for (event in events) {
                    val label = orgEventMessageKey(event.eventType)
                        ?.let { context.resources.getIdentifier(it.replace('.', '_'), "string", context.packageName) }
                        ?.takeIf { it != 0 }
                        ?.let { stringResource(it) }
                        ?: event.eventType
                    val actor = event.actor ?: if (event.eventType.startsWith("scim-")) stringResource(R.string.organisation_byIdentityProvider) else null
                    SettingsRow(label, listOfNotNull(actor, event.subject, formatDate(event.createdAt, long = true)).joinToString(" · "))
                }
            }
        }
    }
}
