package app.octap.android.ui.vault

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsBottomHeight
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.ExpandLess
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.PushPin
import androidx.compose.material.icons.outlined.QrCode2
import androidx.compose.material.icons.outlined.Restore
import androidx.compose.material.icons.outlined.Star
import androidx.compose.material.icons.outlined.StarOutline
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.octap.android.model.Toast
import app.octap.android.model.code
import app.octap.android.model.errorMessage
import app.octap.android.platform.WifiConnect
import app.octap.android.platform.WifiInvalid
import app.octap.android.platform.WifiUnsupported
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.ItemIcon
import app.octap.android.ui.components.SecondaryButton
import app.octap.android.ui.sharing.MoveCopyDialog
import app.octap.android.ui.sharing.ShareLinkDialog
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.theme.monoStyle
import app.octap.android.ui.tools.EntryRow
import app.octap.android.ui.util.formatDate
import app.octap.android.ui.util.rememberLive
import app.octap.resources.R
import app.octap.vault.CardDetails
import app.octap.vault.ErrorCode
import app.octap.vault.HealthEntry
import app.octap.vault.HealthReport
import app.octap.vault.IdentityDetails
import app.octap.vault.Item
import app.octap.vault.ItemDetails
import app.octap.vault.LoginDetails
import app.octap.vault.PasswordHistoryEntry
import app.octap.vault.RecoveryInfo
import app.octap.vault.RecoveryKind
import app.octap.vault.Vault
import app.octap.vault.VaultRole
import app.octap.vault.VaultType
import app.octap.vault.WifiDetails
import app.octap.vault.qrChoices
import app.octap.vault.uniqueWebsites
import kotlinx.coroutines.launch

/** The host of a website address, as the item header and links show it (`hostnameOf`). */
fun hostOf(url: String): String? = runCatching {
    val withScheme = if (Regex("^[a-z][a-z0-9+.-]*://", RegexOption.IGNORE_CASE).containsMatchIn(url)) url else "https://$url"
    Uri.parse(withScheme).host?.removePrefix("www.")
}.getOrNull()

fun formatCardNumber(number: String) = number.replace(" ", "").chunked(4).joinToString(" ")

/** Whether this item can change here: not in the trash, not read-only, in a vault that verifies. */
private fun isEditable(item: Item, vault: Vault?) = item.deletedAt == null && vault?.role != VaultRole.READ && vault?.untrusted != true

/** One item (`ItemDetail`), kept fresh when the vault changes. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ItemScreen(id: String) {
    val vault = LocalVault.current
    val model = vault.model
    val loaded = rememberLive(model, id) { model.vault.getItem(id) }
    val vaults = rememberLive(model, sharing = true) { model.vault.listVaults() }.data
    val context = LocalContext.current
    var busy by remember { mutableStateOf(false) }
    var qr by remember { mutableStateOf(false) }
    var shareLink by remember { mutableStateOf(false) }
    var moveCopy by remember { mutableStateOf<Boolean?>(null) }
    var linking by remember { mutableStateOf(false) }
    var history by remember { mutableStateOf(false) }
    val item = loaded.data

    Scaffold(
        contentWindowInsets = WindowInsets(0),
        topBar = {
            TopAppBar(
                title = {},
                navigationIcon = {
                    IconButton(onClick = { vault.close() }, modifier = Modifier.testTag("item.back")) {
                        Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = stringResource(R.string.detail_back))
                    }
                },
                actions = { if (item != null) ItemActions(item, vaults, busy, { busy = it }, onQr = { qr = true }, onShareLink = { shareLink = true }, onMoveCopy = { moveCopy = it }, onLink = { linking = true }, onHistory = { history = true }) },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                loaded.error != null && item == null -> {
                    val notFound = loaded.error!!.code == ErrorCode.NOT_FOUND
                    Empty(
                        Icons.Outlined.ErrorOutline,
                        stringResource(if (notFound) R.string.detail_notFound else R.string.detail_loadFailed),
                        if (notFound) stringResource(R.string.detail_notFoundBody) else errorMessage(context, loaded.error!!),
                    ) { SecondaryButton(stringResource(R.string.detail_backToList), { vault.close() }) }
                }
                item == null || item.id != id -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                // Copying a field here, or opening the website, counts as using the item.
                else -> CompositionLocalProvider(LocalUsedItem provides item.id.takeIf { item.deletedAt == null }) { ItemBody(item, vaults) }
            }
        }
    }
    if (qr && item != null) QrSheet(item) { qr = false }
    if (shareLink && item != null) ShareLinkDialog(item) { shareLink = false }
    moveCopy?.let { move -> if (item != null) MoveCopyDialog(item, move) { moveCopy = null } }
    if (linking && item != null) app.octap.android.ui.tools.LinkToLoginDialog(item) { linking = false }
    if (history && item != null) ItemHistorySheet(item, isEditable(item, vaults?.firstOrNull { it.id == item.vaultId })) { history = false }
}

@Composable
private fun ItemActions(
    item: Item,
    vaults: List<Vault>?,
    busy: Boolean,
    setBusy: (Boolean) -> Unit,
    onQr: () -> Unit,
    onShareLink: () -> Unit,
    onMoveCopy: (Boolean) -> Unit,
    onLink: () -> Unit,
    onHistory: () -> Unit,
) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val inVault = vaults?.firstOrNull { it.id == item.vaultId }
    val readOnly = inVault?.role == VaultRole.READ
    val trashed = item.deletedAt != null
    var menu by remember { mutableStateOf(false) }

    fun run(action: suspend () -> Unit, message: String, after: () -> Unit = {}) {
        setBusy(true)
        scope.launch {
            try {
                action()
                model.toast(message, Toast.Tone.Success)
                after()
            } catch (error: Exception) {
                model.toastError(error)
            } finally {
                setBusy(false)
            }
        }
    }

    if (trashed) {
        TextButton(
            onClick = { run({ model.vault.restoreItem(item.id) }, context.getString(R.string.detail_restored, item.title)) { vault.nav.showScope(Scope.All); vault.open(Route.Item(item.id)) } },
            enabled = !busy,
            modifier = Modifier.testTag("item.restore"),
        ) {
            Icon(Icons.Outlined.Restore, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.trash_restore))
        }
        return
    }
    if (!readOnly) {
        IconButton(
            onClick = { run({ model.vault.setFavorite(item.id, !item.favorite) }, context.getString(if (item.favorite) R.string.detail_unfavorited else R.string.detail_favorited)) },
            enabled = !busy,
            modifier = Modifier.testTag("item.favorite"),
        ) {
            Icon(
                if (item.favorite) Icons.Outlined.Star else Icons.Outlined.StarOutline,
                contentDescription = stringResource(if (item.favorite) R.string.detail_removeFavorite else R.string.detail_addFavorite),
                tint = if (item.favorite) Brand.colors.warn else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        IconButton(onClick = { vault.open(Route.Edit(item.id)) }, modifier = Modifier.testTag("item.edit")) {
            Icon(Icons.Outlined.Edit, contentDescription = stringResource(R.string.common_edit))
        }
    }
    val otherVaults = vaults.orEmpty().any { it.id != item.vaultId && it.role != VaultRole.READ && !it.untrusted }
    val hasQr = remember(item) { qrChoices(item).isNotEmpty() }
    Box {
        IconButton(onClick = { menu = true }, modifier = Modifier.testTag("item.more")) { Icon(Icons.Outlined.MoreVert, contentDescription = stringResource(R.string.detail_more)) }
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
            if (!readOnly) {
                DropdownMenuItem(
                    text = { Text(stringResource(if (item.pinned) R.string.detail_unpin else R.string.detail_pin)) },
                    leadingIcon = { Icon(Icons.Outlined.PushPin, null) },
                    onClick = {
                        menu = false
                        run({ model.vault.setPinned(item.id, !item.pinned) }, context.getString(if (item.pinned) R.string.detail_unpinned else R.string.detail_pinned))
                    },
                    modifier = Modifier.testTag("item.pin"),
                )
            }
            if (hasQr) {
                DropdownMenuItem(text = { Text(stringResource(R.string.phone_showQr)) }, leadingIcon = { Icon(Icons.Outlined.QrCode2, null) }, onClick = { menu = false; onQr() }, modifier = Modifier.testTag("item.qr"))
            }
            if (!readOnly && item.details.let { (it as? ItemDetails.Login)?.login ?: (it as? ItemDetails.Password)?.login }?.totp.isNullOrEmpty() && (item.details is ItemDetails.Login || item.details is ItemDetails.Password)) {
                DropdownMenuItem(text = { Text(stringResource(R.string.otp_addCode)) }, onClick = { menu = false; vault.nav.push(Route.AddCode(item.id)) }, modifier = Modifier.testTag("item.addCode"))
            }
            if (!readOnly && app.octap.android.ui.tools.isCodeOnly(item)) {
                DropdownMenuItem(text = { Text(stringResource(R.string.otp_linkAction)) }, onClick = { menu = false; onLink() }, modifier = Modifier.testTag("item.linkCode"))
            }
            if (!model.isLocal) DropdownMenuItem(text = { Text(stringResource(R.string.history_action)) }, leadingIcon = { Icon(Icons.Outlined.History, null) }, onClick = { menu = false; onHistory() }, modifier = Modifier.testTag("item.history"))
            if (!model.isLocal) DropdownMenuItem(text = { Text(stringResource(R.string.shareLink_action)) }, onClick = { menu = false; onShareLink() }, modifier = Modifier.testTag("item.shareLink"))
            if (otherVaults && !readOnly) DropdownMenuItem(text = { Text(stringResource(R.string.moveCopy_move)) }, onClick = { menu = false; onMoveCopy(true) }, modifier = Modifier.testTag("item.move"))
            if (otherVaults) DropdownMenuItem(text = { Text(stringResource(R.string.moveCopy_copy)) }, onClick = { menu = false; onMoveCopy(false) }, modifier = Modifier.testTag("item.copyTo"))
            if (!readOnly) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.detail_moveToTrash), color = Brand.colors.dangerText) },
                    leadingIcon = { Icon(Icons.Outlined.Delete, null, tint = Brand.colors.dangerText) },
                    onClick = {
                        menu = false
                        run({ model.vault.deleteItem(item.id) }, context.getString(R.string.detail_trashed, item.title)) { vault.close() }
                    },
                    modifier = Modifier.testTag("item.trash"),
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ItemBody(item: Item, vaults: List<Vault>?) {
    val vault = LocalVault.current
    val model = vault.model
    val inVault = vaults?.firstOrNull { it.id == item.vaultId }
    val host = item.urls.firstOrNull()?.takeIf { item.urlMatch[it] != "regex" }?.let(::hostOf)
    val isDocument = item.details is ItemDetails.Document
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).testTag("item.body")) {
        Column(Modifier.widthIn(max = 720.dp).fillMaxWidth()) {
            item.deletedAt?.let {
                val left = daysLeft(it)
                Alert(pluralStringResource(R.plurals.trash_itemNotice, left, left), AlertTone.Warn, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
            }
            if (inVault?.role == VaultRole.READ) Alert(stringResource(R.string.detail_readOnly, vaultName(inVault)), AlertTone.Info, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
            if (isEditable(item, inVault)) PlaceSuggestion(item)

            Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                ItemIcon(model, item.title, app.octap.vault.iconDomain(item.urls), 64.dp)
                Column(Modifier.weight(1f)) {
                    Text(item.title.ifEmpty { stringResource(R.string.detail_untitled) }, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.semantics { heading() }.testTag("item.title"))
                    Text(host ?: stringResource(typeRes(item.itemType)), style = MaterialTheme.typography.bodyMedium.copy(textDirection = if (host != null) TextDirection.Ltr else TextDirection.Content), color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.padding(top = 4.dp)) {
                        Icon(Icons.Outlined.Lock, contentDescription = null, tint = Brand.colors.freeText, modifier = Modifier.size(13.dp))
                        Text(stringResource(R.string.detail_encrypted), style = MaterialTheme.typography.labelSmall, color = Brand.colors.freeText)
                    }
                }
            }

            val editable = isEditable(item, inVault)
            if (isDocument) ItemFiles(item, editable)
            TypeFields(item, live = item.deletedAt == null, editable = editable)
            if (!isDocument && item.itemType != app.octap.vault.ItemType.CustomTemplate) ItemFiles(item, editable)

            if (item.tags.isNotEmpty()) {
                FlowRow(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    for (tag in item.tags) {
                        Text(tag, style = MaterialTheme.typography.labelMedium, modifier = Modifier.clip(CircleShape).background(MaterialTheme.colorScheme.surfaceContainer).padding(horizontal = 10.dp, vertical = 4.dp))
                    }
                }
            }
            if (item.deletedAt == null) ItemPlaces(item, isEditable(item, inVault))
            Meta(item, inVault)
            Spacer(Modifier.windowInsetsBottomHeight(WindowInsets.navigationBars))
        }
    }
}

/**
 * An item's fields. [live]: the item itself in the vault, so it can be shared on. [editable]: it
 * can also change, which a counter-based code does each time it's used. [pastVersion]: an old
 * version, so Connect isn't offered: it would join with what was saved then. With neither live
 * nor editable, as for emergency access, nothing is shared on or saved.
 */
@Composable
fun TypeFields(item: Item, live: Boolean = false, editable: Boolean = false, pastVersion: Boolean = false) {
    val model = LocalVault.current.model
    when (val details = item.details) {
        is ItemDetails.Login -> LoginFields(item, details.login, editable, live)
        is ItemDetails.Password -> LoginFields(item, details.login, editable, live)
        is ItemDetails.Card -> CardFields(details.card)
        is ItemDetails.Identity -> IdentityFields(details.identity)
        is ItemDetails.SecureNote -> FieldList { Field(stringResource(R.string.fields_note), details.note.notes.ifEmpty { null }, model, secret = true, tag = "note") }
        is ItemDetails.Wifi -> WifiFields(item, details.wifi, live, pastVersion)
        is ItemDetails.Document -> details.document.notes?.takeIf { it.isNotEmpty() }?.let { notes ->
            FieldList(stringResource(R.string.fields_notes)) { Field(stringResource(R.string.fields_notes), notes, model, secret = true) }
        }
        is ItemDetails.SshKey -> SshKeyFields(item, details.key)
        is ItemDetails.Environment -> EnvironmentFields(item, details.environment)
        is ItemDetails.Structured -> StructuredFields(details.itemType, details.structured)
        is ItemDetails.MaskedEmailProvider, is ItemDetails.Other -> Unit
    }
}

@Composable
private fun LoginFields(item: Item, details: LoginDetails, editable: Boolean, live: Boolean) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    // Health's report, for the reused-password warning and the recovery map's counts.
    val report = rememberLive(model) { model.vault.healthReport() }.data
    if (live) ReusedPassword(item.id, report)
    FieldList {
        Field(stringResource(R.string.fields_username), details.username, model, secret = false, tag = "username")
        SecretField(stringResource(R.string.fields_password), details.password, model, tag = "password")
        TotpField(details.totp, model, itemId = if (editable) item.id else null)
        // Each site once: other apps write one site several ways (`https://a.example/`, `/login`, `www.`).
        uniqueWebsites(item.urls, item.urlMatch).forEachIndexed { i, url ->
            val mode = item.urlMatch[url]
            Field(stringResource(if (i == 0) R.string.fields_website else R.string.fields_otherWebsite), url, model, what = stringResource(R.string.fields_website), secret = false) {
                Column {
                    // A regular expression isn't an address: it reads as what it is, not a link.
                    if (mode == "regex") {
                        Text(url, style = monoStyle.copy(textDirection = TextDirection.Ltr), modifier = Modifier.testTag("item.url.$i"))
                    } else {
                        Row(
                            Modifier.clickable {
                                val target = if (Regex("^https?://", RegexOption.IGNORE_CASE).containsMatchIn(url)) url else "https://$url"
                                try {
                                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(target)))
                                    // Opening the website counts as using the login, as copying from it does.
                                    if (item.deletedAt == null) model.vault.recordItemUse(item.id)
                                } catch (error: ActivityNotFoundException) {
                                    model.toast(R.string.errors_noFileViewer, Toast.Tone.Danger)
                                }
                            },
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(hostOf(url) ?: url, style = MaterialTheme.typography.bodyLarge.copy(textDirection = TextDirection.Ltr), color = Brand.colors.trustText)
                            Spacer(Modifier.width(4.dp))
                            Icon(Icons.AutoMirrored.Outlined.OpenInNew, contentDescription = null, tint = Brand.colors.trustText, modifier = Modifier.size(14.dp))
                        }
                    }
                    if (mode != null && mode != DEFAULT_MATCH_MODE) {
                        Text(stringResource(matchModeRes(mode)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.testTag("item.matchMode.$i"))
                    }
                }
            }
        }
        Field(stringResource(R.string.fields_httpRealm), details.httpRealm, model, copy = false)
    }
    if (details.passkeys.isNotEmpty()) {
        FieldList(stringResource(R.string.detail_passkeys)) {
            for (passkey in details.passkeys) {
                Field(passkey.rpId, passkey.userName, model, copy = false) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Outlined.Key, contentDescription = null, modifier = Modifier.size(18.dp))
                        Column {
                            Text(passkey.userName, style = MaterialTheme.typography.bodyLarge)
                            Text(stringResource(R.string.detail_passkeySaved, formatDate(passkey.createdAt)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        }
    }
    details.recovery?.let { RecoveryFields(item.id, it, report) }
    if (details.customFields.isNotEmpty()) {
        FieldList(stringResource(R.string.detail_moreFields)) {
            for (field in details.customFields) {
                if (field.hidden) SecretField(field.label, field.value, model) else Field(field.label, field.value, model, secret = false)
            }
        }
    }
    details.notes?.takeIf { it.isNotEmpty() }?.let { notes ->
        FieldList(stringResource(R.string.fields_notes)) { Field(stringResource(R.string.fields_notes), notes, model, secret = true, tag = "notes") }
    }
    if (details.passwordHistory.isNotEmpty()) PasswordHistory(details.passwordHistory)
}

/**
 * "Password used on 3 other logins", from Health's reused groups (the same password, whatever the
 * username). A group dismissed in Health isn't in the report, so it shows nothing. "See them" lists
 * the others, each opening its item, with "Change password": the site's change-password page, then
 * the generator to save the new one.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ReusedPassword(itemId: String, report: HealthReport?) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var open by remember(itemId) { mutableStateOf(false) }
    var changing by remember(itemId) { mutableStateOf<HealthEntry?>(null) }
    val others = report?.reused?.firstOrNull { group -> group.any { it.itemId == itemId } }?.filter { it.itemId != itemId }.orEmpty()
    if (others.isNotEmpty()) {
        Alert(pluralStringResource(R.plurals.detail_reuseTitle, others.size, others.size), AlertTone.Warn, Modifier.testTag("item.reused")) {
            Text(stringResource(R.string.detail_reuseBody), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface)
            TextButton(onClick = { open = true }, modifier = Modifier.testTag("item.reused.see")) { Text(stringResource(R.string.detail_reuseSee)) }
        }
    }
    if (open && others.isNotEmpty()) {
        ModalBottomSheet(onDismissRequest = { open = false }, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
            Column(Modifier.padding(bottom = 24.dp).verticalScroll(rememberScrollState()).testTag("item.reused.sheet")) {
                Text(stringResource(R.string.detail_reuseList), style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp).semantics { heading() })
                for (entry in others) {
                    // The change-password address is on the login's first website, so its host names the site.
                    val site = entry.changePasswordUrl?.let(::hostOf)
                    EntryRow(entry.copy(subtitle = listOfNotNull(entry.subtitle?.ifEmpty { null }, site).joinToString(" · ").ifEmpty { null }))
                    TextButton(
                        onClick = {
                            entry.changePasswordUrl?.let { url ->
                                try {
                                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                                } catch (ignored: ActivityNotFoundException) {
                                }
                            }
                            open = false
                            changing = entry
                        },
                        modifier = Modifier.padding(start = 60.dp).testTag("item.reused.change.${entry.itemId}"),
                    ) { Text(stringResource(R.string.health_change_action)) }
                }
            }
        }
    }
    changing?.let { entry ->
        GeneratorSheet(
            model,
            onUse = { password ->
                changing = null
                scope.launch { runCatching { model.vault.updatePassword(entry.itemId, password) } }
            },
            onDismiss = { changing = null },
        )
    }
}

private fun twoFactorRes(method: String) = when (method) {
    "totp" -> R.string.twoFactor_totp
    "passkey" -> R.string.twoFactor_passkey
    "key" -> R.string.twoFactor_key
    "sms" -> R.string.twoFactor_sms
    "email" -> R.string.twoFactor_email
    else -> R.string.twoFactor_none
}

@Composable
private fun RecoveryFields(itemId: String, recovery: RecoveryInfo, report: HealthReport?) {
    val vault = LocalVault.current
    val model = vault.model
    var showCodes by remember { mutableStateOf(false) }

    @Composable
    fun contact(kind: RecoveryKind, value: String?, source: app.octap.vault.RecoverySource?) {
        if (value.isNullOrEmpty()) return
        val others = report?.recovery
            ?.firstOrNull { it.kind == kind && it.value.equals(value.trim(), ignoreCase = true) && it.logins.any { l -> l.itemId == itemId } }
            ?.logins?.count { it.itemId != itemId }
        val identity = if (source?.kind == "identity" && source.itemId != null) rememberLive(model, source.itemId) { model.vault.getItem(source.itemId!!) }.data else null
        val link = when {
            source?.kind == "alias" -> stringResource(R.string.detail_linkedAlias, providerName(source.provider))
            identity != null -> stringResource(R.string.detail_linkedIdentity, identity.title)
            else -> null
        }
        Field(stringResource(if (kind == RecoveryKind.EMAIL) R.string.fields_recoveryEmail else R.string.fields_recoveryPhone), value, model, secret = false) {
            Column {
                Text(value, style = MaterialTheme.typography.bodyLarge.copy(textDirection = TextDirection.Ltr))
                if (link != null) {
                    Text(
                        link,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (identity != null) Brand.colors.trustText else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = if (identity != null) Modifier.clickable { vault.open(Route.Item(identity.id)) } else Modifier,
                    )
                }
                if (others != null && others > 0) {
                    Text(
                        pluralStringResource(R.plurals.detail_alsoResets, others, others),
                        style = MaterialTheme.typography.bodySmall,
                        color = Brand.colors.trustText,
                        modifier = Modifier.clickable { vault.nav.push(Route.RecoveryMap) },
                    )
                }
            }
        }
    }

    FieldList(stringResource(R.string.detail_recovery)) {
        recovery.twoFactorMethod?.let { Field(stringResource(R.string.fields_twoFactorMethod), stringResource(twoFactorRes(it)), model, copy = false) }
        contact(RecoveryKind.EMAIL, recovery.email, recovery.emailSource)
        contact(RecoveryKind.PHONE, recovery.phone, recovery.phoneSource)
        val codes = recovery.backupCodes
        if (codes.isNotEmpty()) {
            val left = codes.count { !it.used }
            Field(
                stringResource(R.string.fields_backupCodes),
                "",
                model,
                copy = false,
                actions = { TextButton(onClick = { showCodes = !showCodes }) { Text(stringResource(if (showCodes) R.string.common_hide else R.string.common_show)) } },
            ) {
                Column {
                    Text(
                        pluralStringResource(R.plurals.detail_codesLeft, codes.size, left, codes.size),
                        color = if (left <= 2) Brand.colors.warnText else MaterialTheme.colorScheme.onSurface,
                    )
                    AnimatedVisibility(showCodes) {
                        Column(Modifier.padding(top = 6.dp)) {
                            for (code in codes) {
                                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                    Text(code.code, style = monoStyle.copy(textDirection = TextDirection.Ltr, color = if (code.used) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface))
                                    Text(stringResource(if (code.used) R.string.detail_codeUsed else R.string.detail_codeUnused), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                        }
                    }
                }
            }
        }
        val answer = stringResource(R.string.fields_securityAnswer)
        recovery.securityQuestions.forEachIndexed { i, entry ->
            SecretField(entry.question.ifEmpty { answer }, entry.answer, model, what = answer, tag = "securityAnswer.$i")
        }
    }
}

@Composable
fun PasswordHistory(history: List<PasswordHistoryEntry>) {
    val model = LocalVault.current.model
    var open by remember { mutableStateOf(false) }
    Column(Modifier.padding(horizontal = 16.dp, vertical = 6.dp)) {
        TextButton(onClick = { open = !open }) {
            Icon(Icons.Outlined.History, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text(pluralStringResource(R.plurals.detail_passwordHistory, history.size, history.size))
            Icon(if (open) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore, contentDescription = null, modifier = Modifier.size(16.dp))
        }
    }
    if (open) {
        FieldList {
            for (entry in history) {
                SecretField(stringResource(R.string.detail_changedOn, formatDate(entry.changedAt)), entry.password, model, what = stringResource(R.string.detail_oldPassword))
            }
        }
    }
}

@Composable
private fun CardFields(details: CardDetails) {
    val model = LocalVault.current.model
    // The card's face: decorative, the fields below say the same.
    Box(
        Modifier
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .widthIn(max = 360.dp)
            .fillMaxWidth()
            .aspectRatio(1.586f)
            .clip(MaterialTheme.shapes.large)
            .background(Brush.linearGradient(Brand.colors.gradient))
            .padding(20.dp),
    ) {
        Spacer(Modifier.size(40.dp, 28.dp).clip(MaterialTheme.shapes.small).background(Color(0xFFE8C97A)))
        Text("•••• ${details.number?.replace(" ", "")?.takeLast(4) ?: "••••"}", style = monoStyle.copy(color = Color.White, textDirection = TextDirection.Ltr), modifier = Modifier.align(Alignment.CenterStart))
        Row(Modifier.align(Alignment.BottomStart).fillMaxWidth()) {
            Text(details.cardholder?.uppercase().orEmpty(), color = Color.White, style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(details.expiry.orEmpty(), color = Color.White, style = MaterialTheme.typography.labelLarge)
        }
        details.brand?.let { Text(it, color = Color.White, fontWeight = FontWeight.Bold, modifier = Modifier.align(Alignment.TopEnd)) }
    }
    FieldList {
        Field(stringResource(R.string.fields_cardholder), details.cardholder, model, secret = false)
        SecretField(stringResource(R.string.fields_cardNumber), details.number, model, tag = "cardNumber", format = ::formatCardNumber)
        Field(stringResource(R.string.fields_expiry), details.expiry, model, secret = false, ltr = true)
        SecretField(stringResource(R.string.fields_cvv), details.cvv, model, tag = "cvv")
        SecretField(stringResource(R.string.fields_pin), details.pin, model, tag = "pin")
        Field(stringResource(R.string.fields_brand), details.brand, model, copy = false)
    }
    details.notes?.takeIf { it.isNotEmpty() }?.let { notes ->
        FieldList(stringResource(R.string.fields_notes)) { Field(stringResource(R.string.fields_notes), notes, model, secret = true) }
    }
}

@Composable
private fun IdentityFields(details: IdentityDetails) {
    val model = LocalVault.current.model
    val name = listOfNotNull(details.firstName, details.lastName).filter { it.isNotEmpty() }.joinToString(" ")
    val a = details.address
    val address = a?.let {
        listOfNotNull(it.line1, it.line2, listOfNotNull(it.city, it.region).filter { s -> s.isNotEmpty() }.joinToString(", "), it.postalCode, it.country).filter { s -> s.isNotEmpty() }.joinToString("\n")
    }.orEmpty()
    FieldList {
        Field(stringResource(R.string.fields_fullName), name.ifEmpty { null }, model, secret = false)
        Field(stringResource(R.string.fields_email), details.email, model, secret = false, ltr = true)
        Field(stringResource(R.string.fields_phone), details.phone, model, secret = false, ltr = true)
        val locale = app.octap.android.ui.util.shownLocale()
        Field(stringResource(R.string.fields_birthDate), details.birthDate?.let { app.octap.android.ui.util.Formats.date("${it}T00:00:00Z", locale) }, model, secret = false)
        Field(stringResource(R.string.fields_address), address.ifEmpty { null }, model, secret = false)
    }
    details.notes?.takeIf { it.isNotEmpty() }?.let { notes ->
        FieldList(stringResource(R.string.fields_notes)) { Field(stringResource(R.string.fields_notes), notes, model, secret = true) }
    }
}

private fun securityRes(security: String) = when (security) {
    "open" -> R.string.wifi_securities_open
    "wep" -> R.string.wifi_securities_wep
    "wpa" -> R.string.wifi_securities_wpa
    "wpaWpa2" -> R.string.wifi_securities_wpaWpa2
    "wpa2Wpa3" -> R.string.wifi_securities_wpa2Wpa3
    "wpa3" -> R.string.wifi_securities_wpa3
    "wpa2Enterprise" -> R.string.wifi_securities_wpa2Enterprise
    "wpa3Enterprise" -> R.string.wifi_securities_wpa3Enterprise
    else -> R.string.wifi_securities_wpa2
}

fun securityLabel(security: String) = securityRes(security)

fun eapRes(method: String) = when (method) {
    "peap" -> R.string.wifi_eapMethods_peap
    "ttls" -> R.string.wifi_eapMethods_ttls
    "tls" -> R.string.wifi_eapMethods_tls
    "pwd" -> R.string.wifi_eapMethods_pwd
    "leap" -> R.string.wifi_eapMethods_leap
    else -> R.string.wifi_eapMethods_fast
}

fun phase2Res(method: String) = when (method) {
    "gtc" -> R.string.wifi_phase2s_gtc
    "pap" -> R.string.wifi_phase2s_pap
    "chap" -> R.string.wifi_phase2s_chap
    "mschap" -> R.string.wifi_phase2s_mschap
    else -> R.string.wifi_phase2s_mschapv2
}

/** A Wi-Fi network (`WifiFields`), with Connect and its marks. Sharing it on is for the [live] item only. */
@Composable
private fun WifiFields(item: Item, details: WifiDetails, live: Boolean, pastVersion: Boolean) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val radar = rememberWifiRadar()
    val enterprise = WifiConnect.enterprise(details.security)
    val connect = rememberLauncherForActivityResult(StartActivityForResult()) { result ->
        model.inSystemUi = false
        when (WifiConnect.outcome(result.resultCode, result.data)) {
            WifiConnect.Outcome.ADDED -> model.toast(context.getString(R.string.phone_connected, details.ssid), Toast.Tone.Success)
            WifiConnect.Outcome.CANCELLED -> Unit
            WifiConnect.Outcome.FAILED -> model.toast(R.string.phone_connectFailed, Toast.Tone.Danger)
        }
    }
    if (!pastVersion) WifiPermissionNote()
    if (item.deletedAt == null && !pastVersion) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 6.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            SecondaryButton(stringResource(R.string.phone_connect), {
                try {
                    val intent = WifiConnect.intent(details)
                    model.inSystemUi = true
                    connect.launch(intent)
                } catch (error: WifiUnsupported) {
                    model.toast(R.string.phone_connectUnsupported, Toast.Tone.Danger)
                } catch (error: WifiInvalid) {
                    model.toast(R.string.phone_connectFailed, Toast.Tone.Danger)
                }
            }, icon = Icons.Outlined.Wifi, modifier = Modifier.testTag("wifi.connect"))
            if (live) {
                WifiGuestLink(item)
                NfcTagButton(details)
            }
        }
    }
    FieldList {
        Field(stringResource(R.string.wifi_ssid), details.ssid, model, secret = false, tag = "ssid") {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(details.ssid, style = MaterialTheme.typography.bodyLarge)
                WifiMark(details.ssid, radar)
            }
        }
        if (details.security != "open") SecretField(stringResource(R.string.fields_password), details.password, model, tag = "password")
        else Field(stringResource(R.string.fields_password), stringResource(R.string.wifi_noPassword), model, copy = false)
        Field(stringResource(R.string.wifi_security), stringResource(securityRes(details.security)), model, copy = false)
        if (details.hidden) Field(stringResource(R.string.wifi_hidden), stringResource(R.string.wifi_yes), model, copy = false)
    }
    if (enterprise) {
        FieldList(stringResource(R.string.wifi_enterprise)) {
            details.eapMethod?.let { Field(stringResource(R.string.wifi_eapMethod), stringResource(eapRes(it)), model, copy = false) }
            details.phase2?.let { Field(stringResource(R.string.wifi_phase2), stringResource(phase2Res(it)), model, copy = false) }
            Field(stringResource(R.string.fields_username), details.username, model, secret = false)
            Field(stringResource(R.string.wifi_identity), details.identity, model, secret = false)
            Field(stringResource(R.string.wifi_serverDomain), details.serverDomain, model, secret = false, ltr = true)
            Field(stringResource(R.string.wifi_caCertificate), details.caCertificate, model, secret = false, mono = true)
        }
    }
    if (details.captivePortal || details.managed || details.hotspot) {
        FieldList(stringResource(R.string.wifi_about)) {
            if (details.captivePortal) Field(stringResource(R.string.wifi_captivePortal), stringResource(R.string.wifi_yes), model, copy = false)
            if (details.managed) Field(stringResource(R.string.wifi_managed), stringResource(R.string.wifi_yes), model, copy = false)
            if (details.hotspot) Field(stringResource(R.string.wifi_hotspot), stringResource(R.string.wifi_yes), model, copy = false)
        }
    }
    if (details.customFields.isNotEmpty()) {
        FieldList(stringResource(R.string.detail_moreFields)) {
            for (field in details.customFields) if (field.hidden) SecretField(field.label, field.value, model) else Field(field.label, field.value, model, secret = false)
        }
    }
    details.notes?.takeIf { it.isNotEmpty() }?.let { notes ->
        FieldList(stringResource(R.string.fields_notes)) { Field(stringResource(R.string.fields_notes), notes, model, secret = true) }
    }
    if (details.passwordHistory.isNotEmpty()) PasswordHistory(details.passwordHistory)
}

@Composable
private fun Meta(item: Item, vault: Vault?) {
    Column(Modifier.padding(horizontal = 20.dp, vertical = 16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        val style = MaterialTheme.typography.bodySmall
        val color = MaterialTheme.colorScheme.onSurfaceVariant
        if (vault != null) {
            val model = LocalVault.current.model
            val members = if (vault.vaultType != VaultType.PERSONAL) rememberLive(model, vault.id, sharing = true) { runCatching { model.vault.listMembers(vault.id).size }.getOrNull() }.data else null
            Text(
                if (members != null) pluralStringResource(R.plurals.detail_inSharedVault, members, vaultName(vault), members) else stringResource(R.string.detail_inVault, vaultName(vault)),
                style = style,
                color = color,
            )
        }
        Text(stringResource(R.string.detail_updated, formatDate(item.shownUpdatedAt ?: item.updatedAt, long = true)), style = style, color = color)
        Text(stringResource(R.string.detail_created, formatDate(item.shownCreatedAt ?: item.createdAt)), style = style, color = color)
        item.passwordChangedAt?.let { Text(stringResource(R.string.detail_passwordChanged, formatDate(it)), style = style, color = color) }
        item.lastUsedAt?.let { Text(stringResource(R.string.detail_lastUsed, formatDate(it)), style = style, color = color) }
    }
}
