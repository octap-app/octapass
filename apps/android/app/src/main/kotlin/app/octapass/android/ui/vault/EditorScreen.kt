package app.octap.android.ui.vault

import android.annotation.SuppressLint
import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsBottomHeight
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.AutoFixHigh
import androidx.compose.material.icons.outlined.Badge
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Mail
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.octap.android.model.AppModel
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.Avatar
import app.octap.android.ui.components.Field as InputField
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.StrengthHint
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.tools.GeneratorPanel
import app.octap.android.ui.tools.Toggle
import app.octap.android.ui.util.formatDate
import app.octap.android.ui.util.rememberLive
import app.octap.resources.R
import app.octap.vault.Address
import app.octap.vault.BackupCode
import app.octap.vault.CardDetails
import app.octap.vault.CustomField
import app.octap.vault.FieldError
import app.octap.vault.GeneratorOptions
import app.octap.vault.IdentityDetails
import app.octap.vault.Item
import app.octap.vault.ItemDetails
import app.octap.vault.ItemDraft
import app.octap.vault.ItemFilter
import app.octap.vault.ItemSummary
import app.octap.vault.ItemType
import app.octap.vault.LoginDetails
import app.octap.vault.MaskedAlias
import app.octap.vault.RecoveryInfo
import app.octap.vault.RecoverySource
import app.octap.vault.SecurityQuestion
import app.octap.vault.Vault
import app.octap.vault.VaultException
import app.octap.vault.VaultRole
import app.octap.vault.VaultType
import app.octap.vault.WifiDetails
import app.octap.vault.generatePassword
import app.octap.vault.itemDraft
import app.octap.vault.newItemDraft
import app.octap.vault.urlMatchModes
import app.octap.vault.validateDraft
import app.octap.vault.wifiChoices
import kotlinx.coroutines.launch

/** The catalog message for a validation key the vault returns (`validation.titleRequired`). */
@SuppressLint("DiscouragedApi")
fun messageFor(context: Context, key: String): String {
    val id = context.resources.getIdentifier(key.replace(Regex("[^A-Za-z0-9_]"), "_"), "string", context.packageName)
    return if (id != 0) context.getString(id) else key
}

fun parseTags(text: String) = text.split(',').map { it.trim() }.filter { it.isNotEmpty() }.distinct()

/** The mode of a website with none stored: the site, the domains above it and the hosts below it. */
const val DEFAULT_MATCH_MODE = "subdomains"

fun matchModeRes(mode: String) = when (mode) {
    "baseDomain" -> R.string.editor_match_baseDomain
    "host" -> R.string.editor_match_host
    "startsWith" -> R.string.editor_match_startsWith
    "regex" -> R.string.editor_match_regex
    "never" -> R.string.editor_match_never
    else -> R.string.editor_match_subdomains
}

/** What a mode offers the login on, shown under the picker; the regular expression has its own warning. */
fun matchHelpRes(mode: String): Int? = when (mode) {
    "subdomains" -> R.string.editor_matchHelp_subdomains
    "baseDomain" -> R.string.editor_matchHelp_baseDomain
    "regex" -> R.string.editor_matchRegexWarning
    else -> null
}

/** Modes are keyed by the URL as written, so one follows its URL as it's typed. Another row with the old text keeps its own. */
fun urlMatchAfterEdit(urlMatch: Map<String, String>, urls: List<String>, index: Int, value: String): Map<String, String> {
    val mode = urlMatch[urls[index]] ?: return urlMatch
    return urlMatchAfterRemove(urlMatch, urls, index) + (value to mode)
}

fun urlMatchAfterRemove(urlMatch: Map<String, String>, urls: List<String>, index: Int): Map<String, String> =
    if (urls.without(index).contains(urls[index])) urlMatch else urlMatch - urls[index]

private fun newTitleRes(type: ItemType) = when (type) {
    ItemType.Password -> R.string.editor_new_password
    ItemType.Card -> R.string.editor_new_card
    ItemType.Identity -> R.string.editor_new_identity
    ItemType.SecureNote -> R.string.editor_new_secureNote
    ItemType.Wifi -> R.string.editor_new_wifi
    ItemType.SshKey -> R.string.editor_new_sshKey
    ItemType.Environment -> R.string.editor_new_environment
    ItemType.Document -> R.string.editor_new_document
    ItemType.BankAccount -> R.string.editor_new_bankAccount
    ItemType.IdDocument -> R.string.editor_new_idDocument
    ItemType.CryptoWallet -> R.string.editor_new_cryptoWallet
    ItemType.ApiCredential -> R.string.editor_new_apiCredential
    ItemType.Database -> R.string.editor_new_database
    ItemType.SoftwareLicense -> R.string.editor_new_softwareLicense
    ItemType.Custom -> R.string.editor_new_custom
    ItemType.CustomTemplate -> R.string.editor_new_customTemplate
    else -> R.string.editor_new_login
}

private fun placeholderRes(type: ItemType) = when (type) {
    ItemType.Password -> R.string.editor_titlePlaceholder_password
    ItemType.Card -> R.string.editor_titlePlaceholder_card
    ItemType.Identity -> R.string.editor_titlePlaceholder_identity
    ItemType.SecureNote -> R.string.editor_titlePlaceholder_secureNote
    ItemType.Wifi -> R.string.editor_titlePlaceholder_wifi
    ItemType.SshKey -> R.string.editor_titlePlaceholder_sshKey
    ItemType.Environment -> R.string.editor_titlePlaceholder_environment
    ItemType.Document -> R.string.editor_titlePlaceholder_document
    ItemType.BankAccount -> R.string.editor_titlePlaceholder_bankAccount
    ItemType.IdDocument -> R.string.editor_titlePlaceholder_idDocument
    ItemType.CryptoWallet -> R.string.editor_titlePlaceholder_cryptoWallet
    ItemType.ApiCredential -> R.string.editor_titlePlaceholder_apiCredential
    ItemType.Database -> R.string.editor_titlePlaceholder_database
    ItemType.SoftwareLicense -> R.string.editor_titlePlaceholder_softwareLicense
    ItemType.Custom -> R.string.editor_titlePlaceholder_custom
    ItemType.CustomTemplate -> R.string.editor_titlePlaceholder_customTemplate
    else -> R.string.editor_titlePlaceholder_login
}

/** The editor for a new or existing item (`ItemEditor`). */
@Composable
fun EditorScreen(route: Route.Edit) {
    val vault = LocalVault.current
    val model = vault.model
    val original = if (route.id != null) rememberLive(model, route.id) { model.vault.getItem(route.id) } else null
    val vaults = rememberLive(model, sharing = true) { model.vault.listVaults() }.data
    val item = original?.data
    when {
        original?.error != null -> Empty(Icons.Outlined.Close, stringResource(R.string.detail_notFound), errorMessage(LocalContext.current, original.error!!))
        (route.id != null && item == null) || vaults == null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
        item != null && vaults.firstOrNull { it.id == item.vaultId }?.role == VaultRole.READ ->
            Empty(Icons.Outlined.Close, stringResource(R.string.editor_readOnlyTitle), stringResource(R.string.detail_readOnly, vaults.first { it.id == item.vaultId }.name))
        // One form per item, so its state always starts from the item being edited.
        else -> androidx.compose.runtime.key(item?.id ?: "new") { EditorForm(route, item, vaults) }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun EditorForm(route: Route.Edit, original: Item?, vaults: List<Vault>) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val writable = vaults.filter { it.role != VaultRole.READ && !it.untrusted }
    val initial = remember {
        val pending = vault.nav.pendingDraft?.takeIf { draft -> original == null && writable.any { it.id == draft.vaultId } }
        vault.nav.pendingDraft = null
        if (original != null) {
            itemDraft(original)
        } else if (pending != null) {
            pending
        } else {
            val vaultId = route.vaultId?.takeIf { id -> writable.any { it.id == id } }
                ?: writable.firstOrNull { it.vaultType == VaultType.PERSONAL }?.id ?: writable.first().id
            newItemDraft(route.type, vaultId).also {
                if (vault.nav.scope == Scope.Favorites) it.favorite = true
                if (vault.nav.scope == Scope.Pinned) it.pinned = true
            }
        }
    }
    var draft by remember { mutableStateOf(initial) }
    var tagsText by remember { mutableStateOf(initial.tags.joinToString(", ")) }
    var errors by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    var formError by remember { mutableStateOf<String?>(null) }
    var saving by remember { mutableStateOf(false) }
    var files by remember { mutableStateOf(FileChanges()) }
    var fileError by remember { mutableStateOf<String?>(null) }
    var discarding by remember { mutableStateOf(false) }
    /** A login already saved for the same site and username, while asking about a copy. */
    var sameLogin by remember { mutableStateOf<ItemSummary?>(null) }
    val type = typeOfDetails(draft.details)
    val current = draft.copy(tags = parseTags(tagsText))
    val dirty = current != initial.copy(tags = parseTags(initial.tags.joinToString(", "))) || files.any

    fun leave() {
        files.add.forEach { it.file.delete() }
        vault.close()
    }

    BackHandler(enabled = dirty && !saving) { discarding = true }

    /** [copy]: the person saw that the vault has this login already and wants another one. */
    fun submit(copy: Boolean = false) {
        if (saving) return
        val found: List<FieldError> = validateDraft(current)
        errors = found.associate { it.field to messageFor(context, it.messageKey) }
        // A document is its file: a new one needs one, and an edit can't remove the last without adding another.
        val kept = (original?.attachments?.size ?: 0) - files.remove.size + files.add.size
        val missingFile = type == ItemType.Document && kept == 0 && !model.isLocal
        fileError = if (missingFile) context.getString(R.string.files_documentRequired) else null
        val count = found.size + if (missingFile) 1 else 0
        if (count > 0) {
            formError = context.resources.getQuantityString(R.plurals.editor_fixErrors, count, count)
            return
        }
        formError = null
        saving = true
        scope.launch {
            try {
                if (original == null && !copy) {
                    // A check that fails (locked meanwhile, say) doesn't stop the save itself.
                    val same = try { model.vault.sameLogin(current) } catch (error: VaultException) { null }
                    if (same != null) {
                        sameLogin = same
                        saving = false
                        return@launch
                    }
                }
                val saved = model.vault.saveItem(current)
                if (files.any) {
                    // A conflict copy is a new item: it takes the new files, and the original keeps its own.
                    val changes = if (saved.id == original?.id) files else files.copy(remove = emptyList())
                    for (failure in applyFileChanges(model, saved.id, changes, context)) model.toast(failure, Toast.Tone.Danger)
                    files = FileChanges()
                }
                // A new item may be offered the place the phone is at (`PlaceSuggestion`).
                if (original == null) FreshItems.add(saved.id)
                model.toast(context.getString(R.string.editor_saved, saved.title), Toast.Tone.Success)
                if (vault.twoPane && vault.nav.stack.size == 1) vault.nav.detail = Route.Item(saved.id)
                else if (original != null) vault.nav.pop() else vault.nav.replace(Route.Item(saved.id))
            } catch (error: Exception) {
                formError = errorMessage(context, error)
                saving = false
            }
        }
    }

    Scaffold(
        contentWindowInsets = WindowInsets(0),
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        if (original != null) stringResource(R.string.editor_editTitle, original.title) else stringResource(newTitleRes(type)),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.semantics { heading() },
                    )
                },
                navigationIcon = {
                    IconButton(onClick = { if (dirty) discarding = true else leave() }, modifier = Modifier.testTag("editor.cancel")) {
                        Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.common_cancel))
                    }
                },
                actions = {
                    TextButton(onClick = { submit() }, enabled = !saving, modifier = Modifier.testTag("editor.save")) {
                        if (saving) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) else Text(stringResource(R.string.common_save))
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .testTag("editor.form"),
        ) {
            Column(Modifier.widthIn(max = 720.dp).fillMaxWidth().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                formError?.let { Alert(it, modifier = Modifier.testTag("editor.error")) }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Avatar(draft.title.ifEmpty { stringResource(typeRes(type)) }, 48.dp)
                    InputField(
                        value = draft.title,
                        onValueChange = { draft = draft.copy(title = it) },
                        label = stringResource(R.string.fields_title),
                        placeholder = stringResource(placeholderRes(type)),
                        error = errors["title"],
                        capitalization = KeyboardCapitalization.Sentences,
                        autoCorrect = true,
                        modifier = Modifier.weight(1f).testTag("editor.title"),
                    )
                }
                if (type == ItemType.Document) EditorFiles(original, files, { files = it }, document = true, error = fileError)
                val update: (ItemDetails) -> Unit = { draft = draft.copy(details = it) }
                when (val details = draft.details) {
                    is ItemDetails.Login -> LoginSection(draft, details.login, isLogin = true, errors, { urls, urlMatch -> draft = draft.copy(urls = urls, urlMatch = urlMatch) }) { update(ItemDetails.Login(it)) }
                    is ItemDetails.Password -> LoginSection(draft, details.login, isLogin = false, errors, { urls, urlMatch -> draft = draft.copy(urls = urls, urlMatch = urlMatch) }) { update(ItemDetails.Password(it)) }
                    is ItemDetails.Card -> CardSection(details.card, errors) { update(ItemDetails.Card(it)) }
                    is ItemDetails.Identity -> IdentitySection(details.identity, errors) { update(ItemDetails.Identity(it)) }
                    is ItemDetails.SecureNote -> Section(stringResource(R.string.fields_note)) {
                        Notes(details.note.notes, minLines = 8, tag = "editor.note") { update(ItemDetails.SecureNote(details.note.copy(notes = it))) }
                    }
                    is ItemDetails.Document -> Section(stringResource(R.string.fields_notes)) {
                        Notes(details.document.notes.orEmpty(), minLines = 4) { update(ItemDetails.Document(details.document.copy(notes = it))) }
                    }
                    is ItemDetails.Wifi -> WifiSection(details.wifi, errors) { update(ItemDetails.Wifi(it)) }
                    is ItemDetails.SshKey -> {
                        SshKeySection(details.key, errors["privateKey"]) { update(ItemDetails.SshKey(it)) }
                        CustomFieldsSection(details.key.customFields) { update(ItemDetails.SshKey(details.key.copy(customFields = it))) }
                        Section(stringResource(R.string.fields_notes)) {
                            Notes(details.key.notes.orEmpty()) { update(ItemDetails.SshKey(details.key.copy(notes = it))) }
                        }
                    }
                    is ItemDetails.Environment -> {
                        EnvironmentSection(details.environment, errors) { update(ItemDetails.Environment(it)) }
                        Section(stringResource(R.string.fields_notes)) {
                            Notes(details.environment.notes.orEmpty()) { update(ItemDetails.Environment(details.environment.copy(notes = it))) }
                        }
                    }
                    is ItemDetails.Structured -> StructuredSection(details.itemType, details.structured, draft.vaultId, draft.title, original == null, errors) { update(ItemDetails.Structured(details.itemType, it)) }
                    is ItemDetails.MaskedEmailProvider, is ItemDetails.Other -> Unit
                }
                if (type != ItemType.Document && type != ItemType.CustomTemplate) EditorFiles(original, files, { files = it }, document = false, error = null)

                Section(stringResource(R.string.editor_organise)) {
                    // An existing item changes vault through Move, which re-encrypts it under the new vault's key.
                    Choice(
                        label = stringResource(R.string.fields_vault),
                        options = writable.map {
                            it.id to when (it.vaultType) {
                                VaultType.SHARED -> stringResource(R.string.editor_sharedVaultOption, vaultName(it))
                                VaultType.FAMILY -> stringResource(R.string.editor_familyVaultOption, vaultName(it))
                                VaultType.PERSONAL -> vaultName(it)
                            }
                        },
                        selected = draft.vaultId,
                        enabled = original == null,
                        tag = "editor.vault",
                    ) { draft = draft.copy(vaultId = it ?: draft.vaultId) }
                    InputField(tagsText, { tagsText = it }, stringResource(R.string.fields_tags), hint = stringResource(R.string.editor_tagsHint), placeholder = stringResource(R.string.editor_tagsPlaceholder), modifier = Modifier.testTag("editor.tags"))
                    Toggle(stringResource(R.string.fields_favorite), draft.favorite, tag = "editor.favorite") { draft = draft.copy(favorite = it) }
                    Toggle(stringResource(R.string.fields_pinned), draft.pinned, tag = "editor.pinned") { draft = draft.copy(pinned = it) }
                }
                Spacer(Modifier.windowInsetsBottomHeight(WindowInsets.navigationBars))
            }
        }
    }

    sameLogin?.let { same ->
        AlertDialog(
            onDismissRequest = { sameLogin = null },
            title = { Text(stringResource(R.string.editor_sameLoginTitle)) },
            text = { Text(stringResource(R.string.editor_sameLoginBody, same.title, vaults.firstOrNull { it.id == same.vaultId }?.let { vaultName(it) } ?: "")) },
            dismissButton = { TextButton(onClick = { sameLogin = null }) { Text(stringResource(R.string.editor_keepEditing)) } },
            confirmButton = {
                TextButton(onClick = { sameLogin = null; submit(copy = true) }, modifier = Modifier.testTag("editor.saveCopy")) {
                    Text(stringResource(R.string.editor_saveAnyway))
                }
            },
        )
    }

    if (discarding) {
        AlertDialog(
            onDismissRequest = { discarding = false },
            title = { Text(stringResource(R.string.editor_discardTitle)) },
            text = { Text(stringResource(R.string.editor_discardBody)) },
            dismissButton = { TextButton(onClick = { discarding = false }) { Text(stringResource(R.string.editor_keepEditing)) } },
            confirmButton = {
                TextButton(onClick = { discarding = false; leave() }, modifier = Modifier.testTag("editor.discard")) {
                    Text(stringResource(R.string.editor_discard), color = Brand.colors.dangerText)
                }
            },
        )
    }
}

fun typeOfDetails(details: ItemDetails): ItemType = when (details) {
    is ItemDetails.Login -> ItemType.Login
    is ItemDetails.Password -> ItemType.Password
    is ItemDetails.Card -> ItemType.Card
    is ItemDetails.Identity -> ItemType.Identity
    is ItemDetails.SecureNote -> ItemType.SecureNote
    is ItemDetails.Document -> ItemType.Document
    is ItemDetails.Wifi -> ItemType.Wifi
    is ItemDetails.SshKey -> ItemType.SshKey
    is ItemDetails.Environment -> ItemType.Environment
    is ItemDetails.MaskedEmailProvider -> ItemType.MaskedEmailProvider
    is ItemDetails.Structured -> details.itemType
    is ItemDetails.Other -> ItemType.Other(details.itemType)
}

/** A titled group of fields (`Section`). */
@Composable
fun Section(title: String, help: String? = null, content: @Composable () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.semantics { heading() })
        if (help != null) Text(help, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        content()
    }
}

@Composable
internal fun Notes(value: String, minLines: Int = 3, tag: String = "editor.notes", onChange: (String) -> Unit) {
    InputField(
        value = value,
        onValueChange = onChange,
        label = stringResource(R.string.fields_notes),
        singleLine = false,
        minLines = minLines,
        capitalization = KeyboardCapitalization.Sentences,
        autoCorrect = true,
        imeAction = ImeAction.Default,
        modifier = Modifier.testTag(tag),
    )
}

/** A dropdown of choices; a null key is "Not set". */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Choice(label: String, options: List<Pair<String?, String>>, selected: String?, enabled: Boolean = true, tag: String? = null, onSelect: (String?) -> Unit) {
    var open by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = open && enabled, onExpandedChange = { if (enabled) open = it }) {
        OutlinedTextField(
            value = options.firstOrNull { it.first == selected }?.second.orEmpty(),
            onValueChange = {},
            readOnly = true,
            enabled = enabled,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(open) },
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier.fillMaxWidth().menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable, enabled).let { if (tag != null) it.testTag(tag) else it },
        )
        ExposedDropdownMenu(expanded = open && enabled, onDismissRequest = { open = false }) {
            for ((key, text) in options) {
                DropdownMenuItem(text = { Text(text) }, onClick = { open = false; onSelect(key) }, modifier = Modifier.testTag("choice.${key ?: "none"}"))
            }
        }
    }
}

/** A list edited in place (`listOps`). */
internal fun <T> List<T>.replaced(index: Int, value: T) = mapIndexed { i, item -> if (i == index) value else item }

internal fun <T> List<T>.without(index: Int) = filterIndexed { i, _ -> i != index }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GeneratorSheet(model: AppModel, onUse: (String) -> Unit, onDismiss: () -> Unit, site: String? = null) {
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(Modifier.padding(horizontal = 20.dp).padding(bottom = 24.dp).verticalScroll(rememberScrollState())) {
            Text(stringResource(R.string.editor_generateTitle), style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(bottom = 12.dp).semantics { heading() })
            GeneratorPanel(model, onUse = onUse, useLabel = stringResource(R.string.editor_usePassword), site = site)
        }
    }
}

/** "Use a masked email": an alias for the login's first website, from the first connected provider. */
private class MaskedEmail(val available: Boolean, val busy: Boolean, val make: (onMade: (MaskedAlias) -> Unit) -> Unit)

@Composable
private fun rememberMaskedEmail(site: String?): MaskedEmail {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val connections = rememberLive(model, sharing = true) { runCatching { model.vault.maskedEmailConnections() }.getOrDefault(emptyList()) }.data
    var busy by remember { mutableStateOf(false) }
    return MaskedEmail(!connections.isNullOrEmpty(), busy) { onMade ->
        if (site.isNullOrBlank()) {
            model.toast(R.string.editor_maskedEmailNeedsSite, Toast.Tone.Danger)
        } else {
            busy = true
            scope.launch {
                try {
                    val alias = model.vault.createAlias(site, null)
                    model.toast(context.getString(R.string.editor_maskedEmailMade, alias.email), Toast.Tone.Success)
                    onMade(alias)
                } catch (error: Exception) {
                    model.toastError(error)
                } finally {
                    busy = false
                }
            }
        }
    }
}

fun aliasSource(alias: MaskedAlias) = RecoverySource(kind = "alias", itemId = null, provider = alias.provider, aliasId = alias.aliasId)

@Composable
private fun LoginSection(draft: ItemDraft, details: LoginDetails, isLogin: Boolean, errors: Map<String, String>, setUrls: (List<String>, Map<String, String>) -> Unit, set: (LoginDetails) -> Unit) {
    val model = LocalVault.current.model
    var generating by remember { mutableStateOf(false) }
    val urls = draft.urls.ifEmpty { listOf("") }
    val modes = remember { urlMatchModes() }
    // A regular expression isn't a site: it has no password rules and no address for an alias.
    val site = urls.firstOrNull { it.isNotBlank() && draft.urlMatch[it] != "regex" }?.trim()
    val masked = rememberMaskedEmail(site)
    Section(stringResource(R.string.editor_signIn)) {
        if (isLogin) {
            InputField(
                value = details.username.orEmpty(),
                onValueChange = { set(details.copy(username = it)) },
                label = stringResource(R.string.fields_username),
                keyboardType = KeyboardType.Email,
                modifier = Modifier.testTag("editor.username"),
                trailing = if (!masked.available) null else ({
                    IconButton(onClick = {
                        // A new alias becomes the username and the recovery email, linked to its provider.
                        masked.make { alias -> set(details.copy(username = alias.email, recovery = (details.recovery ?: emptyRecovery()).copy(email = alias.email, emailSource = aliasSource(alias)))) }
                    }, enabled = !masked.busy, modifier = Modifier.testTag("editor.maskedEmail")) {
                        Icon(Icons.Outlined.Mail, contentDescription = stringResource(if (masked.busy) R.string.editor_makingMaskedEmail else R.string.editor_useMaskedEmail))
                    }
                }),
            )
        }
        Column {
            Row(verticalAlignment = Alignment.Top) {
                PasswordField(
                    value = details.password.orEmpty(),
                    onValueChange = { set(details.copy(password = it)) },
                    label = stringResource(R.string.fields_password),
                    imeAction = ImeAction.Next,
                    contentType = null,
                    modifier = Modifier.weight(1f).testTag("editor.password"),
                )
                IconButton(onClick = { generating = true }, modifier = Modifier.padding(top = 8.dp).testTag("editor.generate")) {
                    Icon(Icons.Outlined.AutoFixHigh, contentDescription = stringResource(R.string.editor_generate))
                }
            }
            if (!details.password.isNullOrEmpty()) StrengthHint(remember(details.password) { model.vault.estimateStrength(details.password!!) }, empty = false)
        }
        if (isLogin) {
            InputField(
                value = details.totp.orEmpty(),
                onValueChange = { set(details.copy(totp = it)) },
                label = stringResource(R.string.fields_totp),
                placeholder = stringResource(R.string.editor_totpPlaceholder),
                hint = stringResource(R.string.editor_totpHint),
                error = errors["totp"],
                mono = true,
                keyboardType = KeyboardType.Ascii,
                modifier = Modifier.testTag("editor.totp"),
            )
        }
    }
    if (isLogin) {
        Section(stringResource(R.string.editor_websites)) {
            urls.forEachIndexed { i, url ->
                val mode = draft.urlMatch[url] ?: DEFAULT_MATCH_MODE
                InputField(
                    value = url,
                    onValueChange = { setUrls(urls.replaced(i, it), urlMatchAfterEdit(draft.urlMatch, urls, i, it)) },
                    label = if (i == 0) stringResource(R.string.fields_website) else stringResource(R.string.editor_websiteN, i + 1),
                    placeholder = if (mode == "regex") "^https://[a-z]+\\.example\\.com/" else "https://example.com",
                    error = errors["urls.$i"],
                    keyboardType = if (mode == "regex") KeyboardType.Text else KeyboardType.Uri,
                    modifier = Modifier.testTag("editor.url.$i"),
                    trailing = if (urls.size <= 1) null else ({
                        IconButton(onClick = { setUrls(urls.without(i), urlMatchAfterRemove(draft.urlMatch, urls, i)) }) { Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.editor_removeWebsite)) }
                    }),
                )
                if (url.isNotBlank()) {
                    Choice(stringResource(R.string.editor_matchRule), modes.map { it to stringResource(matchModeRes(it)) }, mode, tag = "editor.matchRule.$i") { chosen ->
                        // The default isn't stored, so going back to it leaves the draft as it was.
                        setUrls(urls, if (chosen == null || chosen == DEFAULT_MATCH_MODE) draft.urlMatch - url else draft.urlMatch + (url to chosen))
                    }
                    matchHelpRes(mode)?.let { help ->
                        Text(stringResource(help), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.testTag("editor.matchHelp.$i"))
                    }
                }
            }
            TextButton(onClick = { setUrls(urls + "", draft.urlMatch) }, modifier = Modifier.testTag("editor.addUrl")) {
                Icon(Icons.Outlined.Add, null, Modifier.size(18.dp))
                Text(stringResource(R.string.editor_addWebsite), Modifier.padding(start = 6.dp))
            }
        }
        RecoverySection(details.recovery ?: emptyRecovery(), errors, site) { set(details.copy(recovery = it)) }
    }
    CustomFieldsSection(details.customFields) { set(details.copy(customFields = it)) }
    if (details.passkeys.isNotEmpty()) {
        Section(stringResource(R.string.detail_passkeys), help = stringResource(R.string.editor_passkeysReadOnly)) {
            for (passkey in details.passkeys) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Outlined.Key, null, Modifier.size(18.dp))
                    Column {
                        Text("${passkey.rpId} · ${passkey.userName}")
                        Text(stringResource(R.string.detail_passkeySaved, formatDate(passkey.createdAt)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
    Section(stringResource(R.string.fields_notes)) { Notes(details.notes.orEmpty()) { set(details.copy(notes = it)) } }
    if (generating) GeneratorSheet(model, onUse = { set(details.copy(password = it)); generating = false }, onDismiss = { generating = false }, site = site)
}

private fun emptyRecovery() = RecoveryInfo(null, null, null, null, emptyList(), emptyList(), null)

/** Five words: a random answer is safer than a true one, and works like a second password (`randomAnswer`). */
private fun randomAnswer() = generatePassword(GeneratorOptions.Passphrase(words = 5u, separator = " ", capitalize = false, includeNumber = false))

private val TWO_FACTOR = listOf("totp", "passkey", "key", "sms", "email", "none")

private fun twoFactorRes(method: String) = when (method) {
    "totp" -> R.string.twoFactor_totp
    "passkey" -> R.string.twoFactor_passkey
    "key" -> R.string.twoFactor_key
    "sms" -> R.string.twoFactor_sms
    "email" -> R.string.twoFactor_email
    else -> R.string.twoFactor_none
}

@Composable
private fun RecoverySection(recovery: RecoveryInfo, errors: Map<String, String>, site: String?, onChange: (RecoveryInfo) -> Unit) {
    val model = LocalVault.current.model
    val masked = rememberMaskedEmail(site)
    var bulk by remember { mutableStateOf(false) }
    var bulkText by remember { mutableStateOf("") }
    // The vault's identities, for linking a recovery email or phone to one.
    val identities = rememberLive(model) {
        model.vault.listItems(ItemFilter(null, ItemType.Identity, null, false, false, false, false, null, null)).map { model.vault.getItem(it.id) }
    }.data.orEmpty()

    fun fromIdentities(email: Boolean) = identities.mapNotNull { identity ->
        val details = (identity.details as? ItemDetails.Identity)?.identity ?: return@mapNotNull null
        val value = (if (email) details.email else details.phone)?.trim()
        if (value.isNullOrEmpty()) null else value to RecoverySource("identity", identity.id, null, null)
    }

    Section(stringResource(R.string.detail_recovery), help = stringResource(R.string.editor_recoveryHelp)) {
        Choice(
            stringResource(R.string.fields_twoFactorMethod),
            listOf<Pair<String?, String>>(null to stringResource(R.string.editor_notSet)) + TWO_FACTOR.map { it to stringResource(twoFactorRes(it)) },
            recovery.twoFactorMethod,
            tag = "editor.twoFactor",
        ) { onChange(recovery.copy(twoFactorMethod = it)) }
        InputField(
            value = recovery.email.orEmpty(),
            // Typing breaks the link: the value no longer comes from the identity or alias.
            onValueChange = { onChange(recovery.copy(email = it, emailSource = null)) },
            label = stringResource(R.string.fields_recoveryEmail),
            error = errors["recovery.email"],
            keyboardType = KeyboardType.Email,
            modifier = Modifier.testTag("editor.recoveryEmail"),
            trailing = if (!masked.available) null else ({
                IconButton(onClick = { masked.make { alias -> onChange(recovery.copy(email = alias.email, emailSource = aliasSource(alias))) } }, enabled = !masked.busy) {
                    Icon(Icons.Outlined.Mail, contentDescription = stringResource(if (masked.busy) R.string.editor_makingMaskedEmail else R.string.editor_useMaskedEmail))
                }
            }),
        )
        ContactLink(recovery.emailSource, recovery.email, fromIdentities(true), identities, { value, source -> onChange(recovery.copy(email = value, emailSource = source)) }) { onChange(recovery.copy(emailSource = null)) }
        InputField(
            value = recovery.phone.orEmpty(),
            onValueChange = { onChange(recovery.copy(phone = it, phoneSource = null)) },
            label = stringResource(R.string.fields_recoveryPhone),
            keyboardType = KeyboardType.Phone,
        )
        ContactLink(recovery.phoneSource, recovery.phone, fromIdentities(false), identities, { value, source -> onChange(recovery.copy(phone = value, phoneSource = source)) }) { onChange(recovery.copy(phoneSource = null)) }

        Text(stringResource(R.string.fields_backupCodes), style = MaterialTheme.typography.labelLarge)
        recovery.backupCodes.forEachIndexed { i, code ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                InputField(code.code, { onChange(recovery.copy(backupCodes = recovery.backupCodes.replaced(i, code.copy(code = it)))) }, stringResource(R.string.editor_codeN, i + 1), mono = true, modifier = Modifier.weight(1f))
                Row(
                    Modifier.toggleable(code.used, role = Role.Checkbox) { onChange(recovery.copy(backupCodes = recovery.backupCodes.replaced(i, code.copy(used = it)))) }.padding(4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(code.used, null)
                    Text(stringResource(R.string.detail_codeUsed))
                }
                IconButton(onClick = { onChange(recovery.copy(backupCodes = recovery.backupCodes.without(i))) }) {
                    Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.editor_removeCode, i + 1))
                }
            }
        }
        if (bulk) {
            InputField(bulkText, { bulkText = it }, stringResource(R.string.editor_pasteCodes), hint = stringResource(R.string.editor_pasteCodesHint), mono = true, singleLine = false, minLines = 4, imeAction = ImeAction.Default)
            TextButton(onClick = {
                val added = bulkText.split(Regex("[\\s,]+")).filter { it.isNotEmpty() }.map { BackupCode(it, false) }
                onChange(recovery.copy(backupCodes = recovery.backupCodes + added))
                bulkText = ""
                bulk = false
            }) { Text(stringResource(R.string.editor_addCodes)) }
        } else {
            Row {
                TextButton(onClick = { onChange(recovery.copy(backupCodes = recovery.backupCodes + BackupCode("", false))) }) {
                    Icon(Icons.Outlined.Add, null, Modifier.size(18.dp))
                    Text(stringResource(R.string.editor_addCode), Modifier.padding(start = 6.dp))
                }
                TextButton(onClick = { bulk = true }) { Text(stringResource(R.string.editor_pasteCodes)) }
            }
        }

        Text(stringResource(R.string.fields_securityQuestions), style = MaterialTheme.typography.labelLarge)
        val questions = recovery.securityQuestions
        questions.forEachIndexed { i, entry ->
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                InputField(entry.question, { onChange(recovery.copy(securityQuestions = questions.replaced(i, entry.copy(question = it)))) }, stringResource(R.string.editor_question, i + 1), capitalization = KeyboardCapitalization.Sentences, modifier = Modifier.testTag("editor.question.$i"))
                Row(verticalAlignment = Alignment.Top) {
                    PasswordField(
                        entry.answer,
                        { onChange(recovery.copy(securityQuestions = questions.replaced(i, entry.copy(answer = it)))) },
                        stringResource(R.string.fields_securityAnswer),
                        imeAction = ImeAction.Next,
                        contentType = null,
                        modifier = Modifier.weight(1f).testTag("editor.answer.$i"),
                    )
                    IconButton(onClick = { onChange(recovery.copy(securityQuestions = questions.replaced(i, entry.copy(answer = randomAnswer())))) }, modifier = Modifier.padding(top = 8.dp).testTag("editor.randomAnswer.$i")) {
                        Icon(Icons.Outlined.AutoFixHigh, contentDescription = stringResource(R.string.editor_randomAnswer))
                    }
                    IconButton(onClick = { onChange(recovery.copy(securityQuestions = questions.without(i))) }, modifier = Modifier.padding(top = 8.dp)) {
                        Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.editor_removeQuestion, i + 1))
                    }
                }
            }
        }
        TextButton(onClick = { onChange(recovery.copy(securityQuestions = questions + SecurityQuestion("", randomAnswer()))) }, modifier = Modifier.testTag("editor.addQuestion")) {
            Icon(Icons.Outlined.Add, null, Modifier.size(18.dp))
            Text(stringResource(R.string.editor_addQuestion), Modifier.padding(start = 6.dp))
        }
        Text(stringResource(R.string.editor_securityQuestionsHelp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** Where a recovery email or phone came from, with Unlink, or else the identities' values to pick from (`ContactLink`). */
@Composable
private fun ContactLink(source: RecoverySource?, value: String?, options: List<Pair<String, RecoverySource>>, identities: List<Item>, onPick: (String, RecoverySource) -> Unit, onUnlink: () -> Unit) {
    if (source != null && !value.isNullOrEmpty()) {
        val identity = if (source.kind == "identity") identities.firstOrNull { it.id == source.itemId } else null
        val label = if (source.kind == "alias") stringResource(R.string.editor_linkedAlias, providerName(source.provider))
        else stringResource(R.string.editor_linkedIdentity, identity?.title ?: stringResource(R.string.types_identity))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(if (source.kind == "alias") Icons.Outlined.Mail else Icons.Outlined.Badge, null, Modifier.size(16.dp))
            Text(label, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(horizontal = 6.dp).weight(1f, fill = false))
            TextButton(onClick = onUnlink) { Text(stringResource(R.string.editor_unlink)) }
        }
        return
    }
    val choices = options.filter { it.first != value }
    if (choices.isEmpty()) return
    Column {
        Text(stringResource(R.string.editor_fromIdentities), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        for ((option, from) in choices) {
            TextButton(onClick = { onPick(option, from) }) { Text(option) }
        }
    }
}

@Composable
internal fun CustomFieldsSection(fields: List<CustomField>, onChange: (List<CustomField>) -> Unit) {
    Section(stringResource(R.string.detail_moreFields)) {
        fields.forEachIndexed { i, field ->
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                InputField(field.label, { onChange(fields.replaced(i, field.copy(label = it))) }, stringResource(R.string.editor_fieldLabel), capitalization = KeyboardCapitalization.Sentences)
                if (field.hidden) PasswordField(field.value, { onChange(fields.replaced(i, field.copy(value = it))) }, stringResource(R.string.editor_fieldValue), contentType = null, imeAction = ImeAction.Next)
                else InputField(field.value, { onChange(fields.replaced(i, field.copy(value = it))) }, stringResource(R.string.editor_fieldValue))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.weight(1f)) { Toggle(stringResource(R.string.editor_fieldHidden), field.hidden) { onChange(fields.replaced(i, field.copy(hidden = it))) } }
                    IconButton(onClick = { onChange(fields.without(i)) }) {
                        Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.editor_removeField, field.label.ifEmpty { "" }), tint = Brand.colors.dangerText)
                    }
                }
            }
        }
        TextButton(onClick = { onChange(fields + CustomField("", "", false)) }, modifier = Modifier.testTag("editor.addField")) {
            Icon(Icons.Outlined.Add, null, Modifier.size(18.dp))
            Text(stringResource(R.string.editor_addField), Modifier.padding(start = 6.dp))
        }
    }
}

@Composable
private fun CardSection(details: CardDetails, errors: Map<String, String>, set: (CardDetails) -> Unit) {
    Section(stringResource(R.string.editor_cardDetails)) {
        InputField(details.cardholder.orEmpty(), { set(details.copy(cardholder = it)) }, stringResource(R.string.fields_cardholder), capitalization = KeyboardCapitalization.Words, modifier = Modifier.testTag("editor.cardholder"))
        PasswordField(details.number.orEmpty(), { set(details.copy(number = it)) }, stringResource(R.string.fields_cardNumber), error = errors["number"], imeAction = ImeAction.Next, contentType = null, modifier = Modifier.testTag("editor.cardNumber"))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            InputField(details.expiry.orEmpty(), { set(details.copy(expiry = it.take(5))) }, stringResource(R.string.fields_expiry), placeholder = stringResource(R.string.editor_expiryPlaceholder), error = errors["expiry"], keyboardType = KeyboardType.Number, modifier = Modifier.weight(1f).testTag("editor.expiry"))
            PasswordField(details.cvv.orEmpty(), { set(details.copy(cvv = it.take(4))) }, stringResource(R.string.fields_cvv), imeAction = ImeAction.Next, contentType = null, modifier = Modifier.weight(1f))
        }
        PasswordField(details.pin.orEmpty(), { set(details.copy(pin = it.take(12))) }, stringResource(R.string.fields_pin), imeAction = ImeAction.Next, contentType = null)
        InputField(details.brand.orEmpty(), { set(details.copy(brand = it)) }, stringResource(R.string.fields_brand), hint = stringResource(R.string.editor_brandHint))
    }
    Section(stringResource(R.string.fields_notes)) { Notes(details.notes.orEmpty()) { set(details.copy(notes = it)) } }
}

@Composable
private fun IdentitySection(details: IdentityDetails, errors: Map<String, String>, set: (IdentityDetails) -> Unit) {
    val address = details.address ?: Address(null, null, null, null, null, null)
    fun setAddress(next: Address) = set(details.copy(address = next))
    Section(stringResource(R.string.editor_person)) {
        InputField(details.firstName.orEmpty(), { set(details.copy(firstName = it)) }, stringResource(R.string.fields_firstName), capitalization = KeyboardCapitalization.Words, modifier = Modifier.testTag("editor.firstName"))
        InputField(details.lastName.orEmpty(), { set(details.copy(lastName = it)) }, stringResource(R.string.fields_lastName), capitalization = KeyboardCapitalization.Words)
        InputField(details.email.orEmpty(), { set(details.copy(email = it)) }, stringResource(R.string.fields_email), error = errors["email"], keyboardType = KeyboardType.Email, modifier = Modifier.testTag("editor.email"))
        InputField(details.phone.orEmpty(), { set(details.copy(phone = it)) }, stringResource(R.string.fields_phone), keyboardType = KeyboardType.Phone)
        BirthDateField(details.birthDate) { set(details.copy(birthDate = it)) }
    }
    Section(stringResource(R.string.fields_address)) {
        InputField(address.line1.orEmpty(), { setAddress(address.copy(line1 = it)) }, stringResource(R.string.fields_addressLine1), capitalization = KeyboardCapitalization.Words)
        InputField(address.line2.orEmpty(), { setAddress(address.copy(line2 = it)) }, stringResource(R.string.fields_addressLine2), capitalization = KeyboardCapitalization.Words)
        InputField(address.city.orEmpty(), { setAddress(address.copy(city = it)) }, stringResource(R.string.fields_city), capitalization = KeyboardCapitalization.Words)
        InputField(address.region.orEmpty(), { setAddress(address.copy(region = it)) }, stringResource(R.string.fields_region), capitalization = KeyboardCapitalization.Words)
        InputField(address.postalCode.orEmpty(), { setAddress(address.copy(postalCode = it)) }, stringResource(R.string.fields_postalCode), capitalization = KeyboardCapitalization.Characters)
        InputField(address.country.orEmpty(), { setAddress(address.copy(country = it)) }, stringResource(R.string.fields_country), capitalization = KeyboardCapitalization.Words)
    }
    Section(stringResource(R.string.fields_notes)) { Notes(details.notes.orEmpty()) { set(details.copy(notes = it)) } }
}

/** A birth date as `YYYY-MM-DD`, or none, chosen in the system's date picker. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BirthDateField(value: String?, set: (String?) -> Unit) {
    val format = remember { java.time.format.DateTimeFormatter.ISO_LOCAL_DATE }
    var open by remember { mutableStateOf(false) }
    val date = value?.let { runCatching { java.time.LocalDate.parse(it, format) }.getOrNull() }
    val label = stringResource(R.string.fields_birthDate)
    Row(verticalAlignment = Alignment.CenterVertically) {
        androidx.compose.material3.OutlinedButton(onClick = { open = true }, modifier = Modifier.weight(1f).testTag("editor.birthDate")) { Text(if (date != null) "$label: ${date.format(format)}" else label) }
        if (value != null) {
            IconButton(onClick = { set(null) }) { Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.common_remove)) }
        }
    }
    if (open) {
        val state = androidx.compose.material3.rememberDatePickerState(
            initialSelectedDateMillis = (date ?: java.time.LocalDate.of(1990, 1, 1)).atStartOfDay(java.time.ZoneOffset.UTC).toInstant().toEpochMilli(),
        )
        androidx.compose.material3.DatePickerDialog(
            onDismissRequest = { open = false },
            confirmButton = {
                TextButton(onClick = {
                    state.selectedDateMillis?.let { set(java.time.Instant.ofEpochMilli(it).atZone(java.time.ZoneOffset.UTC).toLocalDate().format(format)) }
                    open = false
                }) { Text(stringResource(R.string.common_save)) }
            },
            dismissButton = { TextButton(onClick = { open = false }) { Text(stringResource(R.string.common_cancel)) } },
        ) { androidx.compose.material3.DatePicker(state) }
    }
}

@Composable
private fun WifiSection(details: WifiDetails, errors: Map<String, String>, set: (WifiDetails) -> Unit) {
    val model = LocalVault.current.model
    val choices = remember { wifiChoices() }
    var generating by remember { mutableStateOf(false) }
    val enterprise = details.security == "wpa2Enterprise" || details.security == "wpa3Enterprise"
    val shared = details.security != "open" && !enterprise
    Section(stringResource(R.string.wifi_network)) {
        InputField(details.ssid, { set(details.copy(ssid = it)) }, stringResource(R.string.wifi_ssid), hint = stringResource(R.string.wifi_ssidHint), error = errors["ssid"], modifier = Modifier.testTag("editor.ssid"))
        Choice(stringResource(R.string.wifi_security), choices.securities.map { it to stringResource(securityLabel(it)) }, details.security, tag = "editor.security") { set(details.copy(security = it ?: details.security)) }
        Text(stringResource(if (details.security == "open") R.string.wifi_openHint else R.string.wifi_securityHint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (shared) {
            Column {
                Row(verticalAlignment = Alignment.Top) {
                    PasswordField(
                        details.password.orEmpty(),
                        { set(details.copy(password = it)) },
                        stringResource(R.string.fields_password),
                        hint = stringResource(if (details.security == "wep") R.string.wifi_wepHint else R.string.wifi_wpaHint),
                        error = errors["password"],
                        imeAction = ImeAction.Next,
                        contentType = null,
                        modifier = Modifier.weight(1f).testTag("editor.wifiPassword"),
                    )
                    if (details.security != "wep") {
                        IconButton(onClick = { generating = true }, modifier = Modifier.padding(top = 8.dp)) { Icon(Icons.Outlined.AutoFixHigh, contentDescription = stringResource(R.string.editor_generate)) }
                    }
                }
                if (!details.password.isNullOrEmpty() && details.security != "wep") StrengthHint(remember(details.password) { model.vault.estimateStrength(details.password!!) }, empty = false)
            }
        }
        Toggle(stringResource(R.string.wifi_hidden), details.hidden, stringResource(R.string.wifi_hiddenHint)) { set(details.copy(hidden = it)) }
    }
    if (enterprise) {
        Section(stringResource(R.string.wifi_enterprise), help = stringResource(R.string.wifi_enterpriseHelp)) {
            Choice(stringResource(R.string.wifi_eapMethod), listOf<Pair<String?, String>>(null to stringResource(R.string.editor_notSet)) + choices.eapMethods.map { it to stringResource(eapRes(it)) }, details.eapMethod) { set(details.copy(eapMethod = it)) }
            if (details.eapMethod == "peap" || details.eapMethod == "ttls") {
                Choice(stringResource(R.string.wifi_phase2), listOf<Pair<String?, String>>(null to stringResource(R.string.editor_notSet)) + choices.phase2.map { it to stringResource(phase2Res(it)) }, details.phase2) { set(details.copy(phase2 = it)) }
            }
            InputField(details.username.orEmpty(), { set(details.copy(username = it)) }, stringResource(R.string.fields_username))
            if (details.eapMethod != "tls") PasswordField(details.password.orEmpty(), { set(details.copy(password = it)) }, stringResource(R.string.fields_password), imeAction = ImeAction.Next, contentType = null)
            InputField(details.identity.orEmpty(), { set(details.copy(identity = it)) }, stringResource(R.string.wifi_identity), hint = stringResource(R.string.wifi_identityHint))
            InputField(details.serverDomain.orEmpty(), { set(details.copy(serverDomain = it)) }, stringResource(R.string.wifi_serverDomain), hint = stringResource(R.string.wifi_serverDomainHint), keyboardType = KeyboardType.Uri)
            InputField(details.caCertificate.orEmpty(), { set(details.copy(caCertificate = it)) }, stringResource(R.string.wifi_caCertificate), hint = stringResource(R.string.wifi_caCertificateHint), mono = true, singleLine = false, minLines = 4, imeAction = ImeAction.Default)
        }
    }
    Section(stringResource(R.string.wifi_about)) {
        Toggle(stringResource(R.string.wifi_captivePortal), details.captivePortal, stringResource(R.string.wifi_captivePortalHint)) { set(details.copy(captivePortal = it)) }
        Toggle(stringResource(R.string.wifi_managed), details.managed, stringResource(R.string.wifi_managedHint)) { set(details.copy(managed = it)) }
        Toggle(stringResource(R.string.wifi_hotspot), details.hotspot, stringResource(R.string.wifi_hotspotHint)) { set(details.copy(hotspot = it)) }
    }
    CustomFieldsSection(details.customFields) { set(details.copy(customFields = it)) }
    Section(stringResource(R.string.fields_notes)) { Notes(details.notes.orEmpty()) { set(details.copy(notes = it)) } }
    if (generating) GeneratorSheet(model, onUse = { set(details.copy(password = it)); generating = false }, onDismiss = { generating = false })
}
