package app.octap.android.ui.vault

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import app.octap.resources.R
import app.octap.android.model.errorMessage
import app.octap.android.ui.components.Field as InputField
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.util.formatDate
import app.octap.vault.FieldSpec
import app.octap.vault.FieldStyle
import app.octap.vault.FieldValue
import app.octap.vault.ItemDetails
import app.octap.vault.ItemFilter
import app.octap.vault.ItemSummary
import app.octap.vault.ItemType
import app.octap.vault.StructuredDetails
import app.octap.vault.TypedField
import app.octap.vault.WalletAddress
import app.octap.vault.customFieldKinds
import app.octap.vault.customKindIsPlain
import app.octap.vault.fieldSpecs
import app.octap.vault.fieldsFromTemplate
import app.octap.vault.newItemDraft
import app.octap.vault.templateFromItem
import kotlinx.coroutines.launch

/*
 * Bank accounts, API credentials, software licences, ID documents, crypto wallets, databases, custom
 * items and custom templates. The vault's `fieldSpecs` says what each holds, so one editor and one
 * detail view cover all of them (the web vault's `TypedItems`).
 */

private fun fieldLabel(context: Context, key: String) = messageFor(context, "itemFields.$key")

/** A choice's words, or what another app wrote when it's not one of ours. */
private fun choiceLabel(context: Context, key: String, value: String): String {
    val catalog = "itemChoices.$key.$value"
    val text = messageFor(context, catalog)
    return if (text == catalog) value else text
}

private fun StructuredDetails.value(key: String) = values.firstOrNull { it.key == key }?.value.orEmpty()

private fun StructuredDetails.with(key: String, value: String) =
    copy(values = values.filter { it.key != key } + if (value.isEmpty()) emptyList() else listOf(FieldValue(key, value)))

@Composable
internal fun StructuredSection(type: ItemType, details: StructuredDetails, vaultId: String, title: String, isNew: Boolean, errors: Map<String, String>, set: (StructuredDetails) -> Unit) {
    val specs = remember(type) { fieldSpecs(type) }
    if (specs.isNotEmpty()) {
        Section(stringResource(typeRes(type))) {
            for (spec in specs) StructuredInput(spec, details.value(spec.key), errors[spec.key]) { set(details.with(spec.key, it)) }
        }
    }
    if (type == ItemType.CryptoWallet) AddressesSection(details.addresses, errors) { set(details.copy(addresses = it)) }
    if (type == ItemType.Custom) {
        if (isNew) TemplateChoice(details, set)
        TypedFieldsSection(details.fields, withValues = true) { set(details.copy(fields = it)) }
        if (details.fields.isNotEmpty()) SaveAsTemplate(details, vaultId, title)
    }
    if (type == ItemType.CustomTemplate) {
        Section(stringResource(R.string.typedItems_fields), help = stringResource(R.string.typedItems_templateHelp)) {}
        TypedFieldsSection(details.fields, withValues = false) { set(details.copy(fields = it)) }
    } else {
        if (type != ItemType.Custom) CustomFieldsSection(details.customFields) { set(details.copy(customFields = it)) }
        Section(stringResource(R.string.fields_notes)) { Notes(details.notes.orEmpty()) { set(details.copy(notes = it)) } }
    }
}

@Composable
private fun StructuredInput(spec: FieldSpec, value: String, error: String?, onChange: (String) -> Unit) {
    val context = LocalContext.current
    val label = fieldLabel(context, spec.key)
    val tag = Modifier.testTag("editor.${spec.key}")
    when (spec.style) {
        FieldStyle.CHOICE -> Choice(
            label,
            listOf<Pair<String?, String>>(null to "") + spec.choices.map { it to choiceLabel(context, spec.key, it) } + if (value.isEmpty() || value in spec.choices) emptyList() else listOf(value to value),
            value.ifEmpty { null },
            tag = "editor.${spec.key}",
        ) { onChange(it.orEmpty()) }
        FieldStyle.SECRET -> PasswordField(value, onChange, label, error = error, imeAction = ImeAction.Next, contentType = null, modifier = tag)
        FieldStyle.SECRET_LONG -> LongSecretInput(label, value, error, spec.key, onChange)
        FieldStyle.CODE -> InputField(value, onChange, label, error = error, mono = true, keyboardType = KeyboardType.Ascii, modifier = tag)
        FieldStyle.DATE -> InputField(value, onChange, label, placeholder = "YYYY-MM-DD", error = error, keyboardType = KeyboardType.Ascii, modifier = tag)
        FieldStyle.EMAIL -> InputField(value, onChange, label, error = error, keyboardType = KeyboardType.Email, modifier = tag)
        FieldStyle.PORT -> InputField(value, onChange, label, error = error, keyboardType = KeyboardType.Number, modifier = tag)
        FieldStyle.TEXT -> InputField(value, onChange, label, error = error, modifier = tag)
    }
}

/** A long secret stays hidden in the editor too, until asked for. */
@Composable
private fun LongSecretInput(label: String, value: String, error: String?, key: String, onChange: (String) -> Unit) {
    var shown by remember { mutableStateOf(false) }
    val hide: (@Composable () -> Unit)? = if (value.isEmpty()) null else { { HideButton(label, shown = true) { shown = false } } }
    if (shown || value.isEmpty()) {
        InputField(
            value,
            onChange,
            label,
            error = error,
            mono = true,
            singleLine = false,
            minLines = 3,
            imeAction = ImeAction.Default,
            modifier = Modifier.testTag("editor.$key"),
            trailing = hide,
        )
    } else {
        InputField("•".repeat(16), {}, label, error = error, mono = true, readOnly = true, modifier = Modifier.testTag("editor.$key"), trailing = { HideButton(label, shown = false) { shown = true } })
    }
}

@Composable
private fun HideButton(label: String, shown: Boolean, onClick: () -> Unit) {
    val description = stringResource(if (shown) R.string.typedItems_secretHide else R.string.typedItems_secretShow, label)
    IconButton(onClick = onClick) { Icon(if (shown) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility, contentDescription = description) }
}

@Composable
private fun AddressesSection(addresses: List<WalletAddress>, errors: Map<String, String>, onChange: (List<WalletAddress>) -> Unit) {
    Section(stringResource(R.string.typedItems_addresses)) {
        addresses.forEachIndexed { i, entry ->
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.weight(1f)) { InputField(entry.network, { onChange(addresses.replaced(i, entry.copy(network = it))) }, stringResource(R.string.typedItems_network), hint = stringResource(R.string.typedItems_networkHint)) }
                    IconButton(onClick = { onChange(addresses.without(i)) }) {
                        Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.typedItems_removeAddress, i + 1), tint = Brand.colors.dangerText)
                    }
                }
                InputField(entry.address, { onChange(addresses.replaced(i, entry.copy(address = it))) }, stringResource(R.string.typedItems_address), error = errors["addresses.$i"], mono = true, keyboardType = KeyboardType.Ascii, modifier = Modifier.testTag("editor.address.$i"))
                InputField(entry.label.orEmpty(), { onChange(addresses.replaced(i, entry.copy(label = it.ifEmpty { null }))) }, stringResource(R.string.typedItems_addressLabel))
            }
        }
        AddRow(stringResource(R.string.typedItems_addAddress), "editor.addAddress") { onChange(addresses + WalletAddress("bitcoin", "", null)) }
    }
}

@Composable
private fun AddRow(label: String, tag: String, onClick: () -> Unit) {
    TextButton(onClick = onClick, modifier = Modifier.testTag(tag)) {
        Icon(Icons.Outlined.Add, null, Modifier.size(18.dp))
        Text(label, Modifier.padding(start = 6.dp))
    }
}

@Composable
private fun TypedFieldsSection(fields: List<TypedField>, withValues: Boolean, onChange: (List<TypedField>) -> Unit) {
    val context = LocalContext.current
    val kinds = remember { customFieldKinds() }
    Section(stringResource(R.string.typedItems_fields)) {
        fields.forEachIndexed { i, field ->
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.weight(1f)) { InputField(field.label, { onChange(fields.replaced(i, field.copy(label = it))) }, stringResource(R.string.editor_fieldLabel)) }
                    IconButton(onClick = { onChange(fields.without(i)) }) {
                        Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.editor_removeField, field.label), tint = Brand.colors.dangerText)
                    }
                }
                if (withValues) {
                    val change = { value: String -> onChange(fields.replaced(i, field.copy(value = value))) }
                    when {
                        field.kind == "multiline" -> InputField(field.value, change, stringResource(R.string.editor_fieldValue), singleLine = false, minLines = 3, imeAction = ImeAction.Default)
                        customKindIsPlain(field.kind) -> InputField(field.value, change, stringResource(R.string.editor_fieldValue))
                        else -> PasswordField(field.value, change, stringResource(R.string.editor_fieldValue), imeAction = ImeAction.Next, contentType = null)
                    }
                }
                Choice(
                    stringResource(R.string.typedItems_fieldKind),
                    kinds.map<String, Pair<String?, String>> { it to choiceLabel(context, "customKind", it) } + if (field.kind in kinds) emptyList() else listOf(field.kind to field.kind),
                    field.kind,
                ) { kind -> onChange(fields.replaced(i, field.copy(kind = kind ?: "text"))) }
            }
        }
        AddRow(stringResource(R.string.editor_addField), "editor.addField") { onChange(fields + TypedField("", "", "text")) }
    }
}

@Composable
private fun TemplateChoice(details: StructuredDetails, set: (StructuredDetails) -> Unit) {
    val model = LocalVault.current.model
    val scope = rememberCoroutineScope()
    var templates by remember { mutableStateOf<List<ItemSummary>>(emptyList()) }
    LaunchedEffect(Unit) {
        templates = runCatching { model.vault.listItems(ItemFilter(null, ItemType.CustomTemplate, null, false, false, false, false)) }.getOrDefault(emptyList())
    }
    if (templates.isEmpty()) return
    Section(stringResource(R.string.typedItems_template)) {
        Choice(
            stringResource(R.string.typedItems_useTemplate),
            listOf<Pair<String?, String>>(null to stringResource(R.string.typedItems_noTemplate)) + templates.map { it.id to it.title },
            details.templateId,
        ) { id ->
            if (id == null) {
                set(details.copy(templateId = null, templateName = null))
            } else {
                scope.launch {
                    val template = runCatching { model.vault.getItem(id) }.getOrNull() ?: return@launch
                    val fields = (template.details as? ItemDetails.Structured)?.structured ?: return@launch
                    set(details.copy(templateId = id, templateName = template.title, fields = fieldsFromTemplate(fields)))
                }
            }
        }
    }
}

@Composable
private fun SaveAsTemplate(details: StructuredDetails, vaultId: String, title: String) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var message by remember { mutableStateOf<String?>(null) }
    OutlinedButton(
        onClick = {
            val name = title.trim()
            if (name.isEmpty()) {
                message = context.getString(R.string.typedItems_templateNeedsName)
            } else {
                scope.launch {
                    val draft = newItemDraft(ItemType.CustomTemplate, vaultId).copy(title = name, details = ItemDetails.Structured(ItemType.CustomTemplate, templateFromItem(details)))
                    message = runCatching { model.vault.saveItem(draft) }.fold(
                        { context.getString(R.string.typedItems_templateSaved, name) },
                        { errorMessage(context, it) },
                    )
                }
            }
        },
        modifier = Modifier.testTag("editor.saveTemplate"),
    ) { Text(stringResource(R.string.typedItems_saveAsTemplate)) }
    message?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
}

@Composable
internal fun StructuredFields(type: ItemType, details: StructuredDetails) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val specs = remember(type) { fieldSpecs(type) }.filter { details.value(it.key).isNotEmpty() }
    if (specs.isNotEmpty()) {
        FieldList {
            for (spec in specs) {
                val label = fieldLabel(context, spec.key)
                val value = details.value(spec.key)
                when (spec.style) {
                    FieldStyle.SECRET, FieldStyle.SECRET_LONG -> SecretField(label, value, model, tag = spec.key)
                    FieldStyle.CHOICE -> Field(label, choiceLabel(context, spec.key, value), model, copy = false)
                    FieldStyle.DATE -> Field(label, formatDate(value), model, secret = false)
                    else -> Field(label, value, model, secret = false, mono = spec.style == FieldStyle.CODE, ltr = spec.style != FieldStyle.TEXT, tag = spec.key)
                }
            }
        }
    }
    if (details.addresses.isNotEmpty()) {
        FieldList(stringResource(R.string.typedItems_addresses)) {
            for (entry in details.addresses) Field(entry.label ?: entry.network, entry.address, model, what = stringResource(R.string.typedItems_address), secret = false, mono = true)
        }
    }
    if (type == ItemType.Custom) {
        FieldList {
            details.templateName?.takeIf { it.isNotEmpty() }?.let { Field(stringResource(R.string.typedItems_template), it, model, copy = false) }
            for (field in details.fields) {
                if (field.value.isEmpty()) continue
                when {
                    field.kind == "totp" -> TotpField(field.value, model)
                    field.kind == "multiline" -> Field(field.label, field.value, model, secret = true)
                    !customKindIsPlain(field.kind) -> SecretField(field.label, field.value, model)
                    field.kind == "date" -> Field(field.label, formatDate(field.value), model, secret = false)
                    else -> Field(field.label, field.value, model, secret = false, ltr = field.kind != "text")
                }
            }
        }
    }
    if (type == ItemType.CustomTemplate && details.fields.isNotEmpty()) {
        FieldList(stringResource(R.string.typedItems_fields)) {
            for (field in details.fields) Field(field.label, choiceLabel(context, "customKind", field.kind), model, copy = false)
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
