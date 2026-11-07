package app.octap.android.ui.vault

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.OpenDocument
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.ExpandLess
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.FileUpload
import androidx.compose.material.icons.outlined.IosShare
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
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
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import app.octap.android.model.Toast
import app.octap.android.platform.Files
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.Field as InputField
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.components.SecondaryButton
import app.octap.android.ui.settings.rememberShareFile
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.tools.Toggle
import app.octap.android.ui.util.rememberLive
import app.octap.resources.R
import app.octap.vault.EnvironmentChoices
import app.octap.vault.EnvironmentDetails
import app.octap.vault.EnvironmentVariable
import app.octap.vault.Item
import app.octap.vault.ItemType
import app.octap.vault.VaultException
import app.octap.vault.environmentDotenv
import app.octap.vault.environmentFileName
import app.octap.vault.isProductionStage
import app.octap.vault.knownEnvironmentStage
import app.octap.vault.mergeDotenv
import app.octap.vault.missingEnvironmentKeys
import app.octap.vault.newEnvironmentVariable
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A stage in the reader's language, a custom one as typed; none is the project's shared set (`stageLabel`). */
@Composable
fun stageLabel(stage: String?): String {
    val context = LocalContext.current
    if (stage.isNullOrEmpty()) return stringResource(R.string.env_sharedSet)
    return knownEnvironmentStage(stage)?.let { messageFor(context, "env.stages.$it") } ?: stage
}

/** The stage next to an environment's subtitle in a list. */
@Composable
fun StageChip(stage: String) {
    val color = if (isProductionStage(stage)) Brand.colors.dangerText else Brand.colors.trustText
    Text(
        stageLabel(stage),
        style = MaterialTheme.typography.labelSmall,
        color = color,
        modifier = Modifier.background(color.copy(alpha = 0.12f), CircleShape).padding(horizontal = 6.dp, vertical = 1.dp),
    )
}

/** An environment in the editor (`EnvironmentSection`): project and stage, variables, a `.env` file. */
@Composable
fun EnvironmentSection(details: EnvironmentDetails, errors: Map<String, String>, set: (EnvironmentDetails) -> Unit) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val files = remember { Files(context) }
    var pasting by remember { mutableStateOf(false) }
    var paste by remember { mutableStateOf("") }
    val variables = details.variables

    fun change(next: List<EnvironmentVariable>) = set(details.copy(variables = next))
    fun update(index: Int, value: EnvironmentVariable) = change(variables.mapIndexed { i, one -> if (i == index) value else one })
    fun move(index: Int, by: Int) {
        val to = index + by
        if (to !in variables.indices) return
        change(variables.toMutableList().also { it[index] = variables[to]; it[to] = variables[index] })
    }

    fun addPasted() {
        try {
            val merged = mergeDotenv(variables, paste)
            change(merged.variables)
            paste = ""
            pasting = false
            model.toast(context.resources.getQuantityString(R.plurals.env_imported, merged.count.toInt(), merged.count.toInt()), Toast.Tone.Success)
        } catch (failure: VaultException.Failed) {
            model.toast(context.getString(R.string.env_importFailed, failure.reason), Toast.Tone.Danger)
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
                            file.file.readText()
                        } finally {
                            file.file.parentFile?.deleteRecursively()
                        }
                    }
                }.onSuccess {
                    paste = it
                    pasting = true
                }.onFailure(model::toastError)
            }
        }
    }

    Section(stringResource(R.string.env_projectAndStage), stringResource(R.string.env_mergeHint)) {
        InputField(details.project.orEmpty(), { set(details.copy(project = it.trim().ifEmpty { null })) }, stringResource(R.string.env_project), error = errors["project"], hint = stringResource(R.string.env_projectHint), placeholder = stringResource(R.string.env_projectPlaceholder), modifier = Modifier.testTag("env.project"))
        InputField(details.stage.orEmpty(), { set(details.copy(stage = it.trim().ifEmpty { null })) }, stringResource(R.string.env_stage), error = errors["stage"], hint = stringResource(R.string.env_stageHint), placeholder = stringResource(R.string.env_stagePlaceholder), modifier = Modifier.testTag("env.stage"))
    }
    Section(stringResource(R.string.env_variables)) {
        if (variables.isEmpty()) Text(stringResource(R.string.env_noVariables), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        variables.forEachIndexed { i, variable ->
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                InputField(variable.key, { update(i, variable.copy(key = it)) }, stringResource(R.string.env_key), error = errors["variables.$i.key"], placeholder = "DATABASE_URL", mono = true, capitalization = KeyboardCapitalization.Characters, modifier = Modifier.testTag("env.key.$i"))
                if (variable.concealed) PasswordField(variable.value, { update(i, variable.copy(value = it)) }, stringResource(R.string.env_value), contentType = null, imeAction = ImeAction.Next, modifier = Modifier.testTag("env.value.$i"))
                else InputField(variable.value, { update(i, variable.copy(value = it)) }, stringResource(R.string.env_value), mono = true, modifier = Modifier.testTag("env.value.$i"))
                InputField(variable.note.orEmpty(), { update(i, variable.copy(note = it.ifEmpty { null })) }, stringResource(R.string.env_note), placeholder = stringResource(R.string.env_notePlaceholder), capitalization = KeyboardCapitalization.Sentences)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.weight(1f)) { Toggle(stringResource(R.string.env_concealed), variable.concealed, tag = "env.concealed.$i") { update(i, variable.copy(concealed = it)) } }
                    IconButton(onClick = { move(i, -1) }, enabled = i > 0) { Icon(Icons.Outlined.ExpandLess, contentDescription = stringResource(R.string.env_moveUp)) }
                    IconButton(onClick = { move(i, 1) }, enabled = i < variables.lastIndex) { Icon(Icons.Outlined.ExpandMore, contentDescription = stringResource(R.string.env_moveDown)) }
                    IconButton(onClick = { change(variables.filterIndexed { index, _ -> index != i }) }, modifier = Modifier.testTag("env.remove.$i")) {
                        Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.env_removeVariable), tint = Brand.colors.dangerText)
                    }
                }
            }
        }
        SecondaryButton(stringResource(R.string.env_addVariable), { change(variables + newEnvironmentVariable()) }, icon = Icons.Outlined.Add, modifier = Modifier.testTag("env.add"))
        SecondaryButton(stringResource(R.string.env_paste), { pasting = !pasting }, modifier = Modifier.testTag("env.paste"))
        SecondaryButton(stringResource(R.string.env_importFile), { model.inSystemUi = true; pick.launch(arrayOf("*/*")) }, icon = Icons.Outlined.FileUpload, modifier = Modifier.testTag("env.importFile"))
        if (pasting) {
            InputField(paste, { paste = it }, stringResource(R.string.env_paste), hint = stringResource(R.string.env_pasteHint), mono = true, singleLine = false, minLines = 5, modifier = Modifier.testTag("env.pasteText"))
            SecondaryButton(stringResource(R.string.env_addPasted), ::addPasted, enabled = paste.isNotBlank(), modifier = Modifier.testTag("env.addPasted"))
        }
    }
}

/**
 * An environment's fields, with copy and save as `.env` (`EnvironmentFields`). Variable names
 * aren't secret; concealed values and the whole file ask first (plan 03).
 */
@Composable
fun EnvironmentFields(item: Item, details: EnvironmentDetails) {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val share = rememberShareFile(model)
    val missing = rememberLive(model, details) {
        if (details.project == null) emptyList()
        else missingEnvironmentKeys(item.id, details, model.vault.listItems(Scope.OfType(ItemType.Environment).filter(null).copy(project = details.project)))
    }.data.orEmpty()

    if (details.project != null || details.stage != null) {
        FieldList(stringResource(R.string.env_projectAndStage)) {
            Field(stringResource(R.string.env_project), details.project, model, ltr = true)
            Field(stringResource(R.string.env_stage), stageLabel(details.stage), model, copy = false)
        }
    }
    FieldList(stringResource(R.string.env_variables)) {
        if (details.variables.isEmpty()) Field(stringResource(R.string.env_variables), stringResource(R.string.env_noVariables), model, copy = false)
        for (variable in details.variables) {
            if (variable.concealed) SecretField(variable.key, variable.value, model, what = variable.note ?: stringResource(R.string.env_value), tag = "env.${variable.key}")
            else Field(variable.key, variable.value, model, mono = true, tag = "env.${variable.key}")
        }
    }
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        SecondaryButton(stringResource(R.string.env_copyDotenv), {
            scope.launch {
                if (model.confirmReveal()) {
                    runCatching { environmentDotenv(details) }.onSuccess { copy(model, it, context.getString(R.string.env_copyDotenvWhat), secret = true, item = item.id) }.onFailure(model::toastError)
                }
            }
        }, icon = Icons.Outlined.ContentCopy, modifier = Modifier.testTag("env.copyDotenv"))
        SecondaryButton(stringResource(R.string.env_downloadDotenv), {
            scope.launch {
                // A file of secrets leaving the app: an export, asked every time.
                if (model.confirmIdentity()) {
                    runCatching { model.vault.writeShareFile(environmentFileName(item.title), environmentDotenv(details)) }.onSuccess { share(it, "text/plain") }.onFailure(model::toastError)
                }
            }
        }, icon = Icons.Outlined.IosShare, modifier = Modifier.testTag("env.saveDotenv"))
    }
    if (missing.isNotEmpty()) Alert(stringResource(R.string.env_missingInStage, missing.joinToString(", ")), AlertTone.Info, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
    if (isProductionStage(details.stage)) Alert(stringResource(R.string.env_productionWarning), AlertTone.Warn, Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
    details.notes?.takeIf { it.isNotEmpty() }?.let { notes ->
        FieldList(stringResource(R.string.fields_notes)) { Field(stringResource(R.string.fields_notes), notes, model, secret = true) }
    }
}

/** The filters above an environment list, for the projects and stages it holds. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun EnvironmentFilters(choices: EnvironmentChoices, project: String?, stage: String?, setProject: (String?) -> Unit, setStage: (String?) -> Unit) {
    FlowRow(Modifier.padding(horizontal = 16.dp, vertical = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        if (choices.projects.isNotEmpty()) {
            FilterMenu(project ?: stringResource(R.string.env_allProjects), stringResource(R.string.env_allProjects), choices.projects.map { it to it }, "env.filterProject", setProject)
        }
        if (choices.stages.isNotEmpty()) {
            val labels = choices.stages.map { it to stageLabel(it) }
            FilterMenu(stage?.let { stageLabel(it) } ?: stringResource(R.string.env_allStages), stringResource(R.string.env_allStages), labels, "env.filterStage", setStage)
        }
    }
}

@Composable
private fun FilterMenu(label: String, all: String, options: List<Pair<String, String>>, tag: String, onSelect: (String?) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        OutlinedButton(onClick = { open = true }, modifier = Modifier.testTag(tag)) { Text(label) }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            DropdownMenuItem(text = { Text(all) }, onClick = { open = false; onSelect(null) })
            for ((value, text) in options) DropdownMenuItem(text = { Text(text) }, onClick = { open = false; onSelect(value) }, modifier = Modifier.testTag("$tag.$value"))
        }
    }
}
