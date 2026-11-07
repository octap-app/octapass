package app.octap.android.ui.settings

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts.OpenDocument
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AttachFile
import androidx.compose.material.icons.outlined.FileUpload
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.octap.android.model.errorMessage
import app.octap.android.model.isCode
import app.octap.android.platform.Files
import app.octap.android.platform.PickedFile
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.PasswordField
import app.octap.android.ui.tools.VaultPage
import app.octap.android.ui.vault.Choice
import app.octap.android.ui.vault.LocalVault
import app.octap.resources.R
import app.octap.vault.ErrorCode
import app.octap.vault.ImportSource
import app.octap.vault.ImportSummary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A source the core imports: a product name (not translated) or a catalog key, and whether files can have a password. */
private data class Source(val value: ImportSource, val name: String, val key: String, val password: Boolean = false)

/** Every source, grouped as people look for them (`SOURCE_GROUPS`). */
private val SOURCE_GROUPS: List<Pair<Int, List<Source>>> = listOf(
    R.string.import_groupOctaPass to listOf(
        Source(ImportSource.OCTA_PASS, "Octa Pass", "octapass", password = true),
        Source(ImportSource.CXF, "import.cxf", "cxf"),
    ),
    R.string.import_groupManagers to listOf(
        Source(ImportSource.ONE_PASSWORD1_PUX, "1Password (1PUX)", "onepassword-1pux"),
        Source(ImportSource.ONE_PASSWORD_CSV, "1Password (CSV)", "onepassword-csv"),
        Source(ImportSource.BITWARDEN_JSON, "Bitwarden (JSON)", "bitwarden-json", password = true),
        Source(ImportSource.BITWARDEN_CSV, "Bitwarden (CSV)", "bitwarden-csv"),
        Source(ImportSource.AVIRA, "Avira", "avira"),
        Source(ImportSource.DASHLANE, "Dashlane", "dashlane"),
        Source(ImportSource.ENPASS, "Enpass", "enpass"),
        Source(ImportSource.KASPERSKY, "Kaspersky", "kaspersky"),
        Source(ImportSource.KEE_PASS, "KeePass, KeePassXC", "keepass", password = true),
        Source(ImportSource.KEEPER, "Keeper", "keeper"),
        Source(ImportSource.LAST_PASS_CSV, "LastPass", "lastpass-csv"),
        Source(ImportSource.MC_AFEE, "McAfee True Key", "mcafee"),
        Source(ImportSource.NORD_PASS, "NordPass", "nordpass"),
        Source(ImportSource.NORTON, "Norton", "norton"),
        Source(ImportSource.PROTON_PASS, "Proton Pass", "protonpass", password = true),
        Source(ImportSource.ROBO_FORM, "RoboForm", "roboform"),
        Source(ImportSource.ZOHO_VAULT, "Zoho Vault", "zoho-vault"),
    ),
    R.string.import_groupBrowsers to listOf(
        Source(ImportSource.CHROME, "import.chrome", "chrome"),
        Source(ImportSource.FIREFOX, "Firefox", "firefox"),
        Source(ImportSource.SAFARI, "import.safari", "safari"),
    ),
    R.string.import_groupAuthenticators to listOf(
        Source(ImportSource.AEGIS, "Aegis", "aegis", password = true),
        Source(ImportSource.TWO_FAS, "2FAS", "2fas", password = true),
        Source(ImportSource.AND_OTP, "andOTP", "andotp", password = true),
        Source(ImportSource.ENTE_AUTH, "Ente Auth", "ente-auth", password = true),
        Source(ImportSource.RAIVO, "Raivo OTP", "raivo", password = true),
        Source(ImportSource.OTPAUTH, "import.otpauth", "otpauth"),
    ),
    R.string.import_groupOther to listOf(Source(ImportSource.GENERIC_CSV, "import.generic", "generic-csv")),
)

private val SOURCES = SOURCE_GROUPS.flatMap { it.second }

/** Authenticator imports, whose one-time codes the user links to logins before saving (`REVIEWED_IMPORTS`). */
private val REVIEWED_IMPORTS = setOf(ImportSource.OTPAUTH, ImportSource.AEGIS, ImportSource.TWO_FAS, ImportSource.AND_OTP, ImportSource.ENTE_AUTH, ImportSource.RAIVO)

/** "12 new, 3 updated, 40 unchanged." for a file imported again, else "Imported 12 items." */
fun importSummaryText(context: android.content.Context, done: ImportSummary): String =
    if (done.updated > 0u || done.unchanged > 0u) {
        context.getString(R.string.import_summary, done.imported.toString(), done.updated.toString(), done.unchanged.toString())
    } else {
        context.resources.getQuantityString(R.plurals.import_done, done.imported.toInt(), done.imported.toInt())
    }

/** Import from another app's export file (`ImportPanel`), into the Personal vault. */
@Composable
fun ImportScreen() {
    val model = LocalVault.current.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val files = remember { Files(context) }
    var source by remember { mutableStateOf(ImportSource.CHROME) }
    var file by remember { mutableStateOf<PickedFile?>(null) }
    var keyFile by remember { mutableStateOf<PickedFile?>(null) }
    var password by remember { mutableStateOf("") }
    var needsPassword by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var result by remember { mutableStateOf<ImportSummary?>(null) }
    var review by remember { mutableStateOf<app.octap.vault.ImportReview?>(null) }
    val logins = app.octap.android.ui.tools.rememberLogins()
    // A review left open holds the parsed file in the vault.
    val pending = remember { mutableStateOf<String?>(null) }
    DisposableEffect(Unit) { onDispose { pending.value?.let { model.vault.cancelImport(it) } } }
    val selected = SOURCES.first { it.value == source }

    // The copies of what the user picked stay in the cache only while this screen is open.
    val current by rememberUpdatedState(listOfNotNull(file, keyFile))
    DisposableEffect(Unit) { onDispose { current.forEach { it.file.parentFile?.deleteRecursively() } } }

    fun pick(into: (PickedFile) -> Unit): (Uri?) -> Unit = { uri ->
        model.inSystemUi = false
        if (uri != null) scope.launch { runCatching { withContext(Dispatchers.IO) { files.copy(listOf(uri)).first() } }.onSuccess(into).onFailure(model::toastError) }
    }
    val pickFile = rememberLauncherForActivityResult(OpenDocument(), pick { picked -> file?.file?.parentFile?.deleteRecursively(); file = picked })
    val pickKey = rememberLauncherForActivityResult(OpenDocument(), pick { picked -> keyFile?.file?.parentFile?.deleteRecursively(); keyFile = picked })

    @Composable
    fun sourceName(s: Source) = if (s.name.startsWith("import.")) stringResource(nameRes(s.name)) else s.name

    val reviewing = review
    if (reviewing != null) {
        VaultPage(stringResource(R.string.otp_reviewTitle), stringResource(R.string.otp_reviewHelp), tag = "import.review") {
            app.octap.android.ui.tools.ReviewSection(reviewing, logins, busy, error, onCancel = {
                pending.value?.let { model.vault.cancelImport(it) }
                pending.value = null
                review = null
            }) { links ->
                busy = true
                error = null
                scope.launch {
                    try {
                        result = model.vault.finishImport(reviewing.id, links)
                        pending.value = null
                        review = null
                    } catch (e: Exception) {
                        error = errorMessage(context, e)
                    } finally {
                        busy = false
                    }
                }
            }
        }
        return
    }
    VaultPage(stringResource(R.string.settings_import), stringResource(R.string.settings_importHelp), tag = "import.title") {
        Choice(
            stringResource(R.string.import_from),
            SOURCE_GROUPS.flatMap { (_, sources) -> sources.map { it.value.name to sourceName(it) } },
            source.name,
            tag = "import.source",
        ) {
            source = ImportSource.valueOf(it ?: source.name)
            password = ""
            keyFile = null
            needsPassword = false
            error = null
        }
        Text(stringResource(helpRes(selected.key)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        OutlinedButton(onClick = { model.inSystemUi = true; pickFile.launch(arrayOf("*/*")) }, modifier = Modifier.testTag("import.file")) {
            Icon(Icons.Outlined.AttachFile, null, Modifier.size(18.dp))
            Text(file?.name ?: stringResource(R.string.import_file), Modifier.padding(start = 6.dp))
        }
        if (selected.password || needsPassword) {
            PasswordField(
                password,
                { password = it },
                stringResource(if (source == ImportSource.OCTA_PASS) R.string.import_exportPassword else R.string.import_filePassword),
                hint = if (needsPassword) null else stringResource(R.string.import_filePasswordHint),
                contentType = null,
                modifier = Modifier.testTag("import.password"),
            )
            if (source == ImportSource.KEE_PASS) {
                OutlinedButton(onClick = { model.inSystemUi = true; pickKey.launch(arrayOf("*/*")) }) { Text(keyFile?.name ?: stringResource(R.string.import_keyFile)) }
            }
        }
        error?.let { Alert(it, modifier = Modifier.testTag("import.error")) }
        result?.let { done ->
            Alert(
                buildString {
                    append(importSummaryText(context, done))
                    if (done.skipped > 0u) append(" ").append(context.resources.getQuantityString(R.plurals.import_skipped, done.skipped.toInt(), done.skipped.toInt()))
                    if (done.files > 0u) append(" ").append(context.resources.getQuantityString(R.plurals.import_files, done.files.toInt(), done.files.toInt()))
                    for (warning in done.warnings) append("\n").append(warning)
                    append("\n").append(context.getString(R.string.import_deleteFile))
                },
                if (done.imported > 0u) AlertTone.Info else AlertTone.Warn,
                Modifier.testTag("import.result"),
            )
        }
        OutlinedButton(
            enabled = !busy,
            modifier = Modifier.testTag("import.go"),
            onClick = {
                val chosen = file
                if (chosen == null) {
                    error = context.getString(R.string.import_chooseFile)
                    return@OutlinedButton
                }
                busy = true
                error = null
                result = null
                scope.launch {
                    try {
                        if (source in REVIEWED_IMPORTS) {
                            // One-time codes: the user checks which login each one joins before anything is saved.
                            val next = model.vault.reviewImport(source, chosen.file.path, password.ifEmpty { null }, keyFile?.file?.path)
                            if (next.codes.isNotEmpty()) {
                                pending.value = next.id
                                review = next
                            } else {
                                result = model.vault.finishImport(next.id, emptyList())
                            }
                        } else {
                            result = model.vault.importFile(source, chosen.file.path, password.ifEmpty { null }, keyFile?.file?.path)
                        }
                        chosen.file.parentFile?.deleteRecursively()
                        file = null
                        password = ""
                        needsPassword = false
                    } catch (e: Exception) {
                        if (e.isCode(ErrorCode.IMPORT_PASSWORD_REQUIRED)) needsPassword = true
                        error = errorMessage(context, e)
                    } finally {
                        busy = false
                    }
                }
            },
        ) {
            if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) else Icon(Icons.Outlined.FileUpload, null, Modifier.size(18.dp))
            Text(stringResource(R.string.import_action), Modifier.padding(start = 6.dp))
        }
    }
}

private fun nameRes(key: String) = when (key) {
    "import.cxf" -> R.string.import_cxf
    "import.chrome" -> R.string.import_chrome
    "import.safari" -> R.string.import_safari
    "import.otpauth" -> R.string.import_otpauth
    else -> R.string.import_generic
}

private fun helpRes(key: String) = when (key) {
    "octapass" -> R.string.import_help_octapass
    "cxf" -> R.string.import_help_cxf
    "onepassword-1pux" -> R.string.import_help_onepassword_1pux
    "onepassword-csv" -> R.string.import_help_onepassword_csv
    "bitwarden-json" -> R.string.import_help_bitwarden_json
    "bitwarden-csv" -> R.string.import_help_bitwarden_csv
    "dashlane" -> R.string.import_help_dashlane
    "enpass" -> R.string.import_help_enpass
    "keepass" -> R.string.import_help_keepass
    "keeper" -> R.string.import_help_keeper
    "lastpass-csv" -> R.string.import_help_lastpass_csv
    "nordpass" -> R.string.import_help_nordpass
    "protonpass" -> R.string.import_help_protonpass
    "roboform" -> R.string.import_help_roboform
    "zoho-vault" -> R.string.import_help_zoho_vault
    "avira" -> R.string.import_help_avira
    "norton" -> R.string.import_help_norton
    "mcafee" -> R.string.import_help_mcafee
    "kaspersky" -> R.string.import_help_kaspersky
    "chrome" -> R.string.import_help_chrome
    "firefox" -> R.string.import_help_firefox
    "safari" -> R.string.import_help_safari
    "aegis" -> R.string.import_help_aegis
    "2fas" -> R.string.import_help_2fas
    "andotp" -> R.string.import_help_andotp
    "ente-auth" -> R.string.import_help_ente_auth
    "raivo" -> R.string.import_help_raivo
    "otpauth" -> R.string.import_help_otpauth
    else -> R.string.import_help_generic_csv
}
