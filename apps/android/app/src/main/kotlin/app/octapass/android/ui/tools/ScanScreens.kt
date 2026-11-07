package app.octap.android.ui.tools

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts.OpenDocument
import androidx.activity.result.contract.ActivityResultContracts.PickVisualMedia
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Image
import androidx.compose.material.icons.outlined.InsertDriveFile
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.octap.android.model.AppModel
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.AlertTone
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.vault.LocalVault
import app.octap.android.ui.vault.Route
import app.octap.resources.R
import app.octap.vault.CodeLink
import app.octap.vault.ImportReview
import app.octap.vault.ImportSummary
import app.octap.vault.ItemSummary
import app.octap.vault.QrScan
import app.octap.vault.VaultRole
import app.octap.vault.VaultType
import app.octap.vault.readQrCodes
import app.octap.vault.scannedDraft
import app.octap.vault.summarizeQrScans
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A one-time code setup link or a Google Authenticator export link. */
fun isOneTimeCode(text: String): Boolean {
    val scheme = text.trim().substringBefore(':').lowercase()
    return scheme == "otpauth" || scheme == "otpauth-migration"
}

/** The text of every QR code in a picked image, read by the core on the phone. */
private suspend fun readImage(model: AppModel, uri: Uri): List<String> = withContext(Dispatchers.IO) {
    val bytes = model.app.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: error("couldn't read the image")
    readQrCodes(bytes)
}

/** The photo picker and the document picker for images with QR codes; [onTexts] gets the codes found. */
internal class ImagePickers(val photo: () -> Unit, val file: () -> Unit)

@Composable
internal fun rememberImagePickers(model: AppModel, onTexts: suspend (List<String>) -> Unit): ImagePickers {
    val scope = rememberCoroutineScope()
    fun take(uri: Uri?) {
        model.inSystemUi = false
        uri ?: return
        scope.launch {
            try {
                onTexts(readImage(model, uri))
            } catch (error: Exception) {
                if (error is kotlinx.coroutines.CancellationException) throw error
                model.toastError(error)
            }
        }
    }
    val photo = rememberLauncherForActivityResult(PickVisualMedia()) { take(it) }
    val file = rememberLauncherForActivityResult(OpenDocument()) { take(it) }
    return ImagePickers(
        photo = { model.inSystemUi = true; photo.launch(PickVisualMediaRequest(PickVisualMedia.ImageOnly)) },
        file = { model.inSystemUi = true; file.launch(arrayOf("image/*")) },
    )
}

/**
 * Scan a QR code (`ScanButton`): with the camera, a photo or an image file. A Wi-Fi network or a
 * contact is saved as an item; a one-time code, or a Google Authenticator export, goes to the
 * review where each code joins a login.
 */
@Composable
fun ScanScreen() {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var camera by remember { mutableStateOf(app.octap.android.ui.tools.CameraState.Asking) }
    var notice by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    suspend fun handle(texts: List<String>) {
        if (texts.isEmpty()) {
            notice = context.getString(R.string.otp_noneFound)
            return
        }
        val codes = texts.filter(::isOneTimeCode)
        if (codes.isNotEmpty()) {
            vault.nav.pendingCodes = codes
            vault.nav.replace(Route.ScanCodes(fromLink = false))
            return
        }
        val vaults = model.vault.listVaults()
        val target = vaults.firstOrNull { it.vaultType == VaultType.PERSONAL } ?: vaults.firstOrNull { it.role != VaultRole.READ }
        val draft = target?.let { v -> texts.firstNotNullOfOrNull { scannedDraft(it, v.id) } }
        if (draft == null) {
            notice = context.getString(R.string.phone_scanUnknown)
            return
        }
        val item = model.vault.saveItem(draft)
        model.toast(context.getString(R.string.phone_scanAdded, item.title), Toast.Tone.Success)
        vault.nav.replace(Route.Item(item.id))
    }

    val pickers = rememberImagePickers(model) { texts -> handle(texts) }

    Box(Modifier.fillMaxSize().background(Color.Black).testTag("scan.screen")) {
        QrCamera(
            stringResource(R.string.otp_source_camera),
            onState = { camera = it },
            onCode = { text ->
                if (!busy) {
                    busy = true
                    scope.launch {
                        try {
                            handle(listOf(text))
                        } catch (error: Exception) {
                            model.toastError(error)
                        } finally {
                            busy = false
                        }
                    }
                }
            },
        )
        Column(Modifier.fillMaxWidth().background(Color.Black.copy(alpha = 0.6f)).statusBarsPadding().padding(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = { vault.nav.pop() }, modifier = Modifier.testTag("scan.back")) {
                    Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = stringResource(R.string.common_back), tint = Color.White)
                }
                Text(stringResource(R.string.phone_scan), color = Color.White, style = MaterialTheme.typography.titleLarge)
            }
        }
        if (camera == app.octap.android.ui.tools.CameraState.Unavailable) {
            Text(stringResource(R.string.phone_scanUnsupported), color = Color.White, textAlign = TextAlign.Center, modifier = Modifier.align(Alignment.Center).padding(32.dp))
        }
        Column(
            Modifier.align(Alignment.BottomCenter).fillMaxWidth().background(Color.Black.copy(alpha = 0.6f)).navigationBarsPadding().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            notice?.let { Text(it, color = Color.White, textAlign = TextAlign.Center, modifier = Modifier.testTag("scan.notice")) }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(onClick = pickers.photo, modifier = Modifier.testTag("scan.photo")) {
                    Icon(Icons.Outlined.Image, null, Modifier.size(18.dp))
                    Text(stringResource(R.string.otp_source_photo), Modifier.padding(start = 6.dp))
                }
                FilledTonalButton(onClick = pickers.file, modifier = Modifier.testTag("scan.file")) {
                    Icon(Icons.Outlined.InsertDriveFile, null, Modifier.size(18.dp))
                    Text(stringResource(R.string.otp_chooseImage), Modifier.padding(start = 6.dp))
                }
            }
        }
        if (busy) CircularProgressIndicator(Modifier.align(Alignment.Center))
    }
}

/**
 * New one-time codes from QR codes or links (`ScanCodesDialog`): every part of a Google
 * Authenticator export adds up; then each code joins a login or becomes its own item. Links the
 * phone opened Octa Pass with come here too, since any website can open one.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ScanCodesScreen(fromLink: Boolean) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val texts = remember { mutableStateListOf<String>().apply { addAll(vault.nav.pendingCodes); vault.nav.pendingCodes = emptyList() } }
    var scan by remember { mutableStateOf<QrScan?>(null) }
    var notice by remember { mutableStateOf<String?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var link by remember { mutableStateOf("") }
    var review by remember { mutableStateOf<ImportReview?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val logins = rememberLogins()
    val export = texts.any { it.trim().lowercase().startsWith("otpauth-migration:") }

    // A review left open holds parsed secrets in the vault: drop it on the way out.
    val pending = remember { mutableStateOf<String?>(null) }
    DisposableEffect(Unit) { onDispose { pending.value?.let { model.vault.cancelImport(it) } } }

    fun add(found: List<String>) {
        notice = null
        if (found.isEmpty()) {
            notice = context.getString(R.string.otp_noneFound)
            return
        }
        texts.addAll(found.map { it.trim() }.filter { it.isNotEmpty() && it !in texts })
        val latest = summarizeQrScans(found)
        if (latest.codes.isEmpty()) {
            notice = if (latest.broken > 0u) context.getString(R.string.otp_broken) else context.resources.getQuantityString(R.plurals.otp_notCode, latest.other.toInt(), latest.other.toInt())
        }
    }
    LaunchedEffect(texts.size) { scan = if (texts.isEmpty()) null else summarizeQrScans(texts.toList()) }
    val pickers = rememberImagePickers(model) { found -> add(found) }

    fun finished(result: ImportSummary) {
        pending.value = null
        val count = result.imported.toInt() + result.updated.toInt()
        model.toast(context.resources.getQuantityString(R.plurals.otp_saved, count, count), Toast.Tone.Success)
        vault.nav.pop()
    }

    val current = review
    BackHandler(enabled = current != null && !busy) {
        pending.value?.let { model.vault.cancelImport(it) }
        pending.value = null
        review = null
    }

    if (scanning) {
        Box(Modifier.fillMaxSize().background(Color.Black)) {
            QrCamera(stringResource(R.string.otp_source_camera), onState = {}, onCode = { text ->
                add(listOf(text))
                scanning = false
            })
            TextButton(onClick = { scanning = false }, modifier = Modifier.align(Alignment.BottomCenter).navigationBarsPadding().padding(24.dp)) {
                Text(stringResource(R.string.common_cancel), color = Color.White)
            }
        }
        BackHandler { scanning = false }
        return
    }

    val title = when {
        current != null -> stringResource(R.string.otp_reviewTitle)
        fromLink && export -> stringResource(R.string.phone_linkExportTitle)
        fromLink -> stringResource(R.string.phone_linkTitle)
        else -> stringResource(R.string.otp_scanTitle)
    }
    val description = when {
        current != null -> stringResource(R.string.otp_reviewHelp)
        fromLink && export -> stringResource(R.string.phone_linkExportBody)
        fromLink -> stringResource(R.string.phone_linkCodeBody)
        else -> stringResource(R.string.otp_scanHelp)
    }
    VaultPage(title, description, tag = "scanCodes.title") {
        if (current == null) {
            val codes = scan?.codes.orEmpty()
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { scanning = true }, modifier = Modifier.testTag("scanCodes.camera")) { Text(stringResource(R.string.otp_source_camera)) }
                OutlinedButton(onClick = pickers.photo) { Text(stringResource(R.string.otp_source_photo)) }
                OutlinedButton(onClick = pickers.file) { Text(stringResource(R.string.otp_chooseImage)) }
            }
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Field(link, { link = it }, stringResource(R.string.otp_pasteLink), hint = stringResource(R.string.otp_pasteLinkHint), mono = true, modifier = Modifier.weight(1f).testTag("scanCodes.link"))
                IconButton(onClick = {
                    if (isOneTimeCode(link)) {
                        add(listOf(link))
                        link = ""
                    } else {
                        notice = context.getString(R.string.otp_invalidLink)
                    }
                }, modifier = Modifier.testTag("scanCodes.addLink")) { Icon(Icons.Outlined.Link, contentDescription = stringResource(R.string.otp_addLink)) }
            }
            notice?.let { Alert(it, AlertTone.Info, Modifier.testTag("scanCodes.notice")) }
            for (batch in scan?.incomplete.orEmpty()) {
                Alert(stringResource(R.string.otp_batch, batch.scanned.size.toString(), batch.size.toString()), AlertTone.Warn)
            }
            if (codes.isNotEmpty()) {
                Text(pluralStringResource(R.plurals.otp_found, codes.size, codes.size), style = MaterialTheme.typography.titleSmall)
                OutlinedCard(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        for (code in codes) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Icon(Icons.Outlined.Schedule, null, Modifier.size(18.dp))
                                Text(codeLabel(code.issuer, code.account) + if (code.counterBased) " · " + stringResource(R.string.otp_counterBasedShort) else "")
                            }
                        }
                    }
                }
            }
            error?.let { Alert(it) }
            PrimaryButton(
                stringResource(R.string.otp_continue),
                {
                    busy = true
                    error = null
                    scope.launch {
                        try {
                            val next = model.vault.reviewScannedCodes(codes.map { it.uri })
                            pending.value = next.id
                            review = next
                        } catch (e: Exception) {
                            error = errorMessage(context, e)
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = codes.isNotEmpty(),
                busy = busy,
                modifier = Modifier.testTag("scanCodes.continue"),
            )
        } else {
            ReviewSection(current, logins, busy, error, onCancel = {
                pending.value?.let { model.vault.cancelImport(it) }
                pending.value = null
                review = null
            }) { links ->
                busy = true
                error = null
                scope.launch {
                    try {
                        finished(model.vault.finishImport(current.id, links))
                    } catch (e: Exception) {
                        error = errorMessage(context, e)
                    } finally {
                        busy = false
                    }
                }
            }
        }
    }
}

/**
 * One row per imported one-time code, with the login it joins or "Keep as a separate item", and a
 * searchable picker to change it (`ImportReviewList`). A login takes one code.
 */
@Composable
fun ReviewSection(review: ImportReview, logins: List<ItemSummary>?, busy: Boolean, error: String?, onCancel: () -> Unit, onSave: (List<CodeLink>) -> Unit) {
    val choices = remember(review.id) { mutableStateOf(review.codes.associate { it.index to it.loginId }) }
    var open by remember(review.id) { mutableStateOf<UInt?>(null) }
    if (logins == null) {
        CircularProgressIndicator()
        return
    }
    for (code in review.codes) {
        val loginId = choices.value[code.index]
        val login = logins.firstOrNull { it.id == loginId }
        val taken = choices.value.filter { (index, id) -> index != code.index && id != null }.values.filterNotNull().toSet()
        val label = codeLabel(code.issuer, code.account, code.title)
        OutlinedCard(Modifier.fillMaxWidth().testTag("review.${code.index}")) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.Schedule, null, Modifier.size(18.dp))
                    Column(Modifier.weight(1f).padding(horizontal = 8.dp)) {
                        Text(label, style = MaterialTheme.typography.bodyLarge)
                        Text(
                            if (login != null) stringResource(R.string.otp_goesTo, login.title) else stringResource(R.string.otp_separate),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    TextButton(onClick = { open = if (open == code.index) null else code.index }, modifier = Modifier.testTag("review.change.${code.index}")) {
                        Text(stringResource(if (open == code.index) R.string.common_done else R.string.otp_change))
                    }
                }
                if (open == code.index) {
                    LoginPicker(logins, loginId, { next -> choices.value = choices.value + (code.index to next) }, stringResource(R.string.otp_pickerLabel, label), taken = taken)
                }
            }
        }
    }
    if (review.warnings.isNotEmpty()) Alert(review.warnings.joinToString("\n"), AlertTone.Warn)
    error?.let { Alert(it) }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = onCancel, enabled = !busy) { Text(stringResource(R.string.common_back)) }
        val count = review.codes.size + review.otherItems.toInt()
        PrimaryButton(
            pluralStringResource(R.plurals.otp_saveCodes, count, count),
            { onSave(choices.value.map { (index, id) -> CodeLink(index, id) }) },
            busy = busy,
            modifier = Modifier.weight(1f).testTag("review.save"),
        )
    }
}
