package app.octap.android.ui.tools

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.octap.android.model.Toast
import app.octap.android.model.errorMessage
import app.octap.android.ui.components.Alert
import app.octap.android.ui.components.Field
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.vault.Choice
import app.octap.android.ui.vault.LocalVault
import app.octap.resources.R
import app.octap.vault.ItemDetails
import app.octap.vault.ScannedCode
import app.octap.vault.itemDraft
import app.octap.vault.summarizeQrScans
import app.octap.vault.totpCode
import kotlinx.coroutines.launch

/** Add a one-time code to a login (`AddCodeDialog`): from a QR code, an image, or the setup link or key. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun AddCodeScreen(itemId: String) {
    val vault = LocalVault.current
    val model = vault.model
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var scanning by remember { mutableStateOf(false) }
    var codes by remember { mutableStateOf<List<ScannedCode>>(emptyList()) }
    var chosen by remember { mutableStateOf<String?>(null) }
    var pasted by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun found(texts: List<String>) {
        val next = summarizeQrScans(texts).codes
        codes = next
        chosen = next.firstOrNull { !it.counterBased }?.uri
        error = if (next.isEmpty()) context.getString(R.string.otp_invalidLink) else null
    }

    fun save(totp: String) {
        busy = true
        error = null
        scope.launch {
            try {
                val item = model.vault.getItem(itemId)
                val draft = itemDraft(item)
                val details = when (val d = draft.details) {
                    is ItemDetails.Login -> ItemDetails.Login(d.login.copy(totp = totp))
                    is ItemDetails.Password -> ItemDetails.Password(d.login.copy(totp = totp))
                    else -> return@launch
                }
                model.vault.saveItem(draft.copy(details = details))
                model.toast(R.string.otp_added, Toast.Tone.Success)
                vault.nav.pop()
            } catch (failure: Exception) {
                error = errorMessage(context, failure)
            } finally {
                busy = false
            }
        }
    }

    /** A setup link goes through the reader; a bare key is saved once a code can be made from it. */
    fun addPasted() {
        val text = pasted.trim()
        if (text.isEmpty()) return
        if (isOneTimeCode(text)) return found(listOf(text))
        val secret = text.replace(Regex("\\s"), "")
        if (runCatching { totpCode(secret, null) }.isSuccess) save(secret) else error = context.getString(R.string.otp_invalidLink)
    }

    val pickers = rememberImagePickers(model) { found(it) }
    if (scanning) {
        Box(Modifier.fillMaxSize().background(Color.Black)) {
            QrCamera(stringResource(R.string.otp_source_camera), onState = {}, onCode = { text ->
                scanning = false
                found(listOf(text))
            })
            TextButton(onClick = { scanning = false }, modifier = Modifier.align(Alignment.BottomCenter).navigationBarsPadding().padding(24.dp)) {
                Text(stringResource(R.string.common_cancel), color = Color.White)
            }
        }
        BackHandler { scanning = false }
        return
    }

    VaultPage(stringResource(R.string.otp_addCode), stringResource(R.string.otp_addCodeHelp), tag = "addCode.title") {
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { scanning = true }, modifier = Modifier.testTag("addCode.camera")) { Text(stringResource(R.string.otp_source_camera)) }
            OutlinedButton(onClick = pickers.photo) { Text(stringResource(R.string.otp_source_photo)) }
            OutlinedButton(onClick = pickers.file) { Text(stringResource(R.string.otp_chooseImage)) }
        }
        Field(pasted, { pasted = it }, stringResource(R.string.otp_pasteLink), hint = stringResource(R.string.otp_pasteLinkHint), mono = true, onImeAction = ::addPasted, modifier = Modifier.testTag("addCode.link"))
        OutlinedButton(onClick = ::addPasted, enabled = pasted.isNotBlank() && !busy, modifier = Modifier.testTag("addCode.addLink")) { Text(stringResource(R.string.otp_addLink)) }
        if (codes.isNotEmpty()) {
            Choice(
                label = stringResource(if (codes.size > 1) R.string.otp_chooseOne else R.string.otp_foundOne),
                options = codes.filter { !it.counterBased }.map { it.uri to codeLabel(it.issuer, it.account) },
                selected = chosen,
                tag = "addCode.code",
            ) { chosen = it }
            PrimaryButton(stringResource(R.string.otp_save), { chosen?.let(::save) }, busy = busy, enabled = chosen != null, modifier = Modifier.testTag("addCode.save"))
        }
        error?.let { Alert(it, modifier = Modifier.testTag("addCode.error")) }
    }
}
