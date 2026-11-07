package app.octap.android.ui.tools

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import app.octap.android.ui.components.Field
import app.octap.android.ui.theme.monoStyle
import app.octap.android.ui.vault.LocalVault
import app.octap.android.ui.vault.copy
import app.octap.resources.R
import app.octap.vault.VaultType
import app.octap.vault.toolkitRun
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

private enum class Panel(val title: Int) {
    Jwt(R.string.tools_panels_jwt),
    Certificates(R.string.tools_panels_certificates),
    Hash(R.string.tools_panels_hash),
    Encoding(R.string.tools_panels_encoding),
    Random(R.string.tools_panels_random),
    Keys(R.string.tools_panels_keys),
}

private val FORMATS = listOf("base64", "base64url", "base32", "hex", "url", "html", "unicode")
private val KEY_KINDS = listOf("ed25519", "p256", "p384", "rsa3072", "rsa4096")

/** Off the main thread: RSA keys take seconds. Every tool is the Rust core's `toolkit::run`. */
private suspend fun run(op: String, input: JSONObject): JSONObject = withContext(Dispatchers.Default) {
    JSONObject(toolkitRun(op, input.toString()))
}

private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }

private data class Row(val label: String, val value: String)

/**
 * The developer toolkit on the phone (plan 16 §5): inspectors, and generators whose private parts
 * go straight to the vault. Private keys are never shown here.
 */
@Composable
fun DeveloperToolsScreen() {
    val model = LocalVault.current.model
    val scope = rememberCoroutineScope()
    var panel by remember { mutableStateOf(Panel.Jwt) }
    var input by remember { mutableStateOf("") }
    var format by remember { mutableStateOf("base64") }
    var keyKind by remember { mutableStateOf("ed25519") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var draft by remember { mutableStateOf<String?>(null) }
    var saved by remember { mutableStateOf(false) }
    val rows = remember { mutableStateListOf<Row>() }
    val notes = remember { mutableStateListOf<String>() }

    val unknownError = stringResource(R.string.tools_errors_unknown)
    val tokenError = stringResource(R.string.tools_errors_invalid_token)
    val certificateError = stringResource(R.string.tools_errors_invalid_certificate)
    val encodingError = stringResource(R.string.tools_errors_invalid_encoding)
    val unverified = stringResource(R.string.tools_jwt_unverified)
    val algNone = stringResource(R.string.tools_jwt_warnings_algNone)
    val expired = stringResource(R.string.tools_jwt_warnings_expired)
    val notYet = stringResource(R.string.tools_jwt_warnings_notYetValid)
    val noExpiry = stringResource(R.string.tools_jwt_warnings_noExpiry)
    val header = stringResource(R.string.tools_jwt_header)
    val payload = stringResource(R.string.tools_jwt_payload)
    val subject = stringResource(R.string.tools_certs_subject)
    val issuer = stringResource(R.string.tools_certs_issuer)
    val names = stringResource(R.string.tools_certs_names)
    val result = stringResource(R.string.tools_encoding_result)
    val publicKey = stringResource(R.string.tools_keys_publicKey)
    val keyTitle = stringResource(R.string.tools_keys_titleFor, keyKind)
    val resources = androidx.compose.ui.platform.LocalContext.current.resources

    fun reset() {
        rows.clear()
        notes.clear()
        error = null
        draft = null
        saved = false
    }

    fun action(work: suspend () -> Unit) {
        reset()
        busy = true
        scope.launch {
            try {
                work()
            } catch (failure: Exception) {
                val text = failure.toString()
                error = when {
                    "invalid_token" in text -> tokenError
                    "invalid_certificate" in text -> certificateError
                    "invalid_encoding" in text -> encodingError
                    else -> unknownError
                }
            } finally {
                busy = false
            }
        }
    }

    suspend fun readToken() {
        val decoded = run("jwt.decode", JSONObject().put("token", input))
        val warnings = decoded.getJSONArray("warnings")
        for (index in 0 until warnings.length()) {
            when (warnings.getString(index)) {
                "algNone" -> notes += algNone
                "expired" -> notes += expired
                "notYetValid" -> notes += notYet
                "noExpiry" -> notes += noExpiry
            }
        }
        notes += unverified
        rows += Row(header, decoded.getJSONObject("header").toString(2))
        decoded.optJSONObject("payload")?.let { rows += Row(payload, it.toString(2)) }
    }

    suspend fun readCertificate() {
        val report = run("cert.read", JSONObject().put("text", input))
        for (certificate in report.getJSONArray("certificates").objects()) {
            rows += Row(subject, certificate.getString("subject"))
            rows += Row(issuer, certificate.getString("issuer"))
            rows += Row(names, certificate.getJSONArray("sans").objects().joinToString(", ") { it.getString("value") })
            val days = certificate.getInt("daysLeft")
            rows += Row(resources.getString(R.string.tools_certs_expires), resources.getQuantityString(R.plurals.tools_certs_daysLeft, days, days))
            rows += Row("SHA-256", certificate.getString("sha256"))
        }
    }

    suspend fun hash() {
        for (hash in run("hash.digest", JSONObject().put("text", input)).getJSONArray("hashes").objects()) {
            rows += Row(hash.getString("algorithm"), hash.getString("hex"))
        }
    }

    suspend fun encode(op: String) {
        val body = JSONObject().put("format", format)
        if (op == "encoding.encode") body.put("text", input) else body.put("value", input)
        val answer = run(op, body)
        rows += Row(result, answer.optString("value").ifEmpty { answer.optString("text").ifEmpty { answer.optString("hex") } })
    }

    suspend fun random() {
        rows += Row(result, run("random.token", JSONObject().put("shape", "base62")).getString("value"))
        rows += Row("UUID v7", run("random.uuid", JSONObject().put("version", 7)).getJSONArray("values").getString(0))
    }

    suspend fun generateKey() {
        val key = run("key.generate", JSONObject().put("type", keyKind))
        rows += Row(publicKey, key.getString("publicOpenssh"))
        draft = run(
            "item.key",
            JSONObject()
                .put("title", keyTitle)
                .put("kind", "asymmetric")
                .put("algorithm", keyKind)
                .put("privateKey", key.getString("privateKey"))
                .put("publicKey", key.getString("publicPem")),
        ).toString()
    }

    VaultPage(stringResource(R.string.tools_title), stringResource(R.string.tools_subtitle), tag = "tools") {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Choose(stringResource(R.string.tools_choose), stringResource(panel.title), Panel.entries.map { stringResource(it.title) }) {
                panel = Panel.entries[it]
                reset()
            }
            if (panel == Panel.Encoding) Choose(stringResource(R.string.tools_encoding_format), format, FORMATS) { format = FORMATS[it] }
            if (panel == Panel.Keys) Choose(stringResource(R.string.tools_keys_type), keyKind, KEY_KINDS) { keyKind = KEY_KINDS[it] }
            if (panel != Panel.Random && panel != Panel.Keys) {
                Field(input, { input = it }, stringResource(panel.title), Modifier.fillMaxWidth().testTag("tools.input"), mono = true)
            }
            when (panel) {
                Panel.Jwt -> Button({ action { readToken() } }, enabled = !busy) { Text(stringResource(R.string.tools_jwt_read)) }
                Panel.Certificates -> Button({ action { readCertificate() } }, enabled = !busy) { Text(stringResource(R.string.tools_certs_readAction)) }
                Panel.Hash -> Button({ action { hash() } }, enabled = !busy) { Text(stringResource(R.string.tools_hash_run)) }
                Panel.Encoding -> {
                    Button({ action { encode("encoding.encode") } }, enabled = !busy) { Text(stringResource(R.string.tools_encoding_encode)) }
                    OutlinedButton({ action { encode("encoding.decode") } }, enabled = !busy) { Text(stringResource(R.string.tools_encoding_decode)) }
                }
                Panel.Random -> Button({ action { random() } }, enabled = !busy) { Text(stringResource(R.string.tools_random_make)) }
                Panel.Keys -> Button({ action { generateKey() } }, enabled = !busy) { Text(stringResource(R.string.tools_keys_generateAction)) }
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            notes.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            rows.forEach { row ->
                OutlinedCard(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(row.label, style = MaterialTheme.typography.labelMedium)
                        Text(row.value, style = monoStyle.copy(textDirection = TextDirection.Ltr))
                        OutlinedButton({ copy(model, row.value, row.label, secret = false) }) {
                            Text(stringResource(R.string.copy_action, row.label))
                        }
                    }
                }
            }
            draft?.let { json ->
                Button(
                    onClick = {
                        scope.launch {
                            try {
                                val vault = model.vault.listVaults().first { it.vaultType == VaultType.PERSONAL }
                                model.vault.saveToolItem(vault.id, json)
                                saved = true
                            } catch (_: Exception) {
                                error = unknownError
                            }
                        }
                    },
                    enabled = !saved,
                ) { Text(stringResource(if (saved) R.string.tools_savedShort else R.string.tools_save)) }
            }
            Text(stringResource(R.string.tools_localNote), style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** A small dropdown: the current choice on a button. */
@Composable
private fun Choose(label: String, current: String, options: List<String>, onChoose: (Int) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium)
        OutlinedButton({ open = true }) { Text(current) }
        DropdownMenu(open, { open = false }) {
            options.forEachIndexed { index, option ->
                DropdownMenuItem({ Text(option) }, {
                    open = false
                    onChoose(index)
                })
            }
        }
    }
}
