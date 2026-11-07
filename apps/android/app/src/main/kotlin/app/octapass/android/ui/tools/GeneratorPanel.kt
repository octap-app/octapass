package app.octap.android.ui.tools

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.octap.android.model.AppModel
import app.octap.android.ui.components.PrimaryButton
import app.octap.android.ui.components.strengthColor
import app.octap.android.ui.components.strengthLabelRes
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.theme.monoStyle
import app.octap.android.ui.vault.copy
import app.octap.resources.R
import app.octap.vault.GeneratorOptions
import app.octap.vault.defaultGeneratorOptions
import app.octap.vault.generatePassword
import app.octap.vault.generatePasswordForSite
import app.octap.vault.generatorEntropyBits
import org.json.JSONObject

/** The generator's options as last used: only the options, never a generated value (`loadOptions`). */
private class StoredOptions(val passphrase: Boolean, val password: GeneratorOptions.Password, val words: GeneratorOptions.Passphrase) {
    val current: GeneratorOptions get() = if (passphrase) words else password

    fun save(context: Context) {
        val json = JSONObject()
            .put("kind", if (passphrase) "passphrase" else "password")
            .put("length", password.length.toInt()).put("uppercase", password.uppercase).put("lowercase", password.lowercase)
            .put("digits", password.digits).put("symbols", password.symbols).put("avoidAmbiguous", password.avoidAmbiguous)
            .put("words", words.words.toInt()).put("separator", words.separator).put("capitalize", words.capitalize).put("includeNumber", words.includeNumber)
        prefs(context).edit().putString(KEY, json.toString()).apply()
    }

    companion object {
        private const val KEY = "generator"

        private fun prefs(context: Context) = context.getSharedPreferences("octapass.ui", Context.MODE_PRIVATE)

        fun load(context: Context): StoredOptions {
            val password = defaultGeneratorOptions(false) as GeneratorOptions.Password
            val words = defaultGeneratorOptions(true) as GeneratorOptions.Passphrase
            val json = prefs(context).getString(KEY, null)?.let { runCatching { JSONObject(it) }.getOrNull() } ?: return StoredOptions(false, password, words)
            return StoredOptions(
                json.optString("kind") == "passphrase",
                GeneratorOptions.Password(
                    json.optInt("length", password.length.toInt()).coerceIn(8, 64).toUInt(),
                    json.optBoolean("uppercase", password.uppercase),
                    json.optBoolean("lowercase", password.lowercase),
                    json.optBoolean("digits", password.digits),
                    json.optBoolean("symbols", password.symbols),
                    json.optBoolean("avoidAmbiguous", password.avoidAmbiguous),
                ),
                GeneratorOptions.Passphrase(
                    json.optInt("words", words.words.toInt()).coerceIn(3, 10).toUInt(),
                    json.optString("separator", words.separator),
                    json.optBoolean("capitalize", words.capitalize),
                    json.optBoolean("includeNumber", words.includeNumber),
                ),
            )
        }
    }
}

private val SEPARATORS = listOf("-", " ", ".", "_", ",")

/** A new value: a password follows what the rules dataset knows about [site]; a passphrase has no rules to follow. */
private fun generated(options: GeneratorOptions, site: String?): String =
    if (site != null && options is GeneratorOptions.Password) generatePasswordForSite(site, options) else generatePassword(options)

/** Passwords and passphrases made on the phone (`GeneratorPanel`). [onUse] puts the value in an editor; [site] is the website it's for. */
@Composable
fun GeneratorPanel(model: AppModel, onUse: ((String) -> Unit)? = null, useLabel: String? = null, site: String? = null) {
    val context = LocalContext.current
    var stored by remember { mutableStateOf(StoredOptions.load(context)) }
    var value by remember { mutableStateOf(runCatching { generated(stored.current, site) }.getOrDefault("")) }
    LaunchedEffect(stored) {
        value = runCatching { generated(stored.current, site) }.getOrDefault(value)
        stored.save(context)
    }
    val estimate = remember(value) { model.vault.estimateStrength(value) }
    val bits = remember(stored) { Math.round(generatorEntropyBits(stored.current)).toInt() }
    val passwordWhat = stringResource(R.string.fields_password)
    val digit = Brand.colors.trustText
    val symbol = Brand.colors.freeText

    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        OutlinedCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                val generated = stringResource(R.string.generator_generated)
                Text(
                    buildAnnotatedString {
                        // Digits and symbols in their own colours, so it's easier to read out or type.
                        for (char in value) {
                            when {
                                char.isDigit() -> withStyle(SpanStyle(color = digit)) { append(char) }
                                !char.isLetterOrDigit() && !char.isWhitespace() -> withStyle(SpanStyle(color = symbol)) { append(char) }
                                else -> append(char)
                            }
                        }
                    },
                    style = monoStyle.copy(fontSize = 22.sp, lineHeight = 30.sp, textDirection = TextDirection.Ltr),
                    modifier = Modifier.semantics {
                        contentDescription = "$generated: $value"
                        liveRegion = LiveRegionMode.Polite
                    }.testTag("generator.value"),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Spacer(Modifier.size(8.dp).clip(CircleShape).background(strengthColor(estimate.score.toInt())))
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "${stringResource(strengthLabelRes(estimate.score.toInt()))} · ${stringResource(R.string.generator_bits, bits)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                    )
                    IconButton(onClick = { value = runCatching { generated(stored.current, site) }.getOrDefault(value) }, modifier = Modifier.testTag("generator.regenerate")) {
                        Icon(Icons.Outlined.Refresh, contentDescription = stringResource(R.string.generator_regenerate))
                    }
                    IconButton(onClick = { copy(model, value, passwordWhat, secret = true) }, modifier = Modifier.testTag("generator.copy")) {
                        Icon(Icons.Outlined.ContentCopy, contentDescription = stringResource(R.string.copy_action, passwordWhat))
                    }
                }
            }
        }

        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            SegmentedButton(selected = !stored.passphrase, onClick = { stored = StoredOptions(false, stored.password, stored.words) }, shape = SegmentedButtonDefaults.itemShape(0, 2), modifier = Modifier.testTag("generator.password")) {
                Text(stringResource(R.string.generator_password))
            }
            SegmentedButton(selected = stored.passphrase, onClick = { stored = StoredOptions(true, stored.password, stored.words) }, shape = SegmentedButtonDefaults.itemShape(1, 2), modifier = Modifier.testTag("generator.passphrase")) {
                Text(stringResource(R.string.generator_passphrase))
            }
        }

        if (!stored.passphrase) {
            val options = stored.password
            fun set(next: GeneratorOptions.Password) {
                stored = StoredOptions(false, next, stored.words)
            }
            LabeledSlider(stringResource(R.string.generator_length), pluralStringResource(R.plurals.generator_lengthValue, options.length.toInt(), options.length.toInt()), options.length.toInt(), 8..64, "generator.length") { set(options.copy(length = it.toUInt())) }
            Toggle(stringResource(R.string.generator_uppercase), options.uppercase) { set(options.copy(uppercase = it)) }
            Toggle(stringResource(R.string.generator_lowercase), options.lowercase) { set(options.copy(lowercase = it)) }
            Toggle(stringResource(R.string.generator_digits), options.digits) { set(options.copy(digits = it)) }
            Toggle(stringResource(R.string.generator_symbols), options.symbols) { set(options.copy(symbols = it)) }
            Toggle(stringResource(R.string.generator_avoidAmbiguous), options.avoidAmbiguous, stringResource(R.string.generator_avoidAmbiguousHint)) { set(options.copy(avoidAmbiguous = it)) }
        } else {
            val options = stored.words
            fun set(next: GeneratorOptions.Passphrase) {
                stored = StoredOptions(true, stored.password, next)
            }
            LabeledSlider(stringResource(R.string.generator_words), pluralStringResource(R.plurals.generator_wordsValue, options.words.toInt(), options.words.toInt()), options.words.toInt(), 3..10, "generator.words") { set(options.copy(words = it.toUInt())) }
            Text(stringResource(R.string.generator_separator), style = MaterialTheme.typography.labelLarge)
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                SEPARATORS.forEachIndexed { i, separator ->
                    SegmentedButton(selected = options.separator == separator, onClick = { set(options.copy(separator = separator)) }, shape = SegmentedButtonDefaults.itemShape(i, SEPARATORS.size)) {
                        Text(if (separator == " ") stringResource(R.string.generator_space) else separator, style = if (separator == " ") MaterialTheme.typography.labelMedium else monoStyle)
                    }
                }
            }
            Toggle(stringResource(R.string.generator_capitalize), options.capitalize) { set(options.copy(capitalize = it)) }
            Toggle(stringResource(R.string.generator_includeNumber), options.includeNumber) { set(options.copy(includeNumber = it)) }
        }

        if (onUse != null) PrimaryButton(useLabel ?: stringResource(R.string.generator_use), { onUse(value) }, icon = Icons.Outlined.Check, modifier = Modifier.testTag("generator.use"))
    }
}

@Composable
private fun LabeledSlider(label: String, valueText: String, value: Int, range: IntRange, tag: String, onChange: (Int) -> Unit) {
    Column {
        Row {
            Text(label, style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f))
            Text(valueText, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Slider(
            value = value.toFloat(),
            onValueChange = { onChange(it.toInt()) },
            valueRange = range.first.toFloat()..range.last.toFloat(),
            steps = range.last - range.first - 1,
            modifier = Modifier.semantics { stateDescription = valueText }.testTag(tag),
        )
    }
}

/** A switch row: the whole row toggles, as in Settings. */
@Composable
fun Toggle(label: String, checked: Boolean, description: String? = null, tag: String? = null, onChange: (Boolean) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .toggleable(value = checked, role = Role.Switch, onValueChange = onChange)
            .padding(vertical = 6.dp)
            .let { if (tag != null) it.testTag(tag) else it },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge)
            if (description != null) Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.width(12.dp))
        Switch(checked = checked, onCheckedChange = null)
    }
}
