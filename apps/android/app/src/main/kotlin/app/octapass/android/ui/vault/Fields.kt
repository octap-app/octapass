package app.octap.android.ui.vault

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import app.octap.android.model.AppModel
import app.octap.android.model.Toast
import app.octap.android.ui.components.Field as InputField
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.theme.monoStyle
import app.octap.resources.R
import app.octap.vault.HotpCode
import app.octap.vault.TotpCode
import app.octap.vault.hotpCounter
import app.octap.vault.isHotp
import app.octap.vault.totpCode
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Copies [value]: a secret clears from the clipboard after 30 seconds (`useCopy`). Android 13 and
 * later confirm copies themselves, so the toast only shows on older phones. Copying from an item
 * ([item]) counts as using it, for Frequently used and Recently used.
 */
fun copy(model: AppModel, value: String, what: String, secret: Boolean, item: String? = null) {
    model.clipboard.copy(what, value, secret)
    if (!model.clipboard.systemConfirms) {
        model.toast(
            if (secret) model.app.getString(R.string.copy_copiedSecret, what) else model.app.getString(R.string.copy_copied, what),
            Toast.Tone.Success,
        )
    }
    if (item != null) model.vault.recordItemUse(item)
}

/** The item a screen shows ([ItemScreen] provides it), so its copy buttons count a use of it. */
val LocalUsedItem = staticCompositionLocalOf<String?> { null }

sealed interface TotpState {
    data class Code(val code: TotpCode) : TotpState
    data object Invalid : TotpState
}

/** The current code for [secret], every second on the second, so it flips exactly on the period boundary (`useTotp`). */
@Composable
fun rememberTotp(secret: String?): TotpState? {
    var state by remember(secret) { mutableStateOf<TotpState?>(null) }
    LaunchedEffect(secret) {
        if (secret.isNullOrBlank()) return@LaunchedEffect
        while (true) {
            state = runCatching { totpCode(secret, null) }.map { TotpState.Code(it) }.getOrDefault(TotpState.Invalid)
            delay(1000 - System.currentTimeMillis() % 1000)
        }
    }
    return if (secret.isNullOrBlank()) null else state
}

/** "123 456". */
fun formatCode(code: String): String {
    val half = (code.length + 1) / 2
    return "${code.take(half)} ${code.drop(half)}"
}

/** The time left in the code's period, amber in the last five seconds. */
@Composable
fun CountdownRing(remaining: ULong, period: ULong, size: Int = 18) {
    CircularProgressIndicator(
        progress = { remaining.toFloat() / period.toFloat() },
        modifier = Modifier.size(size.dp),
        strokeWidth = 3.dp,
        color = if (remaining <= 5uL) Brand.colors.warn else Brand.colors.free,
        trackColor = MaterialTheme.colorScheme.outlineVariant,
    )
}

/** A group of fields in a card, with an optional title (`FieldList`). */
@Composable
fun FieldList(title: String? = null, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Column(modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp)) {
        if (title != null) {
            Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(start = 4.dp, bottom = 6.dp).semantics { heading() })
        }
        OutlinedCard(Modifier.fillMaxWidth()) { Column { content() } }
    }
}

/**
 * One labelled value with its actions (`Field`). Nothing shows when there's no value. [ltr] for
 * addresses and numbers, which read left to right in Arabic too.
 */
@Composable
fun Field(
    label: String,
    value: String?,
    model: AppModel,
    what: String = label,
    copy: Boolean = true,
    secret: Boolean = false,
    /** Copying asks "Confirm it's you" first (plan 03); secrets do, unless they say otherwise. */
    gated: Boolean = secret,
    mono: Boolean = false,
    ltr: Boolean = false,
    tag: String? = null,
    actions: (@Composable () -> Unit)? = null,
    content: (@Composable () -> Unit)? = null,
) {
    if (value.isNullOrEmpty() && content == null) return
    val scope = rememberCoroutineScope()
    val usedItem = LocalUsedItem.current
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(start = 16.dp, end = 4.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).semantics(mergeDescendants = true) {}) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (content != null) {
                content()
            } else {
                val style: TextStyle = if (mono) monoStyle else MaterialTheme.typography.bodyLarge
                Text(value!!, style = if (ltr || mono) style.copy(textDirection = TextDirection.Ltr) else style, modifier = if (tag != null) Modifier.testTag(tag) else Modifier)
            }
        }
        actions?.invoke()
        if (copy && !value.isNullOrEmpty()) {
            IconButton(
                onClick = {
                    scope.launch { if (!gated || model.confirmReveal()) copy(model, value, what, secret, usedItem) }
                },
                modifier = Modifier.testTag("copy.${tag ?: label}"),
            ) {
                Icon(Icons.Outlined.ContentCopy, contentDescription = stringResource(R.string.copy_action, what))
            }
        }
    }
}

@Composable
fun FieldDivider() = HorizontalDivider(Modifier.padding(start = 16.dp), color = MaterialTheme.colorScheme.outlineVariant)

/** A secret as dots until revealed, after confirming it's the owner; revealing is per field and resets with the item (`SecretField`). */
@Composable
fun SecretField(label: String, value: String?, model: AppModel, what: String = label, tag: String? = null, format: (String) -> String = { it }) {
    if (value.isNullOrEmpty()) return
    var revealed by rememberSaveable(value) { mutableStateOf(false) }
    val hidden = stringResource(R.string.detail_hiddenValue)
    val scope = rememberCoroutineScope()
    Field(
        label = label,
        value = value,
        model = model,
        what = what,
        secret = true,
        tag = tag,
        actions = {
            IconButton(
                onClick = {
                    scope.launch { if (revealed || model.confirmReveal()) revealed = !revealed }
                },
                modifier = Modifier.semantics { stateDescription = if (revealed) "" else hidden }.testTag("reveal.${tag ?: label}"),
            ) {
                Icon(
                    if (revealed) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                    contentDescription = stringResource(if (revealed) R.string.common_hideWhat else R.string.common_revealWhat, what),
                )
            }
        },
    ) {
        if (revealed) {
            Text(format(value), style = monoStyle.copy(textDirection = TextDirection.Ltr), modifier = if (tag != null) Modifier.testTag("$tag.value") else Modifier)
        } else {
            Text("•".repeat(value.length.coerceIn(8, 16)), style = monoStyle, modifier = Modifier.semantics { contentDescription = hidden })
        }
    }
}

/**
 * A counter-based code (`HotpField`): nothing to show until one is asked for, and each one asked
 * for is used up. The code stays through the item's refresh when the counter moves, so its state
 * follows the item, not the secret. An old version or a shared copy only says what kind of code
 * this is.
 */
@Composable
private fun HotpField(secret: String, model: AppModel, itemId: String?) {
    val scope = rememberCoroutineScope()
    var code by remember(itemId) { mutableStateOf<HotpCode?>(null) }
    var counter by remember(itemId) { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val next = remember(secret) { hotpCounter(secret) }
    if (next == null) {
        Field(stringResource(R.string.fields_totp), stringResource(R.string.detail_totpInvalid), model, copy = false)
        return
    }

    fun run(action: suspend () -> Unit) {
        busy = true
        scope.launch {
            try {
                action()
            } catch (error: Exception) {
                model.toastError(error)
            } finally {
                busy = false
            }
        }
    }

    Field(stringResource(R.string.fields_totp), code?.code, model, what = stringResource(R.string.fields_totpShort), secret = true, tag = "totp") {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    code?.let { formatCode(it.code) } ?: "––– –––",
                    style = monoStyle.copy(textDirection = TextDirection.Ltr),
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag("totp.value"),
                )
                if (itemId != null) {
                    OutlinedButton(onClick = { run { code = model.vault.nextHotpCode(itemId) } }, enabled = !busy, modifier = Modifier.testTag("totp.next")) {
                        Text(stringResource(R.string.detail_hotpNext))
                    }
                }
            }
            Text(
                stringResource(R.string.detail_hotpCounter, next.toString()),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag("totp.counter"),
            )
            val editing = counter
            if (itemId != null && editing == null) {
                TextButton(onClick = { counter = next.toString() }, modifier = Modifier.testTag("totp.resync")) { Text(stringResource(R.string.detail_hotpResync)) }
            }
            if (itemId != null && editing != null) {
                val value = editing.takeIf { it.length in 1..15 }?.toULongOrNull()
                InputField(
                    value = editing,
                    onValueChange = { counter = it },
                    label = stringResource(R.string.detail_hotpCounterField),
                    error = if (value == null) stringResource(R.string.detail_hotpCounterInvalid) else null,
                    hint = stringResource(R.string.detail_hotpCounterHint),
                    mono = true,
                    keyboardType = KeyboardType.Number,
                    modifier = Modifier.testTag("totp.counterField"),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = {
                            run {
                                model.vault.setHotpCounter(itemId, value!!)
                                code = null
                                counter = null
                            }
                        },
                        enabled = value != null && !busy,
                        modifier = Modifier.testTag("totp.counterSave"),
                    ) { Text(stringResource(R.string.common_save)) }
                    TextButton(onClick = { counter = null }) { Text(stringResource(R.string.common_cancel)) }
                }
            }
        }
    }
}

/** The login's one-time code (`TotpField`). [itemId]: the item a counter-based code can move in; left out where nothing can be saved. */
@Composable
fun TotpField(secret: String?, model: AppModel, itemId: String? = null) {
    val hotp = remember(secret) { secret != null && isHotp(secret) }
    if (hotp && secret != null) HotpField(secret, model, itemId) else TimeCodeField(secret, model)
}

/** A time-based code with its countdown. */
@Composable
private fun TimeCodeField(secret: String?, model: AppModel) {
    val state = rememberTotp(secret) ?: if (secret.isNullOrBlank()) return else null
    if (state == TotpState.Invalid) {
        Field(stringResource(R.string.fields_totp), stringResource(R.string.detail_totpInvalid), model, copy = false)
        return
    }
    val code = (state as? TotpState.Code)?.code
    Field(stringResource(R.string.fields_totp), code?.code ?: "", model, what = stringResource(R.string.fields_totpShort), secret = true, gated = false, tag = "totp") {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(code?.let { formatCode(it.code) } ?: "––– –––", style = monoStyle.copy(textDirection = TextDirection.Ltr), modifier = Modifier.testTag("totp.value"))
            if (code != null) {
                CountdownRing(code.remaining, code.period, 20)
                Text(
                    pluralStringResource(R.plurals.detail_totpRemaining, code.remaining.toInt(), code.remaining.toInt()),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
