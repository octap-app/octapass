package app.octap.android.ui.components

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.autofill.ContentType
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentType
import androidx.compose.ui.semantics.error
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import app.octap.android.R
import app.octap.android.ui.theme.Brand
import app.octap.android.ui.theme.monoStyle
import app.octap.resources.R as S

/** The app icon's tile: the white monogram on the brand gradient. */
@Composable
fun Logo(size: Dp = 56.dp, modifier: Modifier = Modifier) {
    Box(
        modifier
            .size(size)
            .clip(RoundedCornerShape(size * 0.28f))
            .background(Brush.linearGradient(listOf(Color(0xFF2456F0), Color(0xFF10B77F)))),
        contentAlignment = Alignment.Center,
    ) {
        Image(painterResource(R.drawable.logo_mark), contentDescription = null, modifier = Modifier.fillMaxSize())
    }
}

/**
 * Every signed-out screen (`AuthLayout`): logo, title, subtitle and the form, centred and
 * scrollable, clear of the bars and the keyboard.
 */
@Composable
fun AuthLayout(
    title: String,
    subtitle: String? = null,
    top: (@Composable () -> Unit)? = null,
    footer: (@Composable () -> Unit)? = null,
    wide: Boolean = false,
    content: @Composable () -> Unit,
) {
    Surface(color = MaterialTheme.colorScheme.background, modifier = Modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(16.dp))
            Column(
                Modifier.widthIn(max = if (wide) 640.dp else 440.dp).fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                top?.invoke()
                Logo(56.dp, Modifier.padding(bottom = 20.dp))
                Text(
                    title,
                    style = MaterialTheme.typography.headlineMedium,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.semantics { heading() },
                )
                if (subtitle != null) {
                    Text(
                        subtitle,
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
                Spacer(Modifier.height(24.dp))
                Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(16.dp)) { content() }
                if (footer != null) {
                    Box(Modifier.padding(top = 24.dp)) { footer() }
                }
            }
        }
    }
}

enum class AlertTone { Danger, Info, Warn }

/** A message above a form (`Alert`). Screen readers hear it when it appears. */
@Composable
fun Alert(text: String, tone: AlertTone = AlertTone.Danger, modifier: Modifier = Modifier, content: (@Composable () -> Unit)? = null) {
    val colors = Brand.colors
    val (fg, bg) = when (tone) {
        AlertTone.Danger -> colors.dangerText to colors.danger.copy(alpha = if (colors.dark) 0.16f else 0.08f)
        AlertTone.Warn -> colors.warnText to colors.warn.copy(alpha = if (colors.dark) 0.16f else 0.10f)
        AlertTone.Info -> colors.trustText to colors.trust.copy(alpha = if (colors.dark) 0.16f else 0.08f)
    }
    Row(
        modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.medium)
            .background(bg)
            .padding(14.dp)
            .semantics { liveRegion = LiveRegionMode.Polite },
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Icon(if (tone == AlertTone.Danger) Icons.Outlined.ErrorOutline else Icons.Outlined.Info, contentDescription = null, tint = fg, modifier = Modifier.size(20.dp))
        Column(Modifier.weight(1f)) {
            Text(text, color = fg, style = MaterialTheme.typography.bodyMedium)
            content?.invoke()
        }
    }
}

/** The main action of a screen: full width, a spinner while it works. */
@Composable
fun PrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    busy: Boolean = false,
    enabled: Boolean = true,
    icon: ImageVector? = null,
    danger: Boolean = false,
) {
    Button(
        onClick = { if (!busy) onClick() },
        enabled = enabled,
        modifier = modifier.fillMaxWidth().heightIn(min = 52.dp),
        shape = MaterialTheme.shapes.medium,
        colors = if (danger) ButtonDefaults.buttonColors(containerColor = Brand.colors.danger, contentColor = Color.White) else ButtonDefaults.buttonColors(),
    ) {
        if (busy) {
            CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = LocalContentColorOr())
        } else {
            if (icon != null) {
                Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.size(8.dp))
            }
            Text(text, style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
private fun LocalContentColorOr(): Color = androidx.compose.material3.LocalContentColor.current

@Composable
fun SecondaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, icon: ImageVector? = null) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.fillMaxWidth().heightIn(min = 52.dp),
        shape = MaterialTheme.shapes.medium,
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.size(8.dp))
        }
        Text(text, style = MaterialTheme.typography.labelLarge)
    }
}

@Composable
fun LinkButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    TextButton(onClick = onClick, enabled = enabled, modifier = modifier.heightIn(min = 48.dp)) {
        Text(text, style = MaterialTheme.typography.labelLarge, textAlign = TextAlign.Center)
    }
}

/**
 * A labelled field with an error or hint under it. [mono] for keys and codes, which read left to
 * right in Arabic too.
 */
@Composable
fun Field(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    error: String? = null,
    hint: String? = null,
    placeholder: String? = null,
    mono: Boolean = false,
    keyboardType: KeyboardType = KeyboardType.Text,
    capitalization: KeyboardCapitalization = KeyboardCapitalization.None,
    autoCorrect: Boolean = false,
    imeAction: ImeAction = ImeAction.Next,
    onImeAction: (() -> Unit)? = null,
    singleLine: Boolean = true,
    minLines: Int = 1,
    contentType: ContentType? = null,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    trailing: (@Composable () -> Unit)? = null,
    readOnly: Boolean = false,
    enabled: Boolean = true,
) {
    val style: TextStyle = if (mono) monoStyle.copy(textDirection = TextDirection.Ltr) else MaterialTheme.typography.bodyLarge
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        placeholder = placeholder?.let { { Text(it, style = style, color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)) } },
        isError = error != null,
        supportingText = (error ?: hint)?.let { { Text(it) } },
        textStyle = style,
        singleLine = singleLine,
        minLines = minLines,
        readOnly = readOnly,
        enabled = enabled,
        visualTransformation = visualTransformation,
        trailingIcon = trailing,
        keyboardOptions = KeyboardOptions(
            capitalization = capitalization,
            autoCorrectEnabled = autoCorrect,
            keyboardType = keyboardType,
            imeAction = imeAction,
        ),
        keyboardActions = KeyboardActions(onAny = { onImeAction?.invoke() }),
        shape = MaterialTheme.shapes.medium,
        modifier = modifier
            .fillMaxWidth()
            .semantics {
                if (contentType != null) this.contentType = contentType
                if (error != null) error(error)
            },
    )
}

/** A password field with Show and Hide; never autocorrected, never suggested by the keyboard. */
@Composable
fun PasswordField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    error: String? = null,
    hint: String? = null,
    imeAction: ImeAction = ImeAction.Done,
    onImeAction: (() -> Unit)? = null,
    contentType: ContentType? = ContentType.Password,
    mono: Boolean = true,
) {
    var shown by rememberSaveable { mutableStateOf(false) }
    Field(
        value = value,
        onValueChange = onValueChange,
        label = label,
        modifier = modifier,
        error = error,
        hint = hint,
        mono = mono && shown,
        keyboardType = KeyboardType.Password,
        imeAction = imeAction,
        onImeAction = onImeAction,
        contentType = contentType,
        visualTransformation = if (shown) VisualTransformation.None else PasswordVisualTransformation(),
        trailing = {
            IconButton(onClick = { shown = !shown }, modifier = Modifier.testTag("reveal")) {
                Icon(
                    if (shown) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                    contentDescription = stringResource(if (shown) S.string.common_hide else S.string.common_reveal),
                )
            }
        },
    )
}

/** A section heading inside a screen. */
@Composable
fun SectionHeading(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier.padding(horizontal = 16.dp, vertical = 8.dp).semantics { heading() },
    )
}
