package app.octap.android.ui.components

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.octap.android.model.AppModel
import app.octap.android.ui.theme.Brand

/** A stable hue per name (`hueFor` in packages/ui), so an item keeps its colour everywhere. */
fun hueFor(name: String): Int {
    var hash = 0L
    for (char in name.lowercase().codePoints()) hash = (hash * 31 + char) and 0xFFFFFFFFL
    return (hash % 360).toInt()
}

/** The item's first letter on its own colour (`Avatar`). Decorative: the row says the name. */
@Composable
fun Avatar(name: String, size: Dp = 40.dp, modifier: Modifier = Modifier) {
    val hue = hueFor(name).toFloat()
    val dark = Brand.colors.dark
    val background = Color.hsl(hue, 0.65f, if (dark) 0.22f else 0.92f)
    val foreground = Color.hsl(hue, 0.55f, if (dark) 0.78f else 0.32f)
    val letter = name.trim().codePoints().findFirst().let { if (it.isPresent) String(Character.toChars(it.asInt)).uppercase() else "?" }
    Box(
        modifier.size(size).clip(MaterialTheme.shapes.medium).background(background).clearAndSetSemantics { },
        contentAlignment = Alignment.Center,
    ) {
        Text(letter, color = foreground, fontWeight = FontWeight.SemiBold, fontSize = (size.value * 0.42f).sp)
    }
}

/** Website icons fetched once per run, by domain (the vault keeps them on disk too). */
private val icons = mutableStateMapOf<String, ImageBitmap?>()

/**
 * The website's icon through the user's own server (`siteIcon`) when Settings → Show website icons
 * is on, else the letter avatar. Nothing is fetched from the website itself.
 */
@Composable
fun ItemIcon(model: AppModel, name: String, domain: String?, size: Dp = 40.dp, modifier: Modifier = Modifier) {
    val settings by model.settings.collectAsState()
    val icon = if (settings.showSiteIcons && domain != null) icons[domain] else null
    if (settings.showSiteIcons && domain != null && !icons.containsKey(domain)) {
        LaunchedEffect(domain) {
            val bytes = runCatching { model.vault.siteIcon(domain) }.getOrNull()
            icons[domain] = bytes?.let { BitmapFactory.decodeByteArray(it, 0, it.size)?.asImageBitmap() }
        }
    }
    if (icon != null) {
        Box(
            modifier.size(size).clip(MaterialTheme.shapes.medium).background(Color.White).clearAndSetSemantics { },
            contentAlignment = Alignment.Center,
        ) {
            Image(icon, contentDescription = null, modifier = Modifier.size(size * 0.7f))
        }
    } else {
        Avatar(name, size, modifier)
    }
}

/** Forgets the icons shown, when the user turns them off or signs out. */
fun forgetIcons() = icons.clear()
