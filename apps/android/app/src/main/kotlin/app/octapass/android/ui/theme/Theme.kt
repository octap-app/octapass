package app.octap.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import app.octap.android.R
import app.octap.resources.Tokens
import app.octap.vault.ThemePreference

/** The brand colours Material's scheme has no slot for (packages/ui tokens). */
@Immutable
data class BrandColors(
    val trust: Color,
    val trustText: Color,
    val free: Color,
    val freeText: Color,
    val warn: Color,
    val warnText: Color,
    val danger: Color,
    val dangerText: Color,
    val ink: Color,
    val mist: Color,
    val line: Color,
    val tile: Color,
    val selected: Color,
    val gradient: List<Color>,
    val dark: Boolean,
)

private fun c(argb: Long) = Color(argb)

private val lightBrand = with(Tokens.LightColors) {
    BrandColors(
        c(trust), c(trustText), c(free), c(freeText), c(warn), c(warnText), c(danger), c(dangerText),
        c(ink), c(mist), c(line), c(tile), c(selected), Tokens.Gradient.lightStops.map { c(it.argb) }, dark = false,
    )
}

private val darkBrand = with(Tokens.DarkColors) {
    BrandColors(
        c(trust), c(trustText), c(free), c(freeText), c(warn), c(warnText), c(danger), c(dangerText),
        c(ink), c(mist), c(line), c(tile), c(selected), Tokens.Gradient.darkStops.map { c(it.argb) }, dark = true,
    )
}

private fun scheme(dark: Boolean): ColorScheme = if (dark) {
    with(Tokens.DarkColors) {
        darkColorScheme(
            // Buttons always use the light trust blue with white text (brand/README.md).
            primary = c(trustText),
            onPrimary = c(paper),
            primaryContainer = c(button),
            onPrimaryContainer = Color.White,
            secondary = c(freeText),
            onSecondary = c(paper),
            secondaryContainer = c(selected),
            onSecondaryContainer = c(ink),
            tertiary = c(warnText),
            background = c(paper),
            onBackground = c(ink),
            surface = c(paper),
            onSurface = c(ink),
            surfaceVariant = c(tile),
            onSurfaceVariant = c(mist),
            surfaceContainerLowest = c(paper),
            surfaceContainerLow = c(surface),
            surfaceContainer = c(tile),
            surfaceContainerHigh = c(raised),
            surfaceContainerHighest = c(raised),
            surfaceBright = c(raised),
            surfaceDim = c(paper),
            inverseSurface = c(ink),
            inverseOnSurface = c(paper),
            outline = c(lineStrong),
            outlineVariant = c(line),
            error = c(danger),
            onError = c(paper),
            errorContainer = c(danger).copy(alpha = 0.16f),
            onErrorContainer = c(dangerText),
            scrim = c(scrim),
        )
    }
} else {
    with(Tokens.LightColors) {
        lightColorScheme(
            primary = c(button),
            onPrimary = Color.White,
            primaryContainer = c(button),
            onPrimaryContainer = Color.White,
            secondary = c(freeText),
            onSecondary = Color.White,
            secondaryContainer = c(selected),
            onSecondaryContainer = c(ink),
            tertiary = c(warnText),
            background = c(paper),
            onBackground = c(ink),
            surface = c(paper),
            onSurface = c(ink),
            surfaceVariant = c(tile),
            onSurfaceVariant = c(mist),
            surfaceContainerLowest = c(surface),
            surfaceContainerLow = c(surface),
            surfaceContainer = c(tile),
            surfaceContainerHigh = c(raised),
            surfaceContainerHighest = c(tile),
            surfaceBright = c(raised),
            surfaceDim = c(tile),
            inverseSurface = c(ink),
            inverseOnSurface = c(paper),
            outline = c(lineStrong),
            outlineVariant = c(line),
            error = c(danger),
            onError = Color.White,
            errorContainer = c(danger).copy(alpha = 0.10f),
            onErrorContainer = c(dangerText),
            scrim = c(scrim),
        )
    }
}

/**
 * Mona Sans, the web's variable font (`res/font`, converted by `tools/native-fonts`), at each
 * weight the app uses. It has Latin only: Arabic and other scripts fall back to the phone's font.
 */
private fun monaSans(weight: Int, width: Float = 100f) = Font(
    R.font.mona_sans,
    FontWeight(weight),
    variationSettings = FontVariation.Settings(FontVariation.weight(weight), FontVariation.width(width)),
)

val SansFamily = FontFamily(monaSans(400), monaSans(500), monaSans(600), monaSans(700))

/** Headlines, as the brand sets them (`.display` in packages/ui): 112% width at weight 740. */
val DisplayFamily = FontFamily(
    Font(
        R.font.mona_sans,
        FontWeight.Bold,
        variationSettings = FontVariation.Settings(FontVariation.weight(740), FontVariation.width(112f)),
    ),
)

/** Monaspace Neon at the web's two weights. */
val MonoFamily = FontFamily(
    Font(R.font.monaspace_neon_regular, FontWeight.Normal),
    Font(R.font.monaspace_neon_semibold, FontWeight.SemiBold),
)

private val typography = with(Tokens.TypeScale) {
    val base = Typography()
    fun TextStyle.sans() = copy(fontFamily = SansFamily)
    Typography(
        displayLarge = base.displayLarge.copy(fontFamily = DisplayFamily, fontWeight = FontWeight.Bold),
        displayMedium = base.displayMedium.copy(fontFamily = DisplayFamily, fontWeight = FontWeight.Bold),
        displaySmall = base.displaySmall.copy(fontFamily = DisplayFamily, fontSize = xl3.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.04).em),
        headlineLarge = base.headlineLarge.copy(fontFamily = DisplayFamily, fontWeight = FontWeight.Bold),
        headlineMedium = base.headlineMedium.copy(fontFamily = DisplayFamily, fontSize = xl2.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.03).em),
        headlineSmall = base.headlineSmall.sans().copy(fontSize = xl.sp, fontWeight = FontWeight.SemiBold, letterSpacing = (-0.02).em),
        titleLarge = base.titleLarge.sans().copy(fontSize = xl.sp, fontWeight = FontWeight.SemiBold),
        titleMedium = base.titleMedium.sans().copy(fontSize = lg.sp, fontWeight = FontWeight.SemiBold),
        titleSmall = base.titleSmall.sans().copy(fontSize = md.sp, fontWeight = FontWeight.SemiBold),
        bodyLarge = base.bodyLarge.sans().copy(fontSize = lg.sp, lineHeight = 24.sp),
        bodyMedium = base.bodyMedium.sans().copy(fontSize = md.sp, lineHeight = 21.sp),
        bodySmall = base.bodySmall.sans().copy(fontSize = sm.sp, lineHeight = 19.sp),
        labelLarge = base.labelLarge.sans().copy(fontSize = md.sp, fontWeight = FontWeight.SemiBold),
        labelMedium = base.labelMedium.sans().copy(fontSize = sm.sp),
        labelSmall = base.labelSmall.sans().copy(fontSize = xs.sp),
    )
}

/** Passwords, codes and keys: always the monospace face, never mirrored. */
val monoStyle = TextStyle(fontFamily = MonoFamily, fontSize = Tokens.TypeScale.lg.sp, letterSpacing = 0.02.em)

private val shapes = Shapes(
    extraSmall = RoundedCornerShape(Tokens.Radius.sm.dp / 2),
    small = RoundedCornerShape(Tokens.Radius.sm.dp),
    medium = RoundedCornerShape(Tokens.Radius.base.dp),
    large = RoundedCornerShape(Tokens.Radius.lg.dp),
    extraLarge = RoundedCornerShape(Tokens.Radius.xl.dp),
)

val LocalBrand = staticCompositionLocalOf { lightBrand }

object Brand {
    val colors: BrandColors
        @Composable get() = LocalBrand.current
}

@Composable
fun isDark(theme: ThemePreference): Boolean = when (theme) {
    ThemePreference.LIGHT -> false
    ThemePreference.DARK -> true
    ThemePreference.SYSTEM -> isSystemInDarkTheme()
}

@Composable
fun OctaPassTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    CompositionLocalProvider(LocalBrand provides if (dark) darkBrand else lightBrand) {
        MaterialTheme(colorScheme = scheme(dark), typography = typography, shapes = shapes, content = content)
    }
}
