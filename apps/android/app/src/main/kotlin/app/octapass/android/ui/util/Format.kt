package app.octap.android.ui.util

import android.text.format.DateUtils
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.platform.LocalConfiguration
import androidx.core.text.BidiFormatter
import java.text.DateFormat
import java.text.DecimalFormat
import java.text.DecimalFormatSymbols
import java.text.NumberFormat
import java.time.Instant
import java.util.Date
import java.util.Locale

/**
 * Dates, sizes and numbers as the web vault writes them (`i18n/core.ts`): in the shown language,
 * with Western digits in Arabic too.
 */
object Formats {
    /** The locale to format in: Arabic keeps Western digits, as on the web. */
    fun locale(shown: Locale): Locale =
        if (shown.language == "ar") Locale.Builder().setLocale(shown).setUnicodeLocaleKeyword("nu", "latn").build() else shown

    fun date(iso: String, shown: Locale, long: Boolean = false): String {
        val instant = parse(iso) ?: return iso
        return DateFormat.getDateInstance(if (long) DateFormat.LONG else DateFormat.MEDIUM, locale(shown)).format(Date.from(instant))
    }

    fun dateTime(iso: String, shown: Locale): String {
        val instant = parse(iso) ?: return iso
        return DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, locale(shown)).format(Date.from(instant))
    }

    /** "3 minutes ago", "in 2 days". */
    fun relative(iso: String, now: Long = System.currentTimeMillis()): String {
        val instant = parse(iso) ?: return iso
        return DateUtils.getRelativeTimeSpanString(instant.toEpochMilli(), now, DateUtils.MINUTE_IN_MILLIS).toString()
    }

    fun number(value: Long, shown: Locale): String = NumberFormat.getIntegerInstance(locale(shown)).format(value)

    private val UNITS = listOf("B", "KB", "MB", "GB", "TB")

    /** "820 B", "1.4 MB": binary multiples, as the web vault shows them. */
    fun bytes(bytes: Long, shown: Locale): String {
        var unit = 0
        var value = bytes.toDouble()
        while (value >= 1024 && unit < UNITS.size - 1) {
            value /= 1024
            unit++
        }
        val format = DecimalFormat(if (unit == 0 || value >= 10) "0" else "0.#", DecimalFormatSymbols.getInstance(locale(shown)))
        return "${format.format(value)} ${UNITS[unit]}"
    }

    fun parse(iso: String): Instant? = runCatching { Instant.parse(iso) }.getOrNull()

    /** Inserted text (a name, an email, a website) keeps its own direction inside a sentence. */
    fun isolate(text: String, shown: Locale): String = BidiFormatter.getInstance(shown).unicodeWrap(text)
}

@Composable
@ReadOnlyComposable
fun shownLocale(): Locale = LocalConfiguration.current.locales[0]

@Composable
@ReadOnlyComposable
fun formatDate(iso: String, long: Boolean = false): String = Formats.date(iso, shownLocale(), long)

@Composable
@ReadOnlyComposable
fun formatDateTime(iso: String): String = Formats.dateTime(iso, shownLocale())

@Composable
@ReadOnlyComposable
fun formatBytes(bytes: Long): String = Formats.bytes(bytes, shownLocale())

@Composable
@ReadOnlyComposable
fun isolate(text: String): String = Formats.isolate(text, shownLocale())
