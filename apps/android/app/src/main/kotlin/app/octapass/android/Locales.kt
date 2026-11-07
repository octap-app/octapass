package app.octap.android

import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import app.octap.vault.LanguagePreference

/** The app's language (Settings → Language): the phone's, English or Arabic (right to left). */
object Locales {
    fun apply(language: LanguagePreference) {
        val tags = when (language) {
            LanguagePreference.SYSTEM -> ""
            LanguagePreference.EN -> "en"
            LanguagePreference.AR -> "ar"
        }
        val locales = LocaleListCompat.forLanguageTags(tags)
        if (AppCompatDelegate.getApplicationLocales() != locales) AppCompatDelegate.setApplicationLocales(locales)
    }
}
