package app.octap.android.autofill

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.autofill.Dataset
import android.service.autofill.InlinePresentation
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.RemoteViews
import androidx.annotation.RequiresApi
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi

/**
 * How a suggestion looks: a row in the dropdown, and a chip in the keyboard's suggestion strip
 * (inline suggestions, Android 11+) when the keyboard asked for them.
 */
class Presentations(private val context: Context, private val inline: InlineSuggestionsRequest?) {
    private var used = 0

    fun menu(title: String, subtitle: String?): RemoteViews =
        RemoteViews(context.packageName, R.layout.octapass_suggestion).apply {
            setTextViewText(R.id.octapass_title, title)
            setTextViewText(R.id.octapass_subtitle, subtitle.orEmpty())
        }

    /** A dataset with one presentation for all of [values]' fields (a null value: filled after authentication). */
    @SuppressLint("NewApi")
    @Suppress("DEPRECATION")
    fun dataset(title: String, subtitle: String?, values: Map<AutofillId, AutofillValue?>): Dataset.Builder {
        val menu = menu(title, subtitle)
        val chip = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) inline(title, subtitle) else null
        val builder = Dataset.Builder(menu)
        for ((id, value) in values) {
            if (chip != null) builder.setValue(id, value, menu, chip) else builder.setValue(id, value, menu)
        }
        return builder
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun inline(title: String, subtitle: String?): InlinePresentation? {
        val request = inline ?: return null
        val specs = request.inlinePresentationSpecs
        if (used >= request.maxSuggestionCount || specs.isEmpty()) return null
        val spec = specs[minOf(used, specs.size - 1)]
        if (UiVersions.INLINE_UI_VERSION_1 !in UiVersions.getVersions(spec.style)) return null
        used++
        // Long-pressing a chip opens the app.
        val attribution = PendingIntent.getActivity(
            context,
            0,
            context.packageManager.getLaunchIntentForPackage(context.packageName) ?: Intent(),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val content = InlineSuggestionUi.newContentBuilder(attribution)
            .setTitle(title)
            .setStartIcon(Icon.createWithResource(context, R.drawable.octapass_icon))
            .apply { if (!subtitle.isNullOrEmpty()) setSubtitle(subtitle) }
            .build()
        return InlinePresentation(content.slice, spec, false)
    }
}
