package app.octap.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import app.octap.android.ui.theme.Brand
import app.octap.resources.R
import app.octap.vault.StrengthEstimate
import app.octap.vault.StrengthFeedback

fun strengthLabelRes(score: Int): Int = when (score) {
    0 -> R.string.strength_score_0
    1 -> R.string.strength_score_1
    2 -> R.string.strength_score_2
    3 -> R.string.strength_score_3
    else -> R.string.strength_score_4
}

fun feedbackRes(feedback: StrengthFeedback): Int = when (feedback) {
    StrengthFeedback.TOO_SHORT -> R.string.strength_feedback_tooShort
    StrengthFeedback.COMMON_PASSWORD -> R.string.strength_feedback_commonPassword
    StrengthFeedback.DICTIONARY_WORD -> R.string.strength_feedback_dictionaryWord
    StrengthFeedback.SEQUENCE -> R.string.strength_feedback_sequence
    StrengthFeedback.REPEAT -> R.string.strength_feedback_repeat
    StrengthFeedback.KEYBOARD_PATTERN -> R.string.strength_feedback_keyboardPattern
    StrengthFeedback.DATE -> R.string.strength_feedback_date
    StrengthFeedback.ADD_MORE_WORDS -> R.string.strength_feedback_addMoreWords
    StrengthFeedback.ADD_VARIETY -> R.string.strength_feedback_addVariety
}

@Composable
fun strengthColor(score: Int): Color = when (score) {
    0, 1 -> Brand.colors.danger
    2 -> Brand.colors.warn
    else -> Brand.colors.free
}

/** The meter plus one tip from the estimator (`StrengthHint`). */
@Composable
fun StrengthHint(estimate: StrengthEstimate, empty: Boolean, modifier: Modifier = Modifier) {
    val score = estimate.score.toInt()
    val label = stringResource(if (empty) R.string.strength_empty else strengthLabelRes(score))
    val hint = when {
        empty -> null
        estimate.feedback != null -> stringResource(feedbackRes(estimate.feedback!!))
        score >= 4 -> stringResource(R.string.strength_great)
        else -> null
    }
    Column(modifier.fillMaxWidth().padding(top = 8.dp, start = 4.dp, end = 4.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            for (i in 0 until 4) {
                val on = !empty && i < maxOf(1, score)
                Spacer(
                    Modifier
                        .weight(1f)
                        .height(4.dp)
                        .clip(CircleShape)
                        .background(if (on) strengthColor(score) else MaterialTheme.colorScheme.outlineVariant),
                )
            }
        }
        Text(
            buildAnnotatedString {
                withStyle(SpanStyle(fontWeight = FontWeight.SemiBold)) { append(label) }
                if (hint != null) append(" $hint")
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
    }
}
