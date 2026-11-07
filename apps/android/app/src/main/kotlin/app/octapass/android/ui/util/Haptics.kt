package app.octap.android.ui.util

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.view.HapticFeedbackConstants
import app.octap.android.model.Toast

tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}

/** The tap that goes with a message: a confirm for success, a reject for an error, a light tick otherwise. */
fun haptic(context: Context, tone: Toast.Tone) {
    val view = context.findActivity()?.window?.decorView ?: return
    val constant = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && tone == Toast.Tone.Success -> HapticFeedbackConstants.CONFIRM
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && tone == Toast.Tone.Danger -> HapticFeedbackConstants.REJECT
        else -> HapticFeedbackConstants.CLOCK_TICK
    }
    view.performHapticFeedback(constant)
}
