package app.octap.android.platform

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Copies and clears 30 seconds later, as the web vault does (`lib/clipboard.ts`). Secrets are
 * marked sensitive, so Android 13+ hides them in its clipboard preview and keyboards don't keep
 * them. Locking clears at once.
 */
class Clipboard(context: Context) {
    private val manager = context.getSystemService(ClipboardManager::class.java)
    private val main = Handler(Looper.getMainLooper())
    private val clear = Runnable { clearNow() }

    @Volatile
    private var holding = false

    fun copy(label: String, value: String, secret: Boolean) {
        val clip = ClipData.newPlainText(label, value)
        if (secret) {
            clip.description.extras = PersistableBundle().apply {
                val key = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE"
                putBoolean(key, true)
            }
        }
        manager.setPrimaryClip(clip)
        main.removeCallbacks(clear)
        holding = secret
        if (secret) main.postDelayed(clear, CLEAR_AFTER_MS)
    }

    /** Clears what Octa Pass copied, if it's still a secret it put there. */
    fun clearNow() {
        main.removeCallbacks(clear)
        if (!holding) return
        holding = false
        try {
            manager.clearPrimaryClip()
        } catch (error: SecurityException) {
            // Another app owns the clipboard now.
        }
    }

    /** Android 13+ shows its own "Copied" confirmation, so the app's toast would be a second one. */
    val systemConfirms: Boolean get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU

    companion object {
        const val CLEAR_AFTER_MS = 30_000L
    }
}
