package app.octap.android.vault

import android.content.Context
import android.content.pm.ApplicationInfo
import android.view.Window
import android.view.WindowManager

/**
 * Screens that show the vault or take the master password are `FLAG_SECURE` (plan 05): no
 * screenshots or screen recording, and a blank card in Recents. Debug builds leave it off so
 * tests can take screenshots.
 */
object SecureWindow {
    fun apply(window: Window?, context: Context) {
        val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (!debuggable) window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}
