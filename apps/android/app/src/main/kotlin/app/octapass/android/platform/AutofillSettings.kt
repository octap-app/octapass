package app.octap.android.platform

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.credentials.CredentialManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.view.autofill.AutofillManager

/**
 * Turning Octa Pass on as the Autofill service and, on Android 14+, as a Credential Manager
 * provider for passwords and passkeys (moved from the Tauri plugin, same behaviour).
 */
class AutofillSettings(private val context: Context) {
    /** Octa Pass is the Autofill service. */
    fun autofillEnabled(): Boolean = context.getSystemService(AutofillManager::class.java)?.hasEnabledAutofillServices() == true

    /** Octa Pass is on in Credential Manager; `null` before Android 14, which has none. */
    fun passkeysEnabled(): Boolean? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return null
        val manager = context.getSystemService(CredentialManager::class.java) ?: return false
        return manager.isEnabledCredentialProviderService(ComponentName(context.packageName, CREDENTIAL_SERVICE))
    }

    /** Asks to make Octa Pass the Autofill service; the result is `RESULT_OK` when it is. */
    fun requestAutofill(): Intent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(Uri.parse("package:${context.packageName}"))

    /** The Credential Manager provider list (Android 14+), else the Autofill choice. */
    fun passkeySettings(): Intent =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            Intent(Settings.ACTION_CREDENTIAL_PROVIDER).setData(Uri.parse("package:${context.packageName}"))
        } else {
            requestAutofill()
        }

    companion object {
        const val CREDENTIAL_SERVICE = "app.octap.android.autofill.OctaPassCredentialService"
    }
}
