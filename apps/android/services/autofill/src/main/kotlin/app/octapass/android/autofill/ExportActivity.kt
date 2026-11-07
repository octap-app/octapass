package app.octap.android.autofill

import android.app.Activity
import android.util.Log
import androidx.credentials.providerevents.IntentHandler
import androidx.credentials.providerevents.exception.ImportCredentialsCancellationException
import androidx.credentials.providerevents.exception.ImportCredentialsException
import androidx.credentials.providerevents.exception.ImportCredentialsNoExportOptionException
import androidx.credentials.providerevents.exception.ImportCredentialsUnknownErrorException
import androidx.credentials.providerevents.transfer.ImportCredentialsResponse
import androidx.credentials.providerevents.transfer.ProviderImportCredentialsRequest
import app.octap.android.vault.AutofillVault
import app.octap.android.vault.Secrets

/**
 * Another password manager on the phone imports from Octa Pass: Google Play services opens this
 * when the user picks Octa Pass in its list. Like every export (plan 07) it asks for the master
 * password, naming the app that gets the items, then hands them over as CXF with only the types
 * that app asked for.
 */
class ExportActivity : UnlockingActivity() {
    private var request: ProviderImportCredentialsRequest? = null
    private val destination by lazy { request?.let { AppNames.label(this, it.callingAppInfo.packageName) }.orEmpty() }

    override val passwordOnly = true
    override val passwordTitle = R.string.octapass_export_title
    override val passwordAction = R.string.octapass_export

    override fun passwordMessage(vault: AutofillVault): String =
        getString(R.string.octapass_export_message, destination, vault.account.email)

    /** Only Google Play services may ask, with the entry Octa Pass listed for this account. */
    override fun accepts(): Boolean {
        val asked = IntentHandler.retrieveProviderImportCredentialsRequest(intent)
        val refused = when {
            asked == null -> "no request"
            callingPackage != CredentialTransfer.PLAY_SERVICES -> "asked by $callingPackage"
            !CredentialTransfer.isCurrentEntry(this, Secrets(this), asked.credId) -> "not the signed-in account's entry"
            else -> null
        }
        if (refused != null) {
            Log.w(TAG, "export refused: $refused")
            reply(ImportCredentialsNoExportOptionException("not an export Octa Pass listed"))
            return false
        }
        request = asked
        return true
    }

    override fun onUnlocked(vault: AutofillVault) {
        val asked = request ?: return onCancelled()
        background({
            val export = vault.exportForApp(asked.request.credentialTypes)
            IntentHandler.setImportCredentialsResponse(this, asked.uri, intent, ImportCredentialsResponse(export.json))
        }) { result ->
            result.exceptionOrNull()?.let {
                Log.w(TAG, "export failed", it)
                return@background reply(ImportCredentialsUnknownErrorException("Octa Pass couldn't export"))
            }
            setResult(Activity.RESULT_OK, intent)
            finish()
        }
    }

    override fun onCancelled() = reply(ImportCredentialsCancellationException())

    /** A failure goes back with `RESULT_OK`, or the other app only hears "cancelled". */
    private fun reply(error: ImportCredentialsException) {
        IntentHandler.setImportCredentialsException(intent, error)
        setResult(Activity.RESULT_OK, intent)
        finish()
    }
}
