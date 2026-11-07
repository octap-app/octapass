package app.octap.android.autofill

import android.content.Intent
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePasswordResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPasswordOption
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import app.octap.android.vault.AutofillVault
import app.octap.core.passkeyAssertionRequestFromJson
import app.octap.core.passkeyCreationRequestFromJson
import java.util.Base64

/**
 * Answers a Credential Manager request once the vault is unlocked: the chosen password or
 * passkey sign-in, a login picked from the other parts of the site's domain (then it offers to add
 * the site to that login), or saving a password or a new passkey. A new passkey is saved to the
 * store before the app gets it, and the app uploads it on its next sync.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CredentialActivity : UnlockingActivity() {
    private val verifier by lazy { CallerVerifier(PrivilegedBrowsers(this)) }

    override fun onUnlocked(vault: AutofillVault) {
        when (intent.action) {
            ACTION_CREATE -> create(vault)
            ACTION_OTHER_PARTS -> otherParts(vault)
            else -> get(vault)
        }
    }

    override fun onCancelled() {
        val result = Intent()
        if (intent.action == ACTION_CREATE) {
            PendingIntentHandler.setCreateCredentialException(result, CreateCredentialCancellationException())
        } else {
            PendingIntentHandler.setGetCredentialException(result, GetCredentialCancellationException())
        }
        setResult(RESULT_OK, result)
        finish()
    }

    private fun get(vault: AutofillVault) {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return onCancelled()
        val option = request.credentialOptions.getOrNull(intent.getIntExtra(EXTRA_OPTION, 0))
        val itemId = intent.getStringExtra(EXTRA_ITEM) ?: return onCancelled()
        background({
            when (option) {
                is GetPasswordOption -> {
                    val url = callerUrl(request.callingAppInfo)
                    // The list came from the cache; the core's matcher decides.
                    if (vault.logins(listOf(url)).none { it.itemId == itemId }) throw NoCredentialException()
                    val (user, password) = vault.credentials(itemId)
                    PasswordCredential(user, password)
                }
                is GetPublicKeyCredentialOption -> {
                    val credentialId = Base64.getUrlDecoder().decode(intent.getStringExtra(EXTRA_CREDENTIAL) ?: throw NoCredentialException())
                    val asked = passkeyAssertionRequestFromJson(option.requestJson)
                    val caller = verifier.verify(request.callingAppInfo, asked.rpId, "webauthn.get", asked.challenge, option.clientDataHash)
                    PublicKeyCredential(vault.assertion(asked.copy(rpId = caller.rpId), caller.client, credentialId).responseJson)
                }
                else -> throw NoCredentialException()
            }
        }) { result ->
            val reply = Intent()
            result.fold(
                { PendingIntentHandler.setGetCredentialResponse(reply, GetCredentialResponse(it)) },
                { PendingIntentHandler.setGetCredentialException(reply, it as? NoCredentialException ?: GetCredentialUnknownException(it.message)) },
            )
            setResult(RESULT_OK, reply)
            finish()
        }
    }

    /**
     * From "Logins for other parts of example.com": the user picks one of them, which signs in.
     * The list before unlocking only guessed the domain, so with nothing there after all this
     * lists what the core matches, if anything.
     */
    private fun otherParts(vault: AutofillVault) {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return onCancelled()
        if (request.credentialOptions.none { it is GetPasswordOption }) return onCancelled()
        background({
            val url = callerUrl(request.callingAppInfo)
            Triple(url, vault.otherLogins(url), vault.logins(listOf(url)))
        }) { result ->
            val (url, others, matches) = result.getOrElse { return@background answer(Result.failure(it)) }
            when {
                others.isNotEmpty() -> otherPartsRow(others) { other ->
                    signIn(vault, other.login.itemId) { reply -> offerWebsite(vault, other, url) { finishWith(reply) } }
                }.pick()
                matches.isNotEmpty() -> choose(getString(R.string.octapass_pick_login), matches.map { login -> Row(loginRow(login)) { signIn(vault, login.itemId, ::finishWith) } })
                else -> answer(Result.failure(NoCredentialException()))
            }
        }
    }

    /** The password sign-in for [itemId]; [then] gets the reply when it worked, otherwise it's sent. */
    private fun signIn(vault: AutofillVault, itemId: String, then: (Intent) -> Unit) {
        background({ vault.credentials(itemId).let { (user, password) -> PasswordCredential(user, password) } }) { result ->
            val reply = reply(result)
            if (result.isSuccess) then(reply) else finishWith(reply)
        }
    }

    private fun answer(result: Result<PasswordCredential>) = finishWith(reply(result))

    private fun reply(result: Result<PasswordCredential>): Intent = Intent().also { reply ->
        result.fold(
            { PendingIntentHandler.setGetCredentialResponse(reply, GetCredentialResponse(it)) },
            { PendingIntentHandler.setGetCredentialException(reply, it as? NoCredentialException ?: GetCredentialUnknownException(it.message)) },
        )
    }

    private fun finishWith(reply: Intent) {
        setResult(RESULT_OK, reply)
        finish()
    }

    private fun create(vault: AutofillVault) {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: return onCancelled()
        background({
            when (val asked = request.callingRequest) {
                is CreatePasswordRequest -> {
                    val url = callerUrl(request.callingAppInfo)
                    val title = if (url.startsWith("androidapp://")) AppNames.label(this, request.callingAppInfo.packageName) else null
                    vault.saveLogin(url, asked.id, asked.password, title)
                    CreatePasswordResponse()
                }
                is CreatePublicKeyCredentialRequest -> {
                    val creation = passkeyCreationRequestFromJson(asked.requestJson)
                    val caller = verifier.verify(request.callingAppInfo, creation.rpId, "webauthn.create", creation.challenge, asked.clientDataHash)
                    CreatePublicKeyCredentialResponse(vault.register(creation.copy(rpId = caller.rpId), caller.client).responseJson)
                }
                else -> throw CreateCredentialUnknownException("unsupported request")
            }
        }) { result ->
            val reply = Intent()
            result.fold(
                { PendingIntentHandler.setCreateCredentialResponse(reply, it) },
                { PendingIntentHandler.setCreateCredentialException(reply, CreateCredentialUnknownException(it.message)) },
            )
            setResult(RESULT_OK, reply)
            finish()
        }
    }

    /** Logins are saved under a page's origin, or the app's `androidapp://` identity. */
    private fun callerUrl(caller: CallingAppInfo): String =
        if (caller.isOriginPopulated()) {
            caller.getOrigin(PrivilegedBrowsers(this).json) ?: throw CallerException("${caller.packageName} isn't a browser Octa Pass trusts")
        } else {
            "androidapp://${caller.packageName}"
        }

    companion object {
        const val ACTION_GET = "app.octap.android.autofill.GET"
        const val ACTION_CREATE = "app.octap.android.autofill.CREATE"
        const val ACTION_OTHER_PARTS = "app.octap.android.autofill.OTHER_PARTS"
        const val EXTRA_OPTION = "option"
        const val EXTRA_ITEM = "item"
        const val EXTRA_CREDENTIAL = "credential"
    }
}
