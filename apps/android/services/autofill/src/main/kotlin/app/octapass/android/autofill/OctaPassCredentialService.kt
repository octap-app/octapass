package app.octap.android.autofill

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.Action
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePasswordCredentialRequest
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import app.octap.android.vault.Container
import app.octap.android.vault.CredentialIdentities
import app.octap.android.vault.CredentialIdentity
import app.octap.android.vault.Secrets
import org.json.JSONObject
import java.net.IDN
import java.net.URI

/**
 * Octa Pass in Credential Manager (Android 14+), for passwords and passkeys (plan 05). Before
 * the vault is unlocked the sheet lists what the app registered after its last sync
 * ([CredentialIdentities]): logins saved for this app, or for this site, a domain above it or a
 * host below it, and passkeys for the relying party. Logins for other parts of the site's domain
 * aren't listed: one quiet action, "Logins for other parts of example.com", opens
 * [CredentialActivity] to pick one. Picking anything opens [CredentialActivity], which unlocks,
 * checks the caller and answers; saving offers the signed-in account.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class OctaPassCredentialService : CredentialProviderService() {
    private val browsers by lazy { PrivilegedBrowsers(this) }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        val identities = if (signedIn()) CredentialIdentities.load(Secrets(this)) else emptyList()
        val caller = request.callingAppInfo
        val entries = mutableListOf<CredentialEntry>()
        val actions = mutableListOf<Action>()
        request.beginGetCredentialOptions.forEachIndexed { index, option ->
            when (option) {
                is BeginGetPasswordOption -> {
                    val page = caller?.let { callerUrl(it) } ?: return@forEachIndexed
                    val passwords = identities.filterIsInstance<CredentialIdentity.Password>()
                    passwords.filter { suggested(it.url, page) }.forEach {
                        entries += PasswordCredentialEntry.Builder(this, it.user.ifEmpty { it.url }, entryIntent(index, it.itemId, null), option).build()
                    }
                    // Never an entry of their own: picked from a list, after unlocking.
                    val site = passwords.firstNotNullOfOrNull { otherPart(it.url, page) }
                    if (site != null && actions.isEmpty()) {
                        actions += Action.Builder(getString(R.string.octapass_other_parts, site), otherPartsIntent()).build()
                    }
                }
                is BeginGetPublicKeyCredentialOption -> {
                    val (named, allowed) = passkeyRequest(option.requestJson)
                    // Without an rpId, a page's passkeys are for its own host.
                    val rpId = named ?: caller?.let { callerUrl(it) }?.let { runCatching { URI(it).host }.getOrNull() } ?: return@forEachIndexed
                    identities.filterIsInstance<CredentialIdentity.Passkey>()
                        .filter { it.rpId.equals(rpId, ignoreCase = true) && (allowed.isEmpty() || it.credentialId in allowed) }
                        .forEach {
                            entries += PublicKeyCredentialEntry.Builder(this, it.userName, entryIntent(index, it.itemId, it.credentialId), option).build()
                        }
                }
            }
        }
        callback.onResult(BeginGetCredentialResponse(credentialEntries = entries, actions = actions))
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        val account = Container.currentAccount(Container.directory(this))
        val supported = request is BeginCreatePasswordCredentialRequest || request is BeginCreatePublicKeyCredentialRequest
        if (account == null || !supported) return callback.onResult(BeginCreateCredentialResponse())
        val intent = Intent(this, CredentialActivity::class.java).setAction(CredentialActivity.ACTION_CREATE)
        val pending = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
        callback.onResult(BeginCreateCredentialResponse(createEntries = listOf(CreateEntry.Builder(account.email, pending).build())))
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        // Nothing is kept per sign-in session.
        callback.onResult(null)
    }

    private fun signedIn() = Container.currentAccount(Container.directory(this)) != null

    /** What the caller's logins are saved under: its web origin when a privileged browser asks. */
    private fun callerUrl(caller: CallingAppInfo): String? =
        if (caller.isOriginPopulated()) caller.getOrigin(browsers.json) else "androidapp://${caller.packageName}"

    private fun entryIntent(option: Int, itemId: String, credentialId: String?): PendingIntent {
        val intent = Intent(this, CredentialActivity::class.java)
            .setAction(CredentialActivity.ACTION_GET)
            .putExtra(CredentialActivity.EXTRA_OPTION, option)
            .putExtra(CredentialActivity.EXTRA_ITEM, itemId)
            .putExtra(CredentialActivity.EXTRA_CREDENTIAL, credentialId)
        // One per entry; mutable because the system adds the request to it.
        return PendingIntent.getActivity(this, (itemId + credentialId).hashCode(), intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
    }

    /** The list of logins for other parts of the site; the system adds the request to it. */
    private fun otherPartsIntent(): PendingIntent {
        val intent = Intent(this, CredentialActivity::class.java).setAction(CredentialActivity.ACTION_OTHER_PARTS)
        return PendingIntent.getActivity(this, CredentialActivity.ACTION_OTHER_PARTS.hashCode(), intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
    }

    companion object {
        /**
         * What the default match rule suggests, on the cached list: exact apps; for web origins
         * the same host, a domain above it or a host below it, ignoring a leading `www.`. A login
         * saved with another rule may be listed and then refused: the core's matcher decides after
         * unlock.
         */
        internal fun suggested(saved: String, page: String): Boolean {
            if (saved.startsWith(ANDROID_APP) || page.startsWith(ANDROID_APP)) return saved.equals(page, ignoreCase = true)
            val savedHost = host(saved) ?: return false
            val pageHost = host(page) ?: return false
            return savedHost == pageHost || pageHost.endsWith(".$savedHost") || savedHost.endsWith(".$pageHost")
        }

        /**
         * The domain, as shown, that a login saved for another part of it shares with the page
         * (`example.com` for `shop.example.com` on `login.example.com`), or null. Only to decide
         * whether to show the "other parts" action before unlocking, so it guesses the
         * registrable domain without the public suffix list (two labels, three under a
         * second-level suffix like `co.uk`); the core's `otherLogins` decides what's listed.
         */
        internal fun otherPart(saved: String, page: String): String? {
            if (saved.startsWith(ANDROID_APP) || page.startsWith(ANDROID_APP) || suggested(saved, page)) return null
            val savedHost = host(saved) ?: return null
            val pageHost = host(page) ?: return null
            if (isAddress(savedHost) || isAddress(pageHost)) return null
            val shared = savedHost.split('.').asReversed().zip(pageHost.split('.').asReversed()).takeWhile { (a, b) -> a == b }.map { it.first }
            val labels = if (shared.size >= 2 && shared[0].length == 2 && shared[1] in SECOND_LEVEL) 3 else 2
            if (shared.size < labels) return null
            val site = shared.take(labels).asReversed().joinToString(".")
            return runCatching { IDN.toUnicode(site) }.getOrDefault(site)
        }

        private const val ANDROID_APP = "androidapp://"

        /** Common second-level suffixes under country domains (`co.uk`, `com.au`, `ne.jp`). */
        private val SECOND_LEVEL = setOf("ac", "co", "com", "edu", "gen", "go", "gob", "gov", "ltd", "mil", "ne", "net", "nic", "nom", "or", "org", "plc", "sch")

        private fun host(url: String): String? =
            runCatching { URI(url).host }.getOrNull()?.lowercase()?.trimEnd('.')?.removePrefix("www.")?.ifEmpty { null }

        private fun isAddress(host: String) = host.contains(':') || host.startsWith('[') || host.all { it.isDigit() || it == '.' }

        /** The `rpId` and allowed credential ids (base64url) of a passkey request. */
        internal fun passkeyRequest(json: String): Pair<String?, Set<String>> {
            val options = runCatching { JSONObject(json) }.getOrNull() ?: return null to emptySet()
            val allowed = options.optJSONArray("allowCredentials")
            val ids = (0 until (allowed?.length() ?: 0)).mapNotNull { allowed?.optJSONObject(it)?.optString("id")?.trimEnd('=') }.toSet()
            return options.optString("rpId").ifEmpty { null } to ids
        }
    }
}
