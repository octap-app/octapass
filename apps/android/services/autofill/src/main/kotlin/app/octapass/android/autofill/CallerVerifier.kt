package app.octap.android.autofill

import android.content.pm.SigningInfo
import androidx.credentials.provider.CallingAppInfo
import app.octap.core.ClientData
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import java.util.Base64
import javax.net.ssl.HttpsURLConnection

class CallerException(message: String) : Exception(message)

/** Who asked for a passkey, checked: the relying party and how `clientDataJSON` is built. */
data class VerifiedCaller(val rpId: String, val client: ClientData)

/**
 * Checks who's asking before a passkey is created or used (plan 14, K's `ClientData` modes):
 *
 * - A privileged browser ([PrivilegedBrowsers], signature checked by Credential Manager) names
 *   the page's origin; the `rpId` must be that host or a parent domain of it. Its
 *   `clientDataHash` is signed, or the core writes `clientDataJSON` for the origin.
 * - Any other app must be listed for the `rpId` in the site's Digital Asset Links
 *   (`https://<rpId>/.well-known/assetlinks.json`, matching package and signing certificate).
 *   Then this provider writes `clientDataJSON` with the app's `android:apk-key-hash:` origin.
 *
 * Fetching the asset links file is the only network call the services make.
 */
class CallerVerifier(
    private val browsers: PrivilegedBrowsers,
    private val fetch: (URL) -> String = ::download,
) {
    fun verify(caller: CallingAppInfo, rpId: String?, type: String, challenge: ByteArray, clientDataHash: ByteArray?): VerifiedCaller {
        if (caller.isOriginPopulated()) {
            val origin = caller.getOrigin(browsers.json) ?: throw CallerException("${caller.packageName} isn't a browser Octa Pass trusts")
            val party = rpId ?: URI(origin).host ?: throw CallerException("no relying party")
            if (!Origins.rpIdMatches(party, origin)) throw CallerException("$party can't be used on $origin")
            return VerifiedCaller(party, clientDataHash?.let { ClientData.Hash(it) } ?: ClientData.Web(origin, null, false))
        }
        val party = rpId ?: throw CallerException("no relying party")
        val certificates = certificates(caller.signingInfo)
        if (certificates.isEmpty()) throw CallerException("${caller.packageName} isn't signed")
        val links = try {
            fetch(URL("https://$party/.well-known/assetlinks.json"))
        } catch (error: Exception) {
            throw CallerException("couldn't check $party's Digital Asset Links")
        }
        if (!AssetLinks.allows(links, caller.packageName, certificates.map { PrivilegedBrowsers.fingerprint(it) })) {
            throw CallerException("$party doesn't allow ${caller.packageName} to use its passkeys")
        }
        val client = clientDataHash?.let { ClientData.Hash(it) }
            ?: ClientData.Json(ClientDataJson.build(type, challenge, Origins.app(certificates.first()), caller.packageName))
        return VerifiedCaller(party, client)
    }

    private fun certificates(info: SigningInfo): List<ByteArray> {
        val signers = if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory
        return signers.orEmpty().map { it.toByteArray() }
    }

    companion object {
        private const val MAX_CHARS = 256 * 1024

        /** The file as served: HTTPS, no redirects (as Android's own verification). */
        fun download(url: URL): String {
            val connection = url.openConnection() as HttpsURLConnection
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.useCaches = false
            try {
                if (connection.responseCode != HttpURLConnection.HTTP_OK) throw CallerException("${url.host} answered ${connection.responseCode}")
                val text = connection.inputStream.bufferedReader().use { reader ->
                    val buffer = CharArray(MAX_CHARS + 1)
                    var read = 0
                    while (read <= MAX_CHARS) {
                        val count = reader.read(buffer, read, buffer.size - read)
                        if (count < 0) break
                        read += count
                    }
                    if (read > MAX_CHARS) throw CallerException("${url.host}'s asset links are too large")
                    String(buffer, 0, read)
                }
                return text
            } finally {
                connection.disconnect()
            }
        }
    }
}

object Origins {
    /** An app's WebAuthn origin: its signing certificate's SHA-256, base64url. */
    fun app(certificate: ByteArray): String =
        "android:apk-key-hash:" + Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate))

    /** WebAuthn's rule: the rpId is the origin's host or a domain it's under, over HTTPS. */
    fun rpIdMatches(rpId: String, origin: String): Boolean {
        val uri = runCatching { URI(origin) }.getOrNull() ?: return false
        val host = uri.host?.lowercase() ?: return false
        val party = rpId.lowercase().trimEnd('.')
        val secure = uri.scheme == "https" || (uri.scheme == "http" && host == "localhost")
        return secure && party.isNotEmpty() && (host == party || host.endsWith(".$party"))
    }
}

object AssetLinks {
    private val RELATIONS = setOf("delegate_permission/common.get_login_creds", "delegate_permission/common.handle_all_urls")

    /** The statements list [packageName] signed with one of [fingerprints] (`AB:CD:…`) for sign-in. */
    fun allows(json: String, packageName: String, fingerprints: List<String>): Boolean {
        val statements = runCatching { JSONArray(json) }.getOrNull() ?: return false
        val wanted = fingerprints.map { it.uppercase() }.toSet()
        return (0 until statements.length()).mapNotNull { statements.optJSONObject(it) }.any { statement ->
            val relations = statement.optJSONArray("relation")?.strings().orEmpty()
            val target = statement.optJSONObject("target") ?: return@any false
            relations.any { it in RELATIONS } &&
                target.optString("namespace") == "android_app" &&
                target.optString("package_name") == packageName &&
                target.optJSONArray("sha256_cert_fingerprints")?.strings().orEmpty().any { it.uppercase() in wanted }
        }
    }

    private fun JSONArray.strings() = (0 until length()).map { optString(it) }
}

object ClientDataJson {
    /** `clientDataJSON` for an app's request, as Android's own provider writes it. */
    fun build(type: String, challenge: ByteArray, origin: String, packageName: String): String =
        JSONObject()
            .put("type", type)
            .put("challenge", Base64.getUrlEncoder().withoutPadding().encodeToString(challenge))
            .put("origin", origin)
            .put("androidPackageName", packageName)
            .toString()
}
