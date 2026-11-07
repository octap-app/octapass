package app.octap.android.autofill

import android.content.Context
import android.content.pm.PackageManager
import org.json.JSONObject
import java.security.MessageDigest

/**
 * The browsers whose word on a page's origin counts: Google's list of privileged apps for
 * Credential Manager (`res/raw/privileged_browsers.json`, from
 * https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json), each with its signing
 * certificates. The Autofill service fills by web domain only in these, and Credential Manager
 * hands their origins to [CallerVerifier].
 */
class PrivilegedBrowsers(context: Context) {
    val json: String = context.resources.openRawResource(R.raw.privileged_browsers).bufferedReader().use { it.readText() }
    private val certificates = parse(json)

    /** [packageName] is on the list and signed with one of its certificates. */
    fun isTrusted(packageManager: PackageManager, packageName: String): Boolean {
        val allowed = certificates[packageName] ?: return false
        return signingFingerprints(packageManager, packageName).any { it in allowed }
    }

    companion object {
        /** Package name → SHA-256 certificate fingerprints (`AB:CD:…`). */
        fun parse(json: String): Map<String, Set<String>> {
            val apps = JSONObject(json).getJSONArray("apps")
            return (0 until apps.length()).map { apps.getJSONObject(it) }
                .filter { it.optString("type") == "android" }
                .associate { app ->
                    val info = app.getJSONObject("info")
                    val signatures = info.getJSONArray("signatures")
                    info.getString("package_name") to (0 until signatures.length())
                        .map { signatures.getJSONObject(it).getString("cert_fingerprint_sha256").uppercase() }
                        .toSet()
                }
        }

        fun fingerprint(certificate: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(certificate).joinToString(":") { "%02X".format(it) }

        fun signingFingerprints(packageManager: PackageManager, packageName: String): List<String> {
            val info = try {
                packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
            } catch (error: PackageManager.NameNotFoundException) {
                null
            } ?: return emptyList()
            val signers = if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory
            return signers.orEmpty().map { fingerprint(it.toByteArray()) }
        }
    }
}
