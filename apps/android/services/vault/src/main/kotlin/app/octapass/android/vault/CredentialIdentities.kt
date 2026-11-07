package app.octap.android.vault

import org.json.JSONArray
import org.json.JSONObject

/**
 * What the system may suggest before the vault is unlocked, as the vault sends it after each sync
 * (`Session.credentialIdentities`): logins by URL and user name, passkeys by relying party. It's
 * the Android side of iOS's `ASCredentialIdentityStore`: kept in [Secrets], so it's encrypted at
 * rest, and only names and addresses, never a password or a key. Picking a suggestion still asks
 * for the device lock before anything is filled.
 */
sealed interface CredentialIdentity {
    val itemId: String

    data class Password(override val itemId: String, val url: String, val user: String) : CredentialIdentity

    /** `credentialId` and `userHandle` in base64url. */
    data class Passkey(
        override val itemId: String,
        val rpId: String,
        val userName: String,
        val credentialId: String,
        val userHandle: String,
    ) : CredentialIdentity
}

object CredentialIdentities {
    private const val NAME = "credentialIdentities"

    fun save(secrets: Secrets, identities: JSONArray) {
        if (identities.length() == 0) secrets.delete(NAME) else secrets.set(NAME, identities.toString())
    }

    fun load(secrets: Secrets): List<CredentialIdentity> =
        secrets.get(NAME)?.let { parse(JSONArray(it)) }.orEmpty()

    /** One-time codes are left out: Android fills them through the Autofill service. */
    fun parse(identities: JSONArray): List<CredentialIdentity> =
        (0 until identities.length()).mapNotNull { identity(identities.getJSONObject(it)) }

    private fun identity(json: JSONObject): CredentialIdentity? {
        val itemId = json.optString("itemId").ifEmpty { return null }
        return when (json.optString("kind")) {
            "password" -> CredentialIdentity.Password(itemId, json.optString("url").ifEmpty { return null }, json.optString("user"))
            "passkey" -> CredentialIdentity.Passkey(
                itemId,
                json.optString("rpId").ifEmpty { return null },
                json.optString("userName"),
                json.optString("credentialId").ifEmpty { return null },
                json.optString("userHandle"),
            )
            else -> null
        }
    }
}
