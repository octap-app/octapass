package app.octap.android.vault

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * The folder the app and its services share, and the account list the app writes there
 * (`accounts.json`, see `crates/octapass-mobile-vault/src/accounts.rs`). It's in the app's private
 * storage, outside backups: the services run in the app's own process.
 */
object Container {
    fun directory(context: Context): File = File(context.noBackupFilesDir, "vault")

    data class Account(
        val tag: String,
        val email: String,
        val serverUrl: String,
        /** Base64url, when this is a vault on this device only that's bound to the Keystore. */
        val chipContext: String? = null,
    ) {
        val storeFile get() = "$tag.opstore"
        val secretKeyName get() = "secretKey.$tag"
        val deviceSecretName get() = "deviceSecret.$tag"
        val chipKeyName get() = "chipKey.$tag"

        /** As `Account::stay_unlocked_name` names it: the key in [StayUnlockedKeys] (plan 18). */
        val stayUnlockedName get() = "stayUnlocked.$tag"
    }

    /** The account the app has open (locked or not), or null when nobody is signed in. */
    fun currentAccount(directory: File): Account? {
        val file = File(directory, "accounts.json")
        if (!file.isFile) return null
        val json = runCatching { JSONObject(file.readText()) }.getOrNull() ?: return null
        val current = json.optString("current").takeIf { it.isNotEmpty() } ?: return null
        val accounts = json.optJSONArray("accounts") ?: return null
        return (0 until accounts.length())
            .map { accounts.getJSONObject(it) }
            .firstOrNull { it.optString("tag") == current }
            ?.let {
                val chip = it.optJSONObject("local")?.optString("chipContext")?.takeIf(String::isNotEmpty)
                Account(it.getString("tag"), it.getString("email"), it.getString("serverUrl"), chip)
            }
    }
}
