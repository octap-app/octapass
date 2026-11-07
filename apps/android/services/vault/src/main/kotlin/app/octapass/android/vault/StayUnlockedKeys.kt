package app.octap.android.vault

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.util.Base64
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Stay unlocked while you're logged in to this phone (plan 18): the opaque key the vault hands
 * over (`storeStayUnlockedKey`), which opens the account with no prompt. It's sealed with
 * AES-GCM under its own Keystore key, in StrongBox when the phone has it, made with
 * `setUnlockedDeviceRequired(true)` and no user-authentication requirement: nothing asks for it,
 * and the Keystore refuses it while the phone is locked. The app and the Autofill and Credential
 * Manager services read it from here (they run in the app's process), by the vault's name for it:
 * `stayUnlocked.<account tag>` ([Container.Account.stayUnlockedName]).
 *
 * It needs a secure lock screen: without one [store] fails as `unsupported` and [get] returns
 * nothing, so the phone falls back to locking as before. Android 9 (API 28, the app's minimum) has
 * `setUnlockedDeviceRequired`, so there's no older path.
 */
class StayUnlockedKeys(private val context: Context) {
    private val prefs = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /** The phone has a PIN, pattern or password (a fingerprint or face needs one too). */
    val available: Boolean
        get() = context.getSystemService(KeyguardManager::class.java).isDeviceSecure

    /** Replaces the key called [name]; fails as `unsupported` without a secure lock screen. */
    fun store(name: String, key: ByteArray) {
        if (!available) throw DeviceUnlockException.unsupported("no screen lock is set")
        val sealed = try {
            Secrets.seal(newKey(alias(name)), name, key)
        } catch (error: GeneralSecurityException) {
            throw DeviceUnlockException.unsupported("the Keystore couldn't keep the key", error)
        } catch (error: IllegalStateException) {
            throw DeviceUnlockException.unsupported("no screen lock is set", error)
        }
        check(prefs.edit().putString(name, Base64.getEncoder().encodeToString(sealed)).commit()) {
            "couldn't save the stay-unlocked key"
        }
    }

    /**
     * The key, with no prompt, or null: none was kept, the phone has no screen lock any more, it's
     * locked right now, or the Keystore dropped the key (then it's deleted).
     */
    fun get(name: String): ByteArray? {
        val sealed = prefs.getString(name, null) ?: return null
        if (!available) return null
        val key = keystore().getKey(alias(name), null) as? SecretKey
        if (key == null) {
            delete(name)
            return null
        }
        return try {
            Secrets.open(key, name, Base64.getDecoder().decode(sealed))
        } catch (error: KeyPermanentlyInvalidatedException) {
            delete(name)
            null
        } catch (error: GeneralSecurityException) {
            // Locked (the Keystore refuses an unlocked-device key), or a passing Keystore problem:
            // the unlock screen shows, and the key stays for next time.
            null
        } catch (error: IllegalArgumentException) {
            delete(name)
            null
        }
    }

    /** Succeeds when there was none. */
    fun delete(name: String) {
        runCatching { keystore().deleteEntry(alias(name)) }
        prefs.edit().remove(name).commit()
    }

    private fun newKey(alias: String): SecretKey {
        keystore().deleteEntry(alias)
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        return try {
            generate(alias, strongBox)
        } catch (error: StrongBoxUnavailableException) {
            generate(alias, strongBox = false)
        }
    }

    private fun generate(alias: String, strongBox: Boolean): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(spec(alias, strongBox))
        return generator.generateKey()
    }

    private fun keystore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    companion object {
        private const val FILE = "octapass.stay-unlocked"
        private const val KEYSTORE = "AndroidKeyStore"

        fun alias(name: String) = "octapass.stayUnlocked.$name"

        /** No user authentication: the phone being unlocked is the whole gate (plan 18). */
        internal fun spec(alias: String, strongBox: Boolean): KeyGenParameterSpec =
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUnlockedDeviceRequired(true)
                .setUserAuthenticationRequired(false)
                .setIsStrongBoxBacked(strongBox)
                .build()
    }
}
