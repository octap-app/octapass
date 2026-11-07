package app.octap.android.vault

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Values the app and its services read without a prompt while the phone is unlocked: the Secret
 * Key, the refresh token and the list of saved credentials the system may suggest. Each is
 * encrypted with AES-GCM under a Keystore key that never leaves the device's secure hardware, and
 * bound to its name; only the ciphertext is in the app's private storage, which is never backed
 * up (`allowBackup="false"`).
 */
class Secrets(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun get(name: String): String? {
        val sealed = prefs.getString(name, null) ?: return null
        return String(open(key(), name, Base64.getDecoder().decode(sealed)), Charsets.UTF_8)
    }

    fun set(name: String, value: String) {
        val sealed = seal(key(), name, value.toByteArray(Charsets.UTF_8))
        check(prefs.edit().putString(name, Base64.getEncoder().encodeToString(sealed)).commit()) {
            "couldn't save $name"
        }
    }

    fun delete(name: String) {
        prefs.edit().remove(name).commit()
    }

    private fun key(): SecretKey {
        val keystore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keystore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    companion object {
        private const val FILE = "octapass.secrets"
        private const val ALIAS = "octapass.secrets"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_SIZE = 12
        private const val TAG_BITS = 128

        /** `iv ‖ ciphertext ‖ tag`, with the name as associated data so values can't be swapped. */
        internal fun seal(key: SecretKey, name: String, plaintext: ByteArray): ByteArray {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
            return cipher.iv + cipher.doFinal(plaintext)
        }

        internal fun open(key: SecretKey, name: String, sealed: ByteArray): ByteArray {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, sealed, 0, IV_SIZE))
            cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
            return cipher.doFinal(sealed, IV_SIZE, sealed.size - IV_SIZE)
        }
    }
}
