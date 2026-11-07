package app.octap.android.vault

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * The device chip's part of a local vault's key (plan 03, *Local mode keys*): a Keystore HMAC key
 * that never leaves the secure hardware, in StrongBox when the phone has it. It works with no
 * prompt, because it's useless without the master password. The `context` kept next to the vault
 * is random: what the key makes of it is the secret, hashed as the desktop app hashes its own.
 */
class ChipSecrets(private val context: Context) {
    val available: Boolean
        get() = runCatching { KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE) }.isSuccess

    /** A new key and what it makes of a new context, or null where the Keystore won't make one. */
    fun create(name: String): Pair<ByteArray, ByteArray>? {
        try {
            generate(alias(name))
        } catch (error: GeneralSecurityException) {
            return null
        }
        val chipContext = ByteArray(32).also { SecureRandom().nextBytes(it) }
        return chipContext to secret(name, chipContext)
    }

    /** The same 32 bytes again. Fails as `failed` when the key is gone. */
    fun secret(name: String, chipContext: ByteArray): ByteArray {
        val key = keystore().getKey(alias(name), null) as? SecretKey
            ?: throw DeviceUnlockException.failed("no chip key")
        val raw = Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256).run {
            init(key)
            doFinal(chipContext)
        }
        return hash(raw)
    }

    fun delete(name: String) {
        keystore().deleteEntry(alias(name))
    }

    private fun generate(alias: String) {
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        try {
            generate(alias, strongBox)
        } catch (error: StrongBoxUnavailableException) {
            generate(alias, strongBox = false)
        }
    }

    private fun generate(alias: String, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setKeySize(256)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE).run {
            init(spec)
            generateKey()
        }
    }

    private fun keystore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun alias(name: String) = "octapass.chip.$name"

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"

        /** As the desktop app's `chip_secret_from`: the shape doesn't depend on the chip. */
        fun hash(raw: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").run {
            update("openpass/v1/chip-secret|".toByteArray())
            digest(raw)
        }
    }
}
