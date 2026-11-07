package app.octap.android.vault

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * The device-unlock secret: 32 random bytes from the vault that wrap the account key in the
 * shared store (plan 03, *Device unlock (Android)*). Each one is encrypted to its own Keystore
 * RSA key, whose private half only decrypts after the fingerprint or face (Class 3) or the screen
 * lock: `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)`, in
 * StrongBox when the phone has it. Turning device unlock on needs no prompt, as on iOS, because
 * encrypting uses only the public key. Enrolling a new fingerprint or face destroys the key.
 *
 * Android 9 and 10 can't bind that pair of authenticators to one use of a key, so there the key
 * is usable for [LEGACY_VALIDITY_SECONDS] after the fingerprint or the screen lock
 * ([DevicePrompt] asks for it first, falling back to `KeyguardManager`).
 */
class DeviceSecrets(private val context: Context) {
    private val prefs = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /** Replaces the secret called [name]; fails as `unsupported` without a screen lock. */
    fun store(name: String, secret: ByteArray) {
        val publicKey = try {
            newKey(alias(name))
        } catch (error: GeneralSecurityException) {
            throw DeviceUnlockException.unsupported("no screen lock is set", error)
        } catch (error: IllegalStateException) {
            throw DeviceUnlockException.unsupported("no screen lock is set", error)
        }
        // The Keystore's own public key object is restricted to its purposes; a plain copy isn't.
        val plain = KeyFactory.getInstance(publicKey.algorithm).generatePublic(X509EncodedKeySpec(publicKey.encoded))
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, plain, OAEP)
        val sealed = cipher.doFinal(secret)
        check(prefs.edit().putString(name, Base64.getEncoder().encodeToString(sealed)).commit()) {
            "couldn't save the device-unlock secret"
        }
    }

    /**
     * On Android 11 and later, a cipher for the prompt's `CryptoObject`: the Keystore lets it
     * decrypt once the user has authenticated. On 9 and 10, call [release] right after the prompt.
     */
    fun cipher(name: String): Cipher {
        val key = keystore().getKey(alias(name), null) as? PrivateKey
        if (key == null || !prefs.contains(name)) throw DeviceUnlockException.failed("no device-unlock secret")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, OAEP)
        } catch (error: KeyPermanentlyInvalidatedException) {
            delete(name)
            throw DeviceUnlockException.failed("a new fingerprint or face was enrolled", error)
        }
        return cipher
    }

    /** The secret, with a cipher the prompt unlocked (or a fresh one inside the legacy window). */
    fun release(name: String, cipher: Cipher = cipher(name)): ByteArray {
        val sealed = prefs.getString(name, null) ?: throw DeviceUnlockException.failed("no device-unlock secret")
        return try {
            cipher.doFinal(Base64.getDecoder().decode(sealed))
        } catch (error: GeneralSecurityException) {
            throw DeviceUnlockException.failed("the device lock didn't release the secret", error)
        }
    }

    fun delete(name: String) {
        keystore().deleteEntry(alias(name))
        prefs.edit().remove(name).commit()
    }

    private fun newKey(alias: String): PublicKey {
        keystore().deleteEntry(alias)
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        return try {
            generate(alias, strongBox)
        } catch (error: StrongBoxUnavailableException) {
            generate(alias, strongBox = false)
        }
    }

    private fun generate(alias: String, strongBox: Boolean): PublicKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT)
            .setKeySize(2048)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setUserAuthenticationRequired(true)
            .setIsStrongBoxBacked(strongBox)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            spec.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            spec.setInvalidatedByBiometricEnrollment(true)
        } else {
            @Suppress("DEPRECATION")
            spec.setUserAuthenticationValidityDurationSeconds(LEGACY_VALIDITY_SECONDS)
        }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE)
        generator.initialize(spec.build())
        return generator.generateKeyPair().public
    }

    private fun keystore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun alias(name: String) = "octapass.device.$name"

    companion object {
        private const val FILE = "octapass.device-secrets"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "RSA/ECB/OAEPPadding"

        /** How long the key stays usable after the prompt on Android 9 and 10. */
        const val LEGACY_VALIDITY_SECONDS = 10

        // MGF1 with SHA-1 is what the Keystore supports on every version; OAEP's digest is SHA-256.
        private val OAEP = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
    }
}
