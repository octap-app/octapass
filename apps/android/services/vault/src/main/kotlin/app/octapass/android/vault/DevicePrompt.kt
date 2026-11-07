package app.octap.android.vault

import android.app.Activity
import android.app.KeyguardManager
import android.content.Intent
import android.os.Build
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.UUID

/**
 * Asks for the fingerprint, face or screen lock, then releases a device-unlock secret
 * ([DeviceSecrets]). Call on the main thread; `done` runs there too.
 */
class DevicePrompt(private val activity: FragmentActivity, private val secrets: DeviceSecrets = DeviceSecrets(activity)) {
    fun unlock(name: String, title: String, subtitle: String?, done: (Result<ByteArray>) -> Unit) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return legacyUnlock(name, title, subtitle, done)
        val cipher = try {
            secrets.cipher(name)
        } catch (error: DeviceUnlockException) {
            return done(Result.failure(error))
        }
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .build()
        val callback = callback(done) { result -> done(release { secrets.release(name, result.cryptoObject!!.cipher!!) }) }
        BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
            .authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    /** Android 9 and 10: the fingerprint with "Use screen lock" as the way out, or the screen lock. */
    private fun legacyUnlock(name: String, title: String, subtitle: String?, done: (Result<ByteArray>) -> Unit) {
        val released = { done(release { secrets.release(name) }) }
        if (!DeviceLock.hasStrongBiometric(activity)) return confirmScreenLock(title, subtitle, released, done)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setNegativeButtonText(activity.getString(R.string.octapass_use_screen_lock))
            .build()
        val callback = callback(done, onNegative = { confirmScreenLock(title, subtitle, released, done) }) { released() }
        BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback).authenticate(info)
    }

    private fun confirmScreenLock(title: String, subtitle: String?, released: () -> Unit, done: (Result<ByteArray>) -> Unit) {
        val keyguard = activity.getSystemService(KeyguardManager::class.java)
        @Suppress("DEPRECATION")
        val intent = keyguard.createConfirmDeviceCredentialIntent(title, subtitle)
            ?: return done(Result.failure(DeviceUnlockException.unsupported("no screen lock is set")))
        lateinit var launcher: ActivityResultLauncher<Intent>
        launcher = activity.activityResultRegistry.register("octapass.keyguard.${UUID.randomUUID()}", StartActivityForResult()) { result ->
            launcher.unregister()
            if (result.resultCode == Activity.RESULT_OK) {
                released()
            } else {
                done(Result.failure(DeviceUnlockException.cancelled("screen lock not confirmed")))
            }
        }
        launcher.launch(intent)
    }

    private fun callback(
        done: (Result<ByteArray>) -> Unit,
        onNegative: (() -> Unit)? = null,
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
    ) = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onSuccess(result)

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON && onNegative != null) return onNegative()
            done(Result.failure(promptError(errorCode, errString.toString())))
        }
    }

    private fun release(read: () -> ByteArray): Result<ByteArray> = try {
        Result.success(read())
    } catch (error: DeviceUnlockException) {
        Result.failure(error)
    } catch (error: Exception) {
        Result.failure(DeviceUnlockException.failed("the device lock didn't release the secret", error))
    }
}

/** The prompt's error codes in the vault's terms. */
internal fun promptError(code: Int, message: String): DeviceUnlockException = when (code) {
    BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_CANCELED ->
        DeviceUnlockException.cancelled(message)
    BiometricPrompt.ERROR_NO_BIOMETRICS, BiometricPrompt.ERROR_HW_NOT_PRESENT, BiometricPrompt.ERROR_HW_UNAVAILABLE,
    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL ->
        DeviceUnlockException.unsupported(message)
    else -> DeviceUnlockException.failed(message)
}
