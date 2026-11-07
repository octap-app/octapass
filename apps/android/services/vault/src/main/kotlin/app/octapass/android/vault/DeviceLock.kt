package app.octap.android.vault

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL

/** The phone's own lock, as device unlock sees it. */
object DeviceLock {
    /** A fingerprint, face or at least a PIN, pattern or password is set. */
    fun available(context: Context): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL) == BiometricManager.BIOMETRIC_SUCCESS
        } else {
            context.getSystemService(KeyguardManager::class.java).isDeviceSecure
        }

    /** A Class 3 fingerprint or face is enrolled. */
    fun hasStrongBiometric(context: Context): Boolean =
        BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    /** What the unlock button names: "Use Fingerprint", "Use Screen lock", in the phone's language. */
    fun label(context: Context): String {
        if (!hasStrongBiometric(context)) return context.getString(R.string.octapass_lock_screen_lock)
        val features = context.packageManager
        val fingerprint = features.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
        val face = features.hasSystemFeature(PackageManager.FEATURE_FACE)
        return context.getString(
            when {
                fingerprint && !face -> R.string.octapass_lock_fingerprint
                face && !fingerprint -> R.string.octapass_lock_face
                else -> R.string.octapass_lock_biometrics
            },
        )
    }
}
