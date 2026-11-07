package app.octap.android.platform

import android.app.ActivityManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.fragment.app.FragmentActivity
import app.octap.android.autofill.CredentialTransfer
import app.octap.android.vault.ChipSecrets
import app.octap.android.vault.CredentialIdentities
import app.octap.android.vault.DeviceLock as PhoneLock
import app.octap.android.vault.DevicePrompt
import app.octap.android.vault.DeviceSecrets
import app.octap.android.vault.DeviceUnlockException
import app.octap.android.vault.Secrets
import app.octap.android.vault.StayUnlockedKeys
import app.octap.vault.ChipKey
import app.octap.vault.CredentialIdentity
import app.octap.vault.DeviceLock
import app.octap.vault.ErrorCode
import app.octap.vault.NativePlatform
import app.octap.vault.VaultException
import org.json.JSONArray
import org.json.JSONObject
import java.lang.ref.WeakReference
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference

/**
 * What the vault asks of the phone (`NativePlatform`), on the same Keystore-backed storage the
 * Autofill and Credential Manager services read: [Secrets] for the Secret Key and tokens,
 * [DeviceSecrets] and [DevicePrompt] for device unlock, [StayUnlockedKeys] for staying unlocked
 * while the phone is (plan 18), and [CredentialIdentities] for what the system suggests before the
 * vault is unlocked. The vault calls on its own threads, so a prompt blocks here until the user
 * answers it on the main thread.
 */
class AndroidPlatform(private val context: Context) : NativePlatform {
    private val secrets = Secrets(context)
    private val deviceSecrets = DeviceSecrets(context)
    private val stayUnlocked = StayUnlockedKeys(context)
    private val chip = ChipSecrets(context)
    private val backups = BackupFolder(context)
    private val main = Handler(Looper.getMainLooper())

    /** The activity on screen, for the device-lock prompt. */
    @Volatile
    private var host: WeakReference<FragmentActivity>? = null

    fun attach(activity: FragmentActivity) {
        host = WeakReference(activity)
    }

    fun detach(activity: FragmentActivity) {
        if (host?.get() === activity) host = null
    }

    override fun secret(name: String): String? = guard { secrets.get(name) }

    override fun setSecret(name: String, value: String) = guard { secrets.set(name, value) }

    override fun deleteSecret(name: String) = guard { secrets.delete(name) }

    override fun deviceLock(): DeviceLock = DeviceLock(PhoneLock.available(context), lockLabel(context))

    override fun storeDeviceSecret(name: String, secret: ByteArray) = guard {
        try {
            deviceSecrets.store(name, secret)
        } finally {
            secret.fill(0)
        }
    }

    override fun deviceSecret(name: String, reason: String): ByteArray {
        val result = AtomicReference<Result<ByteArray>>()
        val answered = CountDownLatch(1)
        main.post {
            val activity = host?.get()
            if (activity == null || activity.isFinishing) {
                result.set(Result.failure(DeviceUnlockException.cancelled("no window to ask in")))
                answered.countDown()
                return@post
            }
            DevicePrompt(activity, deviceSecrets).unlock(name, reason, null) {
                result.set(it)
                answered.countDown()
            }
        }
        answered.await()
        return result.get().getOrElse { throw failure(it) }
    }

    override fun deleteDeviceSecret(name: String) = guard { deviceSecrets.delete(name) }

    /** The desktop services' approval (plan 19): the Mac app's only, so never asked here. */
    override fun verifyUser(reason: String) {
        throw VaultException.Failed(ErrorCode.DEVICE_UNLOCK_UNSUPPORTED, "desktop services only")
    }

    override fun storeStayUnlockedKey(name: String, key: ByteArray) = guard {
        try {
            stayUnlocked.store(name, key)
        } finally {
            key.fill(0)
        }
    }

    override fun stayUnlockedKey(name: String): ByteArray? = guard { stayUnlocked.get(name) }

    override fun deleteStayUnlockedKey(name: String) = guard { stayUnlocked.delete(name) }

    /** After each sync and on sign-out; the account other apps can import from follows. */
    override fun setCredentialIdentities(identities: List<CredentialIdentity>) = guard {
        CredentialIdentities.save(secrets, identitiesJson(identities))
        CredentialTransfer.register(context, secrets)
    }

    override fun chipAvailable(): Boolean = chip.available

    override fun createChipKey(name: String): ChipKey? = guard {
        chip.create(name)?.let { (context, secret) -> ChipKey(context, secret) }
    }

    override fun chipSecret(name: String, context: ByteArray): ByteArray = guard { chip.secret(name, context) }

    override fun deleteChipKey(name: String) = guard { chip.delete(name) }

    override fun lowMemory(): Boolean = context.getSystemService(ActivityManager::class.java).isLowRamDevice

    override fun backupFolderFiles(folder: String): List<String> = guard { backups.list(folder) }

    override fun writeBackupFile(folder: String, name: String, source: String) = guard { backups.write(folder, name, source) }

    override fun deleteBackupFile(folder: String, name: String) = guard { backups.delete(folder, name) }

    private inline fun <T> guard(work: () -> T): T = try {
        work()
    } catch (error: VaultException) {
        throw error
    } catch (error: Exception) {
        throw failure(error)
    }

    companion object {
        /**
         * What the vault calls the phone's lock, in English (it never shows it; the screens say
         * "fingerprint, face or screen lock" in the user's language).
         */
        fun lockLabel(context: Context): String = if (PhoneLock.hasStrongBiometric(context)) "Fingerprint" else "Screen lock"

        /** The prompt's and the Keystore's errors in the vault's codes. */
        fun failure(error: Throwable): VaultException {
            if (error is VaultException) return error
            val code = when ((error as? DeviceUnlockException)?.reason) {
                DeviceUnlockException.Reason.CANCELLED -> ErrorCode.DEVICE_UNLOCK_CANCELLED
                DeviceUnlockException.Reason.UNSUPPORTED -> ErrorCode.DEVICE_UNLOCK_UNSUPPORTED
                DeviceUnlockException.Reason.FAILED -> ErrorCode.DEVICE_UNLOCK_FAILED
                null -> ErrorCode.UNEXPECTED
            }
            return VaultException.Failed(code, error.message ?: error.javaClass.simpleName)
        }

        /** The list as the services read it ([CredentialIdentities]): binary values in base64url. */
        fun identitiesJson(identities: List<CredentialIdentity>): JSONArray {
            val base64 = Base64.getUrlEncoder().withoutPadding()
            val list = JSONArray()
            for (identity in identities) {
                list.put(
                    when (identity) {
                        is CredentialIdentity.Password -> JSONObject()
                            .put("kind", "password").put("itemId", identity.itemId).put("url", identity.url).put("user", identity.user)
                        is CredentialIdentity.Passkey -> JSONObject()
                            .put("kind", "passkey").put("itemId", identity.itemId).put("rpId", identity.rpId)
                            .put("userName", identity.userName)
                            .put("credentialId", base64.encodeToString(identity.credentialId))
                            .put("userHandle", base64.encodeToString(identity.userHandle))
                        is CredentialIdentity.OneTimeCode -> JSONObject()
                            .put("kind", "oneTimeCode").put("itemId", identity.itemId).put("url", identity.url).put("label", identity.label)
                    },
                )
            }
            return list
        }
    }
}
