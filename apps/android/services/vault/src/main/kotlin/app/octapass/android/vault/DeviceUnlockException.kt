package app.octap.android.vault

/** Why device unlock didn't release the secret, in the codes the vault and the web view know. */
class DeviceUnlockException(val reason: Reason, message: String, cause: Throwable? = null) :
    Exception(message, cause) {
    enum class Reason(val code: String) {
        /** The user closed the prompt. */
        CANCELLED("cancelled"),

        /** No screen lock is set, or this device can't keep the key. */
        UNSUPPORTED("unsupported"),

        /** The secret is gone (a new fingerprint or face was enrolled) or the prompt locked out. */
        FAILED("failed"),
    }

    companion object {
        fun cancelled(message: String) = DeviceUnlockException(Reason.CANCELLED, message)
        fun unsupported(message: String, cause: Throwable? = null) = DeviceUnlockException(Reason.UNSUPPORTED, message, cause)
        fun failed(message: String, cause: Throwable? = null) = DeviceUnlockException(Reason.FAILED, message, cause)
    }
}
