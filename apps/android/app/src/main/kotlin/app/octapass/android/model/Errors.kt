package app.octap.android.model

import android.content.Context
import app.octap.resources.R
import app.octap.vault.ErrorCode
import app.octap.vault.VaultException

/**
 * The catalog message for each of the vault's error codes, as the web vault shows them
 * (`lib/errors.ts`), with the phone's own words where the web's are about a browser.
 */
fun errorMessageRes(code: ErrorCode): Int = when (code) {
    ErrorCode.INVALID_CREDENTIALS -> R.string.errors_invalidCredentials
    ErrorCode.SECRET_KEY_REQUIRED -> R.string.errors_secretKeyRequired
    ErrorCode.INVALID_SECRET_KEY -> R.string.errors_invalidSecretKey
    ErrorCode.EMAIL_TAKEN -> R.string.errors_emailTaken
    ErrorCode.INVALID_EMAIL -> R.string.errors_invalidEmail
    ErrorCode.INVALID_VERIFICATION_CODE -> R.string.errors_invalidVerificationCode
    ErrorCode.SIGNUP_EXPIRED -> R.string.errors_signupExpired
    ErrorCode.RESET_EXPIRED -> R.string.errors_resetExpired
    ErrorCode.INVALID_RECOVERY_CODE -> R.string.errors_invalidRecoveryCode
    ErrorCode.SIGNUPS_CLOSED -> R.string.errors_signupsClosed
    ErrorCode.INSECURE_SERVER_URL -> R.string.errors_insecureServerUrl
    ErrorCode.SERVER_UNREACHABLE -> R.string.errors_serverUnreachable
    ErrorCode.SERVER_ERROR -> R.string.errors_serverError
    ErrorCode.RATE_LIMITED -> R.string.errors_rateLimited
    ErrorCode.SESSION_EXPIRED -> R.string.errors_sessionExpired
    ErrorCode.ACCOUNT_DELETED -> R.string.errors_accountDeleted
    ErrorCode.REAUTH_REQUIRED -> R.string.errors_reauthRequired
    ErrorCode.LOCKED -> R.string.errors_locked
    ErrorCode.NOT_FOUND -> R.string.errors_notFound
    ErrorCode.READ_ONLY_VAULT -> R.string.errors_readOnlyVault
    ErrorCode.INVALID_IMPORT_FILE -> R.string.errors_invalidImportFile
    ErrorCode.IMPORT_PASSWORD_REQUIRED -> R.string.errors_importPasswordRequired
    ErrorCode.WRONG_IMPORT_PASSWORD -> R.string.errors_wrongImportPassword
    ErrorCode.EMAIL_MISMATCH -> R.string.errors_emailMismatch
    ErrorCode.DEVICE_UNLOCK_UNSUPPORTED -> R.string.phone_native_unlockUnsupported
    ErrorCode.DEVICE_UNLOCK_CANCELLED -> R.string.errors_deviceUnlockCancelled
    ErrorCode.DEVICE_UNLOCK_FAILED -> R.string.errors_deviceUnlockFailed
    ErrorCode.PASSWORD_REQUIRED -> R.string.lock_passwordRequired
    ErrorCode.ACCOUNT_NOT_FOUND -> R.string.errors_accountNotFound
    ErrorCode.NOT_ALLOWED -> R.string.errors_notAllowed
    ErrorCode.ALREADY_EXISTS -> R.string.errors_alreadyExists
    ErrorCode.FAMILY_FULL -> R.string.errors_familyFull
    ErrorCode.QUOTA_EXCEEDED -> R.string.errors_quotaExceeded
    ErrorCode.UNTRUSTED_VAULT -> R.string.errors_untrustedVault
    ErrorCode.WRONG_PASSPHRASE -> R.string.errors_wrongPassphrase
    ErrorCode.SSH_PASSPHRASE_REQUIRED -> R.string.errors_sshPassphraseRequired
    ErrorCode.INVALID_SSH_KEY -> R.string.errors_invalidSshKey
    ErrorCode.UNSUPPORTED_SSH_KEY -> R.string.errors_unsupportedSshKey
    ErrorCode.SSH_PUBLIC_KEY_ONLY -> R.string.errors_sshPublicKeyOnly
    ErrorCode.INVALID_SHARE_LINK -> R.string.errors_invalidShareLink
    ErrorCode.FILE_TOO_LARGE -> R.string.errors_fileTooLarge
    ErrorCode.INVALID_TWO_STEP_CODE -> R.string.errors_invalidTwoStepCode
    ErrorCode.TWO_STEP_EXPIRED -> R.string.errors_twoStepExpired
    ErrorCode.SECURITY_KEY_CANCELLED -> R.string.errors_securityKeyCancelled
    ErrorCode.SECURITY_KEY_UNSUPPORTED -> R.string.errors_securityKeyUnsupported
    ErrorCode.MASKED_EMAIL_NOT_SET_UP -> R.string.errors_maskedEmailNotSetUp
    ErrorCode.MASKED_EMAIL_BLOCKED -> R.string.errors_maskedEmailBlocked
    ErrorCode.MASKED_EMAIL_TOKEN -> R.string.errors_maskedEmailToken
    ErrorCode.SSO_PENDING -> R.string.errors_ssoPending
    ErrorCode.ORG_POLICY -> R.string.errors_orgPolicy
    ErrorCode.ORG_VAULT_ORPHANED -> R.string.errors_orgVaultOrphaned
    ErrorCode.SSO_CONFIG -> R.string.errors_ssoConfig
    ErrorCode.MASKED_EMAIL_RATE_LIMITED -> R.string.errors_maskedEmailRateLimited
    ErrorCode.MASKED_EMAIL_UNREACHABLE -> R.string.errors_maskedEmailUnreachable
    ErrorCode.MASKED_EMAIL_FAILED -> R.string.errors_maskedEmailFailed
    ErrorCode.NO_FILE_VIEWER -> R.string.errors_noFileViewer
    ErrorCode.CAMERA_UNAVAILABLE -> R.string.errors_cameraUnavailable
    ErrorCode.INVALID_IMAGE -> R.string.errors_invalidImage
    ErrorCode.IMPORT_REVIEW_EXPIRED -> R.string.errors_importReviewExpired
    ErrorCode.NEEDS_SYNC -> R.string.errors_needsSync
    ErrorCode.WEAK_MASTER_PASSWORD -> R.string.errors_weakMasterPassword
    ErrorCode.INVALID_BACKUP -> R.string.errors_invalidBackup
    ErrorCode.INVALID_NAME -> R.string.errors_invalidName
    ErrorCode.INVALID_INPUT, ErrorCode.UNEXPECTED -> R.string.phone_native_unexpected
}

val Throwable.code: ErrorCode
    get() = (this as? VaultException.Failed)?.code ?: ErrorCode.UNEXPECTED

fun Throwable.isCode(code: ErrorCode) = this.code == code

/** A sentence that says what went wrong and what to do next (`errorMessage` in the web vault). */
fun errorMessage(context: Context, error: Throwable): String {
    val failed = error as? VaultException.Failed ?: return context.getString(R.string.phone_native_unexpected)
    val message = context.getString(errorMessageRes(failed.code))
    return when (failed.code) {
        // Import errors carry the parser's reason, and provider errors the provider's words.
        ErrorCode.INVALID_IMPORT_FILE, ErrorCode.MASKED_EMAIL_FAILED ->
            if (failed.reason.isNotBlank() && failed.reason != app.octap.vault.errorCodeName(failed.code)) "$message ${failed.reason}" else message
        ErrorCode.MASKED_EMAIL_BLOCKED -> context.getString(R.string.errors_maskedEmailBlocked, failed.reason)
        else -> message
    }
}
