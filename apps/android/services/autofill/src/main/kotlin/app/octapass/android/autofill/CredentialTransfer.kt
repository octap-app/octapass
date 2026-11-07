package app.octap.android.autofill

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.core.content.pm.PackageInfoCompat
import androidx.core.graphics.drawable.toBitmap
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.providerevents.ProviderEventsManager
import androidx.credentials.providerevents.exception.ClearExportException
import androidx.credentials.providerevents.exception.ImportCredentialsException
import androidx.credentials.providerevents.exception.RegisterExportException
import androidx.credentials.providerevents.transfer.ClearExportRequest
import androidx.credentials.providerevents.transfer.ClearExportResponse
import androidx.credentials.providerevents.transfer.CredentialTypes
import androidx.credentials.providerevents.transfer.ExportEntry
import androidx.credentials.providerevents.transfer.ImportCredentialsRequest
import androidx.credentials.providerevents.transfer.ProviderImportCredentialsResponse
import androidx.credentials.providerevents.transfer.RegisterExportRequest
import androidx.credentials.providerevents.transfer.RegisterExportResponse
import app.octap.android.vault.Container
import app.octap.android.vault.Secrets
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.Executors

/**
 * Credential transfer between password managers on the phone (`androidx.credentials.providerevents`,
 * the FIDO Credential Exchange Protocol): Google Play services shows the list of apps, and passes
 * the items between the two apps in the FIDO Credential Exchange Format (CXF), in a file only they
 * can read. Octa Pass lists the signed-in account so other apps can import from it
 * ([ExportActivity]), and asks other apps for theirs ([receive]); the core reads and writes CXF.
 */
object CredentialTransfer {
    /** Google Play services, which runs the transfer and is the only app that may ask for an export. */
    const val PLAY_SERVICES = "com.google.android.gms"

    /** What Octa Pass's CXF export writes (`octapass_core::export::cxf`). */
    val EXPORTS: Set<String> = setOf(
        CredentialTypes.CREDENTIAL_TYPE_BASIC_AUTH,
        CredentialTypes.CREDENTIAL_TYPE_PUBLIC_KEY,
        CredentialTypes.CREDENTIAL_TYPE_TOTP,
        CredentialTypes.CREDENTIAL_TYPE_NOTE,
        CredentialTypes.CREDENTIAL_TYPE_CREDIT_CARD,
        CredentialTypes.CREDENTIAL_TYPE_PERSON_NAME,
        CredentialTypes.CREDENTIAL_TYPE_ADDRESS,
        CredentialTypes.CREDENTIAL_TYPE_CUSTOM_FIELDS,
        CredentialTypes.CREDENTIAL_TYPE_WIFI,
    )

    /**
     * What Octa Pass takes: everything the core's CXF importer turns into an item. Files and links
     * to other items can't come across.
     */
    val IMPORTS: Set<String> = EXPORTS + setOf(
        CredentialTypes.CREDENTIAL_TYPE_API_KEY,
        CredentialTypes.CREDENTIAL_TYPE_GENERATED_PASSWORD,
        CredentialTypes.CREDENTIAL_TYPE_DRIVERS_LICENSE,
        CredentialTypes.CREDENTIAL_TYPE_PASSPORT,
        CredentialTypes.CREDENTIAL_TYPE_IDENTITY_DOCUMENT,
        CredentialTypes.CREDENTIAL_TYPE_SSH_KEY,
    )

    /** Where the export entry's id is kept, with the account it's for. */
    private const val ENTRY = "exportEntry"

    private val work = Executors.newSingleThreadExecutor()

    /** The account listed since the app started: listing again on every sync isn't needed. */
    @Volatile private var listed: String? = null

    /**
     * Google Play services 25.38 or later, the version `providerevents-play-services`
     * (1.0.0-beta01) checks for before it does anything.
     */
    private const val MIN_PLAY_SERVICES = 253_800_000L

    /** The transfer needs a recent Google Play services. */
    fun available(context: Context): Boolean = try {
        val info = context.packageManager.getPackageInfo(PLAY_SERVICES, 0)
        PackageInfoCompat.getLongVersionCode(info) >= MIN_PLAY_SERVICES
    } catch (error: PackageManager.NameNotFoundException) {
        false
    }

    /**
     * Lists the signed-in account for other apps to import from, or takes Octa Pass off the list
     * when nobody is signed in. The app calls it after each sync; it lists each account once per
     * run and never waits for the answer.
     */
    fun register(context: Context, secrets: Secrets) {
        if (!available(context)) return
        val app = context.applicationContext
        work.execute {
            try {
                val manager = ProviderEventsManager.create(app)
                val account = Container.currentAccount(Container.directory(app))
                if (account == null) {
                    listed = null
                    secrets.delete(ENTRY)
                    manager.clearExportAsync(ClearExportRequest(), work, logged<ClearExportResponse, ClearExportException>("clear"))
                    return@execute
                }
                if (listed == account.tag) return@execute
                val (id, stored) = ExportEntries.entryFor(secrets.get(ENTRY), account.tag) { newId() }
                if (stored != null) secrets.set(ENTRY, stored)
                val icon = ContextCompat.getDrawable(app, R.drawable.octapass_icon)!!.toBitmap(ICON_SIZE, ICON_SIZE)
                val entry = ExportEntry(id, app.getString(R.string.octapass_service_name), account.email, icon, EXPORTS)
                manager.registerExportAsync(
                    RegisterExportRequest.create(app, listOf(entry)),
                    work,
                    object : CredentialManagerCallback<RegisterExportResponse, RegisterExportException> {
                        override fun onResult(result: RegisterExportResponse) {
                            listed = account.tag
                        }

                        override fun onError(e: RegisterExportException) {
                            Log.w(TAG, "credential transfer: register failed", e)
                        }
                    },
                )
            } catch (error: Exception) {
                Log.w(TAG, "credential transfer: couldn't list Octa Pass", error)
            }
        }
    }

    /** The export entry the system passed on is the current account's. */
    fun isCurrentEntry(context: Context, secrets: Secrets, credId: String): Boolean {
        val account = Container.currentAccount(Container.directory(context)) ?: return false
        return ExportEntries.matches(secrets.get(ENTRY), account.tag, credId)
    }

    /** Items another password manager handed over: CXF, and the app's name. */
    class Received(val json: String, val from: String)

    /**
     * Shows the system's list of password managers that can hand over their items, and answers
     * with what the chosen one sent: `null` when the user backed out or no app could.
     */
    fun receive(activity: Activity, done: (Result<Received?>) -> Unit) {
        ProviderEventsManager.create(activity).importCredentialsAsync(
            activity,
            ImportCredentialsRequest(IMPORTS, emptySet()),
            null,
            ContextCompat.getMainExecutor(activity),
            object : CredentialManagerCallback<ProviderImportCredentialsResponse, ImportCredentialsException> {
                override fun onResult(result: ProviderImportCredentialsResponse) {
                    val from = AppNames.label(activity, result.callingAppInfo.packageName)
                    done(Result.success(Received(result.response.responseJson, from)))
                }

                override fun onError(e: ImportCredentialsException) {
                    Log.i(TAG, "credential transfer: ${e.type}: ${e.errorMessage}")
                    done(if (TransferErrors.isNothing(e.type)) Result.success(null) else Result.failure(e))
                }
            },
        )
    }

    private fun <R, E : Exception> logged(what: String) = object : CredentialManagerCallback<R, E> {
        override fun onResult(result: R) = Unit

        override fun onError(e: E) {
            Log.w(TAG, "credential transfer: $what failed", e)
        }
    }

    private fun newId(): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32).also { SecureRandom().nextBytes(it) })

    private const val ICON_SIZE = 192
}

/**
 * The export entry's id: a random secret the system hands back when another app asks for the
 * account, so Octa Pass knows the request came from its own entry (and is for the account that's
 * signed in now). Kept in [Secrets] as `{"tag": …, "id": …}`.
 */
object ExportEntries {
    /** The id for the account [tag], and what to store when it's new (else `null`). */
    fun entryFor(stored: String?, tag: String, newId: () -> String): Pair<String, String?> {
        parse(stored)?.takeIf { it.first == tag }?.let { return it.second to null }
        val id = newId()
        return id to JSONObject().put("tag", tag).put("id", id).toString()
    }

    fun matches(stored: String?, tag: String, credId: String): Boolean {
        val (storedTag, id) = parse(stored) ?: return false
        return storedTag == tag && MessageDigest.isEqual(id.toByteArray(), credId.toByteArray())
    }

    private fun parse(stored: String?): Pair<String, String>? {
        val json = stored?.let { runCatching { JSONObject(it) }.getOrNull() } ?: return null
        val tag = json.optString("tag").ifEmpty { return null }
        val id = json.optString("id").ifEmpty { return null }
        return tag to id
    }
}

/** How the transfer's failures read to the app. */
object TransferErrors {
    /** The user backed out, or no app could hand anything over: nothing to say. */
    fun isNothing(type: String): Boolean =
        type.endsWith("CANCELLATION_EXCEPTION") || type.endsWith("NO_EXPORT_OPTION")

    /** The other app sent something that isn't CXF. */
    fun isInvalid(type: String): Boolean = type.endsWith("INVALID_JSON_EXCEPTION")
}
