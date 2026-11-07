package app.octap.android.autofill

import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.Toast
import app.octap.android.vault.AutofillVault
import app.octap.android.vault.Container
import app.octap.android.vault.Core
import java.util.concurrent.Executors

/**
 * Octa Pass in the Autofill framework (plan 05). A sign-in form gets one suggestion, "Octa Pass",
 * that unlocks in [FillActivity] (with no prompt while "Stay unlocked" is on, plan 18; otherwise the
 * device lock or the master password) and then fills the login matching the app or site; a sign-up
 * or change-password form also gets a suggested password, generated here without unlocking.
 * Submitted passwords are offered for saving, and a Save never asks to unlock: while "Stay
 * unlocked" is on it goes straight into the vault, otherwise it's sealed into the store's save inbox
 * here and added to the vault at the next unlock (plan 03, Saving while locked). Nothing about the
 * vault is known here before it's unlocked, so the system's sheet always says "Save", never "Update".
 */
class OctaPassAutofillService : AutofillService() {
    private val browsers by lazy { PrivilegedBrowsers(this) }
    private val work = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val form = request.fillContexts.last().structure.form()
        val account = Container.currentAccount(Container.directory(this))
        if (form.packageName == packageName || account == null || (!form.hasLogin && !form.hasNewPassword)) {
            return callback.onSuccess(null)
        }
        val inline = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) request.inlineSuggestionsRequest else null
        val presentations = Presentations(this, inline)
        val response = FillResponse.Builder()

        if (form.hasLogin) {
            val unlock = FillActivity.intentSender(this, form.url(trusted(form)), form, request.id)
            val fields = form.ids(FieldKind.USERNAME, FieldKind.PASSWORD, FieldKind.ONE_TIME_CODE)
            response.addDataset(
                presentations.dataset(getString(R.string.octapass_suggestion), account.email, fields.associate { it as AutofillId to null })
                    .setAuthentication(unlock)
                    .build(),
            )
        }
        if (form.hasNewPassword) {
            val password = AutofillValue.forText(suggestedPassword(form.url(trusted(form))))
            val fields = form.ids(FieldKind.NEW_PASSWORD)
            response.addDataset(
                presentations.dataset(getString(R.string.octapass_suggested_password), getString(R.string.octapass_suggested_password_detail), fields.associate { it as AutofillId to password })
                    .build(),
            )
        }
        saveInfo(form)?.let(response::setSaveInfo)
        callback.onSuccess(response.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val forms = request.fillContexts.map { it.structure.form() }
        val form = forms.last()
        val password = form.typed(FieldKind.NEW_PASSWORD) ?: form.typed(FieldKind.PASSWORD)
        if (password == null || form.packageName == packageName) return callback.onSuccess()
        // Multi-step sign-ins ask for the user name on an earlier screen.
        val username = forms.asReversed().firstNotNullOfOrNull { it.typed(FieldKind.USERNAME) }
        val url = form.url(trusted(form))
        val title = if (url.startsWith("androidapp://")) AppNames.label(this, form.packageName) else null
        val save = PendingSave(url, title, username, password)
        callback.onSuccess()
        work.execute {
            val saved = runCatching { AutofillVault.open(this)?.use { save(it, save) } }
                .onFailure { android.util.Log.w(TAG, "saving to the inbox failed", it) }
                .getOrNull()
            main.post {
                if (saved != null) {
                    Toast.makeText(this, saved, Toast.LENGTH_SHORT).show()
                } else {
                    // Nobody signed in (it says so), or the inbox can't take it yet (no unlock here
                    // since it was added, or it's full): unlock and save, as before. Started here
                    // rather than handed back as an IntentSender: the framework starts that from the
                    // form's activity, which is usually gone by now. Services the system binds for
                    // autofill may start activities.
                    startActivity(SaveActivity.intent(this, PendingSaves.put(save)))
                }
            }
        }
    }

    /**
     * Stay unlocked (plan 18) opens the vault with no prompt, so the save goes straight in, as a
     * new login or the new password of the login with that user name. Otherwise it's sealed into
     * the inbox. What to say, or null when neither worked.
     */
    private fun save(vault: AutofillVault, save: PendingSave): Int? = when {
        vault.unlockStayingUnlocked() -> {
            vault.saveLogin(save.url, save.username, save.password, save.title)
            R.string.octapass_saved
        }
        vault.saveLocked(save.url, save.username, save.password, save.title) -> R.string.octapass_saved_locked
        else -> null
    }

    override fun onDestroy() {
        super.onDestroy()
        work.shutdown()
    }

    private fun trusted(form: Form) = form.webDomain != null && browsers.isTrusted(packageManager, form.packageName)

    private fun saveInfo(form: Form): SaveInfo? {
        val passwords = form.ids(FieldKind.NEW_PASSWORD).ifEmpty { form.ids(FieldKind.PASSWORD) }
        if (passwords.isEmpty()) return null
        val usernames = form.ids(FieldKind.USERNAME)
        val type = SaveInfo.SAVE_DATA_TYPE_PASSWORD or if (usernames.isEmpty()) 0 else SaveInfo.SAVE_DATA_TYPE_USERNAME
        return SaveInfo.Builder(type, passwords.map { it as AutofillId }.toTypedArray())
            .apply { if (usernames.isNotEmpty()) setOptionalIds(usernames.map { it as AutofillId }.toTypedArray()) }
            // Web sign-ins often move on without leaving the page: save when the fields go away.
            .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
            .build()
    }

    /**
     * The generator's defaults (plan 01), adjusted to what the password rules dataset knows about
     * [url]. An app's `androidapp://` address, and a page outside a trusted browser, get the defaults.
     */
    private fun suggestedPassword(url: String): String {
        Core.load()
        return app.octap.core.suggestedPassword(url)
    }
}
