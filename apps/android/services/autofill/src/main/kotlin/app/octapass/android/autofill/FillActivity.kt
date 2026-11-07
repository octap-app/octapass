package app.octap.android.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.net.Uri
import android.os.Build
import android.service.autofill.Dataset
import android.util.Log
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import androidx.appcompat.app.AlertDialog
import app.octap.android.vault.AutofillVault
import app.octap.android.vault.Login
import app.octap.android.vault.OtherPartLogin

/**
 * Opened from the "Octa Pass" suggestion: unlocks, then fills the login for the app or site (the
 * same host, a domain above it or a host below it), or lets the user pick when several match.
 * Logins for other parts of the site's domain (`shop.example.com` on `login.example.com`) are
 * never filled on their own: they wait behind one quiet entry in the list, and after the user
 * fills one from there, it offers to add this site to it. With no match, any login can be picked,
 * after saying that it isn't saved for this app or site; an `http` page gets a warning first
 * (plan 03).
 */
class FillActivity : UnlockingActivity() {
    private val url by lazy { intent.getStringExtra(EXTRA_URL)!! }

    override fun onUnlocked(vault: AutofillVault) {
        background({
            // Only ever listed, so a problem there doesn't stand in the way of the fill.
            val others = runCatching { vault.otherLogins(url) }.onFailure { Log.w(TAG, "other logins failed", it) }.getOrDefault(emptyList())
            vault.logins(listOf(url)) to others
        }) { result ->
            val (logins, others) = result.getOrElse { return@background fail(getString(R.string.octapass_fill_failed), it) }
            val otherParts = if (others.isEmpty()) null else otherPartsRow(others) { fill(vault, it.login, it) }
            when {
                logins.isEmpty() -> pickAny(vault, otherParts)
                logins.size == 1 && otherParts == null -> fill(vault, logins.single())
                else -> choose(getString(R.string.octapass_pick_login), logins.map { login -> Row(loginRow(login)) { fill(vault, login) } } + listOfNotNull(otherParts))
            }
        }
    }

    /** No login matches: the other parts of the site first, then every login. */
    private fun pickAny(vault: AutofillVault, otherParts: Row?) {
        background({ vault.search("") }) { result ->
            val logins = result.getOrDefault(emptyList())
            if (logins.isEmpty() && otherParts == null) return@background fail(getString(R.string.octapass_no_logins))
            val rows = logins.map { login ->
                Row(loginRow(login)) { confirm(getString(R.string.octapass_fill_unmatched, login.title, site())) { fill(vault, login) } }
            }
            choose(getString(R.string.octapass_no_match, site()), listOfNotNull(otherParts) + rows)
        }
    }

    /** [other] is set when the user picked the login from another part of the site. */
    private fun fill(vault: AutofillVault, login: Login, other: OtherPartLogin? = null) {
        if (login.schemeMismatch && url.startsWith("http://")) {
            return confirm(getString(R.string.octapass_insecure_page, site())) { fillNow(vault, login, other) }
        }
        fillNow(vault, login, other)
    }

    private fun fillNow(vault: AutofillVault, login: Login, other: OtherPartLogin?) {
        val codes = ids(EXTRA_CODES)
        background({
            val (user, password) = vault.credentials(login.itemId)
            val code = if (login.hasTotp && codes.isNotEmpty()) vault.oneTimeCode(login.itemId) else null
            Triple(user, password, code)
        }) { result ->
            val (user, password, code) = result.getOrElse { return@background fail(getString(R.string.octapass_fill_failed), it) }
            val values = ids(EXTRA_USERNAMES).associateWith { user } + ids(EXTRA_PASSWORDS).associateWith { password } +
                (if (code != null) codes.associateWith { code } else emptyMap())
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset(values)))
            // The result is set, so the fill goes through whatever the answer.
            if (other != null) offerWebsite(vault, other, url) { finish() } else finish()
        }
    }

    /** The values to fill; the framework already shows the suggestion, so no presentation. */
    @Suppress("DEPRECATION")
    private fun dataset(values: Map<AutofillId, String>): Dataset =
        Dataset.Builder().apply { values.forEach { (id, text) -> setValue(id, AutofillValue.forText(text)) } }.build()

    private fun confirm(message: String, yes: () -> Unit) {
        AlertDialog.Builder(this)
            .setMessage(message)
            .setPositiveButton(R.string.octapass_fill) { _, _ -> yes() }
            .setNegativeButton(android.R.string.cancel) { _, _ -> onCancelled() }
            .setOnCancelListener { onCancelled() }
            .show()
    }

    /** The site's host or the app's package, as the user knows it. */
    private fun site(): String = if (url.startsWith(ANDROID_APP)) url.removePrefix(ANDROID_APP) else Uri.parse(url).host ?: url

    private fun ids(name: String): List<AutofillId> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableArrayListExtra(name, AutofillId::class.java).orEmpty()
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableArrayListExtra<AutofillId>(name).orEmpty()
        }

    companion object {
        private const val ANDROID_APP = "androidapp://"
        private const val EXTRA_URL = "url"
        private const val EXTRA_USERNAMES = "usernames"
        private const val EXTRA_PASSWORDS = "passwords"
        private const val EXTRA_CODES = "codes"

        fun intentSender(context: Context, url: String, form: Form, requestId: Int): IntentSender {
            fun list(kind: FieldKind) = ArrayList(form.ids(kind).map { it as AutofillId })
            val intent = Intent(context, FillActivity::class.java)
                .putExtra(EXTRA_URL, url)
                .putParcelableArrayListExtra(EXTRA_USERNAMES, list(FieldKind.USERNAME))
                .putParcelableArrayListExtra(EXTRA_PASSWORDS, list(FieldKind.PASSWORD))
                .putParcelableArrayListExtra(EXTRA_CODES, list(FieldKind.ONE_TIME_CODE))
            // Mutable: the framework adds the screen's structure to the intent.
            return PendingIntent.getActivity(context, requestId, intent, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE).intentSender
        }
    }
}
