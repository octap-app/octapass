package app.octap.android.autofill

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.util.Log
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import app.octap.android.vault.AutofillVault
import app.octap.android.vault.DevicePrompt
import app.octap.android.vault.DeviceUnlockException
import app.octap.android.vault.Login
import app.octap.android.vault.OtherPartLogin
import app.octap.android.vault.SecureWindow
import app.octap.android.vault.SignedOutException
import app.octap.core.OctaPassException
import java.util.concurrent.Executors

internal const val TAG = "OctaPass"

/** A row in a list of logins to pick from. */
class Row(val label: CharSequence, val pick: () -> Unit)

/**
 * An invisible activity that unlocks the shared store before doing what the system asked: with
 * no prompt at all while "Stay unlocked" is on (plan 18), otherwise the device lock first when
 * device unlock is on (plan 03), otherwise, or when that fails, the master password. The keys are
 * zeroed when it finishes.
 */
abstract class UnlockingActivity : AppCompatActivity() {
    private val work = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var vault: AutofillVault? = null

    /** The vault is unlocked; finish when done. Runs on the main thread. */
    protected abstract fun onUnlocked(vault: AutofillVault)

    /** Whether to go on with the request at all; when not, it has already answered and finished. */
    protected open fun accepts(): Boolean = true

    /** Always the master password, never the device lock: exports (plan 07). */
    protected open val passwordOnly = false
    protected open val passwordTitle = R.string.octapass_unlock_title
    protected open val passwordAction = R.string.octapass_unlock

    /** What the master password dialog says. */
    protected open fun passwordMessage(vault: AutofillVault): String = vault.account.email

    /** The user backed out, or nobody is signed in to Octa Pass. */
    protected open fun onCancelled() {
        setResult(RESULT_CANCELED)
        finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecureWindow.apply(window, this)
        // Recreated after the process was gone: what was asked for is gone with it.
        if (savedInstanceState != null) return onCancelled()
        if (!accepts()) return
        background({ AutofillVault.open(this)?.also(::stayUnlocked) }) { result ->
            val opened = result.getOrElse { return@background fail(getString(R.string.octapass_open_failed), it) }
                ?: return@background fail(getString(R.string.octapass_signed_out))
            vault = opened
            when {
                opened.isUnlocked -> onUnlocked(opened)
                opened.deviceUnlockAvailable && !passwordOnly -> unlockWithDevice(opened)
                else -> askPassword(opened, null)
            }
        }
    }

    /**
     * Stay unlocked (plan 18): the app's key for this account opens the store with no prompt. Never
     * for what asks for the master password every time ([passwordOnly]). Without the key, with the
     * 14-day check due or a key that no longer works, the vault stays locked and today's unlock
     * follows. Runs off the main thread.
     */
    private fun stayUnlocked(vault: AutofillVault) {
        if (passwordOnly) return
        runCatching { vault.unlockStayingUnlocked() }.onFailure { Log.w(TAG, "stay unlocked failed", it) }
    }

    override fun onDestroy() {
        super.onDestroy()
        val opened = vault
        work.execute { opened?.close() }
        work.shutdown()
    }

    /** Runs [task] off the main thread, then [done] on it. */
    protected fun <T> background(task: () -> T, done: (Result<T>) -> Unit) {
        work.execute {
            val result = runCatching(task)
            main.post { if (!isFinishing && !isDestroyed) done(result) }
        }
    }

    protected fun fail(message: String, error: Throwable? = null) {
        Log.w(TAG, message, error)
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        onCancelled()
    }

    /** A list to pick from; backing out is [onCancelled]. */
    protected fun choose(title: String, rows: List<Row>) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setItems(rows.map { it.label }.toTypedArray()) { _, index -> rows[index].pick() }
            .setOnCancelListener { onCancelled() }
            .show()
    }

    /** A login as a row: its title and user name, and the host it's saved for when that isn't this site. */
    protected fun loginRow(login: Login, host: String? = null): CharSequence {
        val name = listOfNotNull(login.title, login.username?.ifEmpty { null }).joinToString(" · ")
        if (host == null) return name
        return SpannableString("$name\n$host").apply { quieten(this, name.length + 1, length) }
    }

    /** Text that stays in the background: the entry for other parts of the site. */
    protected fun quiet(text: String): CharSequence = SpannableString(text).apply { quieten(this, 0, length) }

    private fun quieten(text: SpannableString, start: Int, end: Int) {
        val attributes = obtainStyledAttributes(intArrayOf(android.R.attr.textColorSecondary))
        val color = attributes.getColorStateList(0)?.defaultColor
        attributes.recycle()
        if (color != null) text.setSpan(ForegroundColorSpan(color), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
    }

    /**
     * The quiet entry ("Logins for other parts of example.com") that lists [others], each with its
     * host. Nothing is filled until the user picks one.
     */
    protected fun otherPartsRow(others: List<OtherPartLogin>, chosen: (OtherPartLogin) -> Unit): Row {
        val title = getString(R.string.octapass_other_parts, others.first().site)
        return Row(quiet(title)) { choose(title, others.map { other -> Row(loginRow(other.login, other.host)) { chosen(other) } }) }
    }

    /**
     * After the user filled [other] on [url], from another part of its domain: offers to add the
     * page's website to it, so it's suggested here next time. [done] runs either way (after the
     * save), so the fill goes through whatever the answer.
     */
    protected fun offerWebsite(vault: AutofillVault, other: OtherPartLogin, url: String, done: () -> Unit) {
        val host = AutofillVault.displayHost(url)
        if (!other.canAddWebsite || host == null) return done()
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.octapass_add_website, host))
            .setMessage(loginRow(other.login))
            .setPositiveButton(R.string.octapass_add) { _, _ ->
                background({ vault.addWebsite(other.login.itemId, url) }) { result ->
                    result.exceptionOrNull()?.let {
                        Log.w(TAG, "couldn't add the website", it)
                        Toast.makeText(this, R.string.octapass_save_failed, Toast.LENGTH_LONG).show()
                    }
                    done()
                }
            }
            .setNegativeButton(R.string.octapass_not_now) { _, _ -> done() }
            .setOnCancelListener { done() }
            .show()
    }

    private fun unlockWithDevice(vault: AutofillVault) {
        DevicePrompt(this).unlock(vault.account.deviceSecretName, getString(R.string.octapass_unlock_title), vault.account.email) { result ->
            result.fold(
                { secret ->
                    background({ vault.unlockWithDevice(secret) }) { unlocked ->
                        unlocked.exceptionOrNull()?.let { Log.w(TAG, "device unlock failed", it) }
                        if (unlocked.isSuccess) onUnlocked(vault) else askPassword(vault, getString(R.string.octapass_device_unlock_failed))
                    }
                },
                { error ->
                    if ((error as? DeviceUnlockException)?.reason == DeviceUnlockException.Reason.CANCELLED) {
                        onCancelled()
                    } else {
                        Log.w(TAG, "device unlock failed", error)
                        askPassword(vault, getString(R.string.octapass_device_unlock_failed))
                    }
                },
            )
        }
    }

    private fun askPassword(vault: AutofillVault, problem: String?) {
        val field = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = getString(R.string.octapass_master_password)
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(passwordTitle)
            .setMessage(problem ?: passwordMessage(vault))
            .setView(field)
            .setPositiveButton(passwordAction) { _, _ ->
                val password = field.text.toString()
                background({ vault.unlockWithPassword(password) }) { result ->
                    when (val error = result.exceptionOrNull()) {
                        null -> onUnlocked(vault)
                        is SignedOutException -> fail(getString(R.string.octapass_signed_out))
                        is OctaPassException.LoginFailed -> askPassword(vault, getString(R.string.octapass_wrong_password))
                        else -> askPassword(vault, error.message ?: getString(R.string.octapass_wrong_password))
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel) { _, _ -> onCancelled() }
            .setOnCancelListener { onCancelled() }
            .create()
        SecureWindow.apply(dialog.window, this)
        dialog.show()
        field.requestFocus()
    }
}
