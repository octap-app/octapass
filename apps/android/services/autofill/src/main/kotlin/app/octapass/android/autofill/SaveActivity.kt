package app.octap.android.autofill

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import app.octap.android.vault.AutofillVault

/**
 * The fallback when the user taps Save on the system's "Save to Octa Pass?" sheet and the save
 * can't go into the inbox without unlocking ([OctaPassAutofillService.onSaveRequest]): no unlock on
 * this device has pinned the inbox key yet, or the inbox is full. Unlocks and saves the login (a
 * new one, or the new password of the login with that user name). The app uploads it on its next
 * sync.
 */
class SaveActivity : UnlockingActivity() {
    private val save by lazy { intent.getStringExtra(EXTRA_ID)?.let(PendingSaves::take) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (save == null) fail(getString(R.string.octapass_save_failed))
    }

    override fun onUnlocked(vault: AutofillVault) {
        val save = save ?: return fail(getString(R.string.octapass_save_failed))
        background({ vault.saveLogin(save.url, save.username, save.password, save.title) }) { result ->
            result.exceptionOrNull()?.let { Log.w(TAG, "saving a login failed", it) }
            val message = if (result.isSuccess) R.string.octapass_saved else R.string.octapass_save_failed
            Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            setResult(if (result.isSuccess) RESULT_OK else RESULT_CANCELED)
            finish()
        }
    }

    companion object {
        private const val EXTRA_ID = "save"

        fun intent(context: Context, id: String): Intent =
            Intent(context, SaveActivity::class.java).putExtra(EXTRA_ID, id).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
}
