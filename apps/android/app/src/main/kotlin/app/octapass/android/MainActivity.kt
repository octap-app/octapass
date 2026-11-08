package app.octap.android

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import app.octap.android.ui.AppRoot
import app.octap.android.platform.askForNotificationsOnce
import app.octap.android.vault.SecureWindow

/**
 * The one activity: every screen is Compose (`ui/`). It's `FLAG_SECURE` in release builds
 * ([SecureWindow]), hands the device-lock prompt its window, and takes one-time code links.
 */
class MainActivity : AppCompatActivity() {
    private val model get() = (application as OctaPassApp).model

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        SecureWindow.apply(window, this)
        // Other apps' autofill services never read or offer to save what's typed here: the master
        // password, the Secret Key and the vault's own fields.
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        model.platform.attach(this)
        takeLinks(intent)
        askForNotificationsOnce(this, model)
        setContent { AppRoot(model) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        takeLinks(intent)
    }

    override fun onResume() {
        super.onResume()
        model.platform.attach(this)
    }

    override fun onDestroy() {
        model.platform.detach(this)
        super.onDestroy()
    }

    /** Any touch or key restarts the auto-lock time. */
    override fun onUserInteraction() {
        super.onUserInteraction()
        model.vault.recordActivity()
    }

    /** `otpauth://` and `otpauth-migration://` links wait for the unlocked vault, which asks first. */
    private fun takeLinks(intent: Intent?) {
        val link = OpenedLinks.accepted(intent?.data?.toString()) ?: return
        model.openedLinks.value = model.openedLinks.value + link
        intent?.data = null
    }
}

/** The links Octa Pass takes from other apps (`src-tauri/src/links.rs`). */
object OpenedLinks {
    private val SCHEMES = setOf("otpauth", "otpauth-migration")

    /** A link is never kept longer than this; real ones are far shorter. */
    private const val MAX_LENGTH = 8 * 1024

    fun accepted(url: String?): String? {
        url ?: return null
        val scheme = url.substringBefore(':', "").lowercase()
        return url.takeIf { scheme in SCHEMES && it.length <= MAX_LENGTH }
    }
}
