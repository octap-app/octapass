package app.octap.android

import android.app.Application
import android.system.ErrnoException
import android.system.Os
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import app.octap.android.model.AppModel
import app.octap.android.platform.SafeDrives
import app.octap.vault.PlatformVerifier
import kotlinx.coroutines.launch

class OctaPassApp : Application() {
    @Volatile
    lateinit var model: AppModel
        private set

    /**
     * Null until [onCreate] has run. The system starts ContentProviders before that, and may call
     * them on another thread meanwhile; a vault that hasn't started has no Safes open anyway.
     */
    val safes: SafeDrives?
        get() = if (::model.isInitialized) model.safes else null

    override fun onCreate() {
        super.onCreate()
        // Rust's temporary folder. Older Android doesn't set this for an app, and the default
        // isn't writable. The Safe engine's staging and its uploads are all ciphertext.
        try {
            Os.setenv("TMPDIR", cacheDir.path, true)
        } catch (ignored: ErrnoException) {
        }
        PlatformVerifier.init(this)
        model = AppModel(this)
        Locales.apply(model.settings.value.language)
        // Before any push service runs: Firebase starts here or not at all (no FCM values, no push).
        model.push.start()
        // Auto-lock and "lock when Octa Pass is in the background" follow the whole app, not one screen.
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) {
                model.inSystemUi = false
                model.vault.appWillEnterForeground()
                // Stay unlocked (plan 18): a locked vault opens with no prompt when the app starts
                // or comes back, before the lock screen asks anything.
                model.scope.launch { model.unlockStayingUnlocked() }
            }

            override fun onStop(owner: LifecycleOwner) {
                // A picker, the camera or a file viewer Octa Pass opened isn't "in the background".
                if (model.inSystemUi) return
                model.vault.appDidEnterBackground()
                // Uses wait a few seconds to be saved together, and the app may not get those
                // seconds: save them now. Never before the lock above: a vault that locks forgets them.
                model.scope.launch { runCatching { model.vault.flushItemUses() } }
            }
        })
    }
}
