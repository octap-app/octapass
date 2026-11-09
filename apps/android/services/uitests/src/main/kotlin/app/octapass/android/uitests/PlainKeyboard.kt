package app.octap.android.uitests

import android.inputmethodservice.InputMethodService
import android.view.View

/**
 * A keyboard with no keys and no inline suggestions, selected while the tests run
 * (`scripts/ui-tests.sh`). With it, Android shows autofill suggestions in its dropdown,
 * which UI automation can read; Gboard draws them as chips in its own surface instead. Text is
 * typed with `adb shell input`.
 */
class PlainKeyboard : InputMethodService() {
    override fun onCreateInputView(): View = View(this)
}
