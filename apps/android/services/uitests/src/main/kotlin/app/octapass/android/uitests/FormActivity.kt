package app.octap.android.uitests

import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import androidx.appcompat.app.AppCompatActivity

/**
 * A plain native form for the Autofill tests: a sign-in form (user name and password) or, with
 * [EXTRA_SIGN_UP], a sign-up form (user name, new password and its confirmation).
 */
class FormActivity : AppCompatActivity() {
    lateinit var username: EditText
    lateinit var password: EditText
    var confirmation: EditText? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val signUp = intent.getBooleanExtra(EXTRA_SIGN_UP, false)
        val passwordHint = if (signUp) NEW_PASSWORD else View.AUTOFILL_HINT_PASSWORD
        username = field("Email", InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS, View.AUTOFILL_HINT_USERNAME)
        password = field("Password", InputType.TYPE_TEXT_VARIATION_PASSWORD, passwordHint)
        if (signUp) confirmation = field("Confirm password", InputType.TYPE_TEXT_VARIATION_PASSWORD, passwordHint)
        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                fitsSystemWindows = true
                setPadding(48, 96, 48, 48)
                listOfNotNull(username, password, confirmation).forEach(::addView)
                // Nothing focused until a test taps a field, so no suggestion covers the next one.
                isFocusableInTouchMode = true
                requestFocus()
            },
        )
    }

    private fun field(label: String, variation: Int, hint: String) = EditText(this).apply {
        this.hint = label
        inputType = InputType.TYPE_CLASS_TEXT or variation
        setAutofillHints(hint)
    }

    companion object {
        const val EXTRA_SIGN_UP = "signUp"

        /** androidx `HintConstants.AUTOFILL_HINT_NEW_PASSWORD`. */
        private const val NEW_PASSWORD = "newPassword"
    }
}
