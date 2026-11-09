package app.octap.android.uitests

import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPasswordOption
import androidx.credentials.PasswordCredential
import androidx.credentials.exceptions.GetCredentialException

/**
 * A plain native form for the Autofill tests: a sign-in form (user name and password) or, with
 * [EXTRA_SIGN_UP], a sign-up form (user name, new password and its confirmation). With
 * [EXTRA_CREDENTIAL_MANAGER] it also asks Credential Manager for a password when it opens, and
 * writes the answer in a line under the form (`result`): `user name / password`, or the error.
 * The app's own UI tests (`apps/android/app/src/androidTest`, `OtherAppsTest`) drive it from
 * outside, and UI automation reads a password field only as dots, so another line (`fields`)
 * repeats what the fields hold: `user name / password / confirmation`.
 */
class FormActivity : AppCompatActivity() {
    lateinit var username: EditText
    lateinit var password: EditText
    var confirmation: EditText? = null
    lateinit var result: TextView
    private lateinit var fields: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val signUp = intent.getBooleanExtra(EXTRA_SIGN_UP, false)
        val passwordHint = if (signUp) NEW_PASSWORD else View.AUTOFILL_HINT_PASSWORD
        username = field("Email", InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS, View.AUTOFILL_HINT_USERNAME)
        password = field("Password", InputType.TYPE_TEXT_VARIATION_PASSWORD, passwordHint)
        if (signUp) confirmation = field("Confirm password", InputType.TYPE_TEXT_VARIATION_PASSWORD, passwordHint)
        result = TextView(this).apply { contentDescription = "result" }
        fields = TextView(this).apply { contentDescription = "fields" }
        val repeat = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                fields.text = listOfNotNull(username, password, confirmation).joinToString(" / ") { it.text }
            }
        }
        listOfNotNull(username, password, confirmation).forEach { it.addTextChangedListener(repeat) }
        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                fitsSystemWindows = true
                setPadding(48, 96, 48, 48)
                listOfNotNull(username, password, confirmation, fields, result).forEach(::addView)
                // Nothing focused until a test taps a field, so no suggestion covers the next one.
                isFocusableInTouchMode = true
                requestFocus()
            },
        )
        if (intent.getBooleanExtra(EXTRA_CREDENTIAL_MANAGER, false)) askCredentialManager()
    }

    private fun askCredentialManager() {
        CredentialManager.create(this).getCredentialAsync(
            this,
            GetCredentialRequest(listOf(GetPasswordOption())),
            null,
            ContextCompat.getMainExecutor(this),
            object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                override fun onResult(result: GetCredentialResponse) {
                    val credential = result.credential as? PasswordCredential
                    this@FormActivity.result.text = credential?.let { "${it.id} / ${it.password}" } ?: "not a password"
                }

                override fun onError(e: GetCredentialException) {
                    this@FormActivity.result.text = "error: ${e.type}"
                }
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
        const val EXTRA_CREDENTIAL_MANAGER = "credentialManager"

        /** androidx `HintConstants.AUTOFILL_HINT_NEW_PASSWORD`. */
        private const val NEW_PASSWORD = "newPassword"
    }
}
