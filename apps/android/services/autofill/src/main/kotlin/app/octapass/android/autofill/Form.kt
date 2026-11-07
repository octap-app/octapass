package app.octap.android.autofill

/** One view of the screen asking to be filled, as far as the parser needs it. */
interface FormNode {
    /** The view's `AutofillId`; null for views the framework can't fill. */
    val id: Any?
    val isTextField: Boolean
    val autofillHints: List<String>
    /** HTML `autocomplete`, `type`, `name` and `id`, for web views. */
    val htmlAttributes: Map<String, String>
    val inputType: Int
    val idEntry: String?
    val hint: String?
    val isFocused: Boolean
    val text: String?
    val webDomain: String?
    val webScheme: String?
    val children: List<FormNode>
}

enum class FieldKind { USERNAME, PASSWORD, NEW_PASSWORD, ONE_TIME_CODE }

data class Field(val id: Any, val kind: FieldKind, val text: String?, val focused: Boolean)

/** The login fields on a screen, and where it comes from. */
data class Form(
    val packageName: String,
    val webDomain: String?,
    val webScheme: String?,
    val fields: List<Field>,
) {
    fun ids(vararg kinds: FieldKind): List<Any> = fields.filter { it.kind in kinds }.map { it.id }

    val hasLogin get() = fields.any { it.kind == FieldKind.USERNAME || it.kind == FieldKind.PASSWORD }
    val hasNewPassword get() = fields.any { it.kind == FieldKind.NEW_PASSWORD }

    /**
     * What logins are matched against. A web page's domain counts only when [trustedBrowser]
     * shows it: any app can put a web view on screen with another site's page in it, so
     * elsewhere the app's own `androidapp://` identity is used (plan 05, *Filling rules*).
     */
    fun url(trustedBrowser: Boolean): String =
        if (trustedBrowser && webDomain != null) "${webScheme ?: "https"}://$webDomain" else "androidapp://$packageName"

    /** The values typed in, for saving: the user name may be on an earlier screen. */
    fun typed(kind: FieldKind): String? = fields.firstOrNull { it.kind == kind && !it.text.isNullOrEmpty() }?.text
}

/** Finds user name, password, new password and one-time code fields (plan 05). */
object FormParser {
    // android.text.InputType, inlined so the parser runs in JVM tests.
    private const val CLASS_MASK = 0x0000000f
    private const val VARIATION_MASK = 0x00000ff0
    private const val CLASS_TEXT = 0x00000001
    private const val CLASS_NUMBER = 0x00000002
    private val PASSWORD_VARIATIONS = setOf(0x00000080, 0x00000090, 0x000000e0)
    private val EMAIL_VARIATIONS = setOf(0x00000020, 0x000000d0)
    private const val NUMBER_PASSWORD = 0x00000010

    private val USERNAME_WORDS = listOf("user", "login", "email", "e-mail", "account", "identifier")
    private val PASSWORD_WORDS = listOf("pass", "pwd", "pin")
    private val NEW_PASSWORD_WORDS = listOf("new", "confirm", "repeat", "retype", "again", "verify")
    private val CODE_WORDS = listOf("otp", "one-time", "onetime", "2fa", "totp", "mfa", "verification", "authcode", "auth_code")
    private val IGNORED_WORDS = listOf("search", "captcha")

    fun parse(packageName: String, roots: List<FormNode>): Form {
        val nodes = roots.flatMap { flatten(it) }
        val web = nodes.firstOrNull { it.webDomain != null }
        val fields = mutableListOf<Field>()
        var lastText: FormNode? = null
        for (node in nodes) {
            val id = node.id ?: continue
            if (!node.isTextField) continue
            val kind = classify(node)
            if (kind == null) {
                if (!ignored(node)) lastText = node
                continue
            }
            // A password field without a user name field before it: the text field just before
            // the password is the user name, as on most sign-in forms.
            if (kind == FieldKind.PASSWORD && fields.none { it.kind == FieldKind.USERNAME }) {
                lastText?.let { previous -> previous.id?.let { fields += Field(it, FieldKind.USERNAME, previous.text, previous.isFocused) } }
            }
            fields += Field(id, kind, node.text, node.isFocused)
            lastText = null
        }
        return Form(packageName, web?.webDomain, web?.webScheme, newPasswords(fields))
    }

    private fun flatten(node: FormNode): List<FormNode> = listOf(node) + node.children.flatMap { flatten(it) }

    internal fun classify(node: FormNode): FieldKind? {
        hintKind(node.autofillHints)?.let { return it }
        autocompleteKind(node.htmlAttributes["autocomplete"])?.let { return it }
        val words = listOfNotNull(node.idEntry, node.hint, node.htmlAttributes["name"], node.htmlAttributes["id"])
            .joinToString(" ").lowercase()
        if (IGNORED_WORDS.any { it in words }) return null
        val htmlType = node.htmlAttributes["type"]?.lowercase()
        val inputClass = node.inputType and CLASS_MASK
        val variation = node.inputType and VARIATION_MASK
        val password = htmlType == "password" ||
            (inputClass == CLASS_TEXT && variation in PASSWORD_VARIATIONS) ||
            (inputClass == CLASS_NUMBER && variation == NUMBER_PASSWORD)
        return when {
            CODE_WORDS.any { it in words } -> FieldKind.ONE_TIME_CODE
            password && NEW_PASSWORD_WORDS.any { it in words } -> FieldKind.NEW_PASSWORD
            password -> FieldKind.PASSWORD
            htmlType == "email" || (inputClass == CLASS_TEXT && variation in EMAIL_VARIATIONS) -> FieldKind.USERNAME
            PASSWORD_WORDS.any { it in words } && htmlType != "hidden" && inputClass != CLASS_NUMBER -> FieldKind.PASSWORD
            USERNAME_WORDS.any { it in words } -> FieldKind.USERNAME
            else -> null
        }
    }

    private fun hintKind(hints: List<String>): FieldKind? {
        for (hint in hints.map { it.lowercase() }) {
            when (hint) {
                "username", "emailaddress", "email", "newusername", "phone" -> return FieldKind.USERNAME
                "password", "current-password" -> return FieldKind.PASSWORD
                "newpassword", "new-password" -> return FieldKind.NEW_PASSWORD
                "smsotpcode", "emailotpcode", "2faappotpcode", "one-time-code", "otp" -> return FieldKind.ONE_TIME_CODE
            }
            if (hint.startsWith("smsotpcode")) return FieldKind.ONE_TIME_CODE
        }
        return null
    }

    private fun autocompleteKind(autocomplete: String?): FieldKind? =
        autocomplete?.lowercase()?.split(' ')?.firstNotNullOfOrNull {
            when (it) {
                "username", "email" -> FieldKind.USERNAME
                "current-password" -> FieldKind.PASSWORD
                "new-password" -> FieldKind.NEW_PASSWORD
                "one-time-code" -> FieldKind.ONE_TIME_CODE
                else -> null
            }
        }

    private fun ignored(node: FormNode): Boolean {
        val words = listOfNotNull(node.idEntry, node.hint, node.htmlAttributes["name"]).joinToString(" ").lowercase()
        return IGNORED_WORDS.any { it in words } || node.htmlAttributes["type"]?.lowercase() in setOf("hidden", "search")
    }

    /**
     * Sign-in forms have one password field. Two are a new password and its confirmation (sign-up);
     * three or more are the current password, then the new one (change password).
     */
    private fun newPasswords(fields: List<Field>): List<Field> {
        val passwords = fields.filter { it.kind == FieldKind.PASSWORD }
        if (passwords.size < 2) return fields
        val current = if (passwords.size >= 3) passwords.first().id else null
        return fields.map { if (it.kind == FieldKind.PASSWORD && it.id != current) it.copy(kind = FieldKind.NEW_PASSWORD) else it }
    }
}
