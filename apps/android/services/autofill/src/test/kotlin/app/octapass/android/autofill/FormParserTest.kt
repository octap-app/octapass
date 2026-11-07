package app.octap.android.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FormParserTest {
    private data class Node(
        override val id: Any? = Any(),
        override val isTextField: Boolean = true,
        override val autofillHints: List<String> = emptyList(),
        override val htmlAttributes: Map<String, String> = emptyMap(),
        override val inputType: Int = TEXT,
        override val idEntry: String? = null,
        override val hint: String? = null,
        override val isFocused: Boolean = false,
        override val text: String? = null,
        override val webDomain: String? = null,
        override val webScheme: String? = null,
        override val children: List<FormNode> = emptyList(),
    ) : FormNode

    private fun parse(vararg nodes: FormNode, domain: String? = null) =
        FormParser.parse("com.example", listOf(Node(id = null, isTextField = false, webDomain = domain, children = nodes.toList())))

    private fun Form.kinds() = fields.map { it.kind }

    @Test
    fun nativeHintsAndInputTypes() {
        val form = parse(
            Node(autofillHints = listOf("username")),
            Node(inputType = TEXT or PASSWORD_VARIATION),
            Node(idEntry = "otp_code", inputType = NUMBER),
        )
        assertEquals(listOf(FieldKind.USERNAME, FieldKind.PASSWORD, FieldKind.ONE_TIME_CODE), form.kinds())
        assertTrue(form.hasLogin)
        assertFalse(form.hasNewPassword)
    }

    @Test
    fun webAutocompleteAttributes() {
        val form = parse(
            Node(htmlAttributes = mapOf("type" to "email", "autocomplete" to "username")),
            Node(htmlAttributes = mapOf("type" to "password", "autocomplete" to "new-password")),
            Node(htmlAttributes = mapOf("autocomplete" to "one-time-code")),
            domain = "example.com",
        )
        assertEquals(listOf(FieldKind.USERNAME, FieldKind.NEW_PASSWORD, FieldKind.ONE_TIME_CODE), form.kinds())
    }

    @Test
    fun theFieldBeforeAPasswordIsTheUserName() {
        val user = Node(hint = "Phone or member number")
        val form = parse(user, Node(htmlAttributes = mapOf("type" to "password")))
        assertEquals(listOf(user.id, form.fields[1].id), form.fields.map { it.id })
        assertEquals(FieldKind.USERNAME, form.fields[0].kind)
    }

    @Test
    fun twoPasswordsAreANewOneAndThreeAChange() {
        val signUp = parse(Node(autofillHints = listOf("username")), Node(inputType = TEXT or PASSWORD_VARIATION), Node(inputType = TEXT or PASSWORD_VARIATION))
        assertEquals(listOf(FieldKind.USERNAME, FieldKind.NEW_PASSWORD, FieldKind.NEW_PASSWORD), signUp.kinds())
        val change = parse(
            Node(inputType = TEXT or PASSWORD_VARIATION),
            Node(inputType = TEXT or PASSWORD_VARIATION),
            Node(inputType = TEXT or PASSWORD_VARIATION),
        )
        assertEquals(listOf(FieldKind.PASSWORD, FieldKind.NEW_PASSWORD, FieldKind.NEW_PASSWORD), change.kinds().takeLast(3))
    }

    @Test
    fun searchBoxesAndHiddenOrUnfillableViewsAreSkipped() {
        val form = parse(
            Node(hint = "Search"),
            Node(id = null, autofillHints = listOf("password")),
            Node(isTextField = false, autofillHints = listOf("username")),
            Node(htmlAttributes = mapOf("type" to "hidden", "name" to "password_token")),
        )
        assertEquals(emptyList<FieldKind>(), form.kinds())
    }

    @Test
    fun webDomainsCountOnlyInTrustedBrowsers() {
        val form = parse(Node(htmlAttributes = mapOf("type" to "password")), domain = "accounts.example.com")
        assertEquals("https://accounts.example.com", form.url(trustedBrowser = true))
        assertEquals("androidapp://com.example", form.url(trustedBrowser = false))
        assertEquals("androidapp://com.example", parse(Node(htmlAttributes = mapOf("type" to "password"))).url(trustedBrowser = true))
    }

    @Test
    fun typedValuesForSaving() {
        val form = parse(Node(autofillHints = listOf("username"), text = "ada"), Node(inputType = TEXT or PASSWORD_VARIATION, text = "pw"))
        assertEquals("ada", form.typed(FieldKind.USERNAME))
        assertEquals("pw", form.typed(FieldKind.PASSWORD))
    }

    companion object {
        const val TEXT = 0x1
        const val NUMBER = 0x2
        const val PASSWORD_VARIATION = 0x80
    }
}
