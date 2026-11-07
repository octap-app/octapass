package app.octap.connect

import org.junit.Assert.assertEquals
import org.junit.Test

class ReferencesTest {
    private fun item(vault: String, name: String, id: String, fields: List<String> = listOf("password")) =
        ItemRef(vault, name, id, "login", fields.map { ItemField(it, true) })

    @Test
    fun `encodes only percent and slash, percent first`() {
        assertEquals("CI%2FCD", encodePart("CI/CD"))
        assertEquals("100%25", encodePart("100%"))
        assertEquals("a%252Fb", encodePart("a%2Fb"))
        assertEquals("My Item: é", encodePart("My Item: é"))
    }

    @Test
    fun `encodes each part on its own`() {
        assertEquals("octapass://Work/Stripe/password", reference("Work", "Stripe", "password"))
        assertEquals("octapass://A%2FB/C%25D/E%2FF", reference("A/B", "C%D", "E/F"))
    }

    @Test
    fun `gives one row per field`() {
        val rows = fieldRows(listOf(item("Work", "Stripe", "id-1", listOf("username", "password"))))
        assertEquals(
            listOf("octapass://Work/Stripe/username", "octapass://Work/Stripe/password"),
            rows.map { it.reference },
        )
    }

    @Test
    fun `writes an id when two items in a vault share a name, whatever the case`() {
        val rows = fieldRows(listOf(item("Work", "Bank", "id-1"), item("Work", "BANK", "id-2"), item("Home", "Bank", "id-3")))
        assertEquals(
            listOf("octapass://Work/id-1/password", "octapass://Work/id-2/password", "octapass://Home/Bank/password"),
            rows.map { it.reference },
        )
        assertEquals("Bank", rows[0].item)
    }

    @Test
    fun `writes an id for an item with no name, and shows it`() {
        val row = fieldRows(listOf(item("Work", " ", "id-1"))).single()
        assertEquals("id-1", row.item)
        assertEquals("octapass://Work/id-1/password", row.reference)
    }

    @Test
    fun `leaves out a field no reference can name`() {
        val rows = fieldRows(listOf(item("Work", "Stripe", "id-1", listOf("", "  ", "key"))))
        assertEquals(listOf("key"), rows.map { it.field })
    }
}

class RunLineTest {
    @Test
    fun `leaves the command as typed`() {
        assertEquals(
            "octapass run -- npm start -- --port 3000",
            runLine("octapass", "  npm start -- --port 3000 ", "/bin/zsh", Os.MAC),
        )
    }

    @Test
    fun `falls back to octapass`() {
        assertEquals("octapass run -- x", runLine("  ", "x", "/bin/bash", Os.LINUX))
    }

    @Test
    fun `keeps a plain path and a home path unquoted`() {
        assertEquals("/opt/bin/octapass run -- x", runLine("/opt/bin/octapass", "x", "/bin/bash", Os.LINUX))
        assertEquals("~/bin/octapass run -- x", runLine("~/bin/octapass", "x", "/bin/bash", Os.LINUX))
    }

    @Test
    fun `quotes the program for the shell in use`() {
        assertEquals("'/my tools/it'\\''s/octapass' run -- x", runLine("/my tools/it's/octapass", "x", "/bin/zsh", Os.MAC))
        assertEquals("'\$(touch pwned)' run -- x", runLine("\$(touch pwned)", "x", "/bin/bash", Os.LINUX))
        val windows = "C:\\Program Files\\Octa Pass\\octapass.exe"
        assertEquals("\"$windows\" run -- x", runLine(windows, "x", "C:\\Windows\\System32\\cmd.exe", Os.WINDOWS))
        assertEquals("& '$windows' run -- x", runLine(windows, "x", "C:\\Program Files\\PowerShell\\7\\pwsh.exe", Os.WINDOWS))
        assertEquals("& '$windows' run -- x", runLine(windows, "x", "", Os.WINDOWS))
    }
}
