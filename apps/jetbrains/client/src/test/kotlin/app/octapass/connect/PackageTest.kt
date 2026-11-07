// What must stay true of the project: both languages complete, no way to read a secret, and the
// client free of the IntelliJ Platform. It reads plugin/ as text, so it needs no SDK.

package app.octap.connect

import java.io.File
import java.util.Properties
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PackageTest {
    private val plugin = File("../plugin/src/main")
    private val messages = File(plugin, "resources/messages")

    private fun bundle(name: String) = Properties().apply { File(messages, name).inputStream().use(::load) }

    private fun sources(dir: File) = dir.walkTopDown().filter { it.extension == "kt" }.toList()

    private val pluginSources = sources(File(plugin, "kotlin"))

    private val placeholders = Regex("""\{\d+\}""")

    @Test
    fun `has the same keys and placeholders in both languages`() {
        val english = bundle("OctaPassBundle.properties")
        val arabic = bundle("OctaPassBundle_ar.properties")
        assertEquals(english.stringPropertyNames(), arabic.stringPropertyNames())
        for (key in english.stringPropertyNames()) {
            assertEquals(
                key,
                placeholders.findAll(english.getProperty(key)).map { it.value }.toList(),
                placeholders.findAll(arabic.getProperty(key)).map { it.value }.toList(),
            )
        }
    }

    @Test
    fun `really is Arabic`() {
        val arabic = bundle("OctaPassBundle_ar.properties")
        assertTrue(arabic.getProperty("error.locked").any { it in '؀'..'ۿ' })
    }

    @Test
    fun `defines every key the code uses`() {
        val english = bundle("OctaPassBundle.properties")
        val used = pluginSources
            .flatMap { Regex("""message\("([\w.]+)"""").findAll(it.readText()).map { match -> match.groupValues[1] }.toList() }
            .toSet()
        assertTrue(used.size > 15)
        assertEquals(emptySet<String>(), used - english.stringPropertyNames())
    }

    @Test
    fun `names every action in the bundle`() {
        val english = bundle("OctaPassBundle.properties")
        val actions = Regex("""<action id="([\w.]+)"""").findAll(File(plugin, "resources/META-INF/plugin.xml").readText())
            .map { it.groupValues[1] }
            .toList()
        assertEquals(5, actions.size)
        for (action in actions) {
            assertTrue(action, english.containsKey("action.$action.text"))
        }
    }

    @Test
    fun `never reads a secret value`() {
        for (file in pluginSources + sources(File("src/main/kotlin"))) {
            assertFalse(file.name, file.readText().contains("/v1/read"))
        }
    }

    @Test
    fun `keeps the client free of the IntelliJ Platform`() {
        for (file in sources(File("src/main/kotlin"))) {
            assertFalse(file.name, Regex("""import (com\.intellij|org\.jetbrains\.)""").containsMatchIn(file.readText()))
        }
    }

    @Test
    fun `keeps the token in PasswordSafe only`() {
        val session = pluginSources.first { it.name == "ConnectSession.kt" }.readText()
        assertTrue(session.contains("PasswordSafe.instance"))
        for (file in pluginSources) {
            assertFalse(file.name, Regex("""PropertiesComponent[^\n]*token""", RegexOption.IGNORE_CASE).containsMatchIn(file.readText()))
        }
    }

    @Test
    fun `opens no connection outside the client`() {
        for (file in pluginSources) {
            assertFalse(file.name, Regex("""java\.net\.|HttpClient|HttpRequests""").containsMatchIn(file.readText()))
        }
    }
}
