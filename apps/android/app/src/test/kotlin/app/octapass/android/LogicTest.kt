package app.octap.android

import app.octap.android.platform.AndroidPlatform
import app.octap.android.platform.FileNames
import app.octap.android.platform.SafeDocuments
import app.octap.android.platform.WifiConnect
import app.octap.android.platform.WifiReading
import app.octap.android.ui.auth.isSecureServerUrl
import app.octap.android.ui.auth.isValidEmail
import app.octap.android.ui.auth.normalizeEmail
import app.octap.android.ui.components.hueFor
import app.octap.android.ui.util.Formats
import app.octap.android.ui.vault.DEFAULT_MATCH_MODE
import app.octap.android.ui.vault.Route
import app.octap.android.ui.vault.Scope
import app.octap.android.ui.vault.Tab
import app.octap.android.ui.vault.VaultNavigator
import app.octap.android.ui.vault.formatCardNumber
import app.octap.android.ui.vault.formatCode
import app.octap.android.ui.vault.matchHelpRes
import app.octap.android.ui.vault.matchModeRes
import app.octap.android.ui.vault.parseTags
import app.octap.android.ui.vault.typeKey
import app.octap.android.ui.vault.typeOf
import app.octap.android.ui.vault.urlMatchAfterEdit
import app.octap.android.ui.vault.urlMatchAfterRemove
import app.octap.resources.R
import app.octap.vault.CredentialIdentity
import app.octap.vault.ItemType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.Locale

class LogicTest {
    @Test
    fun safeDocumentIds() {
        val id = SafeDocuments.documentId("0191-item", "0000-object")
        assertEquals("0191-item:0000-object", id)
        assertEquals("0191-item" to "0000-object", SafeDocuments.parse(id))
        assertNull(SafeDocuments.parse("no-separator"))
        assertNull(SafeDocuments.parse(":object"))
        assertNull(SafeDocuments.parse("item:"))
        assertNull(SafeDocuments.parse("item:a:b"))
    }

    @Test
    fun safeDocumentNames() {
        assertEquals("a.txt", SafeDocuments.uniqueName("a.txt", setOf("b.txt")))
        assertEquals("a (2).txt", SafeDocuments.uniqueName("a.txt", setOf("a.txt")))
        assertEquals("a (3).txt", SafeDocuments.uniqueName("a.txt", setOf("a.txt", "a (2).txt")))
        assertEquals("Scans (2)", SafeDocuments.uniqueName("Scans", setOf("Scans")))
        assertEquals(".env (2)", SafeDocuments.uniqueName(".env", setOf(".env")))
        assertEquals("notes.txt", SafeDocuments.withExtension("notes", "txt"))
        assertEquals("NOTES.TXT", SafeDocuments.withExtension("NOTES.TXT", "txt"))
        assertEquals("notes", SafeDocuments.withExtension("notes", null))
    }

    @Test
    fun onlyOneTimeCodeLinksAreTaken() {
        assertEquals("otpauth://totp/A?secret=JBSW", OpenedLinks.accepted("otpauth://totp/A?secret=JBSW"))
        assertEquals("otpauth-migration://offline?data=x", OpenedLinks.accepted("otpauth-migration://offline?data=x"))
        assertNull(OpenedLinks.accepted("https://example.com"))
        assertNull(OpenedLinks.accepted(null))
        assertNull(OpenedLinks.accepted("otpauth://" + "a".repeat(9000)))
    }

    @Test
    fun wifiReadings() {
        assertEquals("Home", WifiReading.ssid("\"Home\""))
        assertNull(WifiReading.ssid("<unknown ssid>"))
        assertNull(WifiReading.ssid("0x"))
        assertEquals(100, WifiReading.signal(-40))
        assertEquals(0, WifiReading.signal(-110))
        assertEquals(listOf("A" to 80, "B" to 40), WifiReading.sightings(listOf("A" to -70, "A" to -60, "B" to -80, null to -30, "" to -30)).map { it.ssid to it.signal })
        assertEquals(listOf(1, 2, 3, 4), listOf(10, 30, 60, 90).map(WifiReading::bars))
    }

    @Test
    fun wifiConnectChoices() {
        assertEquals(0, WifiConnect.eapMethod("peap"))
        assertNull(WifiConnect.eapMethod("leap"))
        assertEquals(3, WifiConnect.phase2("peap", null))
        assertEquals(4, WifiConnect.phase2("ttls", "gtc"))
        assertNull(WifiConnect.phase2("pwd", "gtc"))
        assertEquals(WifiConnect.Outcome.ADDED, WifiConnect.outcome(emptyList()))
        assertTrue(WifiConnect.enterprise("wpa3Enterprise"))
        assertFalse(WifiConnect.enterprise("wpa2"))
    }

    @Test
    fun fileNames() {
        assertEquals("a_b", FileNames.safe("a/b"))
        assertEquals("file", FileNames.safe("..."))
        val folder = Files.createTempDirectory("names").toFile()
        File(folder, "scan.pdf").writeText("x")
        assertEquals("scan 2.pdf", FileNames.unique(folder, "scan.pdf").name)
        assertEquals("PDF", FileNames.kind("scan.pdf", ""))
        assertEquals("PNG", FileNames.kind("image", "image/png"))
        folder.deleteRecursively()
    }

    @Test
    fun formats() {
        assertEquals("820 B", Formats.bytes(820, Locale.ENGLISH))
        assertEquals("1.5 KB", Formats.bytes(1536, Locale.ENGLISH))
        assertEquals("1,234", Formats.number(1234, Locale.ENGLISH))
        // Arabic keeps Western digits, as the web vault shows them.
        assertTrue(Formats.number(1234, Locale.forLanguageTag("ar")).contains("1"))
        assertEquals("123 456", formatCode("123456"))
        assertEquals("4111 1111 1111 1111", formatCardNumber("4111111111111111"))
        assertEquals(listOf("work", "travel"), parseTags(" work, travel ,, work"))
    }

    @Test
    fun matchModesFollowTheirUrl() {
        val modes = mapOf("a.example" to "host")
        assertEquals(mapOf("ab.example" to "host"), urlMatchAfterEdit(modes, listOf("a.example"), 0, "ab.example"))
        assertEquals(modes, urlMatchAfterEdit(modes, listOf("a.example", "b.example"), 1, "c.example"))
        assertEquals(emptyMap<String, String>(), urlMatchAfterRemove(modes, listOf("a.example", "b.example"), 0))
        // Keyed by the text, so a second row with the same text keeps the mode.
        assertEquals(modes, urlMatchAfterRemove(modes, listOf("a.example", "a.example"), 0))
        assertEquals(modes + ("c.example" to "host"), urlMatchAfterEdit(modes, listOf("a.example", "a.example"), 1, "c.example"))
    }

    @Test
    fun theDefaultMatchModeIsTheSiteAndItsSubdomains() {
        assertEquals("subdomains", DEFAULT_MATCH_MODE)
        assertEquals(R.string.editor_match_subdomains, matchModeRes(DEFAULT_MATCH_MODE))
        assertEquals(R.string.editor_match_baseDomain, matchModeRes("baseDomain"))
        assertEquals(R.string.editor_matchHelp_subdomains, matchHelpRes("subdomains"))
        assertEquals(R.string.editor_matchHelp_baseDomain, matchHelpRes("baseDomain"))
        assertEquals(R.string.editor_matchRegexWarning, matchHelpRes("regex"))
        assertNull(matchHelpRes("host"))
    }

    @Test
    fun signInChecks() {
        assertTrue(isValidEmail("me@example.com"))
        assertFalse(isValidEmail("me@example"))
        assertEquals("me@example.com", normalizeEmail("  Me@Example.com "))
        assertTrue(isSecureServerUrl("https://vault.example.com"))
        assertTrue(isSecureServerUrl("http://localhost:8080"))
        assertFalse(isSecureServerUrl("http://vault.example.com"))
    }

    @Test
    fun scopesAndTypes() {
        assertEquals("v-abc", Scope.InVault("abc").countKey)
        assertEquals("vault", Scope.InVault("abc").view)
        assertEquals("wifi", Scope.OfType(ItemType.Wifi).view)
        assertTrue(Scope.Codes.filter(null).totp)
        assertEquals("query", Scope.Trash.filter(" query ".trim()).query)
        assertTrue(Scope.Trash.filter("").trash)
        assertNull(Scope.All.filter("  ").query)
        for (type in listOf(ItemType.Login, ItemType.Card, ItemType.Wifi, ItemType.Document)) assertEquals(type, typeOf(typeKey(type)))
        assertEquals(hueFor("GitHub"), hueFor("github"))
    }

    @Test
    fun navigatorKeepsOneStackPerTab() {
        val nav = VaultNavigator()
        nav.open(Route.Item("a"), twoPane = false)
        assertEquals(Route.Item("a"), nav.top)
        nav.close(twoPane = false)
        assertEquals(Route.Items(Scope.All), nav.top)
        // Wide screens open an item beside the list.
        nav.open(Route.Item("b"), twoPane = true)
        assertEquals(Route.Item("b"), nav.detail)
        assertEquals(1, nav.stack.size)
        nav.close(twoPane = true)
        assertNull(nav.detail)
        nav.showScope(Scope.Favorites)
        nav.select(Tab.Safes)
        assertEquals(Tab.Safes, nav.tab)
        nav.select(Tab.Items)
        assertEquals(Route.Items(Scope.All), nav.top)
        assertFalse(nav.pop())
    }

    @Test
    fun pinnedIsAFilterOfItsOwn() {
        val filter = Scope.Pinned.filter(" bank ")
        assertTrue(filter.pinned)
        assertFalse(filter.favorites)
        assertEquals("bank", filter.query?.trim())
        assertEquals("pinned", Scope.Pinned.view)
        assertEquals("pinned", Scope.Pinned.countKey)
        assertFalse(Scope.Favorites.filter(null).pinned)
    }

    @Test
    fun credentialListForTheServices() {
        val json = AndroidPlatform.identitiesJson(
            listOf(
                CredentialIdentity.Password("1", "https://a.example", "me"),
                CredentialIdentity.Passkey("2", "a.example", "me", byteArrayOf(1, 2, 3), byteArrayOf(4)),
            ),
        )
        assertEquals("password", json.getJSONObject(0).getString("kind"))
        assertEquals("AQID", json.getJSONObject(1).getString("credentialId"))
        assertEquals("BA", json.getJSONObject(1).getString("userHandle"))
    }
}
