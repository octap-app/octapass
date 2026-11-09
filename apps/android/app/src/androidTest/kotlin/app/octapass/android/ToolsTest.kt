package app.octap.android

import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.octap.android.TestSupport.model
import app.octap.vault.ItemDetails
import app.octap.vault.ItemType
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Group 4 (plan 17): the generator, Health with the recovery map, QR codes and masked email. */
@RunWith(AndroidJUnit4::class)
class ToolsTest {
    @get:Rule(order = 0)
    val rule = createAndroidComposeRule<MainActivity>()

    // Inside the Compose rule, so the screen is still there when a test fails.
    @get:Rule(order = 1)
    val failures = ScreenshotOnFailure()

    private lateinit var personal: String

    @Before
    fun account() {
        TestSupport.signOut()
        TestSupport.createAccount()
        personal = runBlocking { model.vault.listVaults() }.first { it.vaultType == VaultType.PERSONAL }.id
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
    }

    @Test
    fun generatorMakesPasswordsAndPassphrases() {
        // The generator is in the drawer; Safes has the tab.
        rule.tap("list.menu")
        rule.tap("nav.generator")
        rule.waitFor("generator.value")
        val first = rule.textOf("generator.value")
        rule.tap("generator.regenerate")
        rule.waitUntil(5_000) { rule.textOf("generator.value") != first }
        rule.tap("generator.passphrase")
        rule.waitUntil(5_000) { rule.textOf("generator.value").contains("-") }
        rule.tap("generator.copy")
        rule.tap("generator.password")
        assertNotEquals(first, rule.textOf("generator.value"))
    }

    @Test
    fun healthFindsAWeakPasswordAndTheRecoveryMap() {
        val weak = runBlocking {
            val draft = newItemDraft(ItemType.Login, personal)
            val login = (draft.details as ItemDetails.Login).login
            val recovery = app.octap.vault.RecoveryInfo("me@mail.example", null, null, null, emptyList(), emptyList(), null)
            model.vault.saveItem(draft.copy(title = "Weak", urls = listOf("https://weak.example"), details = ItemDetails.Login(login.copy(username = "me", password = "password1", recovery = recovery)))).id
        }
        rule.tap("tab.health")
        rule.waitFor("health.score", 60_000)
        // Each check's tile opens its own list.
        rule.tap("health.tile.Weak")
        rule.waitFor("health.check.Weak")
        rule.waitFor("health.entry.$weak", 60_000)
        TestSupport.device.pressBack()
        rule.waitFor("health.score", 60_000)
        rule.tap("health.recoveryMap")
        rule.waitFor("recoveryMap.title")
    }

    @Test
    fun wifiShowsConnectAndAQrCode() {
        val wifi = runBlocking {
            val draft = newItemDraft(ItemType.Wifi, personal)
            model.vault.saveItem(draft.copy(title = "Home", details = ItemDetails.Wifi((draft.details as ItemDetails.Wifi).wifi.copy(ssid = "HomeNet", password = "home-network-1")))).id
        }
        rule.tap("row.$wifi")
        rule.waitFor("wifi.connect")
        rule.tap("item.more")
        rule.tap("item.qr")
        // Wi-Fi joins show straight away, without asking for the device lock.
        rule.waitFor("qr.code")
        rule.tap("qr.close")
    }

    @Test
    fun aPasswordQrCodeShowsWhileTheVaultIsOpen() {
        val id = runBlocking {
            val draft = newItemDraft(ItemType.Password, personal)
            model.vault.saveItem(draft.copy(title = "Disk key", details = ItemDetails.Password((draft.details as ItemDetails.Password).login.copy(password = "correct-horse-battery")))).id
        }
        rule.tap("row.$id")
        rule.tap("item.more")
        rule.tap("item.qr")
        // The open vault covers it (maintainer decision, plan 03 History 2026-11-06).
        rule.waitFor("qr.code")
        assertTrue(rule.onAllNodesWithTag("qr.password").fetchSemanticsNodes().isEmpty())
        rule.tap("qr.close")
    }

    @Test
    fun maskedEmailOffersTheProviders() {
        rule.tap("list.menu")
        rule.tap("nav.maskedEmail")
        rule.waitFor("maskedEmail.providers")
        rule.waitFor("maskedEmail.provider")
        assertTrue(rule.onAllNodesWithTag("maskedEmail.connectButton").fetchSemanticsNodes().isNotEmpty())
    }
}
