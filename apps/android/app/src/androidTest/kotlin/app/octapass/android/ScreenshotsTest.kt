package app.octap.android

import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.octap.android.TestSupport.model
import app.octap.vault.ItemDetails
import app.octap.vault.ItemType
import app.octap.vault.LanguagePreference
import app.octap.vault.ThemePreference
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Screenshots of the main screens (list, item, generator, Health, Sharing, Settings, SSH keys and
 * environments, the lock screen) in both themes and in English and Arabic, and on a tablet-sized
 * display, into /sdcard/octapass-screenshots; scripts/ui-tests.sh pulls them. On its own:
 * `scripts/ui-tests.sh build/screenshots -Pandroid.testInstrumentationRunnerArguments.class=app.octap.android.ScreenshotsTest`.
 */
@RunWith(AndroidJUnit4::class)
class ScreenshotsTest {
    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    /** Runs a shell command and waits for it to end (its output closes then). */
    private fun shell(command: String) {
        android.os.ParcelFileDescriptor.AutoCloseInputStream(InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command)).use { it.readBytes() }
    }

    private fun shot(name: String) {
        rule.waitForIdle()
        Thread.sleep(800)
        TestSupport.screenshot(name)
    }

    @After
    fun reset() {
        shell("wm size reset")
        shell("wm density reset")
        model.updateSettings { it.copy(language = LanguagePreference.SYSTEM, theme = ThemePreference.SYSTEM) }
    }

    @Test
    fun mainScreens() {
        TestSupport.signOut()
        shot("01-sign-in")
        TestSupport.createAccount()
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
        val personal = runBlocking { model.vault.listVaults() }.first { it.vaultType == VaultType.PERSONAL }.id
        val github = runBlocking {
            fun login(title: String, user: String, url: String, totp: String? = null): String {
                val draft = newItemDraft(ItemType.Login, personal)
                val details = (draft.details as ItemDetails.Login).login.copy(username = user, password = "c0rrect-Horse-battery", totp = totp)
                return runBlocking { model.vault.saveItem(draft.copy(title = title, urls = listOf(url), details = ItemDetails.Login(details))).id }
            }
            login("GitHub", "octo@example.com", "https://github.com", "JBSWY3DPEHPK3PXP").also {
                login("GitHub work", "octo@work.example", "https://github.com")
                login("Bank", "me", "https://bank.example")
            }
        }
        runBlocking {
            val card = newItemDraft(ItemType.Card, personal)
            model.vault.saveItem(card.copy(title = "Visa", details = ItemDetails.Card((card.details as ItemDetails.Card).card.copy(cardholder = "Sam Doe", number = "4111111111111111", expiry = "08/29"))))
            val wifi = newItemDraft(ItemType.Wifi, personal)
            model.vault.saveItem(wifi.copy(title = "Home", details = ItemDetails.Wifi((wifi.details as ItemDetails.Wifi).wifi.copy(ssid = "HomeNet", password = "home-network-1"))))
        }
        val (sshKey, environment) = runBlocking {
            val key = newItemDraft(ItemType.SshKey, personal)
            val made = model.vault.generateSshKey(app.octap.vault.SshKeyKind.ED25519, "sam@laptop")
            val saved = model.vault.saveItem(key.copy(title = "Laptop key", details = ItemDetails.SshKey(app.octap.vault.withSshKey((key.details as ItemDetails.SshKey).key, made, null))))
            val env = newItemDraft(ItemType.Environment, personal)
            fun vars(vararg keys: String) = keys.map { app.octap.vault.EnvironmentVariable(it, "value", true, null) }
            model.vault.saveItem(env.copy(title = "Shop staging", details = ItemDetails.Environment(app.octap.vault.EnvironmentDetails("shop-api", null, "staging", vars("API_KEY", "DEBUG"), null))))
            saved.id to model.vault.saveItem(env.copy(title = "Shop production", details = ItemDetails.Environment(app.octap.vault.EnvironmentDetails("shop-api", null, "production", vars("API_KEY"), null)))).id
        }
        // SSH keys and environments.
        fun developerScreens(suffix: String) {
            rule.runOnUiThread { model.nav.open(app.octap.android.ui.vault.Route.Item(sshKey), false) }
            rule.waitFor("ssh.publicKey")
            shot("10-ssh-key$suffix")
            rule.runOnUiThread { model.nav.pop() }
            rule.runOnUiThread { model.nav.open(app.octap.android.ui.vault.Route.Item(environment), false) }
            rule.waitFor("reveal.env.API_KEY")
            shot("11-environment$suffix")
            rule.runOnUiThread { model.nav.pop() }
            rule.runOnUiThread { model.nav.showScope(app.octap.android.ui.vault.Scope.OfType(ItemType.Environment)) }
            rule.waitFor("row.$environment")
            shot("12-environments$suffix")
            rule.runOnUiThread { model.nav.showScope(app.octap.android.ui.vault.Scope.All) }
            rule.waitFor("list.title")
        }

        // The main screens in each language and theme: "", "-dark", "-arabic", "-dark-arabic".
        fun screens(suffix: String) {
            rule.runOnUiThread { model.nav.showScope(app.octap.android.ui.vault.Scope.All) }
            rule.waitFor("site.github.com")
            // The two GitHub logins share a row that opens in place.
            if (rule.onAllNodesWithTag("row.$github", useUnmergedTree = true).fetchSemanticsNodes().isEmpty()) rule.tap("site.github.com")
            rule.waitFor("row.$github")
            shot("02-list$suffix")
            rule.tap("row.$github")
            rule.waitFor("item.title")
            shot("03-item$suffix")
            rule.runOnUiThread { model.nav.reset(app.octap.android.ui.vault.Route.Generator) }
            rule.waitFor("generator.value")
            shot("08-generator$suffix")
            rule.runOnUiThread { model.nav.reset(app.octap.android.ui.vault.Route.Health) }
            rule.waitFor("health.score", 60_000)
            shot("09-health$suffix")
            rule.runOnUiThread { model.nav.reset(app.octap.android.ui.vault.Route.Sharing) }
            rule.waitFor("sharing.newVault")
            shot("13-sharing$suffix")
            rule.runOnUiThread { model.nav.reset(app.octap.android.ui.vault.Route.Settings) }
            rule.waitFor("settings.title")
            shot("06-settings$suffix")
            rule.runOnUiThread { model.nav.showScope(app.octap.android.ui.vault.Scope.All) }
            developerScreens(suffix)
        }

        fun language(language: LanguagePreference, direction: Int) {
            model.updateSettings { it.copy(language = language) }
            rule.waitUntil(10_000) { rule.activity.resources.configuration.layoutDirection == direction }
        }

        model.updateSettings { it.copy(theme = ThemePreference.LIGHT) }
        screens("")
        model.updateSettings { it.copy(theme = ThemePreference.DARK) }
        screens("-dark")
        language(LanguagePreference.AR, android.view.View.LAYOUT_DIRECTION_RTL)
        screens("-dark-arabic")
        model.updateSettings { it.copy(theme = ThemePreference.LIGHT) }
        screens("-arabic")

        // The lock screen, in Arabic and then English.
        runBlocking { model.vault.lock() }
        rule.waitFor("lock.password")
        shot("14-locked-arabic")
        language(LanguagePreference.EN, android.view.View.LAYOUT_DIRECTION_LTR)
        rule.waitFor("lock.password")
        shot("14-locked")
        runBlocking { model.vault.unlock(TestSupport.PASSWORD) }
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")

        // A large tablet: the sidebar beside the list, the item beside it.
        shell("wm size 2560x1600")
        shell("wm density 320")
        rule.waitUntil(10_000) { rule.activity.resources.configuration.screenWidthDp >= 840 }
        rule.waitFor("nav.all")
        rule.tap("nav.all")
        rule.waitFor("site.github.com")
        if (rule.onAllNodesWithTag("row.$github", useUnmergedTree = true).fetchSemanticsNodes().isEmpty()) rule.tap("site.github.com")
        rule.waitFor("row.$github")
        rule.tap("row.$github")
        rule.waitFor("item.title")
        shot("07-tablet")
    }
}
