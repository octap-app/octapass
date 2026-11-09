package app.octap.android

import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.octap.android.TestSupport.PASSWORD
import app.octap.android.TestSupport.model
import app.octap.vault.ItemDetails
import app.octap.vault.ItemType
import app.octap.vault.LanguagePreference
import app.octap.vault.ThemePreference
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import app.octap.vault.totpCode
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Group 5 (plan 17): settings, two-step sign-in, sharing, families and share links. */
@RunWith(AndroidJUnit4::class)
class SettingsTest {
    @get:Rule(order = 0)
    val rule = createAndroidComposeRule<MainActivity>()

    // Inside the Compose rule, so the screen is still there when a test fails.
    @get:Rule(order = 1)
    val failures = ScreenshotOnFailure()

    @Before
    fun account() {
        TestSupport.signOut()
        TestSupport.createAccount()
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
    }

    @After
    fun englishAgain() {
        model.updateSettings { it.copy(language = LanguagePreference.SYSTEM, theme = ThemePreference.SYSTEM, stayUnlocked = true) }
    }

    private fun openSettings() {
        rule.tap("tab.settings")
        rule.waitFor("settings.title")
    }

    @Test
    fun themeLanguageAndAutoLock() {
        openSettings()
        rule.tap("settings.theme.2")
        rule.waitUntil(5_000) { model.settings.value.theme == ThemePreference.DARK }

        // Auto-lock is greyed out under stay unlocked, which is on by default.
        rule.runOnUiThread { model.updateSettings { it.copy(stayUnlocked = false) } }
        rule.tap("settings.autoLock")
        rule.tap("choice.5")
        rule.waitUntil(5_000) { model.settings.value.autoLockMinutes == 5u }

        // Arabic: the catalog's words, right to left.
        rule.tap("settings.language.ar")
        rule.waitUntil(10_000) { rule.activity.resources.configuration.layoutDirection == android.view.View.LAYOUT_DIRECTION_RTL }
        rule.waitUntil(10_000) { rule.onAllNodesWithText("الإعدادات").fetchSemanticsNodes().isNotEmpty() }
        assertEquals(LanguagePreference.AR, model.settings.value.language)
    }

    @Test
    fun devicesAndTheSecurityLog() {
        openSettings()
        rule.waitFor("settings.devices")
        rule.waitFor("devices.rename")
        rule.tap("settings.securityLog")
        rule.waitFor("securityLog.title")
    }

    @Test
    fun turnOnTwoStepSignIn() {
        openSettings()
        rule.tap("twoStep.turnOn")
        rule.type("twoStepSettings.password", PASSWORD)
        rule.tap("twoStepSettings.continue")
        val secret = rule.textOf("twoStepSettings.secret").replace(" ", "")
        rule.type("twoStepSettings.code", totpCode(secret, null).code)
        rule.tap("twoStepSettings.confirm")
        rule.waitFor("twoStepSettings.codes")
        rule.tap("twoStepSettings.saved")
        rule.tap("twoStepSettings.done")
        rule.waitUntil(20_000) { runBlocking { model.vault.twoStepStatus().enabled } }
        rule.waitFor("twoStep.turnOff")
    }

    @Test
    fun shareLinkFamilyAndSharedVault() {
        val personal = runBlocking { model.vault.listVaults() }.first { it.vaultType == VaultType.PERSONAL }.id
        val id = runBlocking {
            val draft = newItemDraft(ItemType.SecureNote, personal)
            model.vault.saveItem(draft.copy(title = "Door code", details = ItemDetails.SecureNote((draft.details as ItemDetails.SecureNote).note.copy(notes = "1234")))).id
        }
        // Share a copy: the link is made on the phone and listed in Sharing.
        rule.tap("row.$id")
        rule.tap("item.more")
        rule.tap("item.shareLink")
        rule.tap("shareLink.create")
        assertTrue(rule.textOf("shareLink.url").contains("#"))
        rule.tap("shareLink.done")
        rule.waitUntil(20_000) { runBlocking { model.vault.listShareLinks() }.size == 1 }

        // A family, and a shared vault from the sidebar.
        rule.tap("item.back")
        rule.tap("list.menu")
        rule.tap("nav.sharing")
        rule.tap("family.create")
        rule.waitUntil(20_000) { runBlocking { model.vault.getFamily() }.family != null }
        rule.tap("sharing.newVault")
        rule.type("newVault.name", "Household")
        rule.tap("newVault.create")
        rule.waitFor("members.title")
        rule.waitUntil(20_000) { runBlocking { model.vault.listVaults() }.any { it.vaultType == VaultType.SHARED && it.name == "Household" } }
    }
}
