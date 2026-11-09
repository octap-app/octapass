package app.octap.android

import androidx.compose.ui.test.assert
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.octap.android.TestSupport.model
import app.octap.android.vault.AutofillVault
import app.octap.android.vault.DeviceLock
import app.octap.vault.ItemDetails
import app.octap.vault.ItemType
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The autofill gate on the phone (plan 03, "Ask on every fill"), with stay unlocked off, on an
 * emulator with a screen lock (scripts/ui-tests.sh sets the PIN): on by default, so the
 * services find no fill key and ask; off, the switch shows its warning and the services fill with
 * no prompt while the app is unlocked; locking takes that away again. Under stay unlocked the
 * switch is greyed out.
 */
@RunWith(AndroidJUnit4::class)
class AutofillGateTest {
    @get:Rule(order = 0)
    val rule = createAndroidComposeRule<MainActivity>()

    // Inside the Compose rule, so the screen is still there when a test fails.
    @get:Rule(order = 1)
    val failures = ScreenshotOnFailure()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun account() {
        assumeTrue("needs a screen lock", DeviceLock.available(context))
        TestSupport.signOut()
        TestSupport.createAccount()
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
        runBlocking {
            val personal = model.vault.listVaults().first { it.vaultType == VaultType.PERSONAL }.id
            val draft = newItemDraft(ItemType.Login, personal)
            val login = (draft.details as ItemDetails.Login).login.copy(username = "gate", password = "filled-without-asking-31")
            model.vault.saveItem(draft.copy(title = "Gate", urls = listOf("https://gate.example"), details = ItemDetails.Login(login)))
            // Device unlock on: the gate has the screen lock to ask with (not the lockless rule).
            model.vault.enableDeviceUnlock()
        }
        rule.runOnUiThread { model.updateSettings { it.copy(stayUnlocked = false, deviceAuthOnAutofill = true) } }
    }

    @After
    fun restore() {
        rule.runOnUiThread { model.updateSettings { it.copy(stayUnlocked = true, deviceAuthOnAutofill = true) } }
    }

    private fun servicesOpenWithoutPrompt(): Boolean = AutofillVault.open(context)!!.use { it.unlockWithoutPrompt() }

    @Test
    fun theSwitchTurnsTheFillKeyOnAndOffAndLockingEndsIt() {
        assertTrue(model.settings.value.deviceAuthOnAutofill)
        assertFalse("every fill asks", servicesOpenWithoutPrompt())

        rule.tap("tab.settings")
        rule.waitFor("settings.title")
        rule.tap("settings.deviceAuthAutofill")
        rule.waitUntil(10_000) { !model.settings.value.deviceAuthOnAutofill && model.vault.fillsWithoutPrompt() }
        rule.waitFor("settings.deviceAuthAutofillOff")

        AutofillVault.open(context)!!.use {
            assertTrue(it.unlockWithoutPrompt())
            val found = it.logins(listOf("https://gate.example")).single()
            assertEquals("gate" to "filled-without-asking-31", it.credentials(found.itemId))
        }

        // A locked vault always asks.
        model.vault.lock()
        assertFalse(model.vault.fillsWithoutPrompt())
        assertFalse(servicesOpenWithoutPrompt())
    }

    @Test
    fun underStayUnlockedTheSwitchIsGreyedOut() {
        rule.runOnUiThread { model.updateSettings { it.copy(stayUnlocked = true, deviceAuthOnAutofill = false) } }
        rule.tap("tab.settings")
        rule.waitFor("settings.title")
        rule.waitFor("settings.stayUnlockedGates")
        // Greyed out: the row takes no taps.
        rule.tag("settings.deviceAuthAutofill").assert(hasClickAction().not())
        // Stay unlocked's own key fills: no fill key, and no warning about it.
        assertFalse(model.vault.fillsWithoutPrompt())
        assertTrue(rule.onAllNodesWithTag("settings.deviceAuthAutofillOff").fetchSemanticsNodes().isEmpty())
    }
}
