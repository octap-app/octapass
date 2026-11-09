package app.octap.android

import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.octap.android.TestSupport.PASSWORD
import app.octap.android.TestSupport.model
import app.octap.android.vault.AutofillVault
import app.octap.android.vault.DeviceLock
import app.octap.vault.ItemDetails
import app.octap.vault.ItemType
import app.octap.vault.SessionStatus
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
 * Stay unlocked while logged in to this phone (plan 18), on an emulator with a screen lock
 * (scripts/ui-tests.sh sets the PIN): the services fill with no prompt from the app's key
 * and fall back without it, "Lock now" holds, reveal and copy never ask while the vault is open
 * (maintainer decision, plan 03 History 2026-11-06), and export asks every time.
 */
@RunWith(AndroidJUnit4::class)
class StayUnlockedTest {
    @get:Rule(order = 0)
    val rule = createAndroidComposeRule<MainActivity>()

    // Inside the Compose rule, so the screen is still there when a test fails.
    @get:Rule(order = 1)
    val failures = ScreenshotOnFailure()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var itemId: String

    @Before
    fun account() {
        assumeTrue("needs a screen lock", DeviceLock.available(context))
        rule.runOnUiThread { model.updateSettings { it.copy(stayUnlocked = true) } }
        TestSupport.signOut()
        // Made through the vault API: the vault is open, but nobody answered a prompt.
        TestSupport.createAccount()
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
        itemId = runBlocking {
            val personal = model.vault.listVaults().first { it.vaultType == VaultType.PERSONAL }.id
            val draft = newItemDraft(ItemType.Login, personal)
            val login = (draft.details as ItemDetails.Login).login.copy(username = "stay", password = "shown-without-asking-77")
            model.vault.saveItem(draft.copy(title = "Stay", urls = listOf("https://stay.example"), details = ItemDetails.Login(login))).id
        }
        // Every unlock keeps the account's key, on its own thread.
        rule.waitUntil(10_000) { model.vault.stayUnlockedStatus().enrolled }
    }

    @After
    fun restore() {
        rule.runOnUiThread { model.updateSettings { it.copy(stayUnlocked = true) } }
    }

    @Test
    fun theServicesFillWithNoPromptAndFallBackWithoutTheKey() {
        AutofillVault.open(context)!!.use {
            assertTrue(it.unlockStayingUnlocked())
            assertTrue(it.isUnlocked)
            val found = it.logins(listOf("https://stay.example")).single()
            assertEquals("stay" to "shown-without-asking-77", it.credentials(found.itemId))
        }

        // Off: the key goes, and the services unlock as before.
        rule.runOnUiThread { model.updateSettings { it.copy(stayUnlocked = false) } }
        assertFalse(model.vault.stayUnlockedStatus().enrolled)
        AutofillVault.open(context)!!.use {
            assertFalse(it.unlockStayingUnlocked())
            assertFalse(it.isUnlocked)
        }
    }

    @Test
    fun lockNowHoldsUntilTheUserUnlocks() {
        model.vault.lock()
        assertFalse(runBlocking { model.unlockStayingUnlocked() })
        assertEquals(SessionStatus.LOCKED, model.vault.snapshot().status)
        rule.type("lock.password", PASSWORD)
        rule.tap("lock.unlock")
        rule.waitFor("list.title", 30_000)
        assertEquals(SessionStatus.UNLOCKED, model.vault.snapshot().status)
    }

    @Test
    fun revealAndCopyNeverAskWhileItsOpen() {
        rule.runOnUiThread { model.nav.open(app.octap.android.ui.vault.Route.Item(itemId), false) }
        rule.tap("reveal.password")
        rule.waitFor("password.value")
        assertTrue(rule.textOf("password.value").contains("shown-without-asking-77"))
        assertFalse("reveal asked", gateShows())
        rule.tap("copy.password")
        rule.waitForIdle()
        assertFalse("copy asked", gateShows())

        // The screen turning off doesn't change that: the vault is still open.
        model.phoneLocked()
        rule.tap("reveal.password")
        rule.tap("reveal.password")
        rule.waitForIdle()
        assertFalse("reveal asked after the screen turned off", gateShows())
    }

    @Test
    fun exportAsksEveryTime() {
        rule.tap("tab.settings")
        rule.tap("settings.export")
        rule.tap("export.json")
        rule.tap("export.go")
        rule.waitFor("gate.password")
        rule.tap("gate.cancel")
    }

    @Test
    fun settingsGreyTheGatesWhileItsOn() {
        rule.tap("tab.settings")
        rule.waitFor("settings.stayUnlocked")
        rule.waitFor("settings.stayUnlockedGates")
        rule.tap("settings.stayUnlocked")
        rule.waitUntil(10_000) { !model.settings.value.stayUnlocked }
        rule.waitUntil(10_000) { rule.onAllNodesWithTag("settings.stayUnlockedGates").fetchSemanticsNodes().isEmpty() }
        assertFalse(model.vault.stayUnlockedStatus().enrolled)
    }

    private fun gateShows() = rule.onAllNodesWithTag("gate.password").fetchSemanticsNodes().isNotEmpty()
}
