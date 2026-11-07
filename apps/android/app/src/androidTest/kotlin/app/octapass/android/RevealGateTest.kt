package app.octap.android

import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.octap.android.TestSupport.PASSWORD
import app.octap.android.TestSupport.model
import app.octap.vault.ItemDetails
import app.octap.vault.ItemType
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * An open vault covers revealing and copying, however it was opened (maintainer decision, plan 03
 * History 2026-11-06); export still asks every time.
 */
@RunWith(AndroidJUnit4::class)
class RevealGateTest {
    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @get:Rule
    val failures = ScreenshotOnFailure()

    private lateinit var itemId: String

    @Before
    fun account() {
        TestSupport.signOut()
        // Made through the vault API, so this session wasn't opened on the lock screen.
        TestSupport.createAccount()
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
        itemId = runBlocking {
            val personal = model.vault.listVaults().first { it.vaultType == VaultType.PERSONAL }.id
            val draft = newItemDraft(ItemType.Login, personal)
            val login = (draft.details as ItemDetails.Login).login.copy(username = "ada", password = "shown-without-asking")
            model.vault.saveItem(draft.copy(title = "Gated", details = ItemDetails.Login(login))).id
        }
    }

    private fun unlockOnTheLockScreen() {
        model.vault.lock()
        rule.type("lock.password", PASSWORD)
        rule.tap("lock.unlock")
        rule.waitFor("list.title", 30_000)
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
    }

    private fun openItem() {
        rule.runOnUiThread { model.nav.open(app.octap.android.ui.vault.Route.Item(itemId), false) }
        rule.waitFor("reveal.password")
    }

    private fun gateShows() = rule.onAllNodesWithTag("gate.password").fetchSemanticsNodes().isNotEmpty()

    private fun revealAndCopyDontAsk() {
        openItem()
        rule.tap("reveal.password")
        rule.waitFor("password.value")
        assertTrue(rule.textOf("password.value").contains("shown-without-asking"))
        assertFalse("reveal asked", gateShows())
        rule.tap("copy.password")
        rule.waitForIdle()
        assertFalse("copy asked", gateShows())
    }

    @Test
    fun aVaultOpenedWithoutTheLockScreenDoesntAsk() {
        revealAndCopyDontAsk()
    }

    @Test
    fun aMasterPasswordUnlockCoversRevealAndCopyButNotExport() {
        unlockOnTheLockScreen()
        revealAndCopyDontAsk()

        // Export asks every time.
        rule.runOnUiThread { model.nav.pop() }
        rule.tap("tab.settings")
        rule.tap("settings.export")
        rule.tap("export.json")
        rule.tap("export.go")
        rule.waitFor("gate.password")
        rule.tap("gate.cancel")
    }

    @Test
    fun withTheAppOpenGateOffRevealDoesntAskEither() {
        rule.runOnUiThread { model.updateSettings { it.copy(deviceAuthOnOpen = false, stayUnlocked = false) } }
        try {
            unlockOnTheLockScreen()
            revealAndCopyDontAsk()
        } finally {
            rule.runOnUiThread { model.updateSettings { it.copy(deviceAuthOnOpen = true, stayUnlocked = true) } }
        }
    }
}
