package app.octap.android

import android.app.Activity
import android.app.Instrumentation
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.octap.android.TestSupport.PASSWORD
import app.octap.android.TestSupport.model
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Local mode (plan 01): vaults on this phone with no account, their lock screen, switching and backups. */
@RunWith(AndroidJUnit4::class)
class LocalVaultTest {
    @get:Rule(order = 0)
    val rule = createAndroidComposeRule<MainActivity>()

    // Inside the Compose rule, so the screen is still there when a test fails.
    @get:Rule(order = 1)
    val failures = ScreenshotOnFailure()

    /** Creating runs Argon2id twice, at 256 MiB on a phone that can spare it. */
    private val slow = 120_000L

    @Before
    fun firstScreen() {
        TestSupport.signOut()
        removeLocalVaults()
        rule.waitFor("local.use")
    }

    @After
    fun tidy() {
        removeLocalVaults()
    }

    /** Local vaults outlive signing out, and the other tests start with none. */
    private fun removeLocalVaults() = runBlocking {
        val vault = model.vault
        for (local in vault.localVaults()) {
            vault.switchLocalVault(local.tag)
            vault.unlock(PASSWORD)
            vault.deleteLocalVault(PASSWORD)
        }
    }

    private fun createVault(name: String) {
        rule.tap("local.use")
        rule.type("local.name", name)
        rule.type("local.password", PASSWORD)
        rule.type("local.confirm", PASSWORD)
        rule.tap("local.create")
        rule.waitFor("local.code", slow)
        assertTrue(rule.textOf("local.code").isNotBlank())
        rule.tap("local.kitConfirm")
        rule.tap("local.kitContinue")
        rule.tap("local.firstBackupLater")
        waitForList()
    }

    private fun waitForList() {
        rule.waitFor("list.title", slow)
        dismissOffer()
    }

    /** The device unlock offer comes a moment after unlocking, where the phone has a screen lock. */
    private fun dismissOffer() {
        runCatching { rule.waitUntil(3_000) { rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty() } }
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
    }

    private fun unlock() {
        rule.type("lock.password", PASSWORD)
        rule.tap("lock.unlock")
        rule.waitUntil(slow) { rule.onAllNodesWithTag("lock.password").fetchSemanticsNodes().isEmpty() }
        dismissOffer()
    }

    private fun waitForText(text: String) {
        rule.waitUntil(20_000) { rule.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty() }
    }

    /** Answers the save dialog with [file], so the test needs no system UI. */
    private fun <T> savingTo(file: File, work: () -> T): T {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val answer = Instrumentation.ActivityResult(Activity.RESULT_OK, Intent().setData(Uri.fromFile(file)))
        val filter = IntentFilter(Intent.ACTION_CREATE_DOCUMENT, "application/octet-stream")
        val monitor = instrumentation.addMonitor(filter, answer, true)
        try {
            return work()
        } finally {
            instrumentation.removeMonitor(monitor)
        }
    }

    @Test
    fun createLockSwitchAndBackUp() {
        createVault("Home")
        assertTrue(model.isLocal)
        assertEquals("Home", model.session.value.email)

        // A login, in the editor as on any vault.
        rule.tap("list.add")
        rule.tap("new.login")
        rule.type("editor.title", "Forum")
        rule.type("editor.username", "reader")
        rule.type("editor.password", "correct-horse-battery")
        rule.type("editor.url.0", "forum.example")
        rule.tap("editor.save")
        rule.waitFor("item.title")
        rule.tap("item.back")

        // What an account has is gone from Settings; this vault's own section is there instead.
        rule.tap("tab.settings")
        rule.waitFor("settings.local")
        assertTrue(rule.onAllNodesWithTag("settings.showSecretKey").fetchSemanticsNodes().isEmpty())
        assertTrue(rule.onAllNodesWithTag("settings.signOut").fetchSemanticsNodes().isEmpty())

        // Locked, it asks for the master password and offers no sign-out or reset. The save's
        // message sits at the bottom of the screen, where the button scrolls to: let it go first.
        rule.waitUntil(30_000) { rule.onAllNodesWithText("saved", substring = true).fetchSemanticsNodes().isEmpty() }
        rule.tap("settings.lockNow")
        rule.waitFor("lock.password")
        assertTrue(rule.onAllNodesWithTag("lock.signOut").fetchSemanticsNodes().isEmpty())
        assertTrue(rule.onAllNodesWithTag("lock.forgotPassword").fetchSemanticsNodes().isEmpty())
        unlock()
        rule.tap("tab.items")
        waitForText("Forum")

        // A second vault, from the first screen, holds nothing of the first.
        val home = model.vault.localVaults().single().tag
        rule.tap("tab.settings")
        rule.tap("local.addVault")
        rule.waitFor("local.open.$home")
        createVault("Work")
        assertEquals("Work", model.session.value.email)
        assertTrue(rule.onAllNodesWithText("Forum").fetchSemanticsNodes().isEmpty())

        // Back to the first, with its own items. Under stay unlocked (plan 18, on by default, local
        // vaults included) it opens with no prompt; otherwise it asks for its master password.
        rule.tap("tab.settings")
        rule.tap("local.open.$home")
        rule.waitUntil(slow) { listOf("lock.password", "list.title").any { rule.onAllNodesWithTag(it).fetchSemanticsNodes().isNotEmpty() } }
        if (rule.onAllNodesWithTag("lock.password").fetchSemanticsNodes().isNotEmpty()) unlock()
        waitForList()
        assertEquals("Home", model.session.value.email)
        waitForText("Forum")

        // A backup to a file, after confirming it's the owner.
        val file = File(rule.activity.cacheDir, "test.octapass-backup").apply { delete() }
        savingTo(file) {
            rule.tap("tab.settings")
            rule.tap("local.backUp")
            rule.type("identity.password", PASSWORD)
            rule.tap("identity.ok")
            rule.waitUntil(slow) { model.vault.localVaults().first { it.current }.lastBackupAt != null }
            rule.waitUntil(20_000) { file.length() > 0 }
        }
        assertNotNull(model.vault.localVaults().first { it.current }.lastBackupAt)
        file.delete()
    }

    @Test
    fun sharingAsksForSync() {
        createVault("Home")
        rule.tap("list.menu")
        rule.tap("nav.sharing")
        rule.waitFor("needsSync.title")
        rule.tap("needsSync.turnOn")
        rule.waitFor("sync.email")
        rule.tap("sync.back")
        rule.waitFor("needsSync.title")
    }
}
