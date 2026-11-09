package app.octap.android

import android.app.Activity
import android.app.Instrumentation
import android.content.Intent
import android.net.Uri
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.octap.android.TestSupport.model
import app.octap.android.ui.vault.Route
import app.octap.vault.ItemDetails
import app.octap.vault.ItemType
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Group 3 (plan 17): an item's files. One comes from the document picker, opens in the system
 * viewer as a read-only copy under its own name, and is removed after a confirm. The pickers and
 * the viewer are other apps, so the test answers for them ([SystemUi]); what the app hands the
 * viewer is read back to check it's the decrypted file.
 */
@RunWith(AndroidJUnit4::class)
class AttachmentsTest {
    @get:Rule(order = 0)
    val rule = createAndroidComposeRule<MainActivity>()

    // Inside the Compose rule, so the screen is still there when a test fails.
    @get:Rule(order = 1)
    val failures = ScreenshotOnFailure()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val system = SystemUi()
    private lateinit var item: String

    @Before
    fun account() {
        TestSupport.signOut()
        TestSupport.createAccount()
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
        item = runBlocking {
            val personal = model.vault.listVaults().first { it.vaultType == VaultType.PERSONAL }.id
            val draft = newItemDraft(ItemType.SecureNote, personal)
            model.vault.saveItem(draft.copy(title = "Lease", details = ItemDetails.SecureNote((draft.details as ItemDetails.SecureNote).note.copy(notes = "Flat 4")))).id
        }
        instrumentation.addMonitor(system)
    }

    @After
    fun tidy() {
        instrumentation.removeMonitor(system)
    }

    @Test
    fun aPickedFileOpensInTheViewerAndIsRemoved() {
        val picked = File(rule.activity.cacheDir, "lease.txt").apply { writeText("Lease agreement, flat 4") }
        system.pick = Uri.fromFile(picked)

        rule.runOnUiThread { model.nav.open(Route.Item(item), false) }
        rule.waitFor("item.title")
        rule.tap("files.pick")
        rule.waitUntil(30_000) { runBlocking { model.vault.getItem(item) }.attachments.any { it.name == "lease.txt" } }
        rule.waitFor("file.open.lease.txt")
        TestSupport.screenshot("70-files")

        // The viewer gets a content URI under the file's own name, read-only, holding the plaintext.
        rule.tap("file.open.lease.txt")
        rule.waitUntil(30_000) { system.viewed != null }
        val viewed = system.viewed!!
        assertEquals("content", viewed.data?.scheme)
        assertTrue(viewed.data.toString(), viewed.data.toString().endsWith("lease.txt"))
        assertTrue(viewed.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0)
        assertTrue(viewed.flags and Intent.FLAG_GRANT_WRITE_URI_PERMISSION == 0)
        assertEquals("Lease agreement, flat 4", system.viewedText)

        rule.tap("file.remove.lease.txt")
        rule.tap("file.removeConfirm")
        rule.waitUntil(30_000) { runBlocking { model.vault.getItem(item) }.attachments.isEmpty() }
        picked.delete()
    }

    /**
     * Answers for the system's document picker with [pick], and for the viewer: keeps the intent
     * it was sent and what its file held, read while the app still has it open.
     */
    private class SystemUi : Instrumentation.ActivityMonitor() {
        var pick: Uri? = null
        @Volatile var viewed: Intent? = null
        @Volatile var viewedText: String? = null

        override fun onStartActivity(intent: Intent): Instrumentation.ActivityResult? = when (intent.action) {
            Intent.ACTION_OPEN_DOCUMENT -> Instrumentation.ActivityResult(Activity.RESULT_OK, Intent().setData(pick))
            Intent.ACTION_VIEW -> {
                val context = InstrumentationRegistry.getInstrumentation().targetContext
                viewedText = intent.data?.let { uri -> context.contentResolver.openInputStream(uri)?.use { it.readBytes().decodeToString() } }
                viewed = intent
                Instrumentation.ActivityResult(Activity.RESULT_OK, null)
            }
            else -> null
        }
    }
}
