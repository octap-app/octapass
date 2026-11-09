package app.octap.android

import android.app.Activity
import android.app.Instrumentation
import android.content.Intent
import android.net.Uri
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.octap.android.TestSupport.PASSWORD
import app.octap.android.TestSupport.model
import app.octap.android.ui.vault.Route
import app.octap.vault.SessionStatus
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Groups 5 and 6 (plan 17): a trusted contact for emergency access, an import from a Chrome CSV
 * file, and deleting the account down to the goodbye screen.
 */
@RunWith(AndroidJUnit4::class)
class AccountTest {
    @get:Rule(order = 0)
    val rule = createAndroidComposeRule<MainActivity>()

    // Inside the Compose rule, so the screen is still there when a test fails.
    @get:Rule(order = 1)
    val failures = ScreenshotOnFailure()

    private lateinit var email: String

    @Before
    fun account() {
        TestSupport.signOut()
        email = TestSupport.newEmail()
        TestSupport.createAccount(email)
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
    }

    @Test
    fun aTrustedContactIsAddedAfterTheFingerprint() {
        // The contact's account, made and left on the server.
        val contact = TestSupport.newEmail()
        TestSupport.signOut()
        TestSupport.createAccount(contact)
        TestSupport.signOut()
        TestSupport.createAccount(email.replace("android-", "android-a-"))
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")

        rule.runOnUiThread { model.nav.reset(Route.Emergency) }
        rule.waitFor("emergency.title")
        rule.type("finder.email", contact)
        rule.tap("finder.find")
        // Their fingerprint, compared before adding them.
        rule.tap("finder.matches")
        TestSupport.screenshot("75-emergency-add")
        rule.tap("finder.submit")
        rule.waitUntil(30_000) { runBlocking { model.vault.listEmergencyContacts() }.granted.any { it.contactEmail == contact } }
    }

    @Test
    fun aChromeExportIsImported() {
        val csv = File(rule.activity.cacheDir, "chrome.csv").apply {
            writeText("name,url,username,password,note\nForum,https://forum.example,ada,imported-Passw0rd-1,\n")
        }
        // Answers for the system's document picker. Matched by action alone: an IntentFilter
        // without the picker's MIME type wouldn't match it.
        val picker = object : Instrumentation.ActivityMonitor() {
            override fun onStartActivity(intent: Intent): Instrumentation.ActivityResult? =
                if (intent.action == Intent.ACTION_OPEN_DOCUMENT) Instrumentation.ActivityResult(Activity.RESULT_OK, Intent().setData(Uri.fromFile(csv))) else null
        }
        InstrumentationRegistry.getInstrumentation().addMonitor(picker)
        try {
            rule.runOnUiThread { model.nav.reset(Route.Import) }
            rule.waitFor("import.title")
            // Chrome is the first choice.
            rule.tap("import.file")
            rule.waitUntil(10_000) { rule.textOf("import.file").contains("chrome.csv") }
            rule.tap("import.go")
            rule.waitFor("import.result", 30_000)
            TestSupport.screenshot("76-imported")
            val found = runBlocking { model.vault.listItems(app.octap.vault.ItemFilter(null, null, "Forum", false, false, false, false)) }
            assertEquals(listOf("Forum"), found.map { it.title })
        } finally {
            InstrumentationRegistry.getInstrumentation().removeMonitor(picker)
            csv.delete()
        }
    }

    @Test
    fun deletingTheAccountEndsOnTheGoodbyeScreen() {
        rule.tap("tab.settings")
        rule.waitFor("settings.title")
        rule.tap("settings.deleteAccount")
        rule.tap("delete.continue")
        rule.type("delete.email", email)
        rule.type("delete.password", PASSWORD)
        rule.tap("delete.confirm")
        rule.waitFor("deleted.back", 30_000)
        TestSupport.screenshot("77-account-deleted")
        assertEquals(SessionStatus.SIGNED_OUT, model.vault.snapshot().status)
        rule.tap("deleted.back")
        rule.waitUntil(10_000) { rule.onAllNodesWithTag("deleted.back").fetchSemanticsNodes().isEmpty() }
    }
}
