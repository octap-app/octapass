package app.octap.android

import android.content.Intent
import android.net.Uri
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.octap.android.TestSupport.model
import app.octap.vault.ItemDetails
import app.octap.vault.ItemFilter
import app.octap.vault.ItemType
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Group 4 (plan 17): one-time codes from links and QR codes, reviewed before they're saved. */
@RunWith(AndroidJUnit4::class)
class ScanTest {
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

    private fun codes() = runBlocking { model.vault.listItems(ItemFilter(null, null, null, false, false, false, true)) }

    @Test
    fun anOpenedLinkJoinsTheMatchingLoginAfterTheReview() {
        val github = runBlocking {
            val draft = newItemDraft(ItemType.Login, personal)
            val login = (draft.details as ItemDetails.Login).login.copy(username = "octo", password = "hunter2-hunter2")
            model.vault.saveItem(draft.copy(title = "GitHub", urls = listOf("https://github.com"), details = ItemDetails.Login(login))).id
        }
        // A website opens Octa Pass with a setup link: nothing is saved before the review.
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        context.startActivity(
            Intent(Intent.ACTION_VIEW, Uri.parse("otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"))
                .setClassName(context, MainActivity::class.java.name)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
        rule.waitFor("scanCodes.title")
        assertEquals(0, codes().size)
        rule.tap("scanCodes.continue")
        rule.waitFor("review.0")
        rule.tap("review.save")
        rule.waitUntil(20_000) { codes().map { it.id } == listOf(github) }
    }

    @Test
    fun aPastedSetupLinkBecomesItsOwnLogin() {
        rule.runOnUiThread {
            val nav = model.navigator("${model.session.value.email}@${model.session.value.serverUrl}")
            nav.push(app.octap.android.ui.vault.Route.ScanCodes(fromLink = false))
        }
        rule.type("scanCodes.link", "otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example")
        rule.tap("scanCodes.addLink")
        rule.tap("scanCodes.continue")
        rule.waitFor("review.0")
        rule.tap("review.save")
        rule.waitUntil(20_000) { codes().size == 1 }
        assertEquals("Example", codes().first().title)
    }
}
