package app.octap.android

import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Until
import app.octap.android.TestSupport.device
import app.octap.android.TestSupport.model
import app.octap.android.vault.DeviceLock
import app.octap.vault.ItemDetails
import app.octap.vault.ItemType
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Group 6 (plan 17): Octa Pass fills another app, as the smoke tests did for the Tauri app. The
 * other app is the test app in `services/uitests` (`app.octap.android.test`, which
 * scripts/ui-tests.sh installs): a sign-in form, a sign-up form and a Credential Manager request.
 * The emulator needs the screen lock the script sets, since "Ask on every fill" asks for it.
 *
 * The credential transfer tests of the old smoke tests aren't here: they need Google Play
 * services 25.38 or later, which the Google APIs emulator images don't have.
 */
@RunWith(AndroidJUnit4::class)
class OtherAppsTest {
    @get:Rule(order = 0)
    val rule = createAndroidComposeRule<MainActivity>()

    // Inside the Compose rule, so the screen is still there when a test fails.
    @get:Rule(order = 1)
    val failures = ScreenshotOnFailure()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val app get() = context.packageName

    @Before
    fun account() {
        // The shell sees every package; the app's own package manager doesn't (package visibility).
        assumeTrue("needs the test app (scripts/ui-tests.sh installs it)", shell("pm list packages $OTHER_APP").lines().any { it.trim() == "package:$OTHER_APP" })
        assumeTrue("needs a screen lock", DeviceLock.available(context))
        TestSupport.signOut()
        TestSupport.createAccount()
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
        runBlocking {
            val personal = model.vault.listVaults().first { it.vaultType == VaultType.PERSONAL }.id
            val draft = newItemDraft(ItemType.Login, personal)
            val login = (draft.details as ItemDetails.Login).login.copy(username = USERNAME, password = PASSWORD)
            model.vault.saveItem(draft.copy(title = "Test app", urls = listOf("androidapp://$OTHER_APP"), details = ItemDetails.Login(login)))
            model.vault.enableDeviceUnlock()
        }
        // Every fill asks for the device lock (the default when stay unlocked is off).
        rule.runOnUiThread { model.updateSettings { it.copy(stayUnlocked = false, deviceAuthOnAutofill = true) } }
        shell("settings put secure autofill_service $app/$AUTOFILL_SERVICE")
        // A keyboard without inline suggestions, so they show in the dropdown UI automation reads.
        shell("ime enable $KEYBOARD")
        shell("ime set $KEYBOARD")
    }

    @After
    fun restore() {
        shell("ime reset")
        shell("am force-stop $OTHER_APP")
        rule.runOnUiThread { model.updateSettings { it.copy(stayUnlocked = true, deviceAuthOnAutofill = true) } }
    }

    @Test
    fun fillsASignInFormAfterTheDeviceLock() {
        openForm()
        device.wait(Until.findObject(By.pkg(OTHER_APP).hint("Email")), TIMEOUT)!!.click()
        pick(SUGGESTION, "71-autofill-suggestion")
        TestSupport.enterPin()
        assertEquals("$USERNAME / $PASSWORD", waitForFields { it.startsWith(USERNAME) })
        TestSupport.screenshot("72-autofill-filled")
    }

    @Test
    fun suggestsAStrongPasswordOnASignUpForm() {
        openForm("signUp true")
        device.wait(Until.findObject(By.pkg(OTHER_APP).hint("Password")), TIMEOUT)!!.click()
        pick(SUGGESTED_PASSWORD, "73-autofill-suggested-password")
        // " / new password / confirmation": both password fields get the same strong one.
        val fields = waitForFields { it.split(" / ").getOrNull(1).orEmpty().isNotEmpty() }.split(" / ")
        assertTrue(fields.toString(), fields[1].length >= 16)
        assertEquals(fields[1], fields[2])
    }

    @Test
    fun answersCredentialManagerWithThePassword() {
        assumeTrue("Credential Manager providers need Android 14", Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
        shell("settings put secure credential_service $app/$CREDENTIAL_SERVICE")
        shell("settings put secure credential_service_primary $app/$CREDENTIAL_SERVICE")
        // The sheet comes up over the form at once, so don't wait for the form itself.
        openForm("credentialManager true", wait = false)
        assertNotNull("Octa Pass's entry in the sheet", device.wait(Until.findObject(By.text(USERNAME)), TIMEOUT))
        TestSupport.screenshot("74-credential-manager")
        // One entry: the sheet offers it with Continue; some versions list it to tap.
        (device.wait(Until.findObject(By.text("Continue")), 5_000) ?: device.findObject(By.text(USERNAME))).click()
        TestSupport.enterPin()
        val result = device.wait(Until.findObject(By.pkg(OTHER_APP).desc("result").textContains("/")), TIMEOUT)
        assertEquals("$USERNAME / $PASSWORD", checkNotNull(result) { "no answer from Credential Manager" }.text)
    }

    /** Opens the test app's form, with `--ez` extras such as `signUp true`. */
    private fun openForm(vararg extras: String, wait: Boolean = true) {
        shell("am start -W -S -n $OTHER_APP/$OTHER_APP_CODE.FormActivity ${extras.joinToString(" ") { "--ez $it" }}")
        if (wait) assertTrue("the test app", device.wait(Until.hasObject(By.pkg(OTHER_APP)), TIMEOUT) == true)
    }

    /** Picks a suggestion in the autofill dropdown. */
    private fun pick(text: String, screenshot: String) {
        val suggestion = device.wait(Until.findObject(By.text(text)), TIMEOUT)
        TestSupport.screenshot(screenshot)
        checkNotNull(suggestion) { "no “$text” suggestion" }.click()
    }

    /** The test app's copy of what its fields hold, once [done] says it's filled. */
    private fun waitForFields(done: (String) -> Boolean): String {
        val deadline = System.currentTimeMillis() + TIMEOUT
        while (System.currentTimeMillis() < deadline) {
            val text = device.findObject(By.pkg(OTHER_APP).desc("fields"))?.text.orEmpty()
            if (done(text)) return text
            Thread.sleep(500)
        }
        error("the form wasn't filled: ${device.findObject(By.pkg(OTHER_APP).desc("fields"))?.text}")
    }

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command)).use { it.readBytes().decodeToString() }

    private companion object {
        const val OTHER_APP = "app.octap.android.test"
        const val OTHER_APP_CODE = "app.octap.android.uitests"
        const val AUTOFILL_SERVICE = "app.octap.android.autofill.OctaPassAutofillService"
        const val CREDENTIAL_SERVICE = "app.octap.android.autofill.OctaPassCredentialService"
        const val KEYBOARD = "$OTHER_APP/$OTHER_APP_CODE.PlainKeyboard"
        const val SUGGESTION = "Octa Pass"
        const val SUGGESTED_PASSWORD = "Suggested password"
        const val USERNAME = "ada"
        const val PASSWORD = "hunter2-hunter2"
        // The emulator's software rendering is slow.
        const val TIMEOUT = 30_000L
    }
}
