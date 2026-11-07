package app.octap.android

import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.octap.android.TestSupport.PASSWORD
import app.octap.android.TestSupport.model
import app.octap.vault.SessionStatus
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Replaces the Secret Key in Settings, signs in with the new one, and gives a vault a new key. */
@RunWith(AndroidJUnit4::class)
class KeyRotationTest {
    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @get:Rule
    val failures = ScreenshotOnFailure()

    @Before
    fun signedOut() = TestSupport.signOut()

    @Test
    fun replaceTheSecretKeyThenSignInWithTheNewOne() {
        val email = TestSupport.newEmail()
        val old = TestSupport.createAccount(email)
        openSettings()

        // Settings → Replace Secret Key, keeping the recovery code.
        rule.tap("settings.rotateSecretKey")
        rule.waitFor("rotate.title")
        rule.type("rotate.password", PASSWORD)
        rule.tap("rotate.submit")

        // The kit says the recovery code stayed. Back and Continue don't leave it until it's saved.
        rule.waitFor("newKit.saved", 60_000)
        val newKey = Regex("OP1-[A-Z0-9-]+").find(rule.textOf("kit.secretKey"))!!.value
        assertNotEquals(old.secretKey, newKey)
        rule.waitFor("kit.recoveryKept")
        assertTrue(rule.onAllNodesWithTag("kit.recoveryCode").fetchSemanticsNodes().isEmpty())
        rule.tag("newKit.continue").assertIsNotEnabled()
        TestSupport.device.pressBack()
        rule.waitFor("newKit.saved")
        rule.tap("newKit.saved")
        rule.tap("newKit.continue")
        rule.waitFor("settings.title")

        // Signing out forgets the account here, so the Secret Key is asked for: the new one works.
        runBlocking { model.vault.signOut() }
        rule.waitFor("signIn.submit", 60_000)
        rule.type("signIn.email", email)
        rule.type("signIn.password", PASSWORD)
        rule.type("signIn.secretKey", newKey)
        rule.tap("signIn.submit")
        rule.waitFor("tab.items", 60_000)
        assertEquals(SessionStatus.UNLOCKED, model.vault.snapshot().status)
    }

    @Test
    fun rotateAVaultKey() {
        TestSupport.createAccount()
        openSettings()

        rule.tap("settings.vaultKeys")
        rule.waitFor("vaultKeys.title")
        val personal = runBlocking { model.vault.listVaults() }.first()
        rule.tap("vaultKeys.rotate.${personal.id}")
        rule.tap("confirm.ok")
        // Back to the button when the rotation finished.
        rule.waitFor("vaultKeys.rotate.${personal.id}", 60_000)
    }

    private fun openSettings() {
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
        rule.tap("tab.settings")
        rule.waitFor("settings.title")
    }
}
