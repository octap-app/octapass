package app.octap.android

import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.octap.android.TestSupport.PASSWORD
import app.octap.android.TestSupport.model
import app.octap.vault.SessionStatus
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Changes the master password in Settings, then resets it from "Forgot your master password?". */
@RunWith(AndroidJUnit4::class)
class MasterPasswordTest {
    @get:Rule(order = 0)
    val rule = createAndroidComposeRule<MainActivity>()

    // Inside the Compose rule, so the screen is still there when a test fails.
    @get:Rule(order = 1)
    val failures = ScreenshotOnFailure()

    @Before
    fun signedOut() = TestSupport.signOut()

    @Test
    fun changeThenResetTheMasterPassword() {
        val email = TestSupport.newEmail()
        val kit = TestSupport.createAccount(email)
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")

        // Settings → Master password.
        rule.tap("tab.settings")
        rule.waitFor("settings.title")
        rule.tap("settings.changePassword")
        rule.waitFor("changePassword.title")
        rule.type("changePassword.current", PASSWORD)
        rule.type("changePassword.new", CHANGED)
        rule.type("changePassword.confirm", CHANGED)
        rule.tap("changePassword.submit")
        rule.waitFor("settings.title")

        // The new password opens the vault.
        rule.tap("settings.lockNow")
        rule.waitFor("lock.password")
        rule.type("lock.password", CHANGED)
        rule.tap("lock.unlock")
        rule.waitFor("tab.items", 60_000)
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")

        // Sign out, then reset with the recovery code and a second new password. (The settings
        // sign-out button sits under the bottom bar; OnboardingTest covers it.)
        runBlocking { model.vault.signOut() }
        rule.waitFor("signIn.submit", 60_000)
        rule.tap("signIn.forgotPassword")
        rule.type("reset.email", email)
        rule.tap("reset.sendCode")
        rule.waitFor("reset.verify", 60_000)
        val code = Regex("\\d{6}").find(rule.textOf("reset.devCode"))!!.value
        rule.type("reset.code", code)
        rule.tap("reset.verify")
        rule.waitFor("reset.recoveryCode", 60_000)
        rule.type("reset.recoveryCode", kit.recoveryCode)
        rule.type("reset.newPassword", RESET)
        rule.type("reset.confirmPassword", RESET)
        rule.tap("reset.submit")
        rule.waitFor("reset.kit.confirm", 60_000)
        rule.tap("reset.kit.confirm")
        rule.tap("reset.kit.continue")
        rule.waitFor("tab.items", 60_000)
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
        rule.tap("tab.items")
        rule.waitFor("list.title")

        // And the second new password opens it.
        runBlocking { model.vault.lock() }
        rule.waitFor("lock.password")
        rule.type("lock.password", RESET)
        rule.tap("lock.unlock")
        rule.waitFor("list.title", 60_000)
        assertEquals(SessionStatus.UNLOCKED, model.vault.snapshot().status)
    }

    private companion object {
        const val CHANGED = "another correct horse battery staple 43"
        const val RESET = "reset correct horse battery staple 44"
    }
}
