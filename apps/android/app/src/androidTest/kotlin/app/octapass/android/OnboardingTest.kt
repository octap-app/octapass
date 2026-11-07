package app.octap.android

import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.octap.android.TestSupport.PASSWORD
import app.octap.android.TestSupport.model
import app.octap.vault.SessionStatus
import app.octap.vault.totpCode
import kotlinx.coroutines.runBlocking
import androidx.compose.ui.semantics.getOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Group 1 (plan 17): sign up, the Recovery Kit, sign in on a new device with two-step, lock and unlock. */
@RunWith(AndroidJUnit4::class)
class OnboardingTest {
    // v2: effects run on a standard test dispatcher. The v1 rule's unconfined one resumes a vault
    // call inside the Rust thread's callback, which JNA can't nest on Android.
    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @get:Rule
    val failures = ScreenshotOnFailure()

    @Before
    fun signedOut() = TestSupport.signOut()

    @Test
    fun signUpShowsTheRecoveryKitThenOpensTheVault() {
        val email = TestSupport.newEmail()
        rule.tap("signIn.createAccount")
        rule.type("signUp.email", email)
        rule.type("signUp.password", PASSWORD)
        rule.type("signUp.confirm", PASSWORD)
        rule.tap("signUp.continue")

        // The development server shows its code instead of emailing it.
        val code = Regex("\\d{6}").find(rule.textOf("verify.devCode"))!!.value
        rule.type("verify.code", code)
        rule.tap("verify.submit")

        val secretKey = rule.textOf("kit.secretKey")
        assertTrue(secretKey, secretKey.startsWith("OP1-"))
        assertTrue(rule.textOf("kit.recoveryCode").isNotBlank())
        rule.tap("kit.confirm")
        rule.tap("kit.continue")
        rule.tap("done.open")
        rule.waitFor("list.title")
        rule.tap("offer.notNow")
        assertEquals(SessionStatus.UNLOCKED, model.vault.snapshot().status)
    }

    @Test
    fun wrongPasswordThenUnlockAndSignOut() {
        TestSupport.createAccount()
        rule.waitFor("list.title")
        model.vault.lock()
        rule.type("lock.password", "not the password")
        rule.tap("lock.unlock")
        rule.waitUntil(20_000) { rule.onAllNodesWithText(rule.activity.getString(app.octap.resources.R.string.errors_invalidCredentials)).fetchSemanticsNodes().isNotEmpty() }
        rule.type("lock.password", PASSWORD)
        rule.tap("lock.unlock")
        rule.waitFor("list.title")
        model.vault.lock()
        rule.tap("lock.signOut")
        rule.waitFor("signIn.submit")
    }

    @Test
    fun newDeviceAsksForTheSecretKeyAndTheAuthenticatorCode() {
        val (kit, setup, _) = accountWithTwoStep()
        signIn(kit.email, otherServer(), kit.secretKey)
        rule.type("twoStep.code", freshCode(setup.secret))
        rule.tap("twoStep.verify")
        rule.waitFor("list.title")
    }

    /**
     * The next code after the one that turned two-step sign-in on: the server takes each code
     * once, so a sign-in within the same 30 seconds needs the next one.
     */
    private fun freshCode(secret: String): String {
        val used = enablingCode
        rule.waitUntil(35_000) { totpCode(secret, null).code != used }
        return totpCode(secret, null).code
    }

    private var enablingCode: String? = null

    @Test
    fun aRecoveryCodeWorksInsteadOfTheAuthenticator() {
        val (kit, _, recoveryCodes) = accountWithTwoStep()
        signIn(kit.email, otherServer(), kit.secretKey)
        rule.tap("twoStep.use.recovery_code")
        rule.type("twoStep.recovery", recoveryCodes.first())
        rule.tap("twoStep.verify")
        rule.waitFor("list.title")
    }

    /** An account with two-step sign-in on, signed out of this phone. */
    private fun accountWithTwoStep(): Triple<app.octap.vault.RecoveryKit, app.octap.vault.TotpSetup, List<String>> {
        val kit = TestSupport.createAccount()
        val setup = runBlocking { model.vault.startTotpSetup(PASSWORD) }
        enablingCode = totpCode(setup.secret, null).code
        val codes = runBlocking { model.vault.confirmTotpSetup(enablingCode!!) }!!
        TestSupport.signOut()
        return Triple(kit, setup, codes)
    }

    /** Another address for the same server: this phone doesn't know the account there. */
    private fun otherServer() = BuildConfig.DEFAULT_SERVER_URL.replace("localhost", "127.0.0.1")

    @Test
    fun deviceUnlockWithTheScreenLock() {
        TestSupport.createAccount()
        rule.tap("offer.turnOn")
        rule.waitUntil(20_000) { runBlocking { model.vault.unlockMethods().deviceUnlockEnabled } }
        model.vault.lock()
        // The prompt starts on its own (Compose has to run for that); the screen lock answers it.
        rule.waitUntil(20_000) { TestSupport.device.hasObject(androidx.test.uiautomator.By.pkg("com.android.systemui").textContains("Use")) }
        try {
            TestSupport.enterPin()
        } catch (error: IllegalStateException) {
            val texts = rule.onAllNodes(androidx.compose.ui.test.hasText("", substring = true), useUnmergedTree = true).fetchSemanticsNodes()
                .mapNotNull { it.config.getOrNull(androidx.compose.ui.semantics.SemanticsProperties.Text)?.joinToString { t -> t.text } }
            throw AssertionError("no prompt; on screen: $texts; methods: ${runBlocking { model.vault.unlockMethods() }}", error)
        }
        rule.waitFor("list.title", 30_000)
        assertEquals(SessionStatus.UNLOCKED, model.vault.snapshot().status)

        // The screen lock opened the vault: revealing a secret doesn't ask again (plan 03 History,
        // 2026-11-05).
        val id = runBlocking {
            val personal = model.vault.listVaults().first { it.vaultType == app.octap.vault.VaultType.PERSONAL }.id
            val draft = app.octap.vault.newItemDraft(app.octap.vault.ItemType.Password, personal)
            val login = (draft.details as app.octap.vault.ItemDetails.Password).login.copy(password = "shown-after-the-lock")
            model.vault.saveItem(draft.copy(title = "Gated", details = app.octap.vault.ItemDetails.Password(login))).id
        }
        rule.runOnUiThread { model.nav.open(app.octap.android.ui.vault.Route.Item(id), false) }
        rule.tap("reveal.password")
        rule.waitFor("password.value", 30_000)
        org.junit.Assert.assertTrue(rule.textOf("password.value").contains("shown-after-the-lock"))
        org.junit.Assert.assertFalse("the screen lock asked again", TestSupport.device.hasObject(androidx.test.uiautomator.By.pkg("com.android.systemui").clazz("android.widget.EditText")))

        // A secret the unlock doesn't cover still asks the screen lock, not the master password.
        rule.runOnUiThread { model.nav.pop() }
        rule.tap("tab.settings")
        rule.tap("settings.showSecretKey")
        TestSupport.enterPin()
        rule.waitFor("settings.secretKey", 30_000)
    }

    private fun signIn(email: String, server: String, secretKey: String?) {
        rule.type("signIn.email", email)
        rule.type("signIn.password", PASSWORD)
        if (rule.onAllNodesWithTag("server.url").fetchSemanticsNodes().isEmpty()) {
            if (rule.onAllNodesWithTag("signIn.changeServer").fetchSemanticsNodes().isNotEmpty()) rule.tap("signIn.changeServer")
            rule.tap("server.self")
        }
        rule.type("server.url", server)
        if (secretKey != null) rule.type("signIn.secretKey", secretKey)
        rule.tap("signIn.submit")
    }
}
