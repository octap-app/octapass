package app.octap.android

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import app.octap.android.model.AppModel
import app.octap.android.model.isLocal
import app.octap.vault.RecoveryKit
import app.octap.vault.SessionStatus
import kotlinx.coroutines.runBlocking
import java.util.UUID

/**
 * What the UI tests share. They run against the development server the app was built for
 * (`-PoctapassServer`, see scripts/android-ui-tests.sh), which shows its email codes on screen.
 */
object TestSupport {
    const val PASSWORD = "correct horse battery staple 42"
    const val PIN = "1111"

    val model: AppModel
        get() = (InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as OctaPassApp).model

    val device: UiDevice get() = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())

    fun newEmail() = "android-${UUID.randomUUID().toString().take(8)}@example.com"

    /** Starts each test signed out. */
    fun signOut() = runBlocking {
        val vault = model.vault
        when {
            vault.snapshot().status == SessionStatus.SIGNED_OUT -> Unit
            // A local vault has nothing to sign out of: it stays on the phone until it's deleted.
            vault.snapshot().isLocal -> vault.leaveLocalVault()
            else -> vault.signOut()
        }
    }

    /** An account made through the vault API, signed in and unlocked. */
    fun createAccount(email: String = newEmail()): RecoveryKit = runBlocking {
        val vault = model.vault
        val started = vault.startSignup(BuildConfig.DEFAULT_SERVER_URL, email, PASSWORD)
        vault.finishSignup(started.signupId, started.devVerificationCode!!)
    }

    /** Types the screen-lock PIN into the system's prompt. */
    fun enterPin() {
        val device = device
        val pinField = By.pkg("com.android.systemui").clazz("android.widget.EditText")
        // With a fingerprint enrolled the prompt asks for it first: "Use PIN" switches to the screen lock.
        val usePin = By.pkg("com.android.systemui").text(java.util.regex.Pattern.compile("(?i)use (pin|password|pattern|screen lock)"))
        val deadline = System.currentTimeMillis() + 20_000
        while (System.currentTimeMillis() < deadline && !device.hasObject(pinField)) {
            device.findObject(usePin)?.click()
            device.wait(Until.hasObject(pinField), 1_000)
        }
        check(device.hasObject(pinField)) { "the screen lock prompt didn't show" }
        device.findObject(pinField).text = PIN
        device.pressEnter()
    }
}

/** The back stack the open vault is showing. */
val AppModel.nav: app.octap.android.ui.vault.VaultNavigator
    get() = vault.snapshot().let { navigator("${it.email}@${it.serverUrl}") }

typealias Rule = AndroidComposeTestRule<*, *>

/** Waits for a node; on time-out the error says what was on screen instead. */
fun Rule.waitFor(tag: String, timeout: Long = 20_000) {
    try {
        waitUntil(timeout) { onAllNodes(hasTestTag(tag), useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }
    } catch (error: androidx.compose.ui.test.ComposeTimeoutException) {
        val screen = runCatching { onAllNodes(androidx.compose.ui.test.isRoot()).fetchSemanticsNodes().joinToString("\n") { it.config.toString() } + "\n" + onAllNodes(androidx.compose.ui.test.hasText("", substring = true)).fetchSemanticsNodes().joinToString(" | ") { n -> n.config.getOrNull(SemanticsProperties.Text)?.joinToString { it.text }.orEmpty() } }.getOrDefault("?")
        throw AssertionError("no \"$tag\" after $timeout ms; on screen: $screen", error)
    }
}

fun Rule.tag(tag: String): SemanticsNodeInteraction =
    if (onAllNodes(hasTestTag(tag)).fetchSemanticsNodes().isNotEmpty()) onNodeWithTag(tag) else onNodeWithTag(tag, useUnmergedTree = true)

/** Scrolls the node into view when it's in a scrolling list or form (not in a dialog). */
private fun SemanticsNodeInteraction.inView(): SemanticsNodeInteraction = apply { runCatching { performScrollTo() } }

fun Rule.type(tag: String, text: String) {
    waitFor(tag)
    tag(tag).inView().performTextReplacement(text)
}

fun Rule.tap(tag: String) {
    waitFor(tag)
    tag(tag).inView().performClick()
}

/** The text of a node and everything in it. */
fun Rule.textOf(tag: String): String {
    waitFor(tag)
    val node = onNodeWithTag(tag, useUnmergedTree = true).fetchSemanticsNode()
    val texts = mutableListOf<String>()
    fun walk(n: androidx.compose.ui.semantics.SemanticsNode) {
        n.config.getOrNull(SemanticsProperties.Text)?.forEach { texts += it.text }
        n.config.getOrNull(SemanticsProperties.EditableText)?.let { texts += it.text }
        n.children.forEach(::walk)
    }
    walk(node)
    return texts.joinToString(" ")
}

/** Saves a screenshot of a failing test to the app's files (`adb pull` it from /sdcard/Android/data/<app>/files/failures). */
class ScreenshotOnFailure : org.junit.rules.TestWatcher() {
    override fun failed(e: Throwable?, description: org.junit.runner.Description) {
        val dir = java.io.File(InstrumentationRegistry.getInstrumentation().targetContext.getExternalFilesDir(null), "failures").apply { mkdirs() }
        TestSupport.device.takeScreenshot(java.io.File(dir, "${description.methodName}.png"))
    }
}
