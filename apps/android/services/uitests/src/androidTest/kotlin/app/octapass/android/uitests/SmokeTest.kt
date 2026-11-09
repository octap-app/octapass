package app.octap.android.uitests

import android.content.ContentValues
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.MediaStore
import androidx.core.content.ContextCompat
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPasswordOption
import androidx.credentials.PasswordCredential
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.providerevents.ProviderEventsManager
import androidx.credentials.providerevents.exception.ImportCredentialsException
import androidx.credentials.providerevents.transfer.CredentialTypes
import androidx.credentials.providerevents.transfer.ExportEntry
import androidx.credentials.providerevents.transfer.ImportCredentialsRequest
import androidx.credentials.providerevents.transfer.ProviderImportCredentialsResponse
import androidx.credentials.providerevents.transfer.RegisterExportRequest
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/**
 * Native smoke tests on the emulator. They cover what the web vault's own tests can't: the app
 * starts, Octa Pass fills other apps through the Autofill framework and Credential Manager,
 * unlocking with the device lock, attachments reach the system's own screens (the viewer, the
 * photo picker), and items move between Octa Pass and another password manager (this app)
 * through credential transfer. They never tap the web view: button clicks there come from the debug hook. `scripts/android-ui-tests.sh`
 * signed up the dev account first (the debug hook's "Example" login, saved for this test app)
 * and set a screen-lock PIN.
 *
 * **Stale since the Tauri phone app was removed (plan 17 History, 2026-11-05):** there's no web
 * view or debug hook in the native app, so these don't run. The native app's
 * `app/src/androidTest` covers the same flows (`OtherAppsTest`, `AttachmentsTest`), except
 * credential transfer, which needs Google Play services 25.38 or later.
 */
@RunWith(AndroidJUnit4::class)
class SmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val device = UiDevice.getInstance(instrumentation)
    /** This test app; Octa Pass is [APP]. */
    private val context = instrumentation.targetContext

    /** See [PlainKeyboard]; starting the tests stops this app, which deselects it each time. */
    @Before
    fun usePlainKeyboard() {
        shell("ime enable $KEYBOARD")
        shell("ime set $KEYBOARD")
        val deadline = System.currentTimeMillis() + TIMEOUT
        while (shellOutput("settings get secure default_input_method").trim() != KEYBOARD) {
            check(System.currentTimeMillis() < deadline) { "the test keyboard wasn't selected" }
            Thread.sleep(500)
        }
    }

    @Test
    fun appStartsWithTheVaultScreens() {
        context.startActivity(context.packageManager.getLaunchIntentForPackage(APP)!!.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        assertTrue("Octa Pass", device.wait(Until.hasObject(By.pkg(APP)), TIMEOUT) == true)
        // When the vault is locked, its lock screen opens the device-unlock prompt by itself.
        if (device.wait(Until.hasObject(By.text(PIN_BUTTON)), 5_000) == true) unlockWithPin()
        assertNotNull("the web view", device.wait(Until.findObject(By.clazz("android.webkit.WebView")), TIMEOUT))
        Thread.sleep(3_000)
        screenshot("app")
    }

    @Test
    fun fillsASignInFormAfterTheDeviceLock() {
        useAutofillService()
        ActivityScenario.launch(FormActivity::class.java).use { scenario ->
            device.wait(Until.findObject(By.hint("Email")), TIMEOUT).click()
            pickSuggestion(SUGGESTION, "autofill-suggestion")
            unlockWithPin()
            device.wait(Until.findObject(By.text("ada")), TIMEOUT)
            screenshot("autofill-filled")
            scenario.onActivity {
                assertEquals("ada", it.username.text.toString())
                assertEquals("hunter2-hunter2", it.password.text.toString())
            }
        }
    }

    @Test
    fun suggestsAStrongPasswordOnASignUpForm() {
        useAutofillService()
        val intent = Intent(context, FormActivity::class.java).putExtra(FormActivity.EXTRA_SIGN_UP, true)
        ActivityScenario.launch<FormActivity>(intent).use { scenario ->
            device.wait(Until.findObject(By.hint("Password")), TIMEOUT).click()
            pickSuggestion(SUGGESTED_PASSWORD, "autofill-suggested-password")
            device.wait(Until.gone(By.text(SUGGESTED_PASSWORD)), 5_000)
            device.waitForIdle()
            scenario.onActivity {
                val password = it.password.text.toString()
                assertEquals(20, password.length)
                assertEquals(password, it.confirmation!!.text.toString())
            }
        }
    }

    @Test
    fun answersCredentialManagerWithThePassword() {
        assumeTrue("Credential Manager providers need Android 14", Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
        shell("settings put secure credential_service $APP/$CREDENTIAL_SERVICE")
        shell("settings put secure credential_service_primary $APP/$CREDENTIAL_SERVICE")
        ActivityScenario.launch(FormActivity::class.java).use { scenario ->
            val answer = CompletableFuture<GetCredentialResponse>()
            scenario.onActivity { activity ->
                CredentialManager.create(activity).getCredentialAsync(
                    activity,
                    GetCredentialRequest(listOf(GetPasswordOption())),
                    null,
                    ContextCompat.getMainExecutor(activity),
                    object : androidx.credentials.CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                        override fun onResult(result: GetCredentialResponse) {
                            answer.complete(result)
                        }

                        override fun onError(e: GetCredentialException) {
                            answer.completeExceptionally(e)
                        }
                    },
                )
            }
            assertNotNull("Octa Pass's entry", device.wait(Until.findObject(By.text("ada")), TIMEOUT))
            screenshot("credential-manager-sheet")
            // One entry: the sheet shows it with a Continue button.
            device.wait(Until.findObject(By.text("Continue")), TIMEOUT).click()
            unlockWithPin()
            val credential = answer.get(TIMEOUT, TimeUnit.MILLISECONDS).credential as PasswordCredential
            assertEquals("ada", credential.id)
            assertEquals("hunter2-hunter2", credential.password)
        }
    }

    @Test
    fun opensAnAttachmentInTheSystemViewer() {
        launchOnDocument(clicking = "Open lease.pdf")
        // Another app shows the decrypted copy, under the file's own name.
        val viewer = device.wait(Until.findObject(By.text("lease.pdf").pkg(java.util.regex.Pattern.compile("^(?!$APP$).*"))), TIMEOUT)
        assertNotNull("a viewer with lease.pdf", viewer)
        Thread.sleep(2_000)
        screenshot("attachment-viewer")
        device.pressBack()
        assertTrue("back in Octa Pass", device.wait(Until.hasObject(By.pkg(APP).depth(0)), TIMEOUT) == true)
    }

    @Test
    fun attachesAPhotoFromThePhotoPicker() {
        val name = "octapass-test-${System.currentTimeMillis()}"
        insertPhoto(name)
        launchOnDocument(clicking = "Photos")
        // The system photo picker (no storage permission): pick the newest photo, then confirm
        // ("Done" on Android 16, "Add" before).
        val photo = device.wait(Until.findObject(By.descContains("Photo taken")), TIMEOUT)
        checkNotNull(photo) { "no photo in the picker" }.click()
        val confirm = device.wait(Until.findObject(By.text(java.util.regex.Pattern.compile("^(Done|Add.*)$"))), TIMEOUT)
        screenshot("photo-picker")
        checkNotNull(confirm) { "no Done button in the picker" }.click()
        val attached = device.wait(Until.findObject(By.textEndsWith("attached")), TIMEOUT)
        assertNotNull("the photo was attached", attached)
        screenshot("photo-attached")
    }

    @Test
    fun anotherAppImportsFromOctaPass() {
        assumeCredentialTransfer()
        // The export runs in Octa Pass's process. On the Android 17 emulator image the system
        // WebView dies (SIGILL in onTrimMemory) once the app is in the background, taking the
        // process with it, so the export starts in a fresh one, as it usually would.
        shell("am force-stop $APP")
        ActivityScenario.launch(FormActivity::class.java).use { scenario ->
            val answer = CompletableFuture<ProviderImportCredentialsResponse>()
            scenario.onActivity { activity ->
                ProviderEventsManager.create(activity).importCredentialsAsync(
                    activity,
                    ImportCredentialsRequest(setOf(CredentialTypes.CREDENTIAL_TYPE_BASIC_AUTH, CredentialTypes.CREDENTIAL_TYPE_TOTP), emptySet()),
                    null,
                    ContextCompat.getMainExecutor(activity),
                    object : androidx.credentials.CredentialManagerCallback<ProviderImportCredentialsResponse, ImportCredentialsException> {
                        override fun onResult(result: ProviderImportCredentialsResponse) {
                            answer.complete(result)
                        }

                        override fun onError(e: ImportCredentialsException) {
                            answer.completeExceptionally(e)
                        }
                    },
                )
            }
            // Google Play services lists the apps that can export; Octa Pass shows the dev account.
            val entry = device.wait(Until.findObject(By.textStartsWith("dev-")), TIMEOUT)
            screenshot("transfer-export-list")
            checkNotNull(entry) { "Octa Pass isn't in the list" }.click()
            assertNotNull("the export dialog", device.wait(Until.findObject(By.text("Export from Octa Pass")), TIMEOUT))
            device.findObject(By.clazz("android.widget.EditText").pkg(APP)).text = DEV_PASSWORD
            screenshot("transfer-export-password")
            // "Export", in the dialog's own capitals.
            device.findObject(By.res("android:id/button1")).click()
            val cxf = JSONObject(answer.get(TIMEOUT, TimeUnit.MILLISECONDS).response.responseJson)
            val items = cxf.getJSONArray("accounts").getJSONObject(0).getJSONArray("items")
            val example = (0 until items.length()).map { items.getJSONObject(it) }.single { it.getString("title") == "Example" }
            val types = example.getJSONArray("credentials").let { list -> (0 until list.length()).map { list.getJSONObject(it).getString("type") } }
            assertEquals(listOf("basic-auth", "totp"), types)
            assertEquals("hunter2-hunter2", example.getJSONArray("credentials").getJSONObject(0).getJSONObject("password").getString("value"))
            // Only what was asked for: the note has no password or code.
            assertTrue((0 until items.length()).none { items.getJSONObject(it).getString("title") == "Door code" })
        }
    }

    @Test
    fun octaPassImportsFromAnotherApp() {
        assumeCredentialTransfer()
        registerOtherManager()
        launchOctaPass("/settings", clicking = "Choose app", then = "Import")
        val entry = device.wait(Until.findObject(By.text(OtherManagerActivity.ACCOUNT)), TIMEOUT)
        screenshot("transfer-import-list")
        checkNotNull(entry) { "the other manager isn't in the list" }.click()
        // What it sent, before anything is saved; the debug hook then taps Import.
        assertNotNull("the review", device.wait(Until.findObject(By.textStartsWith("Import from")), TIMEOUT))
        screenshot("transfer-import-review")
        assertTrue("the review closed", device.wait(Until.gone(By.textStartsWith("Import from")), TIMEOUT) == true)
        // The script made a fresh account: these items can only have come from the other app.
        launchOctaPass("/items/all", clicking = null)
        assertNotNull("the imported login", device.wait(Until.findObject(By.text(OtherManagerActivity.LOGIN)), TIMEOUT))
        assertNotNull("the imported card", device.findObject(By.text("Travel card")))
        screenshot("transfer-imported")
    }

    /** Credential transfer needs Google Play services 25.38 or later (not the Android 16 Google APIs image's 25.26). */
    private fun assumeCredentialTransfer() {
        val version = runCatching { context.packageManager.getPackageInfo("com.google.android.gms", 0).longVersionCode }.getOrDefault(0L)
        assumeTrue("credential transfer needs Google Play services 25.38+", version >= 253_800_000L)
    }

    /** This app lists itself as a password manager Octa Pass can import from. */
    private fun registerOtherManager() {
        val icon = Bitmap.createBitmap(48, 48, Bitmap.Config.ARGB_8888).apply { eraseColor(Color.rgb(200, 90, 40)) }
        val entry = ExportEntry(OtherManagerActivity.ENTRY_ID, OtherManagerActivity.ACCOUNT, "grace@example.com", icon, setOf(CredentialTypes.CREDENTIAL_TYPE_BASIC_AUTH, CredentialTypes.CREDENTIAL_TYPE_CREDIT_CARD))
        runBlocking { ProviderEventsManager.create(context).registerExport(RegisterExportRequest.create(context, listOf(entry))) }
    }

    /** Opens Octa Pass on the dev account's Document; the debug hook then clicks [clicking]. */
    private fun launchOnDocument(clicking: String) = launchOctaPass("/items/all/{document}", clicking)

    /** Opens Octa Pass on [route]; the debug hook then clicks [clicking], and [then] in the dialog that opens. */
    private fun launchOctaPass(route: String, clicking: String?, then: String? = null) {
        shell("am force-stop $APP")
        val intent = Intent().setClassName(APP, "$APP.MainActivity")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            .putExtra("OCTAPASS_DEV_SERVER", DEV_SERVER)
            .putExtra("OCTAPASS_DEV_ROUTE", route)
        clicking?.let { intent.putExtra("OCTAPASS_DEV_CLICK", it) }
        then?.let { intent.putExtra("OCTAPASS_DEV_THEN", it) }
        context.startActivity(intent)
        assertTrue("Octa Pass", device.wait(Until.hasObject(By.pkg(APP)), TIMEOUT) == true)
    }

    /** A plain image in the shared Pictures, so the photo picker has something to offer. */
    private fun insertPhoto(name: String) {
        val values = ContentValues().apply {
            put(MediaStore.Images.Media.DISPLAY_NAME, "$name.png")
            put(MediaStore.Images.Media.MIME_TYPE, "image/png")
        }
        val resolver = context.contentResolver
        val uri = checkNotNull(resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values))
        val bitmap = Bitmap.createBitmap(64, 64, Bitmap.Config.ARGB_8888).apply { eraseColor(Color.rgb(31, 128, 112)) }
        resolver.openOutputStream(uri)!!.use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    private fun useAutofillService() {
        shell("settings put secure autofill_service $APP/$AUTOFILL_SERVICE")
    }

    /** Picks a suggestion in the autofill dropdown. */
    private fun pickSuggestion(text: String, screenshotName: String) {
        val suggestion = device.wait(Until.findObject(By.text(text)), TIMEOUT)
        screenshot(screenshotName)
        checkNotNull(suggestion) { "no “$text” suggestion" }.click()
    }

    /** The device-lock prompt's other way in: the screen-lock PIN the script set. */
    private fun unlockWithPin() {
        checkNotNull(device.wait(Until.findObject(By.text(PIN_BUTTON)), TIMEOUT)) { "no device-lock prompt" }.click()
        val field = checkNotNull(device.wait(Until.findObject(By.res("com.android.systemui:id/lockPassword")), TIMEOUT)) { "no PIN field" }
        field.text = PIN
        shell("input keyevent KEYCODE_ENTER")
    }

    private fun shell(command: String) {
        shellOutput(command)
        Thread.sleep(300)
    }

    private fun shellOutput(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command)).use {
            it.readBytes().decodeToString()
        }

    /** Into this app's files, which the script pulls (debug builds of Octa Pass aren't FLAG_SECURE). */
    private fun screenshot(name: String) {
        val folder = File(context.getExternalFilesDir(null), "screenshots").apply { mkdirs() }
        device.takeScreenshot(File(folder, "$name.png"))
    }

    companion object {
        private const val APP = "app.octap.android"
        /** As the script forwards it through adb. */
        private const val DEV_SERVER = "http://localhost:8090"
        private const val AUTOFILL_SERVICE = "app.octap.android.autofill.OctaPassAutofillService"
        private const val CREDENTIAL_SERVICE = "app.octap.android.autofill.OctaPassCredentialService"
        private const val SUGGESTION = "Octa Pass"
        private const val SUGGESTED_PASSWORD = "Suggested password"
        private const val PIN_BUTTON = "Use PIN"
        private const val PIN = "1111"
        /** The dev account's master password (`src-tauri/src/dev.rs`). */
        private const val DEV_PASSWORD = "correct horse battery staple"
        private const val KEYBOARD = "app.octap.android.test/app.octap.android.uitests.PlainKeyboard"
        // The emulator's software rendering is slow.
        private const val TIMEOUT = 30_000L
    }
}
