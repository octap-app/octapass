package app.octap.android

import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.octap.android.TestSupport.PASSWORD
import app.octap.android.TestSupport.model
import app.octap.android.vault.AutofillVault
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Saving while locked (plan 03): the Autofill service's Save seals the login into the store's
 * save inbox without unlocking, and the app's next unlock adds it, tagged for review.
 */
@RunWith(AndroidJUnit4::class)
class SaveLockedTest {
    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @Test
    fun aLoginSavedWhileLockedIsAddedAtTheNextUnlock() {
        TestSupport.signOut()
        TestSupport.createAccount()
        model.vault.lock()

        // What OctaPassAutofillService.onSaveRequest does: no unlock, no session.
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val service = AutofillVault.open(context)
        assertNotNull(service)
        service!!.use {
            assertTrue(it.saveLocked("androidapp://com.example.locked", "locked-user", "sealed-password-31", "Locked App"))
        }

        runBlocking { model.vault.unlock(PASSWORD) }
        val autofill = AutofillVault.open(context)!!
        autofill.use {
            it.unlockWithPassword(PASSWORD)
            val found = it.logins(listOf("androidapp://com.example.locked")).single()
            assertEquals("locked-user" to "sealed-password-31", it.credentials(found.itemId))
            val item = runBlocking { model.vault.getItem(found.itemId) }
            assertEquals("Locked App", item.title)
            assertEquals(listOf("Unconfirmed"), item.tags)
        }
    }
}
