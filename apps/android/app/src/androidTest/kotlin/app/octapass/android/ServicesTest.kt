package app.octap.android

import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.octap.android.TestSupport.PASSWORD
import app.octap.android.TestSupport.model
import app.octap.android.vault.AutofillVault
import app.octap.vault.ItemDetails
import app.octap.vault.ItemType
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Group 6 (plan 17): the Autofill and Credential Manager services moved in from the Tauri app open
 * the store the native app writes, through `octapass-ffi`'s bindings in `liboctapass_mobile.so`.
 */
@RunWith(AndroidJUnit4::class)
class ServicesTest {
    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @Test
    fun theAutofillVaultReadsWhatTheAppSaved() {
        TestSupport.signOut()
        TestSupport.createAccount()
        val personal = runBlocking { model.vault.listVaults() }.first { it.vaultType == VaultType.PERSONAL }.id
        val id = runBlocking {
            val draft = newItemDraft(ItemType.Login, personal)
            val login = (draft.details as ItemDetails.Login).login.copy(username = "filler", password = "fill-me-in-please")
            model.vault.saveItem(draft.copy(title = "Example", urls = listOf("https://example.com"), details = ItemDetails.Login(login))).id
        }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val vault = AutofillVault.open(context)
        assertNotNull(vault)
        try {
            vault!!.unlockWithPassword(PASSWORD)
            val found = vault.logins(listOf("https://example.com"))
            assertEquals(listOf(id), found.map { it.itemId })
            assertEquals("filler" to "fill-me-in-please", vault.credentials(id))
            // A password saved from another app (named after the app, as the services do) goes to the store.
            assertTrue(vault.saveLogin("androidapp://com.example.app", "new-user", "a-new-password-1", "Example app").isNotEmpty())
        } finally {
            vault?.close()
        }
    }
}
