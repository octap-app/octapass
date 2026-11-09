package app.octap.android

import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.octap.android.TestSupport.model
import app.octap.android.platform.DeviceLocation
import app.octap.android.ui.vault.NearbyLogic
import app.octap.vault.ItemDetails
import app.octap.vault.ItemType
import app.octap.vault.PlaceDraft
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Nearby with the location fixed in the test (no permission prompt, no real location): the place
 * the phone is at comes first with its items, the others after it, nearest first.
 */
@RunWith(AndroidJUnit4::class)
class NearbyTest {
    @get:Rule(order = 0)
    val rule = createAndroidComposeRule<MainActivity>()

    @get:Rule(order = 1)
    val failures = ScreenshotOnFailure()

    private lateinit var personal: String

    @Before
    fun account() {
        // About 30 m north of the office below.
        DeviceLocation.source = { NearbyLogic.Reading(51.507621, -0.127758, 15.0) }
        TestSupport.signOut()
        TestSupport.createAccount()
        personal = runBlocking { model.vault.listVaults() }.first { it.vaultType == VaultType.PERSONAL }.id
        rule.waitFor("list.title")
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
    }

    @After
    fun realLocation() {
        DeviceLocation.source = DeviceLocation.systemSource
    }

    private fun place(name: String, latitude: Double?, longitude: Double?): String = runBlocking {
        model.vault.savePlace(PlaceDraft(null, personal, null, name, latitude, longitude, null, emptyList(), null)).id
    }

    @Test
    fun theOfficeComesFirstWithItsItemsThenTheOtherPlacesByDistance() {
        val office = place("Office", 51.507351, -0.127758)
        place("Café", 51.515445, -0.127758)
        place("Attic", null, null)
        runBlocking {
            val draft = newItemDraft(ItemType.SecureNote, personal)
            val note = (draft.details as ItemDetails.SecureNote).note.copy(notes = "4821")
            model.vault.saveItem(draft.copy(title = "Door code", details = ItemDetails.SecureNote(note)).also { it.places = listOf(office) })
        }

        rule.tap("list.menu")
        rule.tap("nav.nearby")
        rule.waitUntil(20_000) { rule.onAllNodesWithText("Now nearby: Office").fetchSemanticsNodes().isNotEmpty() }
        rule.waitUntil(10_000) { rule.onAllNodesWithText("Door code").fetchSemanticsNodes().isNotEmpty() }
        rule.waitUntil(10_000) { rule.onAllNodes(hasText("870 m", substring = true)).fetchSemanticsNodes().isNotEmpty() }
        val order = rule.onAllNodesWithTag("place.name", useUnmergedTree = true).fetchSemanticsNodes().map { node ->
            node.config.getOrElse(androidx.compose.ui.semantics.SemanticsProperties.Text) { emptyList() }.joinToString { it.text }
        }
        assertEquals(listOf("Now nearby: Office", "Café", "Attic"), order)
        TestSupport.screenshot("nearby")
    }

    @Test
    fun aNewItemSavedAtThePlaceIsOfferedIt() {
        val office = place("Office", 51.507351, -0.127758)
        rule.tap("list.menu")
        rule.tap("nav.nearby")
        rule.waitUntil(20_000) { rule.onAllNodesWithText("Now nearby: Office").fetchSemanticsNodes().isNotEmpty() }
        rule.tap("place.add")
        rule.waitUntil(10_000) { rule.onAllNodes(hasTestTag("editor.title")).fetchSemanticsNodes().isNotEmpty() }
        rule.type("editor.title", "Printer")
        rule.tap("editor.save")
        // Made from the place, it starts there: nothing to offer.
        rule.waitUntil(10_000) { runBlocking { model.vault.listItems(app.octap.vault.ItemFilter(vaultId = null, itemType = null, query = null, trash = false, favorites = false, passkeys = false, totp = false, project = null, stage = null, pinned = false)) }.any { it.title == "Printer" && office in it.places } }
    }
}
