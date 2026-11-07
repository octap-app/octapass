package app.octap.android

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.octap.android.TestSupport.model
import app.octap.vault.ItemDetails
import app.octap.vault.ItemDraft
import app.octap.vault.ItemType
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Groups 2 and 3 (plan 17): the list with its menu, website rows, search, favourites, the trash, the editor and the item view. */
@RunWith(AndroidJUnit4::class)
class VaultTest {
    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @get:Rule
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

    private fun login(title: String, username: String, url: String, password: String = "hunter2-hunter2"): String = runBlocking {
        val draft = newItemDraft(ItemType.Login, personal)
        val details = (draft.details as ItemDetails.Login).login.copy(username = username, password = password)
        model.vault.saveItem(draft.copy(title = title, urls = listOf(url), details = ItemDetails.Login(details))).id
    }

    private fun save(draft: ItemDraft) = runBlocking { model.vault.saveItem(draft).id }

    @Test
    fun listGroupsSortsSearchesAndCombinesWebsites() {
        login("GitHub work", "me@work.example", "https://github.com")
        login("GitHub home", "me@home.example", "https://github.com/login")
        login("Bank", "me", "https://bank.example")
        save(newItemDraft(ItemType.SecureNote, personal).let { it.copy(title = "Alarm code", details = ItemDetails.SecureNote((it.details as ItemDetails.SecureNote).note.copy(notes = "4321"))) })

        // Two logins for github.com share a row that opens in place.
        rule.waitFor("site.github.com")
        rule.tap("site.github.com")
        rule.waitUntil(10_000) { rule.onAllNodesWithText("GitHub work").fetchSemanticsNodes().isNotEmpty() }

        // Group by first letter: a header per letter.
        rule.tap("list.arrange")
        rule.tap("group.letter")
        rule.waitUntil(10_000) { rule.onAllNodes(hasText("B") and !hasTestTag("list.search")).fetchSemanticsNodes().isNotEmpty() }

        // Search ignores the groups and finds by username.
        rule.type("list.search", "home.example")
        rule.waitUntil(10_000) { rule.onAllNodesWithText("Bank").fetchSemanticsNodes().isEmpty() }
        rule.onNodeWithText("GitHub home").assertIsDisplayed()
        rule.type("list.search", "")

        // Name, Z to A puts the note last-letter first.
        rule.tap("list.arrange")
        rule.tap("group.none")
        rule.tap("list.arrange")
        rule.tap("sort.name_desc")
        val arrangement = model.vault.listArrangement("all", 1u)
        assertEquals(app.octap.vault.ListSort.NAME_DESC, arrangement.sort)
        assertEquals(app.octap.vault.ListGrouping.NONE, arrangement.grouping)
    }

    @Test
    fun favouriteTrashAndRestore() {
        val id = login("Mail", "me@mail.example", "https://mail.example")
        rule.tap("row.$id")
        rule.waitFor("item.title")
        rule.tap("item.favorite")
        rule.waitUntil(10_000) { runBlocking { model.vault.getItem(id).favorite } }

        rule.tap("item.more")
        rule.tap("item.trash")
        rule.waitUntil(10_000) { runBlocking { model.vault.getItem(id).deletedAt != null } }

        // The trash lists it with its days left, and restores it.
        rule.waitFor("list.menu")
        rule.tap("list.menu")
        rule.tap("nav.trash")
        rule.tap("row.$id")
        rule.tap("item.restore")
        rule.waitUntil(10_000) { runBlocking { model.vault.getItem(id).deletedAt == null } }
    }

    @Test
    fun newLoginThroughTheEditorThenRevealAndCopy() {
        rule.tap("list.add")
        rule.tap("new.login")
        rule.type("editor.title", "Forum")
        rule.type("editor.username", "reader")
        rule.type("editor.password", "correct-horse-battery")
        rule.type("editor.url.0", "forum.example")
        rule.tap("editor.save")

        rule.waitFor("item.title")
        rule.waitFor("reveal.password")
        rule.tap("reveal.password")
        // No device lock on this account: the master password stands in.
        rule.type("gate.password", TestSupport.PASSWORD)
        rule.tap("gate.confirm")
        rule.waitFor("password.value")
        assertTrue(rule.textOf("password.value").contains("correct-horse-battery"))
        rule.tap("copy.password")
        rule.type("gate.password", TestSupport.PASSWORD)
        rule.tap("gate.confirm")
        val saved = runBlocking { model.vault.listItems(app.octap.vault.ItemFilter(null, null, "Forum", false, false, false, false)) }
        assertEquals(listOf("Forum"), saved.map { it.title })
    }

    @Test
    fun counterCodeMovesOnlyWhenAsked() {
        val id = save(newItemDraft(ItemType.Login, personal).let { draft ->
            val details = (draft.details as ItemDetails.Login).login.copy(totp = "otpauth://hotp/Bank?secret=JBSWY3DPEHPK3PXP&counter=4")
            draft.copy(title = "Bank", details = ItemDetails.Login(details))
        })
        rule.tap("row.$id")
        rule.waitFor("totp.next")
        assertTrue(rule.textOf("totp.counter").contains("4"))
        rule.tap("totp.next")
        rule.waitUntil(10_000) { rule.textOf("totp.counter").contains("5") }
        assertTrue(rule.textOf("totp.value").any(Char::isDigit))
    }

    @Test
    fun matchRuleAndSecurityQuestionThroughTheEditor() {
        rule.tap("list.add")
        rule.tap("new.login")
        rule.type("editor.title", "Forum")
        rule.type("editor.url.0", "forum.example")
        // The default (this site and its subdomains) explains what it offers the login on.
        rule.waitFor("editor.matchHelp.0")
        rule.tap("editor.matchRule.0")
        rule.tap("choice.host")
        rule.tap("editor.addQuestion")
        rule.type("editor.question.0", "First pet")
        rule.tap("editor.save")

        rule.waitFor("item.matchMode.0")
        rule.waitFor("reveal.securityAnswer.0")
        val saved = runBlocking {
            val row = model.vault.listItems(app.octap.vault.ItemFilter(null, null, "Forum", false, false, false, false)).first()
            model.vault.getItem(row.id)
        }
        assertEquals(mapOf("forum.example" to "host"), saved.urlMatch)
    }

    @Test
    fun anEarlierVersionShowsAndRestores() {
        val id = login("Mail", "me@mail.example", "https://mail.example", password = "first-password-1")
        runBlocking {
            val draft = app.octap.vault.itemDraft(model.vault.getItem(id))
            val details = (draft.details as ItemDetails.Login).login.copy(password = "second-password-2")
            model.vault.saveItem(draft.copy(details = ItemDetails.Login(details)))
        }
        // Versions come from the server, so the first one shows once the edit has uploaded.
        var revision: ULong? = null
        rule.waitUntil(20_000) {
            revision = runBlocking { model.vault.itemVersions(id) }.firstOrNull { (it.item.details as ItemDetails.Login).login.password == "first-password-1" }?.revision
            revision != null
        }
        rule.tap("row.$id")
        rule.waitFor("item.more")
        rule.tap("item.more")
        rule.tap("item.history")
        rule.waitFor("history.show.$revision")
        rule.tap("history.restore.$revision")
        rule.tap("confirm.ok")
        rule.waitUntil(10_000) { runBlocking { (model.vault.getItem(id).details as ItemDetails.Login).login.password == "first-password-1" } }
    }

    @Test
    fun editorValidatesAndEveryTypeOpens() {
        // A login without a title is refused with the catalog's message.
        rule.tap("list.add")
        rule.tap("new.login")
        rule.tap("editor.save")
        rule.waitFor("editor.error")

        rule.tap("editor.cancel")

        val card = save(newItemDraft(ItemType.Card, personal).let { it.copy(title = "Visa", details = ItemDetails.Card((it.details as ItemDetails.Card).card.copy(number = "4111111111111111", expiry = "08/29", cvv = "123"))) })
        val wifi = save(newItemDraft(ItemType.Wifi, personal).let { it.copy(title = "Home", details = ItemDetails.Wifi((it.details as ItemDetails.Wifi).wifi.copy(ssid = "HomeNet", password = "home-network-1"))) })
        rule.tap("row.$card")
        rule.waitFor("reveal.cardNumber")
        rule.tap("item.back")
        rule.tap("row.$wifi")
        rule.waitFor("wifi.connect")
        rule.waitFor("copy.ssid")
    }
}
