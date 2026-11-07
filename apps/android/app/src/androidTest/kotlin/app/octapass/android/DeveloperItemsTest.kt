package app.octap.android

import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.octap.android.TestSupport.model
import app.octap.vault.EnvironmentDetails
import app.octap.vault.EnvironmentVariable
import app.octap.vault.ItemDetails
import app.octap.vault.ItemType
import app.octap.vault.VaultType
import app.octap.vault.newItemDraft
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** SSH keys and environments through their real screens (plan 17, phase 3), and "Confirm it's you". */
@RunWith(AndroidJUnit4::class)
class DeveloperItemsTest {
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

    private fun shows(tag: String) = rule.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    /** Device unlock is off on this account, so the gate is the master password. */
    private fun confirm() {
        rule.type("gate.password", TestSupport.PASSWORD)
        rule.tap("gate.confirm")
    }

    @Test
    fun generatedKeyIsNamedAfterItsCommentAndItsPrivateKeyIsGated() {
        rule.runOnUiThread { model.nav.open(app.octap.android.ui.vault.Route.Edit(null, ItemType.SshKey), false) }
        rule.tap("ssh.generate")
        rule.waitFor("ssh.fingerprint", 60_000)
        rule.type("ssh.comment", "me@phone")
        rule.tap("editor.save")
        rule.waitFor("item.title")
        assertEquals("me@phone", rule.textOf("item.title"))
        assertTrue(rule.textOf("ssh.publicKey").startsWith("ssh-ed25519 "))
        assertTrue(rule.textOf("ssh.fingerprint").startsWith("SHA256:"))

        assertFalse(shows("ssh.privateKey"))
        rule.tap("ssh.showPrivate")
        // Cancelling keeps it hidden.
        rule.tap("gate.cancel")
        rule.waitUntil(5_000) { !shows("gate.password") }
        assertFalse(shows("ssh.privateKey"))
        rule.tap("ssh.showPrivate")
        confirm()
        rule.waitFor("ssh.privateKey", 30_000)
        assertTrue(rule.textOf("ssh.privateKey").contains("BEGIN OPENSSH PRIVATE KEY"))
    }

    @Test
    fun aWrongPassphraseStaysOnTheDialog() {
        rule.runOnUiThread { model.nav.open(app.octap.android.ui.vault.Route.Edit(null, ItemType.SshKey), false) }
        rule.waitFor("ssh.paste")
        val locked = runBlocking {
            val key = model.vault.generateSshKey(app.octap.vault.SshKeyKind.ED25519, "")
            val draft = (newItemDraft(ItemType.SshKey, personal).details as ItemDetails.SshKey).key
            val path = model.vault.exportSshKey(app.octap.vault.withSshKey(draft, key, null), "fixture", "open sesame")
            java.io.File(path).readText().also { model.vault.closeAttachment(path) }
        }
        rule.type("ssh.paste", locked)
        rule.tap("ssh.pasteAction")
        rule.type("ssh.readPassphrase", "wrong")
        rule.tap("ssh.readAction")
        rule.waitUntil(30_000) { rule.onAllNodes(hasText("That passphrase doesn’t open this key.", substring = true), useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }
        rule.type("ssh.readPassphrase", "open sesame")
        rule.tap("ssh.readAction")
        rule.waitFor("ssh.fingerprint", 30_000)
    }

    private fun environment(title: String, project: String, stage: String, keys: List<String>) = runBlocking {
        val draft = newItemDraft(ItemType.Environment, personal)
        val details = EnvironmentDetails(project, null, stage, keys.map { EnvironmentVariable(it, "value-$it", true, null) }, null)
        model.vault.saveItem(draft.copy(title = title, details = ItemDetails.Environment(details))).id
    }

    @Test
    fun environmentsGroupFilterAndWarn() {
        val production = environment("Shop production", "shop-api", "production", listOf("API_KEY"))
        environment("Shop staging", "shop-api", "staging", listOf("API_KEY", "DEBUG"))
        environment("Blog staging", "blog", "staging", listOf("TOKEN"))
        rule.runOnUiThread { model.nav.showScope(app.octap.android.ui.vault.Scope.OfType(ItemType.Environment)) }

        rule.waitFor("row.$production")
        // Filtering to a project hides the other.
        rule.tap("env.filterProject")
        rule.tap("env.filterProject.blog")
        rule.waitUntil(10_000) { !shows("row.$production") }
        rule.tap("env.filterProject")
        rule.tap("env.filterProject.shop-api")
        rule.waitFor("row.$production")

        rule.tap("row.$production")
        rule.waitFor("reveal.env.API_KEY")
        rule.waitUntil(10_000) { rule.onAllNodes(hasText("DEBUG", substring = true), useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }
        rule.tap("reveal.env.API_KEY")
        confirm()
        rule.waitFor("env.API_KEY.value")
        assertEquals("value-API_KEY", rule.textOf("env.API_KEY.value"))
    }

    @Test
    fun aPastedFileBecomesVariablesAndABadNameIsRefused() {
        rule.runOnUiThread { model.nav.open(app.octap.android.ui.vault.Route.Edit(null, ItemType.Environment), false) }
        rule.type("editor.title", "Pasted")
        rule.tap("env.paste")
        rule.type("env.pasteText", "API_KEY=abc\nexport DEBUG=\"1\"\n")
        rule.tap("env.addPasted")
        rule.waitFor("env.key.1")
        assertTrue(rule.textOf("env.key.1").startsWith("DEBUG"))
        rule.tap("env.add")
        rule.type("env.key.2", "1BAD")
        rule.tap("editor.save")
        rule.waitFor("editor.error")
        rule.tap("env.remove.2")
        rule.tap("editor.save")
        rule.waitFor("item.title")
        rule.waitFor("reveal.env.API_KEY")
    }
}
