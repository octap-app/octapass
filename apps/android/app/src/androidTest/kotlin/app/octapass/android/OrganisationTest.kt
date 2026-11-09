package app.octap.android

import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.octap.android.TestSupport.PASSWORD
import app.octap.android.TestSupport.model
import app.octap.android.ui.vault.Route
import app.octap.android.ui.vault.Scope
import app.octap.vault.ItemType
import app.octap.vault.VaultRole
import app.octap.vault.newItemDraft
import kotlinx.coroutines.runBlocking
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * An organisation between two accounts on one phone: the owner creates it and invites the
 * member on screen; the member joins on screen; the owner reviews the member's fingerprint and
 * gives access on screen; the member then sees the login in the organisation vault. The owner's
 * vault, its login and the group linked to it are set up through the vault API in between.
 */
@RunWith(AndroidJUnit4::class)
class OrganisationTest {
    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @get:Rule
    val failures = ScreenshotOnFailure()

    @Before
    fun signedOut() = TestSupport.signOut()

    private fun waitForText(text: String, timeout: Long = 30_000) =
        rule.waitUntil(timeout) { rule.onAllNodes(hasText(text, substring = true), useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }

    private fun signIn(email: String, secretKey: String) = runBlocking {
        model.vault.signOut()
        model.vault.signIn(BuildConfig.DEFAULT_SERVER_URL, email, PASSWORD, secretKey)
    }

    /** Waits for a node, answering "Wait" when the busy emulator says something isn't responding. */
    private fun patiently(tag: String, timeout: Long) {
        val deadline = System.currentTimeMillis() + timeout
        while (System.currentTimeMillis() < deadline) {
            TestSupport.device.findObject(androidx.test.uiautomator.By.text("Wait"))?.click()
            if (rule.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()) return
            Thread.sleep(1_000)
        }
        rule.waitFor(tag, 1_000)
    }

    private fun open(route: Route) = rule.runOnUiThread { model.nav.reset(route) }

    /** After a sign-in the app offers device unlock: not now. */
    private fun vaultOpen() {
        rule.waitFor("tab.items", 60_000)
        runCatching { rule.waitUntil(5_000) { rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty() } }
        if (rule.onAllNodesWithTag("offer.notNow").fetchSemanticsNodes().isNotEmpty()) rule.tap("offer.notNow")
    }

    @Test
    fun anOrganisationSharesAVaultWithASecondAccount() {
        val member = TestSupport.newEmail()
        val memberKey = TestSupport.createAccount(member).secretKey
        runBlocking { model.vault.signOut() }
        val owner = TestSupport.newEmail()
        val ownerKey = TestSupport.createAccount(owner).secretKey

        // The owner creates the organisation and invites the member.
        vaultOpen()
        open(Route.Organisation)
        rule.type("org.name", "Acme")
        rule.tap("org.createButton")
        rule.waitFor("org.role", 30_000)
        TestSupport.screenshot("org-created")
        rule.tap("org.members")
        rule.type("org.invite.email", member)
        rule.tap("org.invite.send")
        waitForText(member)
        TestSupport.screenshot("org-invited")

        // A vault with a login, and a group linked to it.
        val (vaultId, groupId) = runBlocking {
            val vault = model.vault.createOrgVault("Deploy")
            model.vault.saveItem(newItemDraft(ItemType.Login, vault.id).copy(title = "Deploy key"))
            val group = model.vault.createOrgGroup("Team")
            model.vault.linkOrgVaultGroup(vault.id, group.id, VaultRole.READ)
            vault.id to group.id
        }

        // The member joins.
        signIn(member, memberKey)
        vaultOpen()
        open(Route.Organisation)
        rule.waitFor("org.accept", 30_000)
        rule.tap("org.accept")
        rule.waitFor("org.role", 30_000)
        TestSupport.screenshot("org-joined")

        // The owner puts them in the group, then gives access after seeing their fingerprint.
        signIn(owner, ownerKey)
        vaultOpen()
        runBlocking {
            val memberId = model.vault.listOrgMembers().members.first { it.email == member }.accountId
            model.vault.addOrgGroupMember(groupId, memberId)
        }
        open(Route.Organisation)
        rule.waitFor("org.review.$vaultId", 60_000)
        rule.tap("org.review.$vaultId")
        patiently("fingerprint.digits", 180_000)
        TestSupport.screenshot("org-review")
        rule.tap("org.review.confirm")
        rule.tap("org.review.apply")
        waitForText("Access given", 60_000)

        // The member sees the login in the organisation vault.
        signIn(member, memberKey)
        vaultOpen()
        rule.runOnUiThread { model.nav.showScope(Scope.InVault(vaultId)) }
        waitForText("Deploy key", 60_000)
        TestSupport.screenshot("org-shared-item")
    }
}
