package app.octap.core

import java.io.File
import java.nio.file.Files
import kotlin.io.path.absolutePathString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Saving while locked (plan 03): the Autofill service seals a login into the store's save inbox
 * without unlocking, and the next unlock merges it.
 */
class InboxTest {
    private val email = "inbox@example.com"
    private val password = "correct horse battery staple"
    private val device = DeviceInfo(name = "Pixel", platform = "android")

    @Test
    fun aLoginSavedWhileLockedIsMergedAtTheNextUnlock() {
        val server = TestServer()
        val api = OctaPassServer("https://octapass.test", Loopback(server))
        val signup = api.startSignup(email, password)
        val secretKey = signup.secretKey()
        val signedUp = signup.finish(signup.devVerificationCode()!!, device)
        val path = Files.createTempDirectory("octapass-inbox").resolve("phone.store").absolutePathString()
        val store = LocalStore.create(path, api.baseUrl(), signedUp.session)
        api.sync(signedUp.tokens.accessToken, store)
        val shop = signedUp.session.saveLogin(
            store,
            LoginDraft(itemId = null, title = "Shop", url = "https://shop.example", username = "maya", password = "old-password-1", totp = null),
        )

        // Before any unlock pinned the inbox key there's nothing to seal to.
        assertFalse(store.inboxAccepts())
        assertFailsWith<OctaPassException> { store.addToInbox("https://a.example", null, "pw", null) }
        assertEquals(InboxMerge(0u, 0u, 0u, 0u), store.mergeInbox(signedUp.session))
        signedUp.session.lock()

        // Locked: the service opens the store and seals, with no session at all.
        val service = LocalStore.open(path)
        assertTrue(service.inboxAccepts())
        service.addToInbox("androidapp://com.example.app", "samuel-rivers", "app-password-17", "Example App")
        service.addToInbox("https://shop.example/login", "maya", "new-password-2", null)
        service.addToInbox("https://shop.example/login", "maya", "new-password-2", null)
        val sealed = File("$path.inbox").readText()
        listOf("app-password-17", "new-password-2", "samuel-rivers", "com.example.app").forEach { assertFalse(sealed.contains(it), it) }

        // The next unlock merges it: a new login for review, a new password on the existing one.
        val session = store.unlockWithPassword(password, secretKey)
        assertEquals(InboxMerge(added = 1u, updated = 1u, dropped = 1u, failed = 0u), store.mergeInbox(session))
        val updated = session.getItem(store, shop)
        assertEquals("new-password-2", updated.login?.password)
        assertTrue(updated.tags.isEmpty())
        val added = session.matchLogins(store, "androidapp://com.example.app").single()
        val item = session.getItem(store, added.item.itemId)
        assertEquals("Example App", item.title)
        assertEquals(listOf("Unconfirmed"), item.tags)
        assertEquals("app-password-17", item.login?.password)
        assertTrue(store.hasPendingChanges())
        assertEquals(InboxMerge(0u, 0u, 0u, 0u), store.mergeInbox(session))
    }
}
