package app.octap.android.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class ContainerTest {
    @get:Rule
    val folder = TemporaryFolder()

    @Test
    fun readsTheCurrentAccountTheAppWrote() {
        // As crates/octapass-mobile-vault/src/accounts.rs writes it.
        File(folder.root, "accounts.json").writeText(
            """
            {
              "accounts": [
                { "tag": "aa", "email": "a@example.com", "serverUrl": "https://a/" },
                { "tag": "bb", "email": "b@example.com", "serverUrl": "https://b/" }
              ],
              "current": "bb"
            }
            """.trimIndent(),
        )
        val account = Container.currentAccount(folder.root)!!
        assertEquals(Container.Account("bb", "b@example.com", "https://b/"), account)
        assertEquals("bb.opstore", account.storeFile)
        assertEquals("secretKey.bb", account.secretKeyName)
        assertEquals("deviceSecret.bb", account.deviceSecretName)
        // As Account::stay_unlocked_name names the key the services open with (plan 18).
        assertEquals("stayUnlocked.bb", account.stayUnlockedName)
    }

    @Test
    fun nobodyIsSignedInWithoutAFileOrACurrentAccount() {
        assertNull(Container.currentAccount(folder.root))
        File(folder.root, "accounts.json").writeText("""{ "accounts": [] }""")
        assertNull(Container.currentAccount(folder.root))
        File(folder.root, "accounts.json").writeText("not json")
        assertNull(Container.currentAccount(folder.root))
    }
}
