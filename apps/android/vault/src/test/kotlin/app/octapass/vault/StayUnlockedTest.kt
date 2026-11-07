package app.octap.vault

import kotlinx.coroutines.runBlocking
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Stay unlocked while logged in to this phone (plan 18), through the bindings the app uses, on a
 * vault on this phone only (no server needed). "Starting the app again" is a new [OctaPassVault]
 * on the same folder and the same Keystore ([TestPlatform]).
 */
class StayUnlockedTest {
    private val phones = mutableListOf<Phone>()

    @AfterTest
    fun cleanUp() {
        phones.forEach { it.directory.deleteRecursively() }
    }

    private suspend fun newPhone(): Phone {
        val phone = Phone("stay").also { phones.add(it) }
        phone.vault.createLocalVault("Stay", PASSWORD)
        // On by default on a new install; every unlock keeps the key, on its own thread.
        assertTrue(phone.vault.settings().stayUnlocked)
        waitFor { phone.vault.stayUnlockedStatus().enrolled }
        return phone
    }

    private fun restart(phone: Phone): Phone {
        phone.vault.close()
        return Phone(phone.email, phone.directory, phone.platform)
    }

    private fun waitFor(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition()) {
            check(System.currentTimeMillis() < deadline) { "timed out" }
            Thread.sleep(50)
        }
    }

    @Test
    fun theAppOpensWithNoPromptAndLockNowHolds() = runBlocking {
        val phone = restart(newPhone())
        assertEquals(SessionStatus.LOCKED, phone.vault.snapshot().status)
        val status = phone.vault.stayUnlockedStatus()
        assertTrue(status.on && status.available && status.enrolled && !status.passwordRequired)
        assertTrue(phone.vault.unlockStayUnlocked())
        assertEquals(SessionStatus.UNLOCKED, phone.vault.snapshot().status)

        // "Lock now" holds until the user unlocks.
        phone.vault.lock()
        assertFalse(phone.vault.unlockStayUnlocked())
        assertEquals(SessionStatus.LOCKED, phone.vault.snapshot().status)
        phone.vault.unlock(PASSWORD)
        phone.vault.lock()
        phone.vault.unlock(PASSWORD)
        assertEquals(SessionStatus.UNLOCKED, phone.vault.snapshot().status)
        phone.vault.close()
    }

    @Test
    fun turnedOffTheAppAsksAsBefore() = runBlocking {
        val phone = newPhone()
        phone.vault.updateSettings(phone.vault.settings().copy(stayUnlocked = false))
        assertFalse(phone.vault.stayUnlockedStatus().enrolled)
        val again = restart(phone)
        assertFalse(again.vault.stayUnlockedStatus().on)
        assertFalse(again.vault.unlockStayUnlocked())
        assertEquals(SessionStatus.LOCKED, again.vault.snapshot().status)
        again.vault.close()
    }

    @Test
    fun withoutAScreenLockItFallsBack() = runBlocking {
        val phone = newPhone()
        phone.platform.lockAvailable = false
        val again = restart(phone)
        assertFalse(again.vault.stayUnlockedStatus().available)
        assertFalse(again.vault.unlockStayUnlocked())
        assertEquals(SessionStatus.LOCKED, again.vault.snapshot().status)
        // Nothing guards the key without a screen lock, so it's gone.
        assertFalse(again.vault.stayUnlockedStatus().enrolled)
        again.vault.close()
    }
}
