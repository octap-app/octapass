package app.octap.android

import app.octap.android.model.RevealCover
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Reveal and copy ask once (plan 03 History 2026-11-05, plan 18). */
class RevealCoverTest {
    private val ada = "https://vault.octap.app\nada@example.com"
    private val bob = "https://vault.octap.app\nbob@example.com"

    @Test
    fun whileTheVaultStaysUnlockedTheFirstRevealAsksAndTheSecondDoesNot() {
        val cover = RevealCover()
        // Opened by itself: not an answer, so the first reveal asks.
        assertFalse(cover.covers(ada, gate = true, staysUnlocked = true))
        cover.revealAnswered(ada, staysUnlocked = true)
        assertTrue(cover.covers(ada, gate = true, staysUnlocked = true))
        // The app-open gate doesn't matter in this mode.
        assertTrue(cover.covers(ada, gate = false, staysUnlocked = true))
    }

    @Test
    fun theScreenTurningOffEndsIt() {
        val cover = RevealCover()
        cover.revealAnswered(ada, staysUnlocked = true)
        cover.end()
        assertFalse(cover.covers(ada, gate = true, staysUnlocked = true))
    }

    @Test
    fun lockingOrAnotherAccountEndsIt() {
        val cover = RevealCover()
        cover.revealAnswered(ada, staysUnlocked = true)
        cover.sessionChanged(ada)
        assertTrue(cover.covers(ada, gate = true, staysUnlocked = true))
        cover.sessionChanged(null)
        assertFalse(cover.covers(ada, gate = true, staysUnlocked = true))

        cover.revealAnswered(ada, staysUnlocked = true)
        cover.sessionChanged(bob)
        assertFalse(cover.covers(bob, gate = true, staysUnlocked = true))
        assertFalse(cover.covers(ada, gate = true, staysUnlocked = true))
    }

    @Test
    fun withStayUnlockedOffARevealAnswerCoversNothing() {
        val cover = RevealCover()
        cover.revealAnswered(ada, staysUnlocked = false)
        assertFalse(cover.covers(ada, gate = true, staysUnlocked = false))
    }

    @Test
    fun anAnsweredUnlockCoversWithTheGateOnOrWhileStayingUnlocked() {
        val cover = RevealCover()
        cover.unlockAnswered(ada, gate = true, staysUnlocked = false)
        assertTrue(cover.covers(ada, gate = true, staysUnlocked = false))
        // Turning the gate off afterwards ends it, outside stay unlocked.
        assertFalse(cover.covers(ada, gate = false, staysUnlocked = false))

        cover.unlockAnswered(ada, gate = false, staysUnlocked = false)
        assertFalse(cover.covers(ada, gate = true, staysUnlocked = false))

        cover.unlockAnswered(ada, gate = false, staysUnlocked = true)
        assertTrue(cover.covers(ada, gate = false, staysUnlocked = true))

        // An unlock that didn't open anything covers nothing.
        cover.unlockAnswered(null, gate = true, staysUnlocked = true)
        assertFalse(cover.covers(ada, gate = true, staysUnlocked = true))
    }

    @Test
    fun aLockedVaultIsNeverCovered() {
        val cover = RevealCover()
        cover.revealAnswered(ada, staysUnlocked = true)
        assertFalse(cover.covers(null, gate = true, staysUnlocked = true))
    }
}
