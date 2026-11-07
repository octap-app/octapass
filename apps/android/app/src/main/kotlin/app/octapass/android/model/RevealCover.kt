package app.octap.android.model

/**
 * What the user's last answer covers, so revealing and copying don't ask again (plan 03 History
 * 2026-11-05, plan 18): the account whose unlock, or whose first reveal while the vault stays
 * unlocked, the user answered. It ends when the vault locks, another account opens, the screen
 * turns off or the app-open gate is turned off. Memory only, never a key. [AppModel] holds one and
 * passes in what it reads from the vault and the settings, so this stays plain Kotlin.
 */
class RevealCover {
    @Volatile
    private var account: String? = null

    /**
     * The user answered an unlock on a lock screen (or signed in or up). [account] is the unlocked
     * vault's, null when it didn't open. It counts with the app-open gate on ([gate]) or while the
     * vault stays unlocked ([staysUnlocked]), where the gate doesn't apply.
     */
    fun unlockAnswered(account: String?, gate: Boolean, staysUnlocked: Boolean) {
        this.account = account?.takeIf { gate || staysUnlocked }
    }

    /**
     * The user answered "Confirm it's you" for a reveal or copy. While the vault stays unlocked
     * that covers the rest, as an answered unlock does; otherwise a vault opened without a check
     * keeps asking on every reveal.
     */
    fun revealAnswered(account: String?, staysUnlocked: Boolean) {
        if (staysUnlocked && account != null) this.account = account
    }

    /** Reveal and copy don't ask. [account] is the unlocked vault's, null while it's locked. */
    fun covers(account: String?, gate: Boolean, staysUnlocked: Boolean): Boolean =
        account != null && account == this.account && (gate || staysUnlocked)

    /** The session changed: locked, or another account. [account] as for [covers]. */
    fun sessionChanged(account: String?) {
        if (account == null || account != this.account) this.account = null
    }

    /** The screen turned off, or a setting ended it: the next reveal asks. */
    fun end() {
        account = null
    }
}
