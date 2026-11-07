package app.octap.android.autofill

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

data class PendingSave(val url: String, val title: String?, val username: String?, val password: String)

/**
 * A login the Autofill framework asked to save, held in this process while [SaveActivity] unlocks
 * the vault, so the password isn't put in an intent that passes through the system.
 */
object PendingSaves {
    private const val LIMIT = 8
    private val saves = ConcurrentHashMap<String, PendingSave>()

    fun put(save: PendingSave): String {
        if (saves.size >= LIMIT) saves.clear()
        return UUID.randomUUID().toString().also { saves[it] = save }
    }

    fun take(id: String): PendingSave? = saves.remove(id)
}
