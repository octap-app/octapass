package app.octap.android.platform

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log
import app.octap.vault.OctaPassVault
import app.octap.vault.SafeDrive
import app.octap.vault.SafeItem
import app.octap.vault.SafeSyncSummary
import app.octap.vault.SessionStatus
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/** An unlocked Safe: its item and the engine's handle on it. */
class OpenSafe(val item: SafeItem, val drive: SafeDrive)

/**
 * Every Safe that's open right now, which is exactly the roots [SafeDocumentsProvider] shows. They
 * open when the vault unlocks, device unlock included, and lock with it: this class holds no key,
 * only the drives the unlocked vault gave it. Blobs live in `filesDir/safes`, encrypted.
 *
 * The vault's observer calls [sessionChanged] and [refresh] on a thread inside a Rust callback,
 * which can't call back into Rust (JNA doesn't nest on Android), so every vault and drive call
 * here runs on [scope]. The map is emptied before that, on the observer's thread, so a lock takes
 * the roots away at once even while a large file is being sealed.
 *
 * Synced Safes sync on their own, as on the Mac and iPhone ([syncSoon]): a few seconds after one
 * changes in the Files app ([SafeDocumentsProvider] reports each change), after each vault sync,
 * and every two minutes while the vault is unlocked. Errors wait for the next round: offline is
 * normal. Sync now on the Safes screen does the same at once.
 */
class SafeDrives(private val context: Context, private val vault: () -> OctaPassVault) {
    /** Where this device keeps its Safes. */
    val folder = File(context.filesDir, "safes")
    private val _open = MutableStateFlow<Map<String, OpenSafe>>(emptyMap())

    /** By item id. */
    val open: StateFlow<Map<String, OpenSafe>> = _open.asStateFlow()

    @OptIn(ExperimentalCoroutinesApi::class)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1))
    private val loading = Mutex()
    private val queued = AtomicBoolean(false)
    private val state = Any()

    /** Moves on at every lock, so a drive that was still opening then is locked, not kept. */
    private var session = 0L
    private var unlocked = false

    /** The two-minute round while unlocked. */
    private var autoSync: Job? = null
    /** Syncs waiting a few seconds for changes to settle, by item id ("" for every synced Safe). */
    private val soon = HashMap<String, Job>()
    private val syncing = Mutex()
    private val syncAgain = AtomicBoolean(false)

    fun sessionChanged(status: SessionStatus) {
        if (status == SessionStatus.UNLOCKED) {
            synchronized(state) {
                unlocked = true
                if (autoSync == null) {
                    autoSync = scope.launch {
                        while (isActive) {
                            delay(SYNC_EVERY_MS)
                            syncAll(null)
                        }
                    }
                }
            }
            refresh()
            return
        }
        val leaving = synchronized(state) {
            if (!unlocked) return
            session++
            unlocked = false
            autoSync?.cancel()
            autoSync = null
            soon.values.forEach { it.cancel() }
            soon.clear()
            _open.value.values.also { _open.value = emptyMap() }
        }
        notifyChanged()
        scope.launch { leaving.forEach(::lock) }
    }

    /** Opens Safes that are new and closes those that are gone, such as after a sync. */
    fun refresh() {
        if (!synchronized(state) { unlocked }) return
        if (!queued.compareAndSet(false, true)) return
        scope.launch {
            loading.withLock {
                queued.set(false)
                load()
            }
        }
    }

    /**
     * Syncs the open synced Safes (or only [itemId]) in a few seconds, once changes have settled.
     * Quietly: a failure waits for the next round. Safe to call from the vault's observer thread:
     * it only starts work on [scope].
     */
    fun syncSoon(itemId: String? = null) {
        val key = itemId.orEmpty()
        synchronized(state) {
            if (!unlocked) return
            soon.remove(key)?.cancel()
            soon[key] = scope.launch {
                delay(SETTLE_MS)
                val self = coroutineContext[Job]
                synchronized(state) { if (soon[key] === self) soon.remove(key) }
                syncAll(itemId)
            }
        }
    }

    /** One round at a time; asked again meanwhile, it goes round once more. */
    private suspend fun syncAll(itemId: String?) {
        if (!syncing.tryLock()) {
            syncAgain.set(true)
            return
        }
        try {
            do {
                syncAgain.set(false)
                val current = synchronized(state) { session.takeIf { unlocked } } ?: return
                val safes = _open.value.values.filter { it.item.sync && (itemId == null || it.item.itemId == itemId) }
                for (safe in safes) {
                    if (synchronized(state) { current != session }) return
                    try {
                        sync(safe)
                    } catch (error: CancellationException) {
                        throw error
                    } catch (error: Exception) {
                        // Offline is normal. The reason never holds a secret.
                        Log.w(TAG, "Couldn't sync a Safe: $error")
                    }
                }
            } while (syncAgain.get())
        } finally {
            syncing.unlock()
        }
    }

    /** Sends and fetches a synced Safe's changes, then has the Files app read them again. */
    suspend fun sync(safe: OpenSafe): SafeSyncSummary {
        val summary = vault().syncSafe(safe.item.itemId, safe.drive)
        notifyChanged()
        return summary
    }

    /**
     * Deletes a Safe: its drive locks and leaves the Files app first, then its item (and key) goes
     * to the trash and its folder here is removed.
     */
    suspend fun delete(item: SafeItem) {
        val leaving = synchronized(state) {
            _open.value[item.itemId].also { _open.value -= item.itemId }
        }
        notifyChanged()
        leaving?.let(::lock)
        vault().deleteSafe(item.itemId, folder.path)
    }

    private suspend fun load() {
        val current = synchronized(state) { session }
        try {
            // This device's: a Safe kept on another device has no files here.
            val items = vault().listSafes(folder.path)
            val wanted = items.map { it.itemId }.toSet()
            val gone = synchronized(state) {
                if (current != session) return
                val (kept, leaving) = _open.value.entries.partition { it.key in wanted }
                _open.value = kept.associate { it.key to it.value }
                leaving.map { it.value }
            }
            gone.forEach(::lock)
            var changed = gone.isNotEmpty()
            for (item in items) {
                if (item.itemId in _open.value) continue
                val opened = opened(item) ?: continue
                val kept = synchronized(state) {
                    (current == session).also { if (it) _open.value += item.itemId to opened }
                }
                if (!kept) {
                    lock(opened)
                    return
                }
                changed = true
            }
            if (changed) notifyChanged()
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            // Mostly the vault locking meanwhile. The reason never holds a secret.
            Log.w(TAG, "Couldn't open the Safes: $error")
        }
    }

    private suspend fun opened(item: SafeItem): OpenSafe? = try {
        folder.mkdirs()
        OpenSafe(item, vault().openSafe(item.itemId, folder.path))
    } catch (error: CancellationException) {
        throw error
    } catch (error: Exception) {
        // One damaged Safe doesn't keep the others closed.
        Log.w(TAG, "Couldn't open a Safe: $error")
        null
    }

    private fun lock(safe: OpenSafe) {
        try {
            safe.drive.lock()
        } catch (error: Exception) {
            // The keys are gone either way: the engine drops them even when a flush fails.
            Log.w(TAG, "Locking a Safe: $error")
        }
    }

    /** The roots, and every folder a Files window is showing, which all live under the authority. */
    private fun notifyChanged() {
        val resolver = context.contentResolver
        val authority = authority(context)
        resolver.notifyChange(DocumentsContract.buildRootsUri(authority), null)
        resolver.notifyChange(Uri.Builder().scheme("content").authority(authority).build(), null)
    }

    companion object {
        private const val TAG = "OctaPassSafes"
        private const val SYNC_EVERY_MS = 120_000L
        private const val SETTLE_MS = 3_000L

        fun authority(context: Context): String = "${context.packageName}.documents"
    }
}
