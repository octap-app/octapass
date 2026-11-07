package app.octap.android.platform

import android.app.Application
import app.octap.android.OctaPassApp
import app.octap.vault.OctaPassVault
import com.google.android.gms.tasks.Tasks
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.Wearable
import com.google.android.gms.wearable.WearableListenerService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Message paths, as in the watch app's `PhoneLink.kt`. */
private const val PATH_PAYLOAD = "/octapass/watch/payload"
private const val PATH_REFRESH = "/octapass/watch/refresh"

/** Codes last 15 minutes. Sending every 5 keeps a watch going while the vault is unlocked. */
private const val REFRESH_INTERVAL_MS = 5 * 60 * 1000L

/**
 * Hands a Wear OS watch what `OctaPassVault.watchPayload` returns. The Rust core decides what that
 * is, codes or a clear, from the session and the setting; this class only carries the text.
 *
 * Only to nearby watches: the data layer can also route through Google's servers when a watch
 * isn't close, and codes and titles don't go that way. Messages, not data items, so nothing stays
 * in the data layer's store. Without Google Play services or a watch, nothing happens.
 */
class WatchCodesLink(private val app: Application, private val vault: OctaPassVault) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var refreshing: Job? = null

    /** Sends what the watch should have now: after an unlock, a lock, a sign-out, an item change, or when the setting changes. */
    fun update() {
        scope.launch { send { true } }
    }

    /** A watch asked. Not an activity: a watch asking can't keep the vault unlocked. */
    fun answer(nodeId: String) {
        scope.launch { send { it == nodeId } }
    }

    /** While the vault is unlocked and the setting is on, keeps the watch's codes from running out. */
    @Synchronized
    fun keepFresh(on: Boolean) {
        refreshing?.cancel()
        refreshing = if (!on) null else scope.launch {
            while (isActive) {
                delay(REFRESH_INTERVAL_MS)
                send { true }
            }
        }
    }

    private suspend fun send(to: (String) -> Boolean) {
        runCatching {
            val nodes = Tasks.await(Wearable.getNodeClient(app).connectedNodes).filter { it.isNearby && to(it.id) }
            if (nodes.isEmpty()) return
            val payload = vault.watchPayload(null).encodeToByteArray()
            val messages = Wearable.getMessageClient(app)
            nodes.forEach { Tasks.await(messages.sendMessage(it.id, PATH_PAYLOAD, payload)) }
        }
    }
}

/** Requests from a watch. A process started this way has a locked vault, so the watch gets a clear. */
class WatchRequests : WearableListenerService() {
    override fun onMessageReceived(event: MessageEvent) {
        if (event.path == PATH_REFRESH) (application as OctaPassApp).model.watch.answer(event.sourceNodeId)
    }
}
