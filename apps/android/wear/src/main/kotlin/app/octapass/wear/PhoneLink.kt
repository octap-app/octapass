package app.octap.wear

import android.app.KeyguardManager
import android.content.Context
import com.google.android.gms.tasks.Tasks
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.Wearable
import com.google.android.gms.wearable.WearableListenerService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** Message paths, as in the phone app's `WatchCodesLink`. */
private const val PATH_PAYLOAD = "/octapass/watch/payload"
private const val PATH_REFRESH = "/octapass/watch/refresh"

/** The codes on this watch, in this process's memory only: a restart forgets them. */
object CodeStore {
    private val state = MutableStateFlow(WatchCodes())
    val codes: StateFlow<WatchCodes> = state.asStateFlow()

    fun receive(text: String) {
        val payload = WatchPayload.decode(text) ?: return
        state.update { it.applying(payload) }
    }

    fun forgetExpired() {
        state.update { it.forgettingExpired(System.currentTimeMillis()) }
    }

    fun forgetAll() {
        state.update { it.applying(WatchPayload.Clear(System.currentTimeMillis())) }
    }
}

/** Whether the watch has a lock. Without one, Octa Pass shows no codes. */
fun Context.hasScreenLock(): Boolean = getSystemService(KeyguardManager::class.java).isDeviceSecure

/** What the phone sends arrives here, whether or not the app is on screen. */
class PhoneMessages : WearableListenerService() {
    override fun onMessageReceived(event: MessageEvent) {
        if (event.path == PATH_PAYLOAD && hasScreenLock()) CodeStore.receive(event.data.decodeToString())
    }
}

/**
 * Asks the phone for fresh codes. The phone answers with a clear unless it's unlocked and the
 * setting is on. Only a phone that's close by: when it isn't, what's here stays until it expires.
 */
object PhoneRequests {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    fun askForCodes(context: Context) {
        val app = context.applicationContext
        scope.launch {
            // No Google Play services, or no phone: the empty screen says what to do.
            runCatching {
                val nodes = Tasks.await(Wearable.getNodeClient(app).connectedNodes)
                val messages = Wearable.getMessageClient(app)
                nodes.filter { it.isNearby }.forEach { Tasks.await(messages.sendMessage(it.id, PATH_REFRESH, ByteArray(0))) }
            }
        }
    }
}
