package app.octap.android.ui.util

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import app.octap.android.model.AppModel
import kotlinx.coroutines.CancellationException

@Stable
class Live<T> {
    var data by mutableStateOf<T?>(null)
        internal set
    var error by mutableStateOf<Throwable?>(null)
        internal set
    internal var attempt by mutableIntStateOf(0)

    fun retry() {
        attempt++
    }
}

/**
 * A vault query that runs again whenever items change (and, with [sharing], whenever members,
 * families, links or emergency contacts change), as the web vault's `useLive`. The last answer
 * stays on screen while the next one loads.
 */
@Composable
fun <T> rememberLive(model: AppModel, vararg keys: Any?, sharing: Boolean = false, load: suspend () -> T): Live<T> {
    val live = remember(*keys) { Live<T>() }
    val items by model.itemsVersion.collectAsState()
    val people by model.sharingVersion.collectAsState()
    LaunchedEffect(live, items, if (sharing) people else 0L, live.attempt) {
        try {
            live.data = load()
            live.error = null
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            live.error = error
        }
    }
    return live
}
