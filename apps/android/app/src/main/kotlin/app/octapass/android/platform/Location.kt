package app.octap.android.platform

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.os.Build
import android.os.CancellationSignal
import androidx.core.content.ContextCompat
import app.octap.android.ui.vault.NearbyLogic
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

/**
 * One reading of the phone's location for Nearby, with Android's own location service (no Google
 * library): only while the app is open, never in the background, never watched or kept. The
 * reading is handed to the vault, which compares it with the places on the phone.
 */
object DeviceLocation {
    /** Android's own location service. */
    val systemSource: suspend (Context) -> NearbyLogic.Reading? = { system(it) }

    /** Where readings come from. UI tests put a fixed one here (and then no permission is asked for). */
    @Volatile
    var source: suspend (Context) -> NearbyLogic.Reading? = systemSource

    /** Whether the app may read the location: precise or approximate, while it's in use. */
    fun granted(context: Context): Boolean =
        listOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
            .any { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }

    /** Location turned on for the whole phone. */
    fun enabled(context: Context): Boolean = context.getSystemService(LocationManager::class.java)?.isLocationEnabled == true

    suspend fun current(context: Context): NearbyLogic.Reading? = source(context.applicationContext)

    @SuppressLint("MissingPermission")
    private suspend fun system(context: Context): NearbyLogic.Reading? {
        val manager = context.getSystemService(LocationManager::class.java) ?: return null
        if (!manager.isLocationEnabled || !granted(context)) return null
        val enabled = manager.getProviders(true)
        val preferred = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) add(LocationManager.FUSED_PROVIDER)
            add(LocationManager.NETWORK_PROVIDER)
            add(LocationManager.GPS_PROVIDER)
        }.filter { it in enabled }
        val fresh = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            preferred.firstOrNull()?.let { provider ->
                withTimeoutOrNull(15_000) {
                    suspendCancellableCoroutine<Location?> { done ->
                        val signal = CancellationSignal()
                        done.invokeOnCancellation { signal.cancel() }
                        manager.getCurrentLocation(provider, signal, context.mainExecutor) { done.resume(it) }
                    }
                }
            }
        } else {
            null
        }
        // Without a fresh one (Android 9 and 10, or no fix in time), the newest the system has.
        val location = fresh ?: preferred.mapNotNull { runCatching { manager.getLastKnownLocation(it) }.getOrNull() }.maxByOrNull { it.time }
        return location?.let { NearbyLogic.Reading(it.latitude, it.longitude, if (it.hasAccuracy()) it.accuracy.toDouble() else null) }
    }
}
