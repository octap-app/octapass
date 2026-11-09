package app.octap.android.ui.vault

import app.octap.vault.Here
import kotlin.math.roundToLong

/**
 * Nearby's plain logic, without Android: the rough distance a list shows, what the phone hands the
 * core about where it is, and when to offer a new item a place. Which place the phone is at is the
 * core's (`OctaPassVault.nearby`), never worked out here.
 */
object NearbyLogic {
    /** A distance to show: metres, or kilometres with [decimals] decimals. */
    data class Distance(val value: Double, val kilometres: Boolean, val decimals: Int)

    /**
     * The web vault's `formatDistance`: tens of metres (at least 10) under a kilometre; above it,
     * kilometres with one decimal under 10 km and whole ones beyond. 996 m is "1 km", not "1,000 m".
     */
    fun distance(metres: Double): Distance {
        val rounded = maxOf(10L, (metres / 10).roundToLong() * 10)
        if (rounded < 1000) return Distance(rounded.toDouble(), kilometres = false, decimals = 0)
        val km = metres / 1000
        return if (km < 10) Distance((km * 10).roundToLong() / 10.0, true, 1) else Distance(km.roundToLong().toDouble(), true, 0)
    }

    /** One location reading. */
    data class Reading(val latitude: Double, val longitude: Double, val accuracy: Double?)

    /** What the phone knows about where it is: the network it's on (when Android says) and one reading. */
    fun here(network: String?, reading: Reading?): Here = Here(
        networks = listOfNotNull(network?.takeIf { it.isNotEmpty() }),
        latitude = reading?.latitude,
        longitude = reading?.longitude,
        accuracy = reading?.accuracy?.takeIf { it > 0 },
    )

    /** Whether the phone can tell anything about where it is. */
    fun knowsWhere(here: Here): Boolean = here.networks.isNotEmpty() || (here.latitude != null && here.longitude != null)

    /**
     * Whether to ask the vault for a place to offer a just-saved item: only for an item made now
     * (`fresh`), once ([asked] holds the ids already asked about), with the setting on, and when
     * the phone knows something about where it is. The vault decides which place, if any.
     */
    fun shouldAsk(itemId: String, fresh: Boolean, settingOn: Boolean, asked: Set<String>, here: Here): Boolean =
        fresh && settingOn && itemId !in asked && knowsWhere(here)

    /** Why no place is marked as nearby. */
    enum class Reason { NO_MATCH, LOCATION_OFF, LOCATION_DENIED, LOCATION_UNAVAILABLE }

    /** What the phone's location reading came to. */
    enum class LocationState { READING, OK, DENIED, UNAVAILABLE, OFF }

    fun reason(here: Here, location: LocationState): Reason = when {
        knowsWhere(here) -> Reason.NO_MATCH
        location == LocationState.DENIED -> Reason.LOCATION_DENIED
        location == LocationState.OFF -> Reason.LOCATION_OFF
        location == LocationState.UNAVAILABLE -> Reason.LOCATION_UNAVAILABLE
        else -> Reason.NO_MATCH
    }

    /**
     * A typed coordinate, with a comma as the decimal mark too. Both or neither: `null` means the
     * pair is wrong (the core checks again when it saves).
     */
    fun point(latitude: String, longitude: String): Result<Pair<Double, Double>?> {
        val lat = latitude.trim().replace(',', '.')
        val lon = longitude.trim().replace(',', '.')
        if (lat.isEmpty() && lon.isEmpty()) return Result.success(null)
        val a = lat.toDoubleOrNull()
        val b = lon.toDoubleOrNull()
        if (a == null || b == null || a !in -90.0..90.0 || b !in -180.0..180.0) return Result.failure(IllegalArgumentException("point"))
        return Result.success(a to b)
    }
}
