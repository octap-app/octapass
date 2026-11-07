package app.octap.wear

import org.json.JSONException
import org.json.JSONObject

/**
 * What the watch does with the codes the phone sends: reading a bundle and picking the code for
 * this moment. No one-time code math: the codes are made in the Rust core on the phone
 * (`crates/octapass-mobile/src/watch.rs`). Plain Kotlin, tested on the JVM.
 */

/** A format this build doesn't know is ignored, never guessed at. */
private const val KNOWN_FORMAT = 1

/** The most a bundle may last, whatever it says: `WATCH_BUNDLE_TTL_MS` in the Rust core. */
private const val LONGEST_LIFETIME_MS = 15 * 60 * 1000L

/** One item's codes, as the core made them. */
data class WatchEntry(
    val id: String,
    val title: String,
    val favorite: Boolean,
    /** Seconds per code. */
    val period: Long,
    /** Characters per code. */
    val digits: Int,
    /** When `codes[0]` started. `codes[n]` starts `n` periods later. */
    val startMs: Long,
    val codes: List<String>,
) {
    /** The code for this moment, or null before the first one or after the last. */
    fun codeAt(nowMs: Long): WatchCode? {
        if (nowMs < startMs) return null
        val periodMs = period * 1000
        val index = (nowMs - startMs) / periodMs
        if (index >= codes.size) return null
        val elapsedMs = (nowMs - startMs) % periodMs
        return WatchCode(codes[index.toInt()], periodMs - elapsedMs, periodMs)
    }
}

/** The code to show now, with what the countdown ring needs. */
data class WatchCode(val text: String, val remainingMs: Long, val periodMs: Long) {
    /** How much of the code's time is left, from 1 down to 0. */
    val fraction: Float get() = remainingMs.toFloat() / periodMs

    /** Whole seconds left, rounded up, so it reaches 1 and never shows 0. */
    val remainingSeconds: Int get() = ((remainingMs + 999) / 1000).toInt()

    /** `123 456`, `1234 5678`. A Steam-style five-character code stays in one piece. */
    val display: String
        get() = if (text.length < 6) text else "${text.take(text.length / 2)} ${text.drop(text.length / 2)}"
}

data class WatchBundle(val issuedAtMs: Long, val expiresAtMs: Long, val entries: List<WatchEntry>) {
    fun isExpired(nowMs: Long): Boolean = nowMs >= minOf(expiresAtMs, issuedAtMs + LONGEST_LIFETIME_MS)
}

/** What the phone sent. */
sealed interface WatchPayload {
    val issuedAtMs: Long

    data class Bundle(val bundle: WatchBundle) : WatchPayload {
        override val issuedAtMs get() = bundle.issuedAtMs
    }

    data class Clear(override val issuedAtMs: Long) : WatchPayload

    companion object {
        /** Null for anything that isn't a payload of a known version. An entry that makes no sense is left out; the rest still show. */
        fun decode(text: String): WatchPayload? = try {
            val json = JSONObject(text)
            when {
                json.getInt("v") != KNOWN_FORMAT -> null
                json.optBoolean("clear") -> Clear(json.getLong("issuedAtMs"))
                else -> Bundle(bundle(json))
            }
        } catch (_: JSONException) {
            null
        }

        private fun bundle(json: JSONObject): WatchBundle {
            val entries = json.getJSONArray("entries")
            return WatchBundle(
                issuedAtMs = json.getLong("issuedAtMs"),
                expiresAtMs = json.getLong("expiresAtMs"),
                entries = (0 until entries.length()).mapNotNull { entry(entries.getJSONObject(it)) },
            )
        }

        private fun entry(json: JSONObject): WatchEntry? {
            val codes = json.getJSONArray("codes")
            val entry = WatchEntry(
                id = json.getString("id"),
                title = json.getString("title"),
                favorite = json.getBoolean("favorite"),
                period = json.getLong("period"),
                digits = json.getInt("digits"),
                startMs = json.getLong("startMs"),
                codes = (0 until codes.length()).map { codes.getString(it) },
            )
            return entry.takeIf { it.period > 0 && it.period <= Long.MAX_VALUE / 1000 && it.codes.isNotEmpty() }
        }
    }
}

/** What the watch has: the newest payload's codes, only until they expire. */
data class WatchCodes(private val bundle: WatchBundle? = null, private val newestIssuedAtMs: Long = 0) {
    /**
     * Payloads can arrive out of order: an older one never replaces a newer one, so a late bundle
     * can't bring back what a clear removed.
     */
    fun applying(payload: WatchPayload): WatchCodes = when {
        payload.issuedAtMs < newestIssuedAtMs -> this
        payload is WatchPayload.Bundle -> WatchCodes(payload.bundle, payload.issuedAtMs)
        else -> WatchCodes(null, payload.issuedAtMs)
    }

    /** Drops the codes once they've expired, so they don't stay in memory. */
    fun forgettingExpired(nowMs: Long): WatchCodes =
        if (bundle?.isExpired(nowMs) == true) copy(bundle = null) else this

    /**
     * The rows to show now, in the phone's order (favourites first). Empty when there's nothing
     * valid: expired, cleared, or a clock too far from the phone's.
     */
    fun rows(nowMs: Long): List<Pair<WatchEntry, WatchCode>> {
        val live = bundle?.takeUnless { it.isExpired(nowMs) } ?: return emptyList()
        return live.entries.mapNotNull { entry -> entry.codeAt(nowMs)?.let { entry to it } }
    }

    /** The phone has answered, with a live bundle, and the vault has no codes. */
    fun isEmptyVault(nowMs: Long): Boolean = bundle?.let { !it.isExpired(nowMs) && it.entries.isEmpty() } ?: false
}
