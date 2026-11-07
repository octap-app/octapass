package app.octap.vault

import android.content.Context

/**
 * Hands the app's context to the HTTPS clients' certificate verifier (`rustls-platform-verifier`,
 * in `crates/octapass-mobile/src/android.rs`), so Android's own trust settings apply. Call it once
 * when the app starts, before the first vault call.
 */
object PlatformVerifier {
    init {
        System.loadLibrary("octapass_mobile")
    }

    @JvmStatic
    external fun init(context: Context)
}
