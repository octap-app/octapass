package app.octap.android.vault

/**
 * The bindings (`app.octap.core`) load the app's own Rust library, which links `octapass-ffi`
 * and exports its UniFFI functions, so the app and its services share one build of the core
 * instead of shipping a second `liboctapass_ffi.so`. Call before the first binding is used.
 *
 * The library is the app's `liboctapass_mobile.so` (`crates/octapass-mobile`, which carries
 * `octapass-ffi`'s API too). A test can name another before any binding is used.
 */
object Core {
    @Volatile
    var library = "octapass_mobile"

    fun load() {
        System.setProperty("uniffi.component.octapass_ffi.libraryOverride", library)
    }
}
