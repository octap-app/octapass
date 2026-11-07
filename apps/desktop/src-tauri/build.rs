fn main() {
    // The Tauri app is for Windows and Linux; on a Mac, Octa Pass is the native app (apps/macos,
    // plan 19). lib.rs stops a macOS build with the reason, so Tauri's own steps are skipped here.
    // The target's OS decides, not the host's: the Windows build cross-compiles on a Mac.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        return;
    }
    tauri_build::build()
}
