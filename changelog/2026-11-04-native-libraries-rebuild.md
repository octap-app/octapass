---
title: The iPhone and Android builds rebuild their Rust library when it changes
date: 2026-11-04
summary: pnpm dev:ios, dev:ios:device, build:ios, dev:android and build:android rebuild the app's Rust library after a pull that changes it, and a failed Xcode build now shows its errors.
tags: [mobile]
---

The iPhone and Android apps link a library built from the Rust crates, through Swift and Kotlin bindings that are committed with the code. The scripts built that library only when it was missing. After a pull that changed the Rust API, they kept the old library. The new bindings then failed to compile against it, with errors like `cannot find 'uniffi_octapass_mobile_fn_…' in scope`.

The scripts now record a hash of the library's Rust sources and rebuild it when the hash changes, like the web vault's WebAssembly core. The first run after this change rebuilds it once.

A failed Xcode build used to show only its last three lines, which rarely named the problem. The scripts now print the error lines and the path of the full log in `apps/ios/build/`.
