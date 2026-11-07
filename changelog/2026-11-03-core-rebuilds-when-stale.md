---
title: Local builds rebuild the WASM core when its sources change
date: 2026-11-03
summary: pnpm start, pnpm build:web, dev:stack, the end-to-end tests and the Safari build now rebuild the WebAssembly core after a pull that changes the Rust crates, instead of reusing an old build.
tags: [core]
---

These commands used to build the WebAssembly core only when no build existed yet. After pulling changes to the Rust crates, they kept the old build, and the web vault failed to type-check against it with errors about missing core exports.

The core's build now records a hash of the Rust sources it was built from. The new `pnpm --filter @octapass/core build:if-stale` rebuilds only when that hash no longer matches, and the commands above call it every time. See [development setup](/docs/contributing/development-setup/).
