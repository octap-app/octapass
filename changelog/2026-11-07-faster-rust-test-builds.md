---
title: Faster Rust test builds
date: 2026-11-07
summary: Each crate's integration tests now build as one binary, and debug builds carry less debug info, so tests link faster and target/ stays much smaller.
tags: [core, server, cli, desktop, mobile]
---

For contributors:

- **One test binary per crate.** `octapass-core`, `octapass-server`, the CLI, the desktop vault and both mobile crates now build their integration tests as a single binary, `tests/main.rs`, instead of one per file. That's about 100 fewer links of the crypto core per full test run. To run one file's tests, use `cargo test -p <crate> --test integration <file>::`. The test-vector files in `octapass-core` keep their own binaries, so their regeneration commands are unchanged.
- **Less debug info.** Debug builds keep file and line numbers for Octa Pass's own code, so backtraces still point at the right line, and drop debug info for dependencies. That speeds up linking and cuts the size of `target/`.

See [Development setup](/docs/contributing/development-setup/#tests).
