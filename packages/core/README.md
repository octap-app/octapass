# @octapass/core

The Octa Pass crypto core (Rust, compiled to WebAssembly) for the web vault. The source is [`crates/octapass-core`](../../crates/octapass-core/) and its bindings are in [`crates/octapass-wasm`](../../crates/octapass-wasm/). The API, the sign-up/login/reauth sequences and how to load it in a worker are documented in [`crates/octapass-wasm/README.md`](../../crates/octapass-wasm/README.md).

```sh
pnpm --filter @octapass/core build            # dist/web, dist/tools, dist/full and dist/node
pnpm --filter @octapass/core build:if-stale   # the same, skipped while dist/ matches the Rust sources
pnpm --filter @octapass/core test    # sign-up → login → encrypt → decrypt → reauth → recovery, in WASM
pnpm --filter @octapass/core bench   # Argon2id unlock time
```

`dist/` is generated and not committed. Each build records a hash of the Rust sources it was built from in `dist/.sources-hash`. `pnpm build:web`, `pnpm start`, `dev:stack`, the web vault's end-to-end tests and the Safari build call `build:if-stale`, so they rebuild the core after a pull that changes the crates instead of type-checking against an old `dist/`.
