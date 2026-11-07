# Contributing to Octa Pass

Thanks for helping. Octa Pass is in early development: the core, server, web vault, browser extension and desktop and phone apps all run, and nothing has had its external security audit yet. Reviews of the security design and code, bug reports, docs and translations are all valuable.

The full guide is on the website: [Contributing](docs/contributing/overview.md) · [Development setup](docs/contributing/development-setup.md) · [Writing docs](docs/contributing/writing-docs.md).

## Quick start

```bash
pnpm install       # Node 22+, pnpm 11
pnpm dev           # website + docs at http://localhost:4321
pnpm build         # must pass before you open a PR
```

The apps run from the repository root too:

```bash
pnpm dev:stack        # web vault at http://localhost:5174 and a throwaway API on :8080
pnpm dev:api          # the API alone on :8080 in dev mode, data in ~/.octapass-dev
pnpm dev:web          # the web vault alone
pnpm dev:extension    # rebuilds the extensions on change, in apps/extension/dist
pnpm dev:ios          # the Simulator, against whichever local server runs (dev:ios:device for an iPhone)
pnpm dev:android      # an emulator or phone, against whichever local server runs

pnpm build:web        # the web vault; build:api the server
pnpm build:extension  # also build:safari, build:ios, build:android, build:desktop (build:macos on a
                      # Mac, build:windows, build:linux), build:cli, build:vscode, build:jetbrains
pnpm start            # builds, then serves the API and web vault together on 127.0.0.1:8380
pnpm start --setup    # asks again where people open it and who can sign up
pnpm serve            # the same without building
```

`pnpm start` is for a tunnel or proxy, so dev mode is off. Its first run in a terminal asks where people open it and who can create an account, and can save the answers in the gitignored `.env.local`. The device scripts ask only what they can't work out. The app builds ask once which server the apps offer as "Octa Pass", and can save it in `.env.local`. Every one takes `--setup` to ask again. [Development setup](docs/contributing/development-setup.md#serve-it-or-run-the-native-apps) has the details, and the settings are at the top of each script.

CI (`.github/workflows/ci.yml`) runs the same checks on every pull request: `cargo fmt --check`, `cargo clippy -D warnings` and `cargo test` for the Rust workspaces (the server also against PostgreSQL), typecheck and unit tests for every package, client tests against a real server, the website build, and the browser end-to-end tests. [Development setup](docs/contributing/development-setup.md) shows how to run each locally.

## The short rules

1. **Sign off your commits** (Developer Certificate of Origin): `git commit -s`. There's no CLA; contributions are licensed under MIT.
2. **Behaviour or architecture changes** update the relevant `plans/` file and the matching `docs/` page in the same PR.
3. **Notable changes** add a file in `changelog/` (see `changelog/README.md`).
4. **Security-sensitive areas** (crypto, keys, auth, sync, autofill) need a "Security considerations" section in the PR description.
5. **No ads, trackers or third-party scripts**, anywhere.
6. **AI-assisted work is fine, but a human is the author.** Don't add AI tools as commit authors or co-authors. Agents: read [`AGENTS.md`](AGENTS.md).

Be kind. We follow the [Code of Conduct](CODE_OF_CONDUCT.md).
