# syntax=docker/dockerfile:1
# The sync server with the web vault built in (served from /web on the same port).
# Build from the repository root:
#   docker build -f apps/server/Dockerfile -t octapass-server .
# Base images are pinned by digest; update the tag and digest together.

# The crypto core for the web vault, compiled to WebAssembly, as packages/core/scripts/build.mjs
# builds it: the small `web` build for everything but PGP imports, the `tools` build the vault worker
# loads when the Tools section opens (developer toolkit and OpenPGP), and the `full` build it loads to
# import a Proton Pass export.
#
# The cargo registry cache is shared with the `build` stage, which BuildKit runs at the same time;
# `sharing=locked` keeps the two from unpacking the same crate at once ("failed to unpack package").
FROM rust:1.98-slim-trixie@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7 AS wasm
WORKDIR /src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install wasm-pack --locked --version 0.15.0
COPY Cargo.toml Cargo.lock rust-toolchain.tom[l] ./
COPY crates crates
# Every workspace member in Cargo.toml, and the app crates they depend on.
COPY apps/server apps/server
COPY apps/relay apps/relay
COPY apps/witness apps/witness
COPY apps/push-relay apps/push-relay
COPY apps/cli apps/cli
COPY apps/desktop/Cargo.toml apps/desktop/Cargo.toml
COPY apps/desktop/crates apps/desktop/crates
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target \
    wasm-pack build crates/octapass-wasm --profile wasm-release --target web \
      --out-dir /src/packages/core/dist/web --out-name octapass_core --no-pack -- --no-default-features \
    && wasm-pack build crates/octapass-wasm --profile wasm-release --target web \
      --out-dir /src/packages/core/dist/tools --out-name octapass_core --no-pack -- --no-default-features --features toolkit,pgp \
    && wasm-pack build crates/octapass-wasm --release --target web \
      --out-dir /src/packages/core/dist/full --out-name octapass_core --no-pack

# The web vault. `same-origin` makes the "Octa Pass" server choice this server.
FROM node:24.22.1-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea AS web
WORKDIR /src
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
COPY . .
COPY --from=wasm /src/packages/core/dist/web packages/core/dist/web
COPY --from=wasm /src/packages/core/dist/tools packages/core/dist/tools
COPY --from=wasm /src/packages/core/dist/full packages/core/dist/full
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --filter @octapass/web...
RUN VITE_SERVER_URL=same-origin pnpm --filter @octapass/web build \
    && find apps/web/dist -name '*.map' -delete \
    && find apps/web/dist -type f \( -name '*.js' -o -name '*.css' -o -name '*.wasm' -o -name '*.svg' -o -name '*.html' \) \
       -exec gzip -9 -k {} +

FROM rust:1.98-slim-trixie@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7 AS build
WORKDIR /src
# rust-toolchain.toml is optional; the glob keeps COPY from failing without it.
COPY Cargo.toml Cargo.lock rust-toolchain.tom[l] ./
COPY crates crates
# Every workspace member in Cargo.toml, and the app crates they depend on.
COPY apps/server apps/server
COPY apps/relay apps/relay
COPY apps/witness apps/witness
COPY apps/push-relay apps/push-relay
COPY apps/cli apps/cli
COPY apps/desktop/Cargo.toml apps/desktop/Cargo.toml
COPY apps/desktop/crates apps/desktop/crates
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p octapass-server \
    && cp target/release/octapass-server /octapass-server
RUN mkdir /data /backups

# Distroless: no shell or package manager, runs as uid 65532.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e
COPY --from=build /octapass-server /usr/local/bin/octapass-server
COPY --from=build --chown=nonroot:nonroot /data /data
COPY --from=build --chown=nonroot:nonroot /backups /backups
COPY --from=web /src/apps/web/dist /web
ENV OCTAPASS_BIND=0.0.0.0:8080 \
    OCTAPASS_DATA_DIR=/data \
    OCTAPASS_WEB_DIR=/web
EXPOSE 8080
VOLUME /data
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/octapass-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/octapass-server"]
