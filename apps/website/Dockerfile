# syntax=docker/dockerfile:1
# The website and docs (https://octap.app): a static Astro build served by nginx.
# Build from the repository root:
#   docker build -f apps/website/Dockerfile -t octapass-website .
FROM node:24.22.1-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea AS build
WORKDIR /src
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
COPY . .
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --filter @octapass/website...
ARG PUBLIC_SITE_URL=https://octap.app
RUN PUBLIC_SITE_URL=$PUBLIC_SITE_URL pnpm --filter @octapass/website build \
    && find apps/website/dist -type f \( -name '*.html' -o -name '*.css' -o -name '*.js' -o -name '*.svg' -o -name '*.xml' -o -name '*.txt' -o -name '*.md' -o -name '*.json' \) \
       -exec gzip -9 -k {} +

FROM nginx:1.29-alpine
COPY apps/website/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/apps/website/dist /usr/share/nginx/html
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
EXPOSE 8080
