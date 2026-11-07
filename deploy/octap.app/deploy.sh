#!/usr/bin/env bash
# Build the images here, copy them to the server over SSH, and restart the stack there.
# The server never builds anything.
#
#   deploy/octap.app/deploy.sh                 # build both images and deploy
#   SKIP_BUILD=1 TAG=20261107-1 deploy.sh      # redeploy images already built locally
#
# Needs: Docker here, an SSH host alias for the server (DEPLOY_HOST, default "macberry"),
# Docker + Compose there, and Traefik's external "proxy" network.
set -euo pipefail

HOST="${DEPLOY_HOST:-macberry}"
DIR="${DEPLOY_DIR:-/opt/stacks/octapass}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TAG="${TAG:-$(date -u +%Y%m%d)-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo local)}"
PLATFORM="${PLATFORM:-linux/amd64}"
# Extra ssh/scp options, e.g. SSH_OPTS="-o IdentityAgent=none -i ~/.ssh/id_ed25519" to skip an agent.
read -r -a SSH_OPTS_ARR <<< "${SSH_OPTS:-}"
ssh() { command ssh ${SSH_OPTS_ARR[@]+"${SSH_OPTS_ARR[@]}"} "$@"; }
scp() { command scp ${SSH_OPTS_ARR[@]+"${SSH_OPTS_ARR[@]}"} "$@"; }

if [[ -z "${SKIP_BUILD:-}" ]]; then
  echo "==> building octapass-server:$TAG"
  docker build --platform "$PLATFORM" -f "$ROOT/apps/server/Dockerfile" -t "octapass-server:$TAG" "$ROOT"
  echo "==> building octapass-website:$TAG"
  # The image has no .git, so hand the website each page's last commit date (sitemap <lastmod>, JSON-LD).
  # Same command as GIT_LOG_ARGS in apps/website/src/lib/lastmod.mjs.
  git -C "$ROOT" -c core.quotePath=false log --format=@@%cI --name-only -- docs changelog apps/website/src \
    > "$ROOT/apps/website/.git-dates.txt"
  docker build --platform "$PLATFORM" -f "$ROOT/apps/website/Dockerfile" -t "octapass-website:$TAG" "$ROOT"
fi

echo "==> copying images to $HOST"
docker save "octapass-server:$TAG" "octapass-website:$TAG" | gzip -1 | ssh "$HOST" 'gunzip | docker load'

echo "==> updating $HOST:$DIR"
ssh "$HOST" "mkdir -p '$DIR/backups' && chmod 700 '$DIR/backups'"
scp -q "$ROOT/deploy/octap.app/docker-compose.yml" "$HOST:$DIR/docker-compose.yml"
ssh "$HOST" bash -s -- "$DIR" "$TAG" <<'REMOTE'
set -euo pipefail
cd "$1"
if [[ ! -f .env ]]; then
  echo "missing $1/.env: copy .env.example there and fill it in" >&2
  exit 1
fi
if grep -q '^OCTAPASS_TAG=' .env; then
  sed -i "s/^OCTAPASS_TAG=.*/OCTAPASS_TAG=$2/" .env
else
  echo "OCTAPASS_TAG=$2" >> .env
fi
docker compose pull --ignore-buildable --quiet db backup 2>/dev/null || docker compose pull --quiet db backup
docker compose up -d --remove-orphans
docker compose ps
# Keep the three newest tags of each image.
for img in octapass-server octapass-website; do
  docker images "$img" --format '{{.Tag}}' | sort -r | tail -n +4 | xargs -r -I{} docker rmi "$img:{}" >/dev/null 2>&1 || true
done
REMOTE
echo "==> deployed $TAG"
