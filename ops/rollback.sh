#!/usr/bin/env bash
# Volta web e worker para as imagens guardadas pelo ultimo ops/deploy.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
for img in backup-monitor-web backup-monitor-worker; do
  docker image inspect "$img:rollback" >/dev/null 2>&1 || { echo "sem imagem $img:rollback" >&2; exit 1; }
  docker tag "$img:rollback" "$img:latest"
done
docker compose -f docker-compose.prod.yml up -d --no-deps --force-recreate web worker
