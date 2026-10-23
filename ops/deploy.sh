#!/usr/bin/env bash
# Atualiza o FP Ops no servidor a partir do GitHub, sem editar arquivo na mao.
# Uso (no servidor, em ~/backup-monitor):  ops/deploy.sh [branch]
# Recusa rodar com alteracao local nao commitada; guarda as imagens atuais como :rollback antes de reconstruir.
set -euo pipefail
cd "$(dirname "$0")/.."
BRANCH="${1:-$(git rev-parse --abbrev-ref HEAD)}"
COMPOSE="docker compose -f docker-compose.prod.yml"

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "Ha alteracoes locais nao commitadas; commite ou descarte antes de atualizar:" >&2
  git status --short --untracked-files=no >&2
  exit 1
fi

git fetch --quiet origin
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"
echo "Versao: $(git log -1 --format='%h %s')"

# guarda o que esta rodando para poder voltar (ops/rollback.sh)
for img in backup-monitor-web backup-monitor-worker; do
  docker image inspect "$img:latest" >/dev/null 2>&1 && docker tag "$img:latest" "$img:rollback"
done

$COMPOSE build web worker
$COMPOSE up -d --no-deps web worker
sleep 10
docker ps --format '{{.Names}} {{.Status}}' | grep backup-monitor
