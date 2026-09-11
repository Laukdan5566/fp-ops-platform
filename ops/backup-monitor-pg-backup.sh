#!/usr/bin/env bash
set -euo pipefail

COMPOSE_DIR="${COMPOSE_DIR:-/home/fp/backup-monitor}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/backup-monitor}"
KEEP_ALL_DAYS="${KEEP_ALL_DAYS:-14}"
KEEP_DAILY_DAYS="${KEEP_DAILY_DAYS:-30}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
PROJECT="${PROJECT:-backup-monitor}"
DB_NAME="${POSTGRES_DB:-backup_monitor}"
DB_USER="${POSTGRES_USER:-backup_monitor}"

umask 077
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

timestamp="$(date +%Y%m%d-%H%M%S)"
backup_file="$BACKUP_DIR/postgres-$timestamp.sql.gz"

cd "$COMPOSE_DIR"
docker compose -f "$COMPOSE_FILE" -p "$PROJECT" exec -T postgres \
  pg_dump -U "$DB_USER" -d "$DB_NAME" --clean --if-exists \
  | gzip -c > "$backup_file"

gzip -t "$backup_file"

python3 - "$BACKUP_DIR" "$KEEP_ALL_DAYS" "$KEEP_DAILY_DAYS" <<'PY'
from collections import defaultdict
from pathlib import Path
import sys
import time

backup_dir = Path(sys.argv[1])
keep_all_days = int(sys.argv[2])
keep_daily_days = int(sys.argv[3])
now = time.time()
day = 86400
files = sorted(backup_dir.glob("postgres-*.sql.gz"), key=lambda p: p.stat().st_mtime)
daily = defaultdict(list)
remove = []

for path in files:
    age_days = (now - path.stat().st_mtime) / day
    if age_days <= keep_all_days:
        continue
    if age_days > keep_daily_days:
        remove.append(path)
        continue
    daily[time.strftime("%Y-%m-%d", time.localtime(path.stat().st_mtime))].append(path)

for paths in daily.values():
    remove.extend(paths[:-1])

removed_bytes = 0
for path in remove:
    removed_bytes += path.stat().st_size
    path.unlink()

print(f"Retention: removed={len(remove)} freed_bytes={removed_bytes}")
PY

echo "Backup created: $backup_file"
