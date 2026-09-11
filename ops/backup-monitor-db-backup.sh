#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/home/fp/backup-monitor}"
BACKUP_DIR="${BACKUP_DIR:-/home/fp/backup-monitor-db-backups}"
DB_PATH="${DB_PATH:-$APP_DIR/data/backups.db}"
KEEP_DAYS="${KEEP_DAYS:-30}"

mkdir -p "$BACKUP_DIR"

timestamp="$(date +%Y%m%d-%H%M%S)"
tmp_file="$BACKUP_DIR/backups-$timestamp.db.tmp"
backup_file="$BACKUP_DIR/backups-$timestamp.db"

if [ ! -f "$DB_PATH" ]; then
  echo "Database not found: $DB_PATH" >&2
  exit 1
fi

python3 - "$DB_PATH" "$tmp_file" <<'PY'
import sqlite3
import sys

src_path, dst_path = sys.argv[1], sys.argv[2]
src = sqlite3.connect(src_path)
dst = sqlite3.connect(dst_path)
try:
    src.backup(dst)
finally:
    dst.close()
    src.close()
PY

mv "$tmp_file" "$backup_file"
gzip -f "$backup_file"

find "$BACKUP_DIR" -name 'backups-*.db.gz' -type f -mtime +"$KEEP_DAYS" -delete

echo "Backup created: $backup_file.gz"
