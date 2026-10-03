#!/usr/bin/env bash
# TunnelPannel canonical restore (P13 §36): verifies checksum, restores DB,
# verifies schema, health-checks. Double confirmation required.
#   scripts/restore.sh <backup.tar.gz>
set -Eeuo pipefail

CONF_DIR="/etc/tunnelpannel"
INSTALL_DIR="/opt/tunnelpannel"
SERVICE="tunnelpannel-api"

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
ARCHIVE="${1:-}"
[[ -n "$ARCHIVE" && -f "$ARCHIVE" ]] || { echo "usage: restore.sh <backup.tar.gz>"; exit 1; }

if [[ "${RESTORE_TUNNELPANNEL:-}" != "YES_I_UNDERSTAND" ]]; then
  echo "restore REPLACES the current database."
  echo "re-run with: RESTORE_TUNNELPANNEL=YES_I_UNDERSTAND scripts/restore.sh $ARCHIVE"
  exit 1
fi

WORK=$(mktemp -d /tmp/tp-restore.XXXX)
trap 'rm -rf "$WORK"' EXIT

# 1. checksum gate
( cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$ARCHIVE").sha256" ) \
  || { echo "checksum mismatch — refusing to restore"; exit 1; }

# 2. unpack
tar -xzf "$ARCHIVE" -C "$WORK"

set -a; . "$CONF_DIR/tunnelpannel.env"; set +a
systemctl stop "$SERVICE"

# 3. restore database
if [[ "$DATABASE_URL" == sqlite:///* ]]; then
  DB_PATH="${DATABASE_URL#sqlite:///}"
  cp -a "$DB_PATH" "$DB_PATH.pre-restore.$(date +%s)"       # safety copy
  install -o tunnelpannel -g tunnelpannel -m 640 "$WORK/database.db" "$DB_PATH"
else
  command -v pg_restore >/dev/null || { echo "pg_restore required"; exit 1; }
  pg_restore --clean --if-exists "$DATABASE_URL" < "$WORK/database.sql"
fi

# 4. schema + health verification
cd "$INSTALL_DIR"
sudo -u tunnelpannel env DATABASE_URL="$DATABASE_URL" \
  "$INSTALL_DIR/.venv/bin/python" -m alembic -c "$INSTALL_DIR/alembic.ini" current
systemctl start "$SERVICE"
for i in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:${TUNNELPANNEL_PORT:-8080}/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "http://127.0.0.1:${TUNNELPANNEL_PORT:-8080}/health" >/dev/null \
  || { echo "restore finished but health check failed — inspect journalctl -u $SERVICE"; exit 1; }

echo "restore complete (health OK). backup receipt:"
cat "$WORK/backup-receipt.json" 2>/dev/null || true
