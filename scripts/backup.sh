#!/usr/bin/env bash
# TunnelPannel canonical backup (P13 §35-§37): DB + desired state + config
# metadata + resource-ownership ledger, checksummed, secret-safe.
#   scripts/backup.sh [output.tar.gz]     (default: /var/lib/tunnelpannel/backups/…)
set -Eeuo pipefail

CONF_DIR="/etc/tunnelpannel"
DATA_DIR="/var/lib/tunnelpannel"
INSTALL_DIR="/opt/tunnelpannel"
OUT="${1:-$DATA_DIR/backups/backup-$(date -u +%Y%m%dT%H%M%SZ).tar.gz}"

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
mkdir -p "$(dirname "$OUT")"
WORK=$(mktemp -d /tmp/tp-backup.XXXX)
trap 'rm -rf "$WORK"' EXIT

set -a; . "$CONF_DIR/tunnelpannel.env"; set +a

# 1. database dump (sqlite: safe online copy via VACUUM INTO; postgres: pg_dump)
if [[ "$DATABASE_URL" == sqlite:///* ]]; then
  DB_PATH="${DATABASE_URL#sqlite:///}"
  sudo -u tunnelpannel sqlite3 "$DB_PATH" "VACUUM INTO '$WORK/database.db'"
else
  command -v pg_dump >/dev/null || { echo "pg_dump required for postgres"; exit 1; }
  pg_dump "$DATABASE_URL" > "$WORK/database.sql"
fi

# 2. state + metadata (secret-safe: the env file is deliberately EXCLUDED)
cp -a "$DATA_DIR/install-receipt.json" "$WORK/" 2>/dev/null || true
cp -a "$INSTALL_DIR/engines/manifests" "$WORK/manifests"
printf '%s\n' "$DATABASE_URL" > "$WORK/db-url.txt"
SCHEMA_REV="$(sudo -u tunnelpannel env DATABASE_URL="$DATABASE_URL" \
  "$INSTALL_DIR/.venv/bin/python" -m alembic -c "$INSTALL_DIR/alembic.ini" current 2>/dev/null \
  | tail -1 | awk '{print $1}')"
cat > "$WORK/backup-receipt.json" <<RECEIPT
{
  "product": "TunnelPannel",
  "kind": "backup",
  "created_at": "$(date -u +%FT%TZ)",
  "included": ["database", "install-receipt", "engine-manifests", "db-url"],
  "secrets_included": false,
  "schema_revision": "${SCHEMA_REV:-unknown}"
}
RECEIPT

# 3. package + checksum
tar -czf "$OUT" -C "$WORK" .
( cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )
echo "backup complete: $OUT (+ .sha256)"
