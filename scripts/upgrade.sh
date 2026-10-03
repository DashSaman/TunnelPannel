#!/usr/bin/env bash
# TunnelPannel upgrade (P13 §48-§50): preflight → backup → fetch → migrate →
# restart → health; keeps the previous version for rollback.
#   curl -fsSL https://raw.githubusercontent.com/DashSaman/TunnelPannel/main/scripts/upgrade.sh | sudo bash
# or: TUNNELPANNEL_VERSION=v1.x.y sudo -E scripts/upgrade.sh
set -Eeuo pipefail

INSTALL_DIR="/opt/tunnelpannel"
CONF_DIR="/etc/tunnelpannel"
DATA_DIR="/var/lib/tunnelpannel"
SERVICE="tunnelpannel-api"
VERSION="${TUNNELPANNEL_VERSION:-main}"
BACKUPS="$DATA_DIR/backups"

STAGE="preflight"
note() { printf '\n[upgrade] [%s] %s\n' "$STAGE" "$*"; }
die()  { printf '\n[upgrade] FAILED at %s: %s — rollback: cd %s && git checkout %s && systemctl restart %s\n' \
              "$STAGE" "$*" "$INSTALL_DIR" "${PREV:-unknown}" "$SERVICE" >&2; exit 1; }
trap 'die "unexpected error"' ERR

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
[[ -d "$INSTALL_DIR/.git" ]] || { echo "no installation at $INSTALL_DIR — run install.sh first"; exit 1; }
PREV="$(git -C "$INSTALL_DIR" rev-parse HEAD)"
note "installed: ${PREV:0:12} → target: $VERSION"

STAGE="backup"
mkdir -p "$BACKUPS"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
bash "$INSTALL_DIR/scripts/backup.sh" "$BACKUPS/pre-upgrade-$STAMP.tar.gz" \
  || die "pre-upgrade backup failed (aborting — system unchanged)"
note "backup written: $BACKUPS/pre-upgrade-$STAMP.tar.gz"

STAGE="fetch"
git -C "$INSTALL_DIR" fetch --tags --quiet
git -C "$INSTALL_DIR" checkout -q "$VERSION" || die "target version not found"
NEW_SHA="$(git -C "$INSTALL_DIR" rev-parse HEAD)"

STAGE="deps"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install -q -r "$INSTALL_DIR/requirements-canonical.txt"

STAGE="migrate"
set -a; . "$CONF_DIR/tunnelpannel.env"; set +a
cd "$INSTALL_DIR"
sudo -u tunnelpannel env DATABASE_URL="$DATABASE_URL" \
  "$INSTALL_DIR/.venv/bin/python" -m alembic upgrade head || die "migration failed"

STAGE="restart"
systemctl restart "$SERVICE"

STAGE="health"
for i in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:${TUNNELPANNEL_PORT:-8080}/health" >/dev/null 2>&1 && { HEALTH=ok; break; }
  sleep 1
done
[[ "${HEALTH:-}" == "ok" ]] || die "post-upgrade health check failed"

SCHEMA_REV="$(sudo -u tunnelpannel env DATABASE_URL="$DATABASE_URL" \
  "$INSTALL_DIR/.venv/bin/python" -m alembic current 2>/dev/null | tail -1 | awk '{print $1}')"
python3 - "$DATA_DIR/install-receipt.json" "$VERSION" "$NEW_SHA" "$SCHEMA_REV" << 'PYEOF'
import json, sys, pathlib
p = pathlib.Path(sys.argv[1])
r = json.loads(p.read_text()) if p.exists() else {}
r.update(version=sys.argv[2], commit=sys.argv[3], schema_revision=sys.argv[4],
         upgraded_at=__import__("datetime").datetime.utcnow().isoformat() + "Z")
p.write_text(json.dumps(r, indent=2))
PYEOF
note "upgrade complete: ${PREV:0:12} → ${NEW_SHA:0:12} (schema $SCHEMA_REV, health OK)"
note "rollback if needed: git -C $INSTALL_DIR checkout ${PREV:0:12} && systemctl restart $SERVICE"
