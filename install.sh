#!/usr/bin/env bash
# TunnelPannel one-line installer (P13 §39-§47)
#
#   curl -fsSL https://raw.githubusercontent.com/DashSaman/TunnelPannel/main/install.sh | sudo bash
#
# Installs the CANONICAL application (apps/api + web UI). The legacy
# Gen1 docker stack remains available in git history and deploy/.
# Idempotent: a second run reconciles (keeps config/secrets/DB), never resets.
# Supported/tested: Ubuntu LTS (22.04/24.04), Debian stable (11/12).
# Other distributions fail honestly instead of guessing.
set -Eeuo pipefail

REPO="https://github.com/DashSaman/TunnelPannel"
INSTALL_DIR="/opt/tunnelpannel"
DATA_DIR="/var/lib/tunnelpannel"
CONF_DIR="/etc/tunnelpannel"
LOG_DIR="/var/log/tunnelpannel"
SERVICE="tunnelpannel-api"
TP_VERSION="${TUNNELPANNEL_VERSION:-main}"   # release tag, or 'main' = development mode
PORT="${TUNNELPANNEL_PORT:-8080}"
LOG_FILE="$LOG_DIR/install.log"

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1
STAGE="preflight"
note() { printf '\n[install] [%s] %s\n' "$STAGE" "$*"; }
die()  { printf '\n[install] FAILED at stage %s: %s\n  log: %s\n  safe retry: fix the cause and re-run install.sh (idempotent)\n' \
              "$STAGE" "$*" "$LOG_FILE" >&2; exit 1; }
trap 'die "unexpected error (see log above)"' ERR

# ── 1. OS / arch detection ────────────────────────────────────────────
STAGE="detect-os"
[[ $EUID -eq 0 ]] || die "run as root (curl … | sudo bash)"
command -v apt-get >/dev/null 2>&1 || die "only apt-based hosts are supported (Ubuntu LTS / Debian stable); refusing to guess"
OS_ID="$(. /etc/os-release >/dev/null 2>&1; echo "$ID")"
OS_VERSION_ID="$(. /etc/os-release >/dev/null 2>&1; echo "$VERSION_ID")"
case "$OS_ID:${OS_VERSION_ID%%.*}" in
  ubuntu:2[24]|debian:1[123]) ;;
  *) die "unsupported distribution: $OS_ID $OS_VERSION_ID (tested: Ubuntu 22.04/24.04, Debian 11/12)" ;;
esac
ARCH="$(dpkg --print-architecture)"
note "detected $OS_ID $OS_VERSION_ID ($ARCH); target version: $TP_VERSION"

# ── 2. base dependencies ──────────────────────────────────────────────
STAGE="base-deps"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl git python3 python3-venv python3-pip sqlite3 openssl sudo >/dev/null

# ── 3. service user + directories (idempotent) ─────────────────────────
STAGE="user-dirs"
id -r tunnelpannel >/dev/null 2>&1 || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin tunnelpannel
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$CONF_DIR" "$LOG_DIR"
chown -R tunnelpannel:tunnelpannel "$DATA_DIR" "$LOG_DIR"

# ── 4. obtain source ──────────────────────────────────────────────────
STAGE="fetch-source"
if [[ -d "$INSTALL_DIR/.git" ]]; then
  note "existing installation detected — reconciling (config/secrets/DB preserved)"
  git -C "$INSTALL_DIR" fetch --tags --quiet
else
  note "cloning into $INSTALL_DIR"
  git clone -q "$REPO" "$INSTALL_DIR"
fi
git -C "$INSTALL_DIR" checkout -q "$TP_VERSION"
GIT_SHA="$(git -C "$INSTALL_DIR" rev-parse HEAD)"
note "checked out $TP_VERSION @ ${GIT_SHA:0:12}"

# ── 5. secrets + runtime config (generated once, preserved on reruns) ──
STAGE="config"
if [[ ! -f "$CONF_DIR/tunnelpannel.env" ]]; then
  SECRET_KEY="$(openssl rand -hex 32)"
  gen_hash() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
  # initial tokens printed to the operator ONCE, stored only as hashes
  V_TOKEN="tp-viewer-$(openssl rand -hex 8)"
  O_TOKEN="tp-operator-$(openssl rand -hex 8)"
  A_TOKEN="tp-admin-$(openssl rand -hex 8)"
  cat > "$CONF_DIR/tunnelpannel.env" <<ENV
# TunnelPannel runtime configuration — generated $(date -u +%FT%TZ). NEVER COMMIT.
DATABASE_URL=sqlite:///$DATA_DIR/tunnelpannel.db
TP_SECRET_KEY=$SECRET_KEY
TP_RBAC_TOKENS=VIEWER:$(gen_hash "$V_TOKEN"),OPERATOR:$(gen_hash "$O_TOKEN"),SUPER_ADMIN:$(gen_hash "$A_TOKEN")
TP_BOT_ALLOWED_IDS=
TELEGRAM_BOT_TOKEN=
ENV
  chmod 640 "$CONF_DIR/tunnelpannel.env"
  chown root:tunnelpannel "$CONF_DIR/tunnelpannel.env"
  SHOW_TOKENS=1
else
  note "existing configuration preserved (no secrets regenerated)"
  SHOW_TOKENS=0
fi

# ── 6. python environment ─────────────────────────────────────────────
STAGE="python-env"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -q -r "$INSTALL_DIR/requirements-canonical.txt"

# ── 7. database migrations ────────────────────────────────────────────
STAGE="migrate"
set -a; . "$CONF_DIR/tunnelpannel.env"; set +a
mkdir -p "$DATA_DIR"; chown -R tunnelpannel:tunnelpannel "$DATA_DIR"
run_migrations() {
  sudo -u tunnelpannel env DATABASE_URL="$DATABASE_URL" \
    "$INSTALL_DIR/.venv/bin/python" -m alembic -c "$INSTALL_DIR/alembic.ini" upgrade head
}
cd "$INSTALL_DIR"
run_migrations || die "alembic migration failed"
SCHEMA_REV="$(sudo -u tunnelpannel env DATABASE_URL="$DATABASE_URL" \
  "$INSTALL_DIR/.venv/bin/python" -m alembic -c "$INSTALL_DIR/alembic.ini" current 2>/dev/null | tail -1 | awk '{print $1}')"
note "schema at revision: ${SCHEMA_REV:-unknown}"

# ── 8. systemd service (idempotent: enable + restart, never duplicate) ─
STAGE="service"
cat > "/etc/systemd/system/$SERVICE.service" <<UNIT
[Unit]
Description=TunnelPannel canonical API + web UI
After=network-online.target

[Service]
Type=simple
User=tunnelpannel
Group=tunnelpannel
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$CONF_DIR/tunnelpannel.env
ExecStart=$INSTALL_DIR/.venv/bin/uvicorn apps.api.main:app --host 127.0.0.1 --port $PORT
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"

# ── 9. health check (real HTTP probe, not just 'systemctl active') ────
STAGE="health"
HEALTH=""
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then HEALTH=ok; break; fi
  sleep 1
done
[[ "$HEALTH" == "ok" ]] || die "service did not become healthy on :$PORT (inspect: journalctl -u $SERVICE -n 50)"

# ── 10. install receipt (no secrets) ──────────────────────────────────
STAGE="receipt"
cat > "$DATA_DIR/install-receipt.json" <<RECEIPT
{
  "product": "TunnelPannel",
  "version": "$TP_VERSION",
  "commit": "$GIT_SHA",
  "install_path": "$INSTALL_DIR",
  "config_path": "$CONF_DIR/tunnelpannel.env",
  "data_path": "$DATA_DIR",
  "schema_revision": "$SCHEMA_REV",
  "services": ["$SERVICE"],
  "port": $PORT,
  "health": "ok",
  "installed_at": "$(date -u +%FT%TZ)"
}
RECEIPT
chown tunnelpannel:tunnelpannel "$DATA_DIR/install-receipt.json"

note "installation complete — API/UI: http://127.0.0.1:$PORT (health OK)"
if [[ "$SHOW_TOKENS" == "1" ]]; then
  echo
  echo "  FIRST-RUN RBAC TOKENS (shown ONCE — only their hashes are stored):"
  echo "    VIEWER:      $V_TOKEN"
  echo "    OPERATOR:    $O_TOKEN"
  echo "    SUPER_ADMIN: $A_TOKEN"
  echo "  Store these now; they cannot be recovered from the server."
  echo "  This notice appears only on first install (reruns never reset credentials)."
fi
