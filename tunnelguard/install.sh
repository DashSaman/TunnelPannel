#!/usr/bin/env bash
# TunnelGuard installer — Ubuntu 22.04 / 24.04 (Debian 12 fallback)
# - installs Docker-free Python service directly on the host (root, needs
#   CAP_NET_ADMIN to control tunnels — Docker layering would get in the way)
# - generates secrets, creates venv, systemd unit, waits for health
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/tunnelguard}"
WEB_BIND_PORT="${WEB_BIND_PORT:-8080}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

echo "== TunnelGuard installer =="
. /etc/os-release
case "${ID:-}" in
  ubuntu|debian) : ;;
  *) echo "WARN: untested distro '${ID:-?}' — continuing anyway" ;;
esac

echo "-- packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip wireguard-tools \
  openvpn nftables curl > /dev/null || \
  echo "WARN: some optional packages failed (strongswan/xl2tpd install separately if needed)"

echo "-- workspace: ${INSTALL_DIR}"
mkdir -p "$INSTALL_DIR"
if [ -d "$INSTALL_DIR/.git" ]; then
  git -C "$INSTALL_DIR" pull --ff-only || true
else
  if [ -n "${TF_SOURCE:-}" ] && [ -d "$TF_SOURCE" ]; then
    cp -r "$TF_SOURCE"/. "$INSTALL_DIR"/
  else
    git clone https://github.com/DashSaman/TunnelPannel.git "$INSTALL_DIR" 2>/dev/null || {
      echo "ERROR: set TF_SOURCE=/path/to/tunnelguard to install from a local checkout"
      exit 1; }
  fi
fi
cd "$INSTALL_DIR"

echo "-- python venv + deps"
python3 -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt

echo "-- secrets"
CONF_DIR=/etc/tunnelguard
mkdir -p "$CONF_DIR"
if [ ! -f "$CONF_DIR/secret.key" ]; then
  python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())" \
    > "$CONF_DIR/secret.key"
  chmod 600 "$CONF_DIR/secret.key"
fi
if [ ! -f "$CONF_DIR/env" ]; then
  ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(python3 -c "import secrets;print(secrets.token_urlsafe(12))")}"
  cat > "$CONF_DIR/env" <<EOF
TF_HOST=127.0.0.1
TF_PORT=${WEB_BIND_PORT}
TF_SECRET_KEY=$(cat "$CONF_DIR/secret.key")
TF_ADMIN_USERNAME=${ADMIN_USERNAME}
TF_ADMIN_PASSWORD=${ADMIN_PASSWORD}
EOF
  chmod 600 "$CONF_DIR/env"
  echo "=============================================================="
  echo "  FIRST ADMIN ->  ${ADMIN_USERNAME} / ${ADMIN_PASSWORD}"
  echo "  (stored in ${CONF_DIR/env} — chmod 600; CHANGE after first login)"
  echo "=============================================================="
fi

echo "-- systemd unit"
cat > /etc/systemd/system/tunnelguard.service <<EOF
[Unit]
Description=TunnelGuard multi-tunnel failover control plane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${CONF_DIR}/env
ExecStart=${INSTALL_DIR}/.venv/bin/python -m tfd
Restart=always
RestartSec=3
# tunnel control needs real kernel access: no sandboxing beyond basics
User=root
NoNewPrivileges=no
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now tunnelguard

echo "-- health wait"
for i in $(seq 1 30); do
  if curl -fs "http://127.0.0.1:${WEB_BIND_PORT}/api/health" > /dev/null 2>&1; then
    echo "OK: TunnelGuard is healthy on http://127.0.0.1:${WEB_BIND_PORT}/"
    echo "    (put your reverse proxy in front for HTTPS — do NOT expose plain 8080)"
    exit 0
  fi
  sleep 2
done
echo "ERROR: health check did not pass — journalctl -u tunnelguard -n 50"
exit 1
