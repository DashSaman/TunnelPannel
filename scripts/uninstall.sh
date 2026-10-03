#!/usr/bin/env bash
# TunnelPannel safe uninstall (P13 §38): removes ONLY proven-owned resources.
# Never flushes firewalls, never touches unknown interfaces/routes/services.
set -Eeuo pipefail

SERVICE="tunnelpannel-api"
INSTALL_DIR="/opt/tunnelpannel"
CONF_DIR="/etc/tunnelpannel"
DATA_DIR="/var/lib/tunnelpannel"
LOG_DIR="/var/log/tunnelpannel"

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
echo "[uninstall] stopping and removing ONLY the $SERVICE service"
systemctl stop "$SERVICE" 2>/dev/null || true
systemctl disable "$SERVICE" 2>/dev/null || true
rm -f "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload

echo "[uninstall] removing TunnelPannel-owned directories"
rm -rf "$INSTALL_DIR" "$LOG_DIR"

echo "[uninstall] preserving data+config by default: $DATA_DIR $CONF_DIR"
echo "            (delete manually if you really want them gone:)"
echo "            rm -rf $DATA_DIR $CONF_DIR"

# explicitly NOT touched: firewall state, network interfaces, routes,
# unrelated systemd units, docker objects, anything without our markers.
echo "[uninstall] done — no shared firewall/network state was modified."
