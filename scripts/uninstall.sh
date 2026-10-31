#!/usr/bin/env bash
# TunnelPannel safe uninstall (P13 §38): removes ONLY proven-owned resources.
# Never flushes firewalls, never touches unknown interfaces/routes/services.
set -Eeuo pipefail

SERVICE="tunnelpannel-api"
INSTALL_DIR="/opt/tunnelpannel"
CONF_DIR="/etc/tunnelpannel"
DATA_DIR="/var/lib/tunnelpannel"
LOG_DIR="/var/log/tunnelpannel"
REPO="${TUNNELPANNEL_REPO:-https://github.com/DashSaman/TunnelPannel}"

check_managed_paths() {
  local path parent occupied=0 effective marker="$CONF_DIR/.managed-paths" origin
  for path in "$INSTALL_DIR" "$DATA_DIR" "$CONF_DIR" "$LOG_DIR"; do
    parent="$path"
    while [[ "$parent" != / && "$parent" != . && "$parent" != *: ]]; do
      [[ ! -L "$parent" ]] || { echo "ownership: symlink path refused: $path" >&2; return 1; }
      parent="$(dirname "$parent")"
    done
    [[ ! -e "$path" || -d "$path" ]] || { echo "ownership: non-directory path refused" >&2; return 1; }
    if [[ -d "$path" && -n "$(find "$path" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then occupied=1; fi
  done
  effective="$(systemctl show "$SERVICE" -p ExecStart --value 2>/dev/null)" || return 1
  if [[ -n "$effective" && "$effective" != '{}' ]]; then
    [[ "$effective" == "{ path=$INSTALL_DIR/.venv/bin/uvicorn ; argv[]=$INSTALL_DIR/.venv/bin/uvicorn apps.api.main:app --host 127.0.0.1 --port "* \
       && "$effective" != *'} {'* && "$effective" != *$'\n'* ]] \
      || { echo "ownership: foreign effective service refused" >&2; return 1; }
  fi
  [[ ! -L "$marker" ]] || { echo "ownership: symlink marker refused" >&2; return 1; }
  if [[ -f "$marker" && "$(stat -c %u "$marker")" == 0 \
        && "$(cat "$marker")" == TunnelPannel-managed-paths-v1 ]]; then return 0; fi
  [[ "$occupied" == 0 && ( -z "$effective" || "$effective" == '{}' ) ]] && return 0
  # Adopt a legacy canonical installation only with its receipt AND source identity.
  [[ -f "$DATA_DIR/install-receipt.json" && ! -L "$DATA_DIR/install-receipt.json" \
     && -d "$INSTALL_DIR/.git" && -f "$INSTALL_DIR/apps/api/main.py" ]] \
    || { echo "ownership: unmarked existing paths refused" >&2; return 1; }
  origin="$(git -C "$INSTALL_DIR" remote get-url origin)" || return 1
  [[ "${origin%.git}" == "${REPO%.git}" ]] \
    || { echo "ownership: foreign source repository refused" >&2; return 1; }
  python3 - "$DATA_DIR/install-receipt.json" "$INSTALL_DIR" "$DATA_DIR" "$CONF_DIR" "$SERVICE" <<'OWNERSHIP'
import json, sys
try:
    r = json.load(open(sys.argv[1], encoding='utf8'))
    assert r['product'] == 'TunnelPannel' and r['install_path'] == sys.argv[2]
    assert r['data_path'] == sys.argv[3] and r['config_path'] == sys.argv[4] + '/tunnelpannel.env'
    assert r['services'] == [sys.argv[5]]
except (OSError, ValueError, KeyError, AssertionError):
    raise SystemExit('ownership: legacy receipt mismatch')
OWNERSHIP
}


[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
check_managed_paths || exit 1
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
