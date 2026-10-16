#!/usr/bin/env bash
# Optional push-only telemetry client. Run from a verified TunnelPannel checkout.
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ $# -eq 1 ]] || { echo 'Usage: agent-install.sh /private/bundle.json | --uninstall' >&2; exit 1; }
command -v systemctl >/dev/null
command -v python3 >/dev/null
CODE=/opt/tunnelpannel-agent
CONF=/etc/tunnelpannel-agent
UNIT=/etc/systemd/system/tunnelpannel-agent.service
for directory in "$CODE" "$CONF"; do
  [[ ! -L "$directory" ]] || { echo 'Refusing symbolic-link installation directory.' >&2; exit 1; }
  if [[ -e "$directory" && ! -f "$directory/.tunnelpannel-agent-owned" ]]; then
    echo 'Existing directory is not owned by this installer.' >&2; exit 1
  fi
done
if [[ $1 == --uninstall ]]; then
  [[ -f "$CODE/.tunnelpannel-agent-owned" ]] || { echo 'No owned client installation.' >&2; exit 1; }
  systemctl disable --now tunnelpannel-agent.service >/dev/null 2>&1 || true
  rm -f -- "$UNIT" "$CODE/telemetry.py" "$CODE/.tunnelpannel-agent-owned" "$CONF/bundle.json" "$CONF/.tunnelpannel-agent-owned"
  rmdir -- "$CODE" "$CONF" 2>/dev/null || true
  systemctl daemon-reload
  echo 'Owned telemetry client removed. Revoke its certificate in the panel.'
  exit 0
fi
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ -f "$ROOT/agent/telemetry.py" && ! -L "$1" && -f "$1" ]] || { echo 'Source or private bundle missing.' >&2; exit 1; }
python3 - "$1" <<'PY'
import json, os, stat, sys
from urllib.parse import urlsplit
path=sys.argv[1]
info=os.stat(path)
if info.st_size>32768 or info.st_mode & 0o077:
    raise SystemExit('Bundle must be a private file (chmod600), at most32KiB.')
bundle=json.load(open(path))
if not all(isinstance(bundle.get(k),str) and bundle[k] for k in ('certificate','private_key','ca','hub_url')):
    raise SystemExit('Incomplete telemetry bundle or hub URL.')
url=urlsplit(bundle['hub_url'])
if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('','/'):
    raise SystemExit('A verified HTTPS hub origin is required.')
PY
if [[ -e "$UNIT" ]] && ! grep -q '^# TunnelPannel owned telemetry client v1$' "$UNIT"; then
  echo 'Refusing an unowned systemd unit.' >&2; exit 1
fi
install -d -m755 "$CODE"
install -d -m700 "$CONF"
printf 'v1\n' > "$CODE/.tunnelpannel-agent-owned"
printf 'v1\n' > "$CONF/.tunnelpannel-agent-owned"
install -m644 "$ROOT/agent/telemetry.py" "$CODE/telemetry.py"
install -m600 "$1" "$CONF/bundle.json"
cat > "$UNIT" <<'UNIT'
# TunnelPannel owned telemetry client v1
[Unit]
Description=TunnelPannel restricted telemetry client
After=network-online.target
Wants=network-online.target
[Service]
DynamicUser=yes
LoadCredential=bundle.json:/etc/tunnelpannel-agent/bundle.json
ExecStart=/usr/bin/python3 /opt/tunnelpannel-agent/telemetry.py --bundle %d/bundle.json
Restart=on-failure
RestartSec=10
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now tunnelpannel-agent.service >/dev/null
systemctl restart tunnelpannel-agent.service
echo 'Unprivileged telemetry client installed; check last_seen in the panel.'
