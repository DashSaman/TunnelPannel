#!/usr/bin/env bash
# TunnelGuard helper — install the Hedioum Pool Tunnel binary for the hub.
# Run this on the IRAN server BEFORE adding a hedioum tunnel in the wizard.
#
#   sudo bash scripts/install_hedioum.sh
#
# The FOREIGN server is configured separately with hedioum's own installer:
#   bash <(curl -fsSL https://raw.githubusercontent.com/hedioum/Hedioum-Pool-Tunnel/main/install.sh)
#   hedioum-tunnel install && hedioum-tunnel setup-foreign --persona auto
# then paste the printed pairing token into the TunnelGuard wizard.
set -euo pipefail

DEST=/usr/local/bin/hedioum-tunnel
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ASSET=hedioum-tunnel ;;
  aarch64) ASSET=hedioum-tunnel-arm64 ;;
  *) echo "unsupported arch: $ARCH (get the armv7 build manually)"; exit 1 ;;
esac

if [ "$(id -u)" -ne 0 ]; then echo "run with sudo"; exit 1; fi

echo ">> downloading $ASSET from GitHub releases…"
URL="https://github.com/hedioum/Hedioum-Pool-Tunnel/releases/latest/download/$ASSET"
curl -fsSL "$URL" -o "$DEST.tmp"
chmod +x "$DEST.tmp"
mv "$DEST.tmp" "$DEST"

echo ">> enabling BBR + fq (hedioum network tuning)…"
sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true

echo ">> version: $("$DEST" version 2>&1 | head -1)"
echo "OK — now run 'hedioum-tunnel setup-foreign' on the foreign server,"
echo "then add a 'Hedioum Pool Tunnel' tunnel in the TunnelGuard wizard"
echo "and paste the pairing token."
