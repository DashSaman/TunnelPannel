#!/usr/bin/env bash
# TunnelGuard — install the paqet binary for the Paqet engine.
#
# Two paths, in order of preference:
#   1. Download a prebuilt release binary from upstream (fastest, static)
#   2. Build from source (needs go >= 1.25 + libpcap-dev)
#
# Usage:
#   sudo bash scripts/install_paqet.sh                 # try release, else source
#   sudo bash scripts/install_paqet.sh --source        # force build from source
#   sudo bash scripts/install_paqet.sh --repo /path/to/paqet   # local checkout
set -euo pipefail

DEST="/usr/local/bin/paqet"
ARCH="$(uname -m)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
FORCE_SOURCE=0
REPO_URL="https://github.com/hanselime/paqet.git"
LOCAL_REPO=""

for arg in "$@"; do
  case "$arg" in
    --source) FORCE_SOURCE=1 ;;
    --repo)   shift_arg=1 ;;
    *) if [ "${shift_arg:-0}" = "1" ]; then LOCAL_REPO="$arg"; shift_arg=0; fi ;;
  esac
done

case "$ARCH" in
  x86_64)  TARCH="amd64" ;;
  aarch64|arm64) TARCH="arm64" ;;
  *) TARCH="$ARCH" ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }

try_release() {
  echo "[i] trying prebuilt release binary (${OS}_${TARCH}) ..."
  local base="https://github.com/hanselime/paqet/releases/latest/download"
  local url="${base}/paqet_${OS}_${TARCH}"
  local tmp
  tmp="$(mktemp)"
  if curl -fsSL --connect-timeout 10 --max-time 120 "$url" -o "$tmp" \
     && [ -s "$tmp" ]; then
    install -m 0755 "$tmp" "$DEST"
    rm -f "$tmp"
    return 0
  fi
  rm -f "$tmp"
  return 1
}

build_source() {
  local src="$1"
  echo "[i] building paqet from $src ..."
  have go || { echo "[✗] go not installed (apt install golang-go >= 1.25)"; return 1; }
  have gcc || { echo "[✗] gcc not installed (apt install build-essential)"; return 1; }
  [ -f /usr/include/pcap.h ] || {
    echo "[i] libpcap headers missing — installing libpcap-dev ..."
    apt-get update -qq && apt-get install -y -qq libpcap-dev
  }
  (cd "$src" && CGO_ENABLED=1 go build -o "$DEST.tmp" ./cmd)
  install -m 0755 "$DEST.tmp" "$DEST"
  rm -f "$DEST.tmp"
}

# 1) already installed?
if [ -x "$DEST" ]; then
  echo "[✓] paqet already installed at $DEST"
  "$DEST" version 2>/dev/null || true
  exit 0
fi

# 2) local checkout given?
if [ -n "$LOCAL_REPO" ] && [ -d "$LOCAL_REPO" ]; then
  build_source "$LOCAL_REPO" || true
  [ -x "$DEST" ] || try_release || true
elif [ "$FORCE_SOURCE" = "1" ]; then
  tmpd="$(mktemp -d)"
  git clone --depth=1 "$REPO_URL" "$tmpd/paqet"
  build_source "$tmpd/paqet" || true
  [ -x "$DEST" ] || { echo "[✗] source build failed"; exit 1; }
else
  # 3) prebuilt release, else source
  try_release || {
    echo "[!] release download failed — falling back to source build"
    tmpd="$(mktemp -d)"
    git clone --depth=1 "$REPO_URL" "$tmpd/paqet"
    build_source "$tmpd/paqet"
  }
fi

[ -x "$DEST" ] || { echo "[✗] paqet not installed"; exit 1; }
echo "[✓] paqet installed: $DEST"
"$DEST" version 2>/dev/null || true
echo
echo "Next: TunnelGuard dashboard → Wizard ⚡ → Paqet → fill role/server/kcp_key"
echo "Server-side firewall rules (NOTRACK + RST drop) are applied automatically"
echo "by the adapter on up() when iptables_setup is on (needs root)."
