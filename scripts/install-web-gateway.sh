#!/usr/bin/env bash
# Website-only gateway. API/DB/queue and tunneling remain on another server.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
[[ "${TP_GATEWAY_VERSION:-}" =~ ^[0-9a-f]{40}$ ]] || { echo 'TP_GATEWAY_VERSION must be an immutable commit SHA' >&2; exit 1; }
: "${TP_GATEWAY_CONTROLLER_HOST:?controller host required}"
: "${TP_GATEWAY_SSH_USER:?forwarding-only SSH user required}"
: "${TP_GATEWAY_KEY_FILE:?private key file required}"
: "${TP_GATEWAY_KNOWN_HOSTS_FILE:?verified SSH host pins required}"
umask 077
work=$(mktemp -d /tmp/tp-web-installer.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
curl -fLsS --connect-timeout 15 --max-time 180 "https://codeload.github.com/DashSaman/TunnelPannel/tar.gz/$TP_GATEWAY_VERSION" -o "$work/source.tar.gz"
mkdir "$work/source"
tar -xzf "$work/source.tar.gz" --strip-components=1 -C "$work/source"
args=(--host "$TP_GATEWAY_CONTROLLER_HOST" --user "$TP_GATEWAY_SSH_USER"
      --ssh-port "${TP_GATEWAY_SSH_PORT:-22}" --api-port "${TP_GATEWAY_API_PORT:-8080}"
      --key-file "$TP_GATEWAY_KEY_FILE" --known-hosts "$TP_GATEWAY_KNOWN_HOSTS_FILE")
[[ -z "${TP_GATEWAY_HTTP_PORT:-}" ]] || args+=(--http-port "$TP_GATEWAY_HTTP_PORT")
[[ -z "${TP_GATEWAY_FORWARD_PORT:-}" ]] || args+=(--forward-port "$TP_GATEWAY_FORWARD_PORT")
python3 "$work/source/scripts/web_gateway.py" "${args[@]}"
