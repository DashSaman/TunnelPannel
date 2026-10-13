#!/usr/bin/env bash
# Run the legacy harness in private network, process and mount namespaces.
# Receipts persist under /opt/multitunnel/data; host routes, XFRM and SSH
# authorization files are inaccessible to the destructive legacy harness.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "root is required for namespace isolation" >&2; exit 1; }
umask 077
command -v unshare >/dev/null
mkdir -p /root/.ssh /root/.mtf_ssh
SCRIPT="$(cd "$(dirname "$0")" && pwd)/run_all_tests.py"
exec unshare --mount --net --pid --fork --kill-child --mount-proc bash -e -o pipefail -c '
  mount --make-rprivate /
  mount -t tmpfs tmpfs /run
  mkdir -p /run/netns /run/sshd
  mount -t tmpfs tmpfs /root/.ssh
  mount -t tmpfs tmpfs /root/.mtf_ssh
  ip link set lo up
  exec python3 "$1"
' bash "$SCRIPT"
