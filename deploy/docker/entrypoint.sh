#!/bin/bash
# MTF container entrypoint — panel + failover engine in one process
set -e
mkdir -p /dev/net || true
[ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200 || true
chmod 600 /dev/net/tun 2>/dev/null || true
mkdir -p /run/sshd /opt/multitunnel/data /opt/multitunnel/logs /opt/multitunnel/methods
cd /opt/multitunnel
exec /opt/mtf-venv/bin/python3 /opt/multitunnel/engine/run_panel.py
