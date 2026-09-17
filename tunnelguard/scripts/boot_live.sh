#!/usr/bin/env bash
# Boot the real TunnelGuard server (sim mode) and drive the wizard flow.
set -e
TG=/home/z/my-project/tunnelguard
export TF_DATA_DIR=/tmp/tg-live
export TF_SIM_MODE=1
export TF_ADMIN_USERNAME=admin
export TF_ADMIN_PASSWORD=livetest123
rm -rf /tmp/tg-live && mkdir -p /tmp/tg-live
cd $TG
python3 -m tfd > /tmp/tg-live/server.log 2>&1 &
echo $! > /tmp/tg-live/server.pid
sleep 5
curl -s http://127.0.0.1:8080/api/health | head -c 200; echo
