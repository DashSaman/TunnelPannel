#!/bin/bash
# srv2_install — isolated MTF deployment on 91.107.138.246 (no interference with existing sites)
# Runs under nohup; stages written to /opt/multitunnel/data/STATUS.json
set -u
BASE=/opt/multitunnel
LOG=$BASE/logs/install.log
mkdir -p "$BASE/data" "$BASE/logs"
exec >> "$LOG" 2>&1
echo "===== srv2 install $(date) ====="

stage(){ python3 -c '
import json,sys,time
p="/opt/multitunnel/data/STATUS.json"
try: d=json.load(open(p))
except Exception: d={}
d.setdefault("stages",{})[sys.argv[1]]={"state":sys.argv[2],"ts":time.time()}
json.dump(d,open(p,"w"),indent=1)
' "$1" "$2" 2>/dev/null; }

stage start running
mkdir -p "$BASE"/{data,logs,certs,methods,bin,tests/receipts}
tar xzf /root/mtf_deploy.tar.gz -C "$BASE" && echo "extract ok" || { stage extract failed; exit 1; }
stage extract done

# --- admin credentials (username+password login) ---
cat > "$BASE/data/panel_secret.json" <<'EOF'
{"username": "admin", "password": "123456@MTF"}
EOF

# --- TLS: wildcard *.softarg.ir shipped in package ---
if [ -s "$BASE/mtf_certs/panel.pem" ]; then
  cp -f "$BASE/mtf_certs/panel.pem" "$BASE/certs/panel.pem"
  cp -f "$BASE/mtf_certs/panel-key.pem" "$BASE/certs/panel-key.pem"
  chmod 600 "$BASE/certs/panel-key.pem"
  echo "wildcard cert installed"
else
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -days 825 -nodes \
    -keyout "$BASE/certs/panel-key.pem" -out "$BASE/certs/panel.pem" \
    -subj "/CN=tun.softarg.ir" -addext "subjectAltName=DNS:tun.softarg.ir,IP:91.107.138.246" >/dev/null 2>&1
  echo "self-signed cert generated"
fi
stage certs done

# --- firewall: open 9443 only if ufw is active (never touching other rules) ---
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 9443/tcp >/dev/null 2>&1 && echo "ufw allow 9443 added"
fi
stage fw done

# --- dedicated docker network (fresh subnet, away from 172.17/22/23/24) ---
docker network create mtfnet --subnet 172.31.0.0/24 >/dev/null 2>&1 || true
docker rm -f mtf-panel >/dev/null 2>&1 || true

stage build running
if docker build -t mtf-panel:2.0 "$BASE/docker"; then stage build done; else stage build FAILED; exit 1; fi

docker run -d --name mtf-panel \
  --privileged --restart unless-stopped \
  --network mtfnet \
  -p 9443:9443 \
  -v "$BASE/data":/opt/multitunnel/data \
  -v "$BASE/logs":/opt/multitunnel/logs \
  -v "$BASE/certs":/opt/multitunnel/certs \
  -v "$BASE/bin":/opt/multitunnel/bin \
  -v "$BASE/engine":/opt/multitunnel/engine \
  -v "$BASE/panel":/opt/multitunnel/panel \
  -v "$BASE/methods":/opt/multitunnel/methods \
  -v "$BASE/tests":/opt/multitunnel/tests \
  mtf-panel:2.0 || { stage run FAILED; exit 1; }
stage run "started"

# --- wait for panel health (max 40s) ---
ok=""
for i in $(seq 1 20); do
  sleep 2
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 4 https://127.0.0.1:9443/health 2>/dev/null)
  if [ "$code" = "200" ]; then ok=1; break; fi
done
if [ -n "$ok" ]; then stage panel "up (https://tun.softarg.ir:9443)"; else stage panel "not-yet"; fi

# --- kick off binary fetcher in background ---
install -m 755 "$BASE/fix_bins_v3.sh" /opt/multitunnel/fix_bins_v3.sh 2>/dev/null || true
[ -s /root/.ghtoken ] && nohup bash /opt/multitunnel/fix_bins_v3.sh >/dev/null 2>&1 &
echo "===== srv2 install end $(date) ====="
