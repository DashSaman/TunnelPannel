#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo; echo "❌ PACK 5 FAILED — SSH session remains open."; echo "docker compose logs --tail 180 api plan_executor"' ERR

cd /opt/network-automation
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="backups/engine-pack5-vpn-ipsec-${STAMP}"
mkdir -p "$BACKUP"
for file in backend/app/execution_capabilities.py backend/app/tunnel_catalog.py plan_executor/executor.py; do
  [[ -f "$file" ]] && cp "$file" "$BACKUP/$(basename "$file")"
done
echo "Backup: /opt/network-automation/$BACKUP"

install -m 0644 "$(dirname "$0")/backend/execution_capabilities.py" backend/app/execution_capabilities.py
install -m 0644 "$(dirname "$0")/plan_executor/executor.py" plan_executor/executor.py

python3 - <<'PY_CATALOG'
from pathlib import Path
import re
path = Path('backend/app/tunnel_catalog.py')
text = path.read_text(encoding='utf-8')
begin = '# NETAUTO_PACK5_VPN_DEFAULTS_BEGIN'
end = '# NETAUTO_PACK5_VPN_DEFAULTS_END'
if begin in text and end in text:
    text = re.sub(re.escape(begin)+r'.*?'+re.escape(end), '', text, count=1, flags=re.S)
patch = r'''

# NETAUTO_PACK5_VPN_DEFAULTS_BEGIN
PACK5_VPN_METHODS = {"OPENVPN", "IKEV2_IPSEC", "L2TP_IPSEC", "VTI", "VTI6"}
for _method in CATALOG:
    if _method.get("id") not in PACK5_VPN_METHODS:
        continue
    _method["simple_supported"] = True
    _method["advanced_supported"] = True
    _defaults = dict(_method.get("simple_defaults", {}))
    _config = dict(_defaults.get("config", {}))
    _config.update({"auto_install": True, "auto_precheck": True, "auto_inventory_refresh": True, "benchmark_enabled": True, "benchmark_duration": 6, "benchmark_max_mbps": 200})
    _defaults["config"] = _config
    _method["simple_defaults"] = _defaults
    if _method["id"] == "L2TP_IPSEC":
        _method["flags"] = ["SINGLE_INSTANCE", "LEGACY", "IPSEC", "PPP"]
        _method["description"] = "Legacy L2TP over IPsec compatibility tunnel; prefer IKEv2 or WireGuard."
    elif _method["id"] == "OPENVPN":
        _method["flags"] = ["MULTI_INSTANCE", "TLS", "UDP", "PEER_FINGERPRINT", "TLS_CRYPT"]
    elif _method["id"] == "IKEV2_IPSEC":
        _method["flags"] = ["MULTI_INSTANCE", "IKEV2", "IPSEC", "XFRM_INTERFACE"]
    else:
        _method["flags"] = ["MULTI_INSTANCE", "IKEV2", "IPSEC", "ROUTE_BASED"]
METHODS = {item["id"]: item for item in CATALOG}
# NETAUTO_PACK5_VPN_DEFAULTS_END
'''
path.write_text(text.rstrip()+'\n'+patch+'\n', encoding='utf-8')
PY_CATALOG

python3 -m py_compile backend/app/execution_capabilities.py backend/app/tunnel_catalog.py plan_executor/executor.py
docker compose config > /tmp/netauto-pack5-compose.yml

docker compose build api plan_executor
docker compose up -d --force-recreate api plan_executor web

healthy=0
for second in $(seq 1 90); do
  if curl -fsS http://127.0.0.1:18080/api/v1/health > /tmp/netauto-pack5-health.json 2>/dev/null; then
    healthy=1; echo "API healthy after ${second}s."; break
  fi
  sleep 1
done
if [[ "$healthy" != 1 ]]; then
  docker compose logs --tail 180 api plan_executor
  exit 1
fi
cat /tmp/netauto-pack5-health.json; echo

docker compose exec -T api python - <<'PY_API'
from app.execution_capabilities import CAPABILITY_PACK, IMPLEMENTED_METHODS
required={"OPENVPN","IKEV2_IPSEC","L2TP_IPSEC","VTI","VTI6"}
missing=required-IMPLEMENTED_METHODS
assert not missing, missing
assert len(IMPLEMENTED_METHODS)==54, len(IMPLEMENTED_METHODS)
print(CAPABILITY_PACK)
print(f"Executable methods: {len(IMPLEMENTED_METHODS)}")
PY_API

docker compose exec -T plan_executor python - <<'PY_EXECUTOR'
import executor
required={"OPENVPN","IKEV2_IPSEC","L2TP_IPSEC","VTI","VTI6"}
missing=required-executor.SUPPORTED
assert not missing, missing
for name in ("deploy_openvpn","deploy_strongswan_route_based","deploy_l2tp_ipsec","deploy_vpn_method"):
    assert hasattr(executor,name), name
print(f"Container executable methods: {len(executor.SUPPORTED)}")
print("OpenVPN engine: OK")
print("IKEv2/IPsec engine: OK")
print("VTI/VTI6 engines: OK")
print("L2TP/IPsec guarded legacy engine: OK")
PY_EXECUTOR

docker compose ps api plan_executor web
docker compose logs --tail 60 plan_executor
if docker compose logs --tail 240 api plan_executor | grep -Eqi 'Traceback|SyntaxError|IndentationError|ImportError|ModuleNotFoundError'; then
  echo 'Python startup/import error detected.'; exit 1
fi

mkdir -p .netauto-master/packs .netauto-master/logs
cp "$0" .netauto-master/packs/05-vpn-ipsec.sh
chmod 700 .netauto-master/packs/05-vpn-ipsec.sh
python3 - <<'PY_STATUS'
from pathlib import Path
from datetime import datetime, timezone
import json
path=Path('.netauto-master/status.json')
try:data=json.loads(path.read_text())
except Exception:data={'phases':{}}
data.setdefault('phases',{})
now=datetime.now(timezone.utc).isoformat(); data['updated_at']=now
data['phases']['05-vpn-ipsec']={'state':'SUCCESS','message':'OpenVPN, IKEv2/IPsec, VTI, VTI6 and guarded L2TP/IPsec engines installed.','updated_at':now}
path.write_text(json.dumps(data,indent=2,ensure_ascii=False))
PY_STATUS
rm -f /tmp/netauto-pack5-compose.yml /tmp/netauto-pack5-health.json /tmp/netauto-*.txt 2>/dev/null || true

echo
echo '✅ PACK 5 — VPN + IPSEC ENGINES READY'
echo 'Executable methods: 54'
echo 'Added: OPENVPN IKEV2_IPSEC L2TP_IPSEC VTI VTI6'
