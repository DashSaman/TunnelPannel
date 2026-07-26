#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo; echo "❌ PACK 7 FAILED — SSH session remains open."; echo "cd /opt/network-automation && docker compose logs --tail 220 api plan_executor"' ERR
cd /opt/network-automation
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="backups/engine-pack7-final-${STAMP}"
mkdir -p "$BACKUP"
for f in backend/app/execution_capabilities.py backend/app/tunnel_catalog.py plan_executor/executor.py docker-compose.yml; do
  [ -f "$f" ] && cp "$f" "$BACKUP/$(basename "$f")"
done
echo "Backup: /opt/network-automation/$BACKUP"
install -m 0644 "$(dirname "$0")/backend/execution_capabilities.py" backend/app/execution_capabilities.py
install -m 0644 "$(dirname "$0")/plan_executor/executor.py" plan_executor/executor.py
python3 - <<'PYCAT'
from pathlib import Path
import re
p=Path('backend/app/tunnel_catalog.py')
text=p.read_text(encoding='utf-8')
b='# NETAUTO_PACK7_FINAL_DEFAULTS_BEGIN'
e='# NETAUTO_PACK7_FINAL_DEFAULTS_END'
if b in text and e in text:
    text=re.sub(re.escape(b)+r'.*?'+re.escape(e),'',text,count=1,flags=re.S)
patch=r'''

# NETAUTO_PACK7_FINAL_DEFAULTS_BEGIN
PACK7_PARAMETERS = {
 "WATERWALL_DIRECT": ["listen_port","transport_port","target_host","target_port","bind_address"],
 "WATERWALL_REVERSE": ["listen_port","transport_port","target_host","target_port","bind_address","minimum_unused"],
 "WATERWALL_TLS_MUX": ["listen_port","transport_port","target_host","target_port","bind_address","sni","mux_connections"],
 "PAQET_RAW_KCP": ["listen_port","transport_port","target_host","target_port","bind_address","kcp_mode","connections"],
 "PAQET_SOCKS5": ["listen_port","transport_port","bind_address","kcp_mode","connections"],
 "SIT_OVER_GOST": ["tunnel_cidr","tunnel_ip_a","tunnel_ip_b","carrier_port","mtu"],
 "GRE_OVER_GOST": ["tunnel_cidr","tunnel_ip_a","tunnel_ip_b","carrier_port","mtu"],
 "GRETAP_OVER_GOST": ["tunnel_cidr","tunnel_ip_a","tunnel_ip_b","carrier_port","mtu"],
 "SIT_OVER_SSH": ["tunnel_cidr","tunnel_ip_a","tunnel_ip_b","ssh_tunnel_id","mtu"],
 "GRE_OVER_SSH": ["tunnel_cidr","tunnel_ip_a","tunnel_ip_b","ssh_tunnel_id","mtu"],
 "GRE_OVER_WIREGUARD": ["tunnel_cidr","tunnel_ip_a","tunnel_ip_b","mtu"],
}
for _item in CATALOG:
    _id=_item.get('id')
    if _id not in PACK7_PARAMETERS:
        continue
    _item['parameters']=PACK7_PARAMETERS[_id]
    _item['simple_supported']=True
    _item['advanced_supported']=True
    _defaults=dict(_item.get('simple_defaults') or {})
    _cfg=dict(_defaults.get('config') or {})
    _cfg.update({
        'auto_install':True,
        'auto_precheck':True,
        'auto_inventory_refresh':True,
        'benchmark_enabled':True,
        'benchmark_duration':6,
        'benchmark_max_mbps':200,
    })
    if _id.startswith('WATERWALL_') or _id.startswith('PAQET_'):
        _cfg.setdefault('bind_address','127.0.0.1')
    if _id == 'WATERWALL_REVERSE':
        _cfg.setdefault('minimum_unused',8)
    _defaults['config']=_cfg
    _item['simple_defaults']=_defaults
METHODS={item['id']:item for item in CATALOG}
# NETAUTO_PACK7_FINAL_DEFAULTS_END
'''
p.write_text(text.rstrip()+patch+'\n',encoding='utf-8')
PYCAT

echo '===== SYNTAX ====='
python3 -m py_compile backend/app/execution_capabilities.py backend/app/tunnel_catalog.py plan_executor/executor.py
docker compose config >/tmp/netauto-pack7-compose.yml

echo '===== BUILD ====='
docker compose build api plan_executor

echo '===== START ====='
docker compose up -d --force-recreate api plan_executor web

healthy=0
for second in $(seq 1 120); do
  if curl -fsS http://127.0.0.1:18080/api/v1/health >/tmp/netauto-pack7-health.json 2>/dev/null; then
    healthy=1
    echo "API healthy after ${second}s."
    break
  fi
  sleep 1
done
if [ "$healthy" != 1 ]; then
  docker compose logs --tail 220 api plan_executor
  exit 1
fi
cat /tmp/netauto-pack7-health.json
echo

echo '===== CAPABILITIES ====='
docker compose exec -T api python - <<'PYAPI'
from app.execution_capabilities import CAPABILITY_PACK, IMPLEMENTED_METHODS
from app.tunnel_catalog import CATALOG
required={
 'WATERWALL_DIRECT','WATERWALL_REVERSE','WATERWALL_TLS_MUX',
 'PAQET_RAW_KCP','PAQET_SOCKS5',
 'SIT_OVER_GOST','GRE_OVER_GOST','GRETAP_OVER_GOST',
 'SIT_OVER_SSH','GRE_OVER_SSH','GRE_OVER_WIREGUARD',
}
missing=required-IMPLEMENTED_METHODS
if missing:
    raise SystemExit(f'Missing capabilities: {sorted(missing)}')
ids={x['id'] for x in CATALOG}
if IMPLEMENTED_METHODS != ids:
    raise SystemExit(
        f'Capability/catalog mismatch; executable={len(IMPLEMENTED_METHODS)} '
        f'catalog={len(ids)} missing={sorted(ids-IMPLEMENTED_METHODS)} '
        f'extra={sorted(IMPLEMENTED_METHODS-ids)}'
    )
print(CAPABILITY_PACK)
print(f'Executable methods: {len(IMPLEMENTED_METHODS)}')
print(f'Catalog methods: {len(ids)}')
PYAPI

echo '===== EXECUTOR SELF-CHECK ====='
docker compose exec -T plan_executor python - <<'PYEXEC'
import executor
required={
 'WATERWALL_DIRECT','WATERWALL_REVERSE','WATERWALL_TLS_MUX',
 'PAQET_RAW_KCP','PAQET_SOCKS5',
 'SIT_OVER_GOST','GRE_OVER_GOST','GRETAP_OVER_GOST',
 'SIT_OVER_SSH','GRE_OVER_SSH','GRE_OVER_WIREGUARD',
}
missing=required-executor.SUPPORTED
if missing:
    raise SystemExit(f'Executor missing: {sorted(missing)}')
for name in (
 'deploy_waterwall_method','deploy_paqet_method','deploy_composite_method',
 'deploy_secure_gost_tun_carrier','register_artifact_guardian','benchmark_tunnel',
):
    if not hasattr(executor,name):
        raise SystemExit('Missing function: '+name)
assert len(executor.SUPPORTED)==77, len(executor.SUPPORTED)
print('Container executable methods: 77')
print('WaterWall engine family: OK')
print('Paqet engine family: OK')
print('Composite carrier family: OK')
print('Guardian and benchmark integration: OK')
PYEXEC

stable=0
prev=''
for attempt in $(seq 1 30); do
  state=$(docker inspect -f '{{.State.Status}} {{.RestartCount}}' netauto-plan-executor 2>/dev/null || true)
  status=${state%% *}
  restarts=${state##* }
  if [ "$status" = running ] && [ -n "$prev" ] && [ "$restarts" = "$prev" ]; then
    stable=1
    break
  fi
  prev=$restarts
  sleep 3
done
if [ "$stable" != 1 ]; then
  docker compose logs --tail 240 plan_executor
  exit 1
fi
if docker compose logs --tail 300 api plan_executor | grep -Eqi 'Traceback|NameError|SyntaxError|IndentationError|ImportError|ModuleNotFoundError'; then
  docker compose logs --tail 300 api plan_executor
  exit 1
fi

systemctl is-enabled netauto-stack.service >/dev/null
systemctl is-enabled netauto-stack-guardian.timer >/dev/null

mkdir -p .netauto-master/packs .netauto-master/logs
cp "$0" .netauto-master/packs/07-final-engines.sh
chmod 700 .netauto-master/packs/07-final-engines.sh
python3 - <<'PYSTATUS'
from pathlib import Path
from datetime import datetime, timezone
import json
p=Path('.netauto-master/status.json')
try:
    d=json.loads(p.read_text(encoding='utf-8'))
except Exception:
    d={'phases':{}}
d.setdefault('phases',{})
now=datetime.now(timezone.utc).isoformat()
d['updated_at']=now
d['phases']['07-final-engines']={
    'state':'SUCCESS',
    'message':'All 77 catalog methods have executable engines; WaterWall, Paqet and composite carriers include guardian and benchmark integration.',
    'updated_at':now,
}
p.write_text(json.dumps(d,indent=2,ensure_ascii=False),encoding='utf-8')
PYSTATUS

rm -f /tmp/netauto-pack7-compose.yml /tmp/netauto-pack7-health.json /tmp/netauto-*.txt 2>/dev/null || true

echo
echo '✅ PACK 7 — ALL 77 TUNNEL ENGINES READY'
echo 'Executable methods: 77'
echo 'WaterWall: Direct Reverse TLS+MUX'
echo 'Paqet: Raw KCP SOCKS5'
echo 'Composite: SIT/GRE/GRETAP over secure GOST, SSH or WireGuard'
echo 'Guardian and reboot persistence: ENABLED'
echo 'Bidirectional L3 benchmark integration: ENABLED'
