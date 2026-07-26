#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo; echo "❌ PACK 2 FAILED — SSH session remains open."' ERR

PROJECT="/opt/network-automation"
cd "$PROJECT"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="backups/engine-pack2-ssh-gost-${STAMP}"
mkdir -p "$BACKUP"

for file in \
  backend/app/execution_capabilities.py \
  plan_executor/executor.py \
  docker-compose.yml
 do
  [[ -f "$file" ]] && cp "$file" "$BACKUP/$(basename "$file")"
done

echo "Backup: $PROJECT/$BACKUP"

if ! docker compose ps plan_executor 2>/dev/null | grep -q netauto-plan-executor; then
  echo "Pack 1 plan_executor is not installed."
  exit 1
fi

install -m 0644 \
  "$(dirname "$0")/backend/execution_capabilities.py" \
  backend/app/execution_capabilities.py

install -m 0644 \
  "$(dirname "$0")/plan_executor/executor.py" \
  plan_executor/executor.py

python3 -m py_compile \
  backend/app/execution_capabilities.py \
  plan_executor/executor.py

echo "Python syntax: OK"

docker compose config > /tmp/netauto-pack2-compose.yml

echo "===== BUILD ====="
docker compose build api plan_executor

echo "===== START ====="
docker compose up -d --force-recreate api plan_executor web

sleep 22

echo "===== HEALTH ====="
curl -fsS http://127.0.0.1:18080/api/v1/health
echo

echo "===== CAPABILITIES ====="
docker compose exec -T api python - <<'PY'
from app.execution_capabilities import CAPABILITY_PACK, IMPLEMENTED_METHODS

required = {
    "SSH_LOCAL_FORWARD",
    "SSH_REMOTE_FORWARD",
    "SSH_DYNAMIC_SOCKS",
    "AUTOSSH_REVERSE",
    "SSH_TUN_L3",
    "SSH_TAP_L2",
    "GOST_TCP_FORWARD",
    "GOST_UDP_FORWARD",
    "GOST_REMOTE_TCP",
    "GOST_REMOTE_UDP",
    "GOST_SOCKS5",
    "GOST_HTTP",
    "GOST_WS",
    "GOST_HTTP2",
    "GOST_GRPC",
    "GOST_QUIC",
    "GOST_SSH",
    "GOST_TUN",
    "GOST_TAP",
}

missing = required - IMPLEMENTED_METHODS
assert not missing, sorted(missing)
print(CAPABILITY_PACK)
print(", ".join(sorted(IMPLEMENTED_METHODS)))
PY

echo "===== EXECUTOR ====="
docker compose ps plan_executor
docker compose logs --tail 40 plan_executor

if docker compose logs --tail 80 plan_executor | grep -q "Traceback"; then
  echo "Executor traceback detected."
  exit 1
fi

mkdir -p .netauto-master/packs .netauto-master/logs
cp "$0" .netauto-master/packs/02-ssh-gost.sh
chmod 700 .netauto-master/packs/02-ssh-gost.sh

python3 - <<'PY'
from pathlib import Path
from datetime import datetime, timezone
import json

path = Path('.netauto-master/status.json')
try:
    data = json.loads(path.read_text(encoding='utf-8'))
except Exception:
    data = {'phases': {}}

data.setdefault('phases', {})
now = datetime.now(timezone.utc).isoformat()
data['updated_at'] = now
data['phases']['02-ssh-gost'] = {
    'state': 'SUCCESS',
    'message': 'SSH and GOST execution engines installed and verified.',
    'updated_at': now,
}
path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
PY

rm -f /tmp/netauto-pack2-compose.yml /tmp/netauto-*.txt 2>/dev/null || true

echo
echo "✅ PACK 2 — SSH + GOST READY"
echo "Total executable methods should now be 27."
