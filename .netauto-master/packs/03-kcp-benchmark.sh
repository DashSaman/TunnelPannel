#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo; echo "❌ PACK 3 FAILED — SSH session remains open."' ERR

PROJECT="/opt/network-automation"
cd "$PROJECT"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="backups/engine-pack3-kcp-benchmark-${STAMP}"
mkdir -p "$BACKUP"

for file in \
  backend/app/execution_capabilities.py \
  backend/app/tunnel_catalog.py \
  plan_executor/executor.py \
  docker-compose.yml
do
  [[ -f "$file" ]] \
    && cp "$file" "$BACKUP/$(basename "$file")"
done

echo "Backup: $PROJECT/$BACKUP"

if ! docker compose ps plan_executor 2>/dev/null \
  | grep -q netauto-plan-executor
then
  echo "Pack 1/2 plan_executor is not installed."
  exit 1
fi

install -m 0644 \
  "$(dirname "$0")/backend/execution_capabilities.py" \
  backend/app/execution_capabilities.py

install -m 0644 \
  "$(dirname "$0")/plan_executor/executor.py" \
  plan_executor/executor.py

python3 - <<'PY'
from pathlib import Path
import re

path = Path("backend/app/tunnel_catalog.py")
text = path.read_text(encoding="utf-8")

begin = "# NETAUTO_PACK3_KCP_CATALOG_BEGIN"
end = "# NETAUTO_PACK3_KCP_CATALOG_END"

if begin in text and end in text:
    text = re.sub(
        re.escape(begin) + r".*?" + re.escape(end),
        "",
        text,
        count=1,
        flags=re.S,
    )

patch = r'''

# NETAUTO_PACK3_KCP_CATALOG_BEGIN

PACK3_METHODS = [
    {
        "id": "GOST_KCP_FORWARD",
        "name": "GOST TCP over KCP",
        "category": "GOST",
        "layer": "STREAM",
        "directions": ["A_TO_B", "B_TO_A"],
        "initiators": ["AUTO", "A", "B"],
        "carriers": [],
        "description": (
            "TCP forwarding between two endpoints "
            "using an authenticated KCP data channel."
        ),
        "flags": [
            "MULTI_INSTANCE",
            "TCP",
            "KCP",
            "UDP_CARRIER",
            "AUTO_TUNE",
        ],
        "simple_supported": True,
        "advanced_supported": True,
        "simple_defaults": {
            "traffic_direction": "A_TO_B",
            "initiator": "AUTO",
            "carrier_method_id": None,
            "config": {
                "mode": "SIMPLE",
                "auto_install": True,
                "auto_precheck": True,
                "auto_inventory_refresh": True,
                "benchmark_enabled": True,
                "benchmark_duration": 6,
                "benchmark_max_mbps": 200,
            },
        },
    },
    {
        "id": "GOST_SOCKS5_KCP",
        "name": "GOST SOCKS5 over KCP",
        "category": "GOST",
        "layer": "PROXY",
        "directions": ["A_TO_B", "B_TO_A"],
        "initiators": ["AUTO", "A", "B"],
        "carriers": [],
        "description": (
            "Authenticated SOCKS5 service "
            "transported by a tuned KCP channel."
        ),
        "flags": [
            "MULTI_INSTANCE",
            "SOCKS5",
            "KCP",
            "UDP_CARRIER",
            "AUTO_TUNE",
        ],
        "simple_supported": True,
        "advanced_supported": True,
        "simple_defaults": {
            "traffic_direction": "A_TO_B",
            "initiator": "AUTO",
            "carrier_method_id": None,
            "config": {
                "mode": "SIMPLE",
                "auto_install": True,
                "auto_precheck": True,
                "auto_inventory_refresh": True,
            },
        },
    },
]

_existing_method_ids = {
    item["id"]
    for item in CATALOG
}

for _item in PACK3_METHODS:
    if _item["id"] not in _existing_method_ids:
        CATALOG.append(_item)
        _existing_method_ids.add(_item["id"])

METHODS = {
    item["id"]: item
    for item in CATALOG
}

# NETAUTO_PACK3_KCP_CATALOG_END
'''

path.write_text(
    text.rstrip() + "\n" + patch + "\n",
    encoding="utf-8",
)
PY

echo "===== PYTHON SYNTAX ====="

python3 -m py_compile \
  backend/app/tunnel_catalog.py \
  backend/app/execution_capabilities.py \
  plan_executor/executor.py

echo "Python syntax: OK"

echo "===== COMPOSE SYNTAX ====="

docker compose config \
  > /tmp/netauto-pack3-compose.yml

echo "Compose syntax: OK"

echo "===== BUILD ====="

docker compose build \
  api \
  plan_executor

echo "===== START ====="

docker compose up -d \
  --force-recreate \
  api \
  plan_executor \
  web

sleep 22

echo "===== HEALTH ====="

curl -fsS \
  http://127.0.0.1:18080/api/v1/health
echo

echo "===== CAPABILITIES ====="

docker compose exec -T api python - <<'PY'
from app.execution_capabilities import (
    CAPABILITY_PACK,
    IMPLEMENTED_METHODS,
)

required = {
    "GOST_KCP_FORWARD",
    "GOST_SOCKS5_KCP",
}

missing = required - IMPLEMENTED_METHODS

if missing:
    raise SystemExit(
        f"Missing execution methods: {sorted(missing)}"
    )

print(CAPABILITY_PACK)
print(
    ", ".join(
        sorted(IMPLEMENTED_METHODS)
    )
)
PY

echo "===== CATALOG ====="

docker compose exec -T api python - <<'PY'
from app.tunnel_catalog import CATALOG

required = {
    "GOST_KCP_FORWARD",
    "GOST_SOCKS5_KCP",
}

ids = {
    item["id"]
    for item in CATALOG
}

missing = required - ids

if missing:
    raise SystemExit(
        f"Missing catalog methods: {sorted(missing)}"
    )

print(f"Catalog methods: {len(CATALOG)}")
print("Pack 3 catalog entries: OK")
PY

echo "===== EXECUTOR ====="

docker compose ps plan_executor

docker compose logs \
  --tail 50 \
  plan_executor

if docker compose logs \
  --tail 100 \
  plan_executor \
  | grep -q "Traceback"
then
  echo "Executor traceback detected."
  exit 1
fi

echo "===== STATIC ENGINE CHECK ====="

docker compose exec -T plan_executor \
  python - <<'PY'
import executor

required = {
    "GOST_KCP_FORWARD",
    "GOST_SOCKS5_KCP",
}

missing = required - executor.SUPPORTED

if missing:
    raise SystemExit(
        f"Executor missing: {sorted(missing)}"
    )

assert hasattr(executor, "benchmark_tunnel")
assert hasattr(executor, "platform_profile")
assert hasattr(executor, "choose_kcp_profile")

print("KCP engine: OK")
print("Platform compatibility layer: OK")
print("Bidirectional benchmark layer: OK")
PY

mkdir -p \
  .netauto-master/packs \
  .netauto-master/logs

cp "$0" \
  .netauto-master/packs/03-kcp-benchmark.sh

chmod 700 \
  .netauto-master/packs/03-kcp-benchmark.sh

python3 - <<'PY'
from pathlib import Path
from datetime import datetime, timezone
import json

path = Path(
    ".netauto-master/status.json"
)

try:
    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )
except Exception:
    data = {
        "phases": {},
    }

data.setdefault(
    "phases",
    {},
)

now = datetime.now(
    timezone.utc
).isoformat()

data["updated_at"] = now

data["phases"][
    "03-kcp-benchmark"
] = {
    "state": "SUCCESS",
    "message": (
        "GOST KCP transport, platform "
        "compatibility checks and sequential "
        "bidirectional benchmarks installed."
    ),
    "updated_at": now,
}

path.write_text(
    json.dumps(
        data,
        indent=2,
        ensure_ascii=False,
    ),
    encoding="utf-8",
)
PY

rm -f \
  /tmp/netauto-pack3-compose.yml \
  /tmp/netauto-*.txt \
  2>/dev/null || true

echo
echo "✅ PACK 3 — KCP + PLATFORM CHECK + BENCHMARK READY"
echo "New methods:"
echo "GOST_KCP_FORWARD"
echo "GOST_SOCKS5_KCP"
echo
echo "Post-tests for L3/TUN methods:"
echo "Bidirectional Ping"
echo "TCP 1-stream and 4-stream in both directions"
echo "UDP ramp test with loss and jitter"
echo "Stability score and transport recommendation"
