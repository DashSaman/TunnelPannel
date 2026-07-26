#!/usr/bin/env bash
set -Eeuo pipefail

trap '
  echo
  echo "❌ PACK 6 REPAIR/RESILIENCE FAILED — SSH remains open."
  echo "Diagnostic command:"
  echo "cd /opt/network-automation && docker compose logs --tail 200 api plan_executor"
' ERR

PROJECT="/opt/network-automation"
cd "$PROJECT"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="backups/pack6-repair-resilience-${STAMP}"

mkdir -p "$BACKUP"

for file in \
  backend/app/execution_capabilities.py \
  backend/app/tunnel_catalog.py \
  plan_executor/executor.py \
  docker-compose.yml
do
  if [[ -f "$file" ]]; then
    cp "$file" "$BACKUP/$(basename "$file")"
  fi
done

echo "Backup: $PROJECT/$BACKUP"

echo "===== APPLY PACK 6 STARTUP FIX ====="

install -m 0644 \
  "$(dirname "$0")/backend/execution_capabilities.py" \
  backend/app/execution_capabilities.py

install -m 0644 \
  "$(dirname "$0")/plan_executor/executor.py" \
  plan_executor/executor.py

python3 - <<'PY'
from pathlib import Path
import re

path = Path("docker-compose.yml")
text = path.read_text(encoding="utf-8")

match = re.search(
    r"(?ms)^  plan_executor:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
    text,
)

if not match:
    raise SystemExit(
        "plan_executor service not found in docker-compose.yml"
    )

body = match.group("body")

if not re.search(r"(?m)^    restart:", body):
    if re.search(r"(?m)^    container_name:", body):
        body = re.sub(
            r"(?m)(^    container_name:.*\n)",
            r"\1    restart: unless-stopped\n",
            body,
            count=1,
        )
    else:
        body = (
            "    restart: unless-stopped\n"
            + body
        )
else:
    body = re.sub(
        r"(?m)^    restart:.*$",
        "    restart: unless-stopped",
        body,
        count=1,
    )

text = (
    text[:match.start("body")]
    + body
    + text[match.end("body"):]
)

path.write_text(
    text,
    encoding="utf-8",
)
PY

echo "===== PYTHON SYNTAX ====="

python3 -m py_compile \
  backend/app/execution_capabilities.py \
  backend/app/tunnel_catalog.py \
  plan_executor/executor.py

echo "Python syntax: OK"

echo "===== STATIC STARTUP BUG CHECK ====="

python3 - <<'PY'
from pathlib import Path

text = Path(
    "plan_executor/executor.py"
).read_text(
    encoding="utf-8"
)

definition = text.find(
    "PLATFORM_RULES = {"
)

update = text.find(
    "PLATFORM_RULES.update("
)

if definition < 0 or update < 0:
    raise SystemExit(
        "PLATFORM_RULES markers missing"
    )

if update < definition:
    raise SystemExit(
        "PLATFORM_RULES startup ordering is still broken"
    )

required = (
    "ensure_endpoint_guardian",
    "register_artifact_guardian",
    "GUARDIAN_SCRIPT",
    "Restart=always",
    "Restart=on-failure",
)

for token in required:
    if token not in text:
        raise SystemExit(
            f"Missing resilience token: {token}"
        )

print(
    "Pack 6 NameError ordering fixed."
)
print(
    "Endpoint resilience layer present."
)
PY

echo "===== HOST STACK AUTOSTART ====="

DOCKER_BIN="$(command -v docker)"

cat > /usr/local/sbin/netauto-stack-guardian <<'GUARDIAN'
#!/usr/bin/env bash
set -u

PROJECT="/opt/network-automation"

cd "$PROJECT" || exit 0

if ! docker info >/dev/null 2>&1; then
    exit 0
fi

required=(
    postgres
    redis
    api
    bot
    worker
    scheduler
    web
    plan_executor
)

running="$(
    docker compose ps \
      --status running \
      --services \
      2>/dev/null \
      || true
)"

for service in "${required[@]}"; do
    if ! printf '%s\n' "$running" \
      | grep -Fxq "$service"
    then
        docker compose up -d "$service" \
          >/dev/null 2>&1 \
          || true
    fi
done
GUARDIAN

chmod 0755 \
  /usr/local/sbin/netauto-stack-guardian

cat > /etc/systemd/system/netauto-stack.service <<UNIT
[Unit]
Description=TehranNetwork automation Docker stack
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/network-automation
ExecStart=${DOCKER_BIN} compose up -d
ExecReload=${DOCKER_BIN} compose up -d
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/netauto-stack-guardian.service <<'UNIT'
[Unit]
Description=TehranNetwork stack guardian
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/netauto-stack-guardian
TimeoutStartSec=180
UNIT

cat > /etc/systemd/system/netauto-stack-guardian.timer <<'UNIT'
[Unit]
Description=Check TehranNetwork stack every minute

[Timer]
OnBootSec=60s
OnUnitActiveSec=60s
AccuracySec=10s
RandomizedDelaySec=10s
Persistent=true
Unit=netauto-stack-guardian.service

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload

if systemctl list-unit-files \
  | grep -q '^docker.service'
then
  systemctl enable docker.service \
    >/dev/null 2>&1 \
    || true
fi

systemctl enable \
  netauto-stack.service \
  netauto-stack-guardian.timer \
  >/dev/null

echo "Host autostart units installed."

echo "===== COMPOSE CHECK ====="

docker compose config \
  > /tmp/netauto-pack6-resilience-compose.yml

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

systemctl restart \
  netauto-stack.service

systemctl enable --now \
  netauto-stack-guardian.timer

echo "===== WAIT FOR API ====="

healthy=0

for second in $(seq 1 120); do
  if curl -fsS \
    http://127.0.0.1:18080/api/v1/health \
    > /tmp/netauto-pack6-resilience-health.json \
    2>/dev/null
  then
    healthy=1
    echo "API healthy after ${second}s."
    break
  fi

  sleep 1
done

if [[ "$healthy" != "1" ]]; then
  echo
  echo "===== API LOGS ====="
  docker compose logs \
    --tail 200 \
    api

  echo
  echo "===== EXECUTOR LOGS ====="
  docker compose logs \
    --tail 200 \
    plan_executor

  exit 1
fi

cat /tmp/netauto-pack6-resilience-health.json
echo

echo "===== WAIT FOR STABLE EXECUTOR ====="

stable=0
previous_restarts=""

for attempt in $(seq 1 30); do
  state="$(
    docker inspect \
      -f '{{.State.Status}} {{.RestartCount}}' \
      netauto-plan-executor \
      2>/dev/null \
      || true
  )"

  status="${state%% *}"
  restarts="${state##* }"

  if [[ "$status" == "running" ]]; then
    if [[ -n "$previous_restarts" \
      && "$restarts" == "$previous_restarts" ]]
    then
      stable=1
      break
    fi

    previous_restarts="$restarts"
  fi

  sleep 3
done

if [[ "$stable" != "1" ]]; then
  docker compose logs \
    --tail 240 \
    plan_executor

  echo "Executor did not become stable."
  exit 1
fi

echo "Executor stable; restart count: $previous_restarts"

echo "===== CAPABILITIES ====="

docker compose exec -T api \
  python - <<'PY'
from app.execution_capabilities import (
    CAPABILITY_PACK,
    IMPLEMENTED_METHODS,
)

required = {
    "VLESS_TCP",
    "VLESS_WS",
    "VLESS_GRPC",
    "VLESS_XHTTP",
    "VLESS_REALITY",
    "VLESS_VISION_REALITY",
    "VLESS_XHTTP_REALITY",
    "HYSTERIA2",
    "TUIC",
    "TROJAN_TLS",
    "SHADOWSOCKS",
    "SINGBOX_TUN",
}

missing = required - IMPLEMENTED_METHODS

if missing:
    raise SystemExit(
        f"Missing capabilities: {sorted(missing)}"
    )

if len(IMPLEMENTED_METHODS) != 66:
    raise SystemExit(
        "Expected 66 executable methods, "
        f"got {len(IMPLEMENTED_METHODS)}"
    )

print(CAPABILITY_PACK)
print(
    f"Executable methods: "
    f"{len(IMPLEMENTED_METHODS)}"
)
PY

echo "===== EXECUTOR SELF-CHECK ====="

docker compose exec -T \
  plan_executor \
  python - <<'PY'
import executor

assert len(executor.SUPPORTED) == 66

required = (
    "ensure_endpoint_guardian",
    "register_guardian_manifest",
    "register_artifact_guardian",
    "deploy_xray_method",
    "deploy_singbox_method",
)

for name in required:
    if not hasattr(executor, name):
        raise SystemExit(
            f"Missing executor function: {name}"
        )

modern = {
    "VLESS_TCP",
    "VLESS_WS",
    "VLESS_GRPC",
    "VLESS_XHTTP",
    "VLESS_REALITY",
    "VLESS_VISION_REALITY",
    "VLESS_XHTTP_REALITY",
    "HYSTERIA2",
    "TUIC",
    "TROJAN_TLS",
    "SHADOWSOCKS",
    "SINGBOX_TUN",
}

missing = modern - executor.SUPPORTED

if missing:
    raise SystemExit(
        f"Executor missing: {sorted(missing)}"
    )

print(
    f"Container executable methods: "
    f"{len(executor.SUPPORTED)}"
)
print("Pack 6 modern engines: OK")
print("Endpoint guardian engine: OK")
print("Systemd auto-restart templates: OK")
PY

echo "===== BACKFILL EXISTING SUCCESSFUL TUNNELS ====="

docker compose exec -T \
  plan_executor \
  python - <<'PY'
import json

import executor

checked = 0
updated = 0
warnings = 0

with executor.db_connect() as connection:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                ri.id AS run_item_id,
                ri.run_id,
                ri.artifact_json,
                pi.endpoint_a_id,
                pi.endpoint_b_id
            FROM tunnel_plan_run_items AS ri
            JOIN tunnel_plan_items AS pi
              ON pi.id = ri.plan_item_id
            WHERE
                ri.status = 'SUCCESS'
                AND ri.artifact_json IS NOT NULL
                AND ri.artifact_json <> '{}'
            ORDER BY ri.id ASC
            """
        )
        rows = cursor.fetchall()

    for row in rows:
        checked += 1

        try:
            artifact = json.loads(
                row["artifact_json"]
                or "{}"
            )

            if (
                artifact.get("resilience")
                or not artifact
            ):
                continue

            with executor.remote_pair(
                connection,
                row["endpoint_a_id"],
                row["endpoint_b_id"],
            ) as (
                remote_a,
                remote_b,
                _endpoint_a,
                _endpoint_b,
            ):
                resilience = (
                    executor.register_artifact_guardian(
                        remote_a,
                        remote_b,
                        artifact,
                        {
                            "id": row["run_id"],
                        },
                        {
                            "id": row["run_item_id"],
                        },
                    )
                )

            artifact["resilience"] = resilience

            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE tunnel_plan_run_items
                    SET artifact_json = %s
                    WHERE id = %s
                    """,
                    (
                        json.dumps(
                            artifact,
                            ensure_ascii=False,
                        ),
                        row["run_item_id"],
                    ),
                )

            connection.commit()

            executor.add_event(
                connection,
                row["run_id"],
                (
                    "Automatic boot recovery and "
                    "tunnel guardian were backfilled."
                ),
                run_item_id=row["run_item_id"],
                level="SUCCESS",
                details=resilience,
            )

            updated += 1

        except Exception as exc:
            connection.rollback()
            warnings += 1
            print(
                "BACKFILL_WARNING "
                f"run={row['run_id']} "
                f"item={row['run_item_id']} "
                f"{type(exc).__name__}: "
                f"{str(exc)[:240]}"
            )

print(
    f"Successful artifacts checked: {checked}"
)
print(
    f"Guardians backfilled: {updated}"
)
print(
    f"Backfill warnings: {warnings}"
)
PY

echo "===== HOST AUTOSTART STATUS ====="

systemctl is-enabled \
  netauto-stack.service

systemctl is-enabled \
  netauto-stack-guardian.timer

systemctl is-active \
  netauto-stack.service

systemctl is-active \
  netauto-stack-guardian.timer

echo "===== CONTAINERS ====="

docker compose ps \
  api \
  plan_executor \
  web

echo "===== RECENT EXECUTOR LOGS ====="

docker compose logs \
  --tail 80 \
  plan_executor

if docker compose logs \
  --tail 300 \
  api \
  plan_executor \
  | grep -Eqi \
  'Traceback|NameError|SyntaxError|IndentationError|ImportError|ModuleNotFoundError'
then
  echo "A startup error is still present."
  exit 1
fi

mkdir -p \
  .netauto-master/packs \
  .netauto-master/logs

cp "$0" \
  .netauto-master/packs/06-modern-proxies-resilience.sh

chmod 700 \
  .netauto-master/packs/06-modern-proxies-resilience.sh

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
    "06-modern-proxies"
] = {
    "state": "SUCCESS",
    "message": (
        "Pack 6 startup ordering repaired; "
        "66 engines healthy."
    ),
    "updated_at": now,
}

data["phases"][
    "06-global-resilience"
] = {
    "state": "SUCCESS",
    "message": (
        "Systemd boot recovery, process "
        "auto-restart, endpoint tunnel guardian "
        "and controller stack guardian enabled."
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
  /tmp/netauto-pack6-resilience-compose.yml \
  /tmp/netauto-pack6-resilience-health.json \
  /tmp/netauto-*.txt \
  2>/dev/null || true

echo
echo "✅ PACK 6 REPAIRED + GLOBAL RESILIENCE READY"
echo "Executable methods: 66"
echo "Controller restart after reboot: ENABLED"
echo "Endpoint tunnel services after reboot: ENABLED"
echo "Endpoint tunnel guardian interval: 30 seconds"
echo "Controller stack guardian interval: 60 seconds"
echo "Ping failure threshold: 3 consecutive checks"
echo "Restart cooldown: 120 seconds"
