#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."

PORT="${WEB_BIND_PORT:-18080}"

echo "===== CONTAINERS ====="
docker compose ps

echo "===== PUBLIC HEALTH ====="
curl -fsS "http://127.0.0.1:${PORT}/api/v1/health"
echo

echo "===== API ROUTES / DATABASE ====="
docker compose exec -T api python - <<'PY'
from sqlalchemy import inspect
from app.db import engine
from app.main import app

paths = set(app.openapi()["paths"])
required = {
    "/api/v1/health",
    "/api/v1/auth/login",
    "/api/v1/ops/overview",
    "/api/v1/ops/jobs",
    "/api/v1/ops/settings",
    "/api/v1/ops/users",
    "/api/v1/ops/audit",
    "/api/v1/ops/deep-health",
    "/api/v1/ops/endpoints/{endpoint_id}/force",
    "/api/v1/bot-control/context/{telegram_id}",
}
missing = sorted(required - paths)
assert not missing, missing
assert "/api/v1/bot/context/{telegram_id}" not in paths
assert "/api/v1/bot/language/{telegram_id}" not in paths
assert "app_settings" in inspect(engine).get_table_names()
print("API version:", app.version)
print("Routes:", len(paths))
print("app_settings table: OK")
print("legacy unauthenticated bot routes: REMOVED")
PY

echo "===== EXECUTION ENGINE ====="
docker compose exec -T plan_executor python - <<'PY'
import inspect
import executor

assert len(executor.SUPPORTED) == 77
source = inspect.getsource(executor.Remote)
assert "EndpointHostKeyPolicy" in source
assert "AutoAddPolicy" not in source
print("Executable methods:", len(executor.SUPPORTED))
print("SSH host-key pinning: OK")
PY

echo "===== WEB ASSETS ====="
test -f web/assets/final.js
test -f web/assets/final.css
grep -q '/assets/final.js' web/admin.html
grep -q '/assets/final.js' web/app.html

echo "===== NGINX ====="
docker compose exec -T web nginx -t

echo
echo "✅ NETAUTO FINAL HEALTHCHECK PASSED"
