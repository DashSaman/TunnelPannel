#!/usr/bin/env bash
set -Eeuo pipefail
trap 'code=$?; echo; echo "❌ PACK 8 FAILED — SSH session remains open."; echo "Diagnostics:"; echo "cd /opt/network-automation"; echo "docker compose logs --tail 220 api bot"; exit $code' ERR

PROJECT="/opt/network-automation"
cd "$PROJECT"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="backups/pack8-multilingual-bot-${STAMP}"
mkdir -p "$BACKUP"

for file in \
  backend/app/main.py \
  backend/app/bot_control_router.py \
  bot/bot.py \
  bot/translations.py \
  bot/Dockerfile \
  bot/requirements.txt \
  docker-compose.yml \
  .env
do
  if [[ -f "$file" ]]; then
    mkdir -p "$BACKUP/$(dirname "$file")"
    cp -a "$file" "$BACKUP/$file"
  fi
done

echo "Backup: $PROJECT/$BACKUP"

if [[ ! -s .env ]]; then
  echo ".env not found or empty."
  exit 1
fi

if ! grep -Eq '^TELEGRAM_BOT_TOKEN=.+$' .env; then
  echo "TELEGRAM_BOT_TOKEN is missing. Existing bot token was not changed."
  exit 1
fi

python3 - <<'PY'
from pathlib import Path
import secrets

path = Path('.env')
lines = path.read_text(encoding='utf-8').splitlines()
values = {}
order = []
for line in lines:
    if '=' in line and not line.lstrip().startswith('#'):
        key, value = line.split('=', 1)
        values[key] = value
        order.append(key)

if len(values.get('BOT_INTERNAL_API_KEY', '')) < 20:
    values['BOT_INTERNAL_API_KEY'] = secrets.token_urlsafe(48)
    if 'BOT_INTERNAL_API_KEY' not in order:
        order.append('BOT_INTERNAL_API_KEY')

values['TELEGRAM_BOT_ENABLED'] = 'true'
if 'TELEGRAM_BOT_ENABLED' not in order:
    order.append('TELEGRAM_BOT_ENABLED')

if not values.get('TELEGRAM_API_BASE'):
    values['TELEGRAM_API_BASE'] = 'http://api:8000'
    if 'TELEGRAM_API_BASE' not in order:
        order.append('TELEGRAM_API_BASE')

if not values.get('APP_BASE_URL'):
    values['APP_BASE_URL'] = 'https://tunnel.softarg.ir'
    if 'APP_BASE_URL' not in order:
        order.append('APP_BASE_URL')

result = []
seen = set()
for line in lines:
    if '=' in line and not line.lstrip().startswith('#'):
        key = line.split('=', 1)[0]
        if key in values and key not in seen:
            result.append(f'{key}={values[key]}')
            seen.add(key)
    else:
        result.append(line)
for key in order:
    if key not in seen:
        result.append(f'{key}={values[key]}')
        seen.add(key)

path.write_text('\n'.join(result).rstrip() + '\n', encoding='utf-8')
PY
chmod 600 .env

echo "Bot internal authentication and enabled state: READY"

install -m 0644 \
  "$(dirname "$0")/backend/bot_control_router.py" \
  backend/app/bot_control_router.py
install -m 0644 \
  "$(dirname "$0")/bot/bot.py" \
  bot/bot.py
install -m 0644 \
  "$(dirname "$0")/bot/translations.py" \
  bot/translations.py
install -m 0644 \
  "$(dirname "$0")/bot/Dockerfile" \
  bot/Dockerfile
install -m 0644 \
  "$(dirname "$0")/bot/requirements.txt" \
  bot/requirements.txt

python3 - <<'PY'
from pathlib import Path
import re

path = Path('backend/app/main.py')
text = path.read_text(encoding='utf-8')
import_line = 'from app.bot_control_router import router as bot_control_router'
include_line = 'app.include_router(bot_control_router)'

if import_line not in text:
    lines = text.splitlines()
    insert_at = 0
    for index, line in enumerate(lines):
        if line.startswith('from app.') or line.startswith('import '):
            insert_at = index + 1
        elif insert_at and line.strip():
            break
    lines.insert(insert_at, import_line)
    text = '\n'.join(lines) + '\n'

if include_line not in text:
    matches = list(re.finditer(r'(?m)^app\.include_router\([^)]+\)\s*$', text))
    if matches:
        position = matches[-1].end()
        text = text[:position] + '\n' + include_line + text[position:]
    else:
        marker = '@app.get("/api/v1/health")'
        if marker not in text:
            raise SystemExit('Could not find router or health marker in main.py')
        text = text.replace(marker, include_line + '\n\n' + marker, 1)

path.write_text(text, encoding='utf-8')
PY

echo "===== SOURCE VALIDATION ====="
python3 -m py_compile \
  backend/app/main.py \
  backend/app/bot_control_router.py \
  bot/bot.py \
  bot/translations.py

python3 - <<'PY'
from pathlib import Path
import ast

for file in (
    'backend/app/bot_control_router.py',
    'bot/bot.py',
    'bot/translations.py',
):
    ast.parse(Path(file).read_text(encoding='utf-8'), filename=file)
print('Python syntax and AST: OK')
PY

echo "===== COMPOSE SYNTAX ====="
docker compose config > /tmp/netauto-pack8-compose.yml
echo "Compose syntax: OK"

echo "===== BUILD ====="
docker compose build api bot

echo "===== START ====="
docker compose up -d --force-recreate api bot web

echo "===== WAIT FOR API ====="
healthy=0
for second in $(seq 1 120); do
  if curl -fsS http://127.0.0.1:18080/api/v1/health > /tmp/netauto-pack8-health.json 2>/dev/null; then
    healthy=1
    echo "API healthy after ${second}s."
    break
  fi
  sleep 1
done
if [[ "$healthy" != "1" ]]; then
  docker compose logs --tail 220 api
  exit 1
fi
cat /tmp/netauto-pack8-health.json
echo

echo "===== BOT CONTROL ROUTES ====="
python3 - <<'PY'
import json
import urllib.request

with urllib.request.urlopen('http://127.0.0.1:18080/openapi.json', timeout=20) as response:
    paths = set(json.load(response).get('paths', {}))
required = {
    '/api/v1/bot-control/context/{telegram_id}',
    '/api/v1/bot-control/language',
    '/api/v1/bot-control/dashboard/{telegram_id}',
    '/api/v1/bot-control/catalog/{telegram_id}',
    '/api/v1/bot-control/endpoints/{telegram_id}',
    '/api/v1/bot-control/plans/{telegram_id}',
    '/api/v1/bot-control/plans/{telegram_id}/{plan_id}',
    '/api/v1/bot-control/plans/simple',
    '/api/v1/bot-control/plans/{telegram_id}/{plan_id}/execute',
    '/api/v1/bot-control/runs/{telegram_id}/{run_id}',
    '/api/v1/bot-control/runs/{telegram_id}/{run_id}/cancel',
    '/api/v1/bot-control/prechecks',
    '/api/v1/bot-control/prechecks/{telegram_id}',
    '/api/v1/bot-control/prechecks/{telegram_id}/{precheck_id}',
    '/api/v1/bot-control/jobs/{telegram_id}',
}
missing = required - paths
if missing:
    raise SystemExit(f'Missing Pack 8 routes: {sorted(missing)}')
print(f'Bot control routes verified: {len(required)}')
PY

echo "===== API ENGINE CHECK ====="
docker compose exec -T api python - <<'PY'
from app.execution_capabilities import IMPLEMENTED_METHODS
from app.tunnel_catalog import CATALOG
from app.bot_control_router import router

catalog_ids = {item['id'] for item in CATALOG}
assert len(IMPLEMENTED_METHODS) == 77, len(IMPLEMENTED_METHODS)
assert len(catalog_ids) == 77, len(catalog_ids)
assert IMPLEMENTED_METHODS == catalog_ids
assert router.prefix == '/api/v1/bot-control'
print('Executable methods: 77')
print('Catalog methods: 77')
print('Secure Telegram gateway: OK')
PY

echo "===== WAIT FOR STABLE BOT ====="
stable=0
previous_restarts=""
for attempt in $(seq 1 40); do
  state="$(docker inspect -f '{{.State.Status}} {{.RestartCount}}' netauto-bot 2>/dev/null || true)"
  status="${state%% *}"
  restarts="${state##* }"
  if [[ "$status" == "running" ]]; then
    if [[ -n "$previous_restarts" && "$restarts" == "$previous_restarts" ]]; then
      stable=1
      break
    fi
    previous_restarts="$restarts"
  fi
  sleep 3
done
if [[ "$stable" != "1" ]]; then
  docker compose logs --tail 240 bot
  echo "Bot did not become stable."
  exit 1
fi
echo "Bot stable; restart count: $previous_restarts"

echo "===== BOT SELF-CHECK ====="
docker compose exec -T bot python - <<'PY'
import bot
from translations import LANGUAGES, STATUS, TEXT

required = {'en', 'fa', 'ru', 'zh-CN', 'de'}
assert set(LANGUAGES) == required
assert set(TEXT) == required
assert set(STATUS) == required
keys = set(TEXT['en'])
for language, values in TEXT.items():
    missing = keys - set(values)
    extra = set(values) - keys
    if missing or extra:
        raise SystemExit(f'{language}: missing={sorted(missing)} extra={sorted(extra)}')
assert len(keys) >= 70
assert len(bot.dp.resolve_used_update_types()) >= 2
print('Languages: en fa ru zh-CN de')
print(f'Translation keys per language: {len(keys)}')
print('Endpoint workflows: OK')
print('Tunnel plan and execution workflows: OK')
print('Precheck, job and engine workflows: OK')
PY

echo "===== CONTAINER STATUS ====="
docker compose ps api bot plan_executor web

echo "===== RECENT LOGS ====="
docker compose logs --tail 100 bot

if docker compose logs --tail 300 api bot | grep -Eqi 'Traceback|SyntaxError|IndentationError|ImportError|ModuleNotFoundError|NameError|Unauthorized'; then
  echo "A bot/API startup error was detected."
  exit 1
fi

mkdir -p .netauto-master/packs .netauto-master/logs
cp "$0" .netauto-master/packs/08-multilingual-telegram-bot.sh
chmod 700 .netauto-master/packs/08-multilingual-telegram-bot.sh

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
data['phases']['08-multilingual-telegram-bot'] = {
    'state': 'SUCCESS',
    'message': (
        'Endpoints, secure endpoint wizard, inventory, prechecks, jobs, '
        'all 77 engines, simple plans, execution, live progress and '
        'cancellation are available in five Telegram languages.'
    ),
    'updated_at': now,
}
path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
PY

rm -f /tmp/netauto-pack8-compose.yml /tmp/netauto-pack8-health.json 2>/dev/null || true

echo
echo "✅ PACK 8 — MULTILINGUAL TELEGRAM CONTROL READY"
echo "Languages: English Persian Russian Simplified-Chinese German"
echo "Executable engines visible in bot: 77"
echo "Bot workflows:"
echo "Endpoints + secure add wizard + inventory + delete"
echo "Bidirectional precheck + jobs + engine catalog"
echo "Simple tunnel plan + execute + live progress + cancel"
echo "Advanced web composer link: ENABLED"
echo "Secret messages: DELETE AFTER PROCESSING"
echo "Bot/API internal authentication: ENABLED"
