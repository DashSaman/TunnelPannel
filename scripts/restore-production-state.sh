#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/.."

[[ "${RESTORE_TUNNELPANNEL:-}" == "YES_I_UNDERSTAND" ]] || { echo "Set RESTORE_TUNNELPANNEL=YES_I_UNDERSTAND." >&2; exit 1; }
: "${DR_PASSPHRASE:?Set DR_PASSPHRASE.}"
[[ $# -eq 1 ]] || { echo "Usage: $0 /path/to/tunnelpannel-state-*.tar.gz.enc" >&2; exit 1; }
[[ -f .env ]] || { echo "Destination .env is required." >&2; exit 1; }
grep -q '^APP_SECRET_KEY=.' .env || { echo "APP_SECRET_KEY is missing from destination .env." >&2; exit 1; }
grep -q '^POSTGRES_PASSWORD=.' .env || { echo "POSTGRES_PASSWORD is missing from destination .env." >&2; exit 1; }

archive="$1"
[[ -f "$archive" ]] || { echo "Backup not found: $archive" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:DR_PASSPHRASE -in "$archive" | tar -xzf - -C "$tmp"

for f in MANIFEST.txt postgres.dump app_data.tar.gz; do
  [[ -f "$tmp/$f" ]] || { echo "Invalid state bundle: missing $f" >&2; exit 1; }
done

set -a
. ./.env
set +a

docker compose stop web api bot worker scheduler plan_executor 2>/dev/null || true
docker compose up -d postgres redis
for _ in $(seq 1 60); do
  docker compose exec -T postgres pg_isready -U "${POSTGRES_USER:-netauto}" -d "${POSTGRES_DB:-netauto}" >/dev/null 2>&1 && break
  sleep 2
done

docker compose exec -T postgres pg_isready -U "${POSTGRES_USER:-netauto}" -d "${POSTGRES_DB:-netauto}" >/dev/null

docker compose exec -T postgres psql \
  -U "${POSTGRES_USER:-netauto}" -d "${POSTGRES_DB:-netauto}" \
  -v ON_ERROR_STOP=1 -v role="${POSTGRES_USER:-netauto}" -v pw="${POSTGRES_PASSWORD}" <<'SQL'
ALTER ROLE :"role" WITH PASSWORD :'pw';
SQL

cat "$tmp/postgres.dump" | docker compose exec -T postgres pg_restore \
  -U "${POSTGRES_USER:-netauto}" -d "${POSTGRES_DB:-netauto}" \
  --clean --if-exists --no-owner --no-privileges

docker compose build api >/dev/null
cat "$tmp/app_data.tar.gz" | docker compose run --rm --no-deps -T api \
  sh -c 'find /app/data -mindepth 1 -maxdepth 1 -exec rm -rf {} +; tar -xzf - -C /app/data'
docker compose up -d --build

port="${WEB_BIND_PORT:-18080}"
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${port}/api/v1/health" >/dev/null 2>&1; then
    echo "Production state restore completed successfully."
    exit 0
  fi
  sleep 2
done

echo "Restore finished but health check failed." >&2
exit 1
