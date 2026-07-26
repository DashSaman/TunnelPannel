#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

timestamp="$(date +%Y%m%d-%H%M%S)"
mkdir -p backups

docker compose exec -T postgres \
  pg_dump -U "${POSTGRES_USER:-netauto}" "${POSTGRES_DB:-netauto}" \
  | gzip > "backups/postgres-${timestamp}.sql.gz"

tar -czf "backups/config-${timestamp}.tar.gz" \
  docker-compose.yml .env web proxy scripts

echo "Backup completed: ${timestamp}"
