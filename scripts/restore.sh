#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 backups/postgres-YYYYMMDD-HHMMSS.sql.gz"
  exit 1
fi

cd "$(dirname "$0")/.."
gzip -dc "$1" | docker compose exec -T postgres \
  psql -U "${POSTGRES_USER:-netauto}" "${POSTGRES_DB:-netauto}"

echo "Database restored."
