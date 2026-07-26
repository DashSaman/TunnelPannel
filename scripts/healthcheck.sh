#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose ps
echo
curl -fsS "http://127.0.0.1:${WEB_BIND_PORT:-18080}/api/v1/health"
echo
