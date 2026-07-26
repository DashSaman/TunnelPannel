#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose pull
docker compose build --pull
docker compose up -d --remove-orphans
docker image prune -f
docker compose ps
