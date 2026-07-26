#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not installed."
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo ".env created. Edit it before running again:"
  echo "nano $(pwd)/.env"
  exit 0
fi

docker compose config >/dev/null
docker compose build
docker compose up -d
docker compose ps
