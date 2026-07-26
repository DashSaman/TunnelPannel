#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Stopping containers. Persistent volumes are preserved."
docker compose down --remove-orphans

echo "To remove all data permanently, run manually:"
echo "docker compose down -v"
