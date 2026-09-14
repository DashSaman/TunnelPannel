#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/.."

: "${DR_PASSPHRASE:?Set DR_PASSPHRASE before exporting.}"
[[ -f .env ]] || { echo ".env not found." >&2; exit 1; }
set -a
. ./.env
set +a

out="${DR_OUTPUT_DIR:-$(pwd)/backups}"
mkdir -p "$out"
ts="$(date -u +%Y%m%dT%H%M%SZ)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

docker compose exec -T postgres pg_dump -U "${POSTGRES_USER:-netauto}" -d "${POSTGRES_DB:-netauto}" -Fc > "$tmp/postgres.dump"
docker compose exec -T api tar -czf - -C /app/data . > "$tmp/app_data.tar.gz"

cat > "$tmp/MANIFEST.txt" <<EOF
format=TunnelPannel-State-v1
created_utc=${ts}
includes=postgres.dump,app_data.tar.gz
runtime_config=stored-separately
EOF

bundle="$out/tunnelpannel-state-${ts}.tar.gz.enc"
tar -C "$tmp" -czf - MANIFEST.txt postgres.dump app_data.tar.gz | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -pass env:DR_PASSPHRASE -out "$bundle"
chmod 600 "$bundle"
sha256sum "$bundle" > "$bundle.sha256"
printf 'State bundle created: %s\n' "$bundle"
