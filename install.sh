#!/usr/bin/env bash
set -Eeuo pipefail

REPO_SLUG="${REPO_SLUG:-DashSaman/TunnelPannel}"
BRANCH="${BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/tunnelpannel}"
WEB_BIND_PORT="${WEB_BIND_PORT:-18080}"
APP_BASE_URL="${APP_BASE_URL:-http://127.0.0.1:${WEB_BIND_PORT}}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ALLOW_EXISTING_NETAUTO="${ALLOW_EXISTING_NETAUTO:-0}"
MARKER_FILE=".tunnelpannel-managed"

log() { printf '\n[ TunnelPannel ] %s\n' "$*"; }
die() { printf '\n[ TunnelPannel ] ERROR: %s\n' "$*" >&2; exit 1; }

if [[ ${EUID} -ne 0 ]]; then
  die "Run as root (for a piped install use: curl ... | sudo -E bash)."
fi

if ! command -v apt-get >/dev/null 2>&1; then
  die "This installer currently supports apt-based Ubuntu/Debian hosts."
fi

export DEBIAN_FRONTEND=noninteractive
log "Installing base prerequisites"
apt-get update -qq
apt-get install -y -qq ca-certificates curl git openssl >/dev/null

if ! command -v docker >/dev/null 2>&1; then
  log "Docker is not installed; installing Docker Engine"
  tmp_docker="$(mktemp)"
  curl -fsSL https://get.docker.com -o "$tmp_docker"
  sh "$tmp_docker"
  rm -f "$tmp_docker"
fi

if ! docker compose version >/dev/null 2>&1; then
  die "Docker Compose v2 is required but was not installed successfully."
fi

existing_netauto="$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^netauto-' || true)"
if [[ -n "$existing_netauto" && ! -f "$INSTALL_DIR/$MARKER_FILE" && "$ALLOW_EXISTING_NETAUTO" != "1" ]]; then
  printf '%s\n' "$existing_netauto" >&2
  die "Existing netauto-* containers detected. Refusing to touch them. Set ALLOW_EXISTING_NETAUTO=1 only if you intentionally own that stack."
fi

script_dir=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
fi

project_dir=""
if [[ -n "$script_dir" && -f "$script_dir/docker-compose.yml" && -d "$script_dir/backend" ]]; then
  project_dir="$script_dir"
  log "Using the local repository checkout at $project_dir"
fi

clone_with_optional_token() {
  local destination="$1"
  local repo_url="https://github.com/${REPO_SLUG}.git"
  local -a auth_args=()
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    local basic
    basic="$(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 | tr -d '\n')"
    auth_args=(-c "http.extraHeader=Authorization: Basic ${basic}")
  fi
  GIT_TERMINAL_PROMPT=0 git "${auth_args[@]}" clone --depth 1 --branch "$BRANCH" "$repo_url" "$destination" || {
    rm -rf "$destination"
    die "Unable to clone ${REPO_SLUG}. For a private repository export GITHUB_TOKEN with Contents:read access."
  }
  git -C "$destination" remote set-url origin "$repo_url"
}

if [[ -z "$project_dir" ]]; then
  if [[ -e "$INSTALL_DIR" && ! -d "$INSTALL_DIR/.git" ]]; then
    die "$INSTALL_DIR already exists and is not a Git checkout. Choose another INSTALL_DIR."
  fi
  if [[ ! -d "$INSTALL_DIR/.git" ]]; then
    log "Cloning $REPO_SLUG"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    clone_with_optional_token "$INSTALL_DIR"
  else
    log "Using existing managed checkout at $INSTALL_DIR"
  fi
  project_dir="$INSTALL_DIR"
fi

cd "$project_dir"
touch "$MARKER_FILE"
chmod 600 "$MARKER_FILE"
chmod +x install.sh scripts/*.sh 2>/dev/null || true

set_env() {
  local key="$1" value="$2" escaped
  escaped="$(printf '%s' "$value" | sed 's/[&|]/\\&/g')"
  if grep -q "^${key}=" .env; then
    sed -i "s|^${key}=.*|${key}=${escaped}|" .env
  else
    printf '%s=%s\n' "$key" "$value" >> .env
  fi
}

fresh_env=0
if [[ ! -f .env ]]; then
  cp .env.example .env
  fresh_env=1
fi
chmod 600 .env

if [[ "$fresh_env" == "1" ]]; then
  log "Generating local application secrets"
  app_secret="$(openssl rand -hex 48)"
  jwt_secret="$(openssl rand -hex 48)"
  postgres_password="$(openssl rand -hex 24)"
  redis_password="$(openssl rand -hex 24)"
  bot_internal_key="$(openssl rand -hex 32)"
  generated_admin_password="${ADMIN_PASSWORD:-$(openssl rand -hex 16)}"

  set_env APP_ENV production
  set_env APP_BASE_URL "$APP_BASE_URL"
  set_env WEB_BIND_PORT "$WEB_BIND_PORT"
  set_env APP_SECRET_KEY "$app_secret"
  set_env JWT_SECRET_KEY "$jwt_secret"
  set_env POSTGRES_PASSWORD "$postgres_password"
  set_env DATABASE_URL "postgresql+psycopg://netauto:${postgres_password}@postgres:5432/netauto"
  set_env REDIS_PASSWORD "$redis_password"
  set_env REDIS_URL "redis://:${redis_password}@redis:6379/0"
  set_env BOOTSTRAP_ADMIN_USERNAME "$ADMIN_USERNAME"
  set_env BOOTSTRAP_ADMIN_PASSWORD "$generated_admin_password"
  set_env BOT_INTERNAL_API_KEY "$bot_internal_key"
fi

required_keys=(APP_SECRET_KEY JWT_SECRET_KEY POSTGRES_PASSWORD DATABASE_URL REDIS_PASSWORD REDIS_URL BOOTSTRAP_ADMIN_USERNAME BOT_INTERNAL_API_KEY)
for key in "${required_keys[@]}"; do
  value="$(grep -E "^${key}=" .env | tail -1 | cut -d= -f2- || true)"
  if [[ -z "$value" || "$value" == CHANGE_ME* ]]; then
    die "$key is missing or still uses a CHANGE_ME placeholder in $project_dir/.env"
  fi
done

log "Validating Docker Compose configuration"
docker compose --env-file .env config >/dev/null

log "Building and starting only the TunnelPannel stack"
docker compose --env-file .env up -d --build

log "Waiting for the local health endpoint"
health_url="http://127.0.0.1:${WEB_BIND_PORT}/api/v1/health"
healthy=0
for _ in $(seq 1 60); do
  if curl -fsS "$health_url" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 2
done

if [[ "$healthy" != "1" ]]; then
  docker compose ps || true
  die "Stack started but $health_url did not become healthy. Check: docker compose logs --tail=200"
fi

log "Installation completed successfully"
printf 'Directory : %s\n' "$project_dir"
printf 'Web/API   : http://127.0.0.1:%s\n' "$WEB_BIND_PORT"
printf 'Health    : %s\n' "$health_url"
printf 'Admin user: %s\n' "$ADMIN_USERNAME"
if [[ "$fresh_env" == "1" ]]; then
  printf 'Admin pass: %s\n' "$generated_admin_password"
  printf '%s\n' 'Save this password now; it is not printed again by the installer.'
fi
printf '%s\n' 'The web port is bound to localhost by default. Add your own HTTPS reverse proxy when ready.'
