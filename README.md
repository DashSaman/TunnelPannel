# TunnelPannel (TehranNetwork / NetAuto)

**English** · [فارسی](README.fa.md)

TunnelPannel is a self-hosted network-automation control plane for registering Linux endpoints, discovering their network inventory, running bidirectional prechecks, composing tunnels, and executing tunnel plans over SSH from a web panel or Telegram bot.

The current execution engine contains **77 tunnel/transport methods** ranging from native Linux GRE/WireGuard/VXLAN to SSH, GOST, FRP, Rathole, Chisel, wstunnel, VLESS, sing-box, IPsec, OpenVPN, WaterWall and Paqet families.

> This software changes networking on servers you register as endpoints. Use it only on systems you administer and keep an out-of-band recovery path for remote machines.

## Highlights

- Web UI for administration, endpoint management and Tunnel Composer.
- SSH-based remote inventory, prechecks and sequential plan execution.
- Pair and multi-step tunnel workflows with progress/cancellation support.
- 77 executable methods in the plan executor.
- PostgreSQL for persistent state and Redis for job/event coordination.
- Encrypted endpoint credentials at rest using Fernet derived from `APP_SECRET_KEY`.
- SSH host-key fingerprint pinning after first discovery (TOFU then strict verification).
- Super-admin/user management, audit log, operations overview and health endpoints.
- Optional multilingual Telegram bot.
- Docker Compose deployment with web exposure bound to `127.0.0.1` by default.

## Architecture

```text
Browser / Telegram
        |
        v
 netauto-web (Nginx, localhost:18080)
        |
        v
 netauto-api (FastAPI) ---- netauto-postgres
        |                         |
        +-------------------- netauto-redis
        |                         |
        +--> netauto-worker ------+
        +--> netauto-scheduler ---+
        +--> netauto-plan-executor
                     |
                     +---- SSH ----> Endpoint A
                     +---- SSH ----> Endpoint B / more endpoints
```

Compose services are `postgres`, `redis`, `api`, `bot`, `worker`, `plan_executor`, `scheduler`, and `web`. Only the web service publishes a host port by default; PostgreSQL, Redis and internal APIs stay on the Docker network.

## Requirements

- Ubuntu 22.04/24.04 or a compatible apt-based Debian host (Debian 12 is the intended fallback).
- Root/sudo access on the control server.
- Internet access for Docker images and tunnel-engine packages used by endpoints.
- SSH access from the control server to every endpoint you want to automate.

## One-line installation

The GitHub repository is currently **private**, so a token with read access to repository contents is required. Export it first, then run:

```bash
export GITHUB_TOKEN='YOUR_GITHUB_TOKEN'; curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/DashSaman/TunnelPannel/contents/install.sh?ref=main' | sudo -E bash
```

The installer clones to `/opt/tunnelpannel`, installs Docker only if Docker is missing, generates strong application/database/Redis secrets, validates Compose, builds the stack, and waits for the health endpoint.

If this repository is made public later, the shorter command works:

```bash
curl -fsSL https://raw.githubusercontent.com/DashSaman/TunnelPannel/main/install.sh | sudo bash
```

Optional installer overrides can be passed as environment variables: `INSTALL_DIR`, `WEB_BIND_PORT`, `APP_BASE_URL`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `BRANCH`, and `REPO_SLUG`.

**Collision protection:** the installer refuses to continue when existing `netauto-*` containers are detected unless the installation is already marked as managed. `ALLOW_EXISTING_NETAUTO=1` is an explicit override and should not be used casually.

## Manual installation

```bash
git clone https://github.com/DashSaman/TunnelPannel.git
cd TunnelPannel
sudo bash install.sh
```

## Configuration

Runtime configuration lives in `.env` and is intentionally ignored by Git. The important variables are:

| Variable | Purpose |
|---|---|
| `APP_BASE_URL` | External HTTPS URL used by links/bot, or localhost during initial setup |
| `APP_SECRET_KEY` | Master secret used to derive credential encryption keys |
| `JWT_SECRET_KEY` | JWT signing secret |
| `WEB_BIND_PORT` | Localhost web port, default `18080` |
| `POSTGRES_PASSWORD` / `DATABASE_URL` | PostgreSQL credentials and DSN |
| `REDIS_PASSWORD` / `REDIS_URL` | Redis credentials and DSN |
| `BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD` | Initial super-admin credentials |
| `BOT_INTERNAL_API_KEY` | Internal API key used by the Telegram bot integration |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_BOT_ENABLED` | Optional Telegram bot configuration |
| `SMTP_*` / `EMAIL_ENABLED` | Optional email delivery configuration |

**Important:** do not casually change `APP_SECRET_KEY` after endpoint credentials have been stored. It is used to derive the Fernet key that encrypts stored SSH/sudo secrets; changing it without a migration makes existing encrypted credentials unreadable.

The installer prints a generated first-admin password once. Store it securely and change it after first login.

## Web access and HTTPS

The Compose file publishes the panel as `127.0.0.1:18080` by default. Put your existing host reverse proxy in front of that port instead of exposing PostgreSQL/Redis or the internal API directly.

Example host Nginx upstream:

```nginx
server {
    listen 443 ssl http2;
    server_name panel.example.com;

    location / {
        proxy_pass http://127.0.0.1:18080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Set `APP_BASE_URL=https://panel.example.com` in `.env` and restart only this Compose project after changing it.

## Supported execution methods (77)

The source of truth is `plan_executor/executor.py` (`SUPPORTED`). The current set is:

- **Native / kernel / overlay:** `GRE`, `GRETAP`, `IPIP`, `SIT_6IN4`, `IP6GRE`, `IP6GRETAP`, `VXLAN`, `VTI`, `VTI6`, `WIREGUARD`, `GRE_OVER_WIREGUARD`.
- **SSH family:** `SSH_LOCAL_FORWARD`, `SSH_REMOTE_FORWARD`, `SSH_DYNAMIC_SOCKS`, `SSH_TUN_L3`, `SSH_TAP_L2`, `AUTOSSH_REVERSE`, `GRE_OVER_SSH`, `SIT_OVER_SSH`.
- **GOST family:** `GOST_SOCKS5`, `GOST_SOCKS5_KCP`, `GOST_HTTP`, `GOST_HTTP2`, `GOST_WS`, `GOST_GRPC`, `GOST_QUIC`, `GOST_SSH`, `GOST_TUN`, `GOST_TAP`, `GOST_TCP_FORWARD`, `GOST_UDP_FORWARD`, `GOST_REMOTE_TCP`, `GOST_REMOTE_UDP`, `GOST_KCP_FORWARD`, `GRE_OVER_GOST`, `GRETAP_OVER_GOST`, `SIT_OVER_GOST`.
- **Chisel:** `CHISEL_TCP`, `CHISEL_UDP`, `CHISEL_SOCKS5`, `CHISEL_REVERSE_TCP`, `CHISEL_REVERSE_UDP`, `CHISEL_REVERSE_SOCKS5`.
- **Rathole:** `RATHOLE_TCP`, `RATHOLE_UDP`, `RATHOLE_TLS`, `RATHOLE_WEBSOCKET`, `RATHOLE_NOISE`.
- **FRP:** `FRP_TCP`, `FRP_UDP`, `FRP_KCP`, `FRP_QUIC`, `FRP_STCP`, `FRP_XTCP`.
- **wstunnel:** `WSTUNNEL_TCP`, `WSTUNNEL_UDP`, `WSTUNNEL_SOCKS5`.
- **VPN / IPsec:** `OPENVPN`, `IKEV2_IPSEC`, `L2TP_IPSEC`.
- **Modern proxy / sing-box:** `VLESS_TCP`, `VLESS_WS`, `VLESS_GRPC`, `VLESS_REALITY`, `VLESS_VISION_REALITY`, `VLESS_XHTTP`, `VLESS_XHTTP_REALITY`, `TROJAN_TLS`, `SHADOWSOCKS`, `HYSTERIA2`, `TUIC`, `SINGBOX_TUN`.
- **WaterWall:** `WATERWALL_DIRECT`, `WATERWALL_TLS_MUX`, `WATERWALL_REVERSE`.
- **Paqet:** `PAQET_RAW_KCP`, `PAQET_SOCKS5`.

Some methods require endpoint OS/kernel capabilities, free ports, package downloads, domains/TLS, or specific routing conditions. Run prechecks before execution; method availability does not mean every method is suitable for every server pair.

## Main UI and API paths

- `/` — landing/login entry
- `/admin` — administration panel
- `/app` — user workspace
- `/composer` — Tunnel Composer
- `/docs` — FastAPI documentation
- `/api/v1/health` — public local health endpoint

## Operations

From the installation directory:

```bash
bash scripts/healthcheck.sh
bash scripts/final_healthcheck.sh
```

Backup PostgreSQL and configuration into the ignored local `backups/` directory:

```bash
bash scripts/backup.sh
```

Restore a database backup:

```bash
bash scripts/restore.sh backups/postgres-YYYYMMDD-HHMMSS.sql.gz
```

Update the containers after pulling a reviewed Git revision:

```bash
git pull --ff-only
bash scripts/update.sh
```

Stop/remove this Compose stack while preserving named volumes:

```bash
bash scripts/uninstall.sh
```

Permanent data deletion is intentionally not automated. `docker compose down -v` destroys the database/Redis/app volumes and should only be run after a verified backup.

## Security notes

- `.env`, backups, dumps, private keys, certificates, databases and logs are excluded from Git.
- Endpoint SSH/sudo credentials are encrypted before database storage.
- SSH server keys are fingerprinted and pinned after initial discovery.
- The web listener is localhost-only by default.
- The installer refuses a host with pre-existing `netauto-*` containers unless explicitly overridden.
- GitHub tokens used to clone a private repository are passed as temporary HTTP headers and are not written into `origin`.

## Repository layout

```text
backend/         FastAPI API, auth, models, endpoint/composer/admin routes
bot/             Telegram bot and translations
plan_executor/   77-method execution engine and SSH orchestration
worker/          Background endpoint/inventory/precheck jobs
scheduler/       Scheduled/heartbeat jobs
web/             Static panel, admin, app and composer UI
proxy/           Internal Nginx reverse proxy/static config
scripts/         Install/update/backup/restore/health/uninstall helpers
tests/           Repository/release smoke tests
```

`.netauto-master/` contains historical engine-pack/state artifacts from the original build process. Production backups and runtime state are intentionally excluded.

## Development and verification

The project is Compose-first. A basic repository test can be run without starting services:

```bash
python3 -m unittest tests.test_release_assets -v
bash -n install.sh
```

With a configured `.env`:

```bash
docker compose config
docker compose run --rm --no-deps api python -m unittest discover app/tests
```

For the full running stack, use `bash scripts/final_healthcheck.sh`; it verifies API routes/database, all 77 executor methods, SSH host-key policy, web assets and Nginx configuration.

## Existing installation compatibility

The original production checkout used `/opt/network-automation` and Compose/container names prefixed with `netauto-`. The GitHub installer defaults to `/opt/tunnelpannel` but intentionally preserves those internal service names for application compatibility. Do not run two copies with the same fixed container/volume names on one Docker host.

## Repository

`https://github.com/DashSaman/TunnelPannel`
