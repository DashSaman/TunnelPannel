# TunnelPannel Agent Guide

This file is the operating guide for coding agents working on TunnelPannel (TehranNetwork / NetAuto).

## Mission
TunnelPannel is a self-hosted network automation control plane. It registers Linux endpoints, discovers inventory, performs bidirectional prechecks, composes tunnel plans, and executes approved plans over SSH from the web UI or Telegram bot.

## Source of truth
- Runtime orchestration: `docker-compose.yml`
- Backend API: `backend/app`
- Tunnel catalog: `backend/app/tunnel_catalog.py`
- Execution engine: `plan_executor/executor.py`
- Canonical executable set: `SUPPORTED` in `plan_executor/executor.py` (currently 77 methods)
- Web UI: `web/`
- Telegram bot: `bot/`
- Background services: `worker/`, `scheduler/`
- Proxy: `proxy/nginx.conf`
- Deployment and recovery helpers: `scripts/`

Current executable code and tests take precedence over historical notes or generated status artifacts.

## Production safety
- Keep changes scoped to TunnelPannel only.
- Record current stack status and health before production changes.
- Prefer an isolated worktree for development and release preparation.
- Do not use registered endpoints as disposable test targets.
- Keep external recovery access available when validating routing changes.
- Preserve the existing application encryption key when restoring an existing database.
- Keep database and cache services on the internal Docker network.

## Architecture rules
`netauto-web` serves the UI and proxies API requests to `netauto-api`. PostgreSQL stores persistent users, endpoints, encrypted credentials, plans and audit data. Redis coordinates transient jobs/events. Worker, scheduler and plan executor perform background and tunnel execution work.

Compose services: `postgres`, `redis`, `api`, `bot`, `worker`, `plan_executor`, `scheduler`, `web`.

- Keep the UI/catalog and executor method set synchronized.
- A tunnel method is executable only when the executor implements it.
- Prechecks must report missing platform, port, routing or dependency requirements before execution.
- Preserve SSH host-key fingerprint verification behavior.
- Method cleanup must remain scoped to resources created by that method.
- New methods require validation, execution, cleanup, progress/error reporting and tests.

## Development workflow
1. Inspect branch, diff, recent commits and relevant tests.
2. Use an isolated worktree for substantial changes.
3. Add or adjust tests before behavior changes where practical.
4. Keep changes focused and avoid unrelated refactors.
5. Run syntax checks, tests, Compose validation and repository hygiene checks before publishing.
6. Report completion only after fresh verification evidence.

## Verification
Minimum release checks:

```bash
python3 -m unittest tests.test_release_assets -v
python3 -m compileall -q backend bot worker scheduler plan_executor
git diff --check
docker compose --env-file .env config >/dev/null
```

For a clean installation also verify the local health endpoint and `scripts/final_healthcheck.sh`. The executor should expose 77 methods unless the catalog is intentionally changed by the release.

## Installation and recovery
- Root installer: `install.sh`; default installation path: `/opt/tunnelpannel`.
- Fresh installs generate local application/database/cache keys automatically.
- Existing `netauto-*` containers are treated as a collision signal unless ownership is explicitly intended.
- `scripts/export-production-state.sh` creates an encrypted production state bundle containing PostgreSQL and app-data state.
- Runtime configuration and the original `APP_SECRET_KEY` are intentionally kept outside Git and outside the state bundle; store them separately in secure backup storage.
- `scripts/restore-production-state.sh` restores the state bundle after the matching runtime configuration is provisioned on the destination.
- Redis is transient coordination state and is recreated.

## Documentation and definition of done
Keep `README.md` and `README.fa.md` aligned. A release is complete only when tests pass, Compose validates, runtime data is excluded from Git, documentation matches behavior, and production health has been rechecked.
