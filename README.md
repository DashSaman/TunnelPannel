# TehranNetwork

TehranNetwork is a multilingual network automation platform for managing remote endpoints, inventory discovery, bidirectional prechecks, secure tunnel planning, sequential execution, and Telegram bot integration.

## Development

- Project root: `/opt/network-automation`
- Compose file: `docker-compose.yml`
- Backend source: `backend/app`
- Bot source: `bot`
- Executor source: `plan_executor`
- Scheduler source: `scheduler`
- Worker source: `worker`
- Web UI: `web`
- Proxy: `proxy`

### Running locally via Docker Compose

Use the project Compose file for all service execution and tests.

```bash
cd /opt/network-automation
docker compose -f docker-compose.yml up -d --build api
```

### Test scaffolding

A minimal Docker-based test scaffold exists in `backend/app/tests`.
Run the backend unit tests through the `api` service:

```bash
docker compose run --rm --no-deps api python -m unittest discover app/tests
```

### Backup and deployment

Existing backups are stored under `/opt/network-automation/backups`.
Create a new timestamped backup before any production changes.

### Important notes

- The repository is managed through Docker Compose.
- Do not use local Python virtual environments in this workspace.
- Keep `.env` and runtime secrets out of version control.
