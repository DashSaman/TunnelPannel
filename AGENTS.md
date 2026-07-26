# TehranNetwork Agent Manifest

This repository is maintained by the Codex development workflow.

## Purpose

- Support secure endpoint registration and inventory.
- Enable bidirectional prechecks before tunnel execution.
- Provide tunnel composer workflows for pair and hub-and-spoke topologies.
- Stream redacted progress to the web panel and Telegram bot.
- Maintain one shared backend, database, and bot integration.

## Project Structure

- `backend/`: FastAPI backend source.
- `bot/`: Telegram bot logic and translations.
- `plan_executor/`: Tunnel execution engine.
- `scheduler/`: Scheduled jobs.
- `worker/`: Background worker processes.
- `web/`: Web UI assets.
- `proxy/`: Nginx configuration.
- `scripts/`: Deployment and backup scripts.
- `backups/`: Preserved backup archives.

## Development Notes

- Use Docker Compose for service management.
- Do not commit secrets or `.env` values.
- Keep the main control server stable and use endpoint test targets for tunnel validation.
