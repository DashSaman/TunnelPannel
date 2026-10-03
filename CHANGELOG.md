# Changelog

## [Unreleased] — canonical rebuild (P0–P13)

### Added (canonical platform, alongside preserved Gen1/Gen2/Gen3 code)
- Canonical core: 30-table data model + Alembic migrations; engine/profile
  catalog (21 engines, 76 profiles, 82 legacy IDs + 6 aliases resolvable).
- Engine layer: validated manifests (16-capability vocabulary), 12-method
  adapter SDK with data-plane truth gates, Local/SSH/Fake executors,
  multi-distro package service.
- Orchestrator: ResourceManager (9 resource kinds, ownership ledger),
  transactional deployment (dry-run/reverse rollback), bounded benchmark
  engine (QUICK/NORMAL/DEEP, honest p99, hard scoring gates), capability-
  driven composition engine (subsumption semantics, profile-qualified
  capabilities, cycle/MTU/route-guard/placement validation), chain
  benchmarking (full-chain truth gate, shared failure domains), failover
  FSM (thresholds/cooldown/flap-lock/emergency/preemption/pin), topology
  multi-hop (loop-free paths, e2e gate, bottleneck metrics), observability
  (rollups/retention/stability) + alert engine (dedupe/resolution), and a
  Telegram bot core (authorization + confirmations + redaction).
- Apps: canonical API/UI (benchmark, failover, ranking, topology), RBAC
  (SUPER_ADMIN/OPERATOR/VIEWER, backend-enforced), optional Prometheus
  metrics.
- Operations: one-line `install.sh` (idempotent, CI-verified),
  `scripts/upgrade.sh`, `scripts/uninstall.sh`, canonical `backup.sh` /
  `restore.sh`; GitHub Actions CI (portable matrix 3.11/3.12, Linux
  integration incl. install acceptance, security scans, release build).

### Security
- Removed two live credentials from tracked files (rotation required —
  see docs/development/SECRET_HYGIENE.md); .gitignore hardened.

### Migration notes
- Canonical schema ships via Alembic (head: `7b6b540f5991`); legacy Gen1
  stack and Gen2 MTF panel remain runnable from their own directories.
