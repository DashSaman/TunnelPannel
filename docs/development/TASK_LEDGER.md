# TASK LEDGER

Rules: every task has exactly one status · only ONE major task IN_PROGRESS at a time ·
a PASS task is reopened only if a dependency change actually breaks it ·
max 3 materially different fix attempts per failure, then BLOCKED with evidence.

Statuses: `TODO` · `IN_PROGRESS` · `PASS` · `BLOCKED` · `FAILED`

**This file is the single authoritative status table.** Phase-epic rows were
consolidated with their execution-log rows (consistency gate A, 2026-10-03);
no duplicate tables exist.

| ID | Phase | Depends on | Task | Status | Files | Test evidence | Result / commit |
|---|---|---|---|---|---|---|---|
| T-P0-001 | P0 | — | Full repository audit → CURRENT_STATE.md | PASS | docs/development/CURRENT_STATE.md | source inspection | 3 generations mapped; canonical picks per subsystem · ae409ed |
| T-P0-002 | P0 | — | Test + dependency baseline | PASS | docs/development/BASELINE.md | 95P/14F/1B frozen at 84d2dd8 | ae409ed |
| T-P0-003 | P0 | T-P0-001 | Secret review + redaction of tracked credentials | PASS | AGENT.md · worklog.md (redacted) | grep 0 matches post-redaction | rotation = OPERATOR_ACTION_REQUIRED · ae409ed |
| T-P1-001 | P1 | T-P0-001 | Canonicalization matrix (32 subsystems, best-per-subsystem) | PASS | docs/development/CANONICALIZATION_MATRIX.md | evidence review | merge-not-survivor · 208fb5c |
| T-P1-002 | P1 | T-P0-002 | Baseline defect fixes (random import, release-asset tests, README installer, probe honesty, VIP kernel-first) | PASS | tunnelguard/tfd/failover.py · README.md · AGENTS.md · .gitignore · deploy/engine/mtf/{core,api}.py | root 8P (was 5P/3F) | 208fb5c |
| T-P1-003 | P1 | — | Test classification tiers + precise win32 skips | PASS | tunnelguard/pytest.ini · 3 test files | 89P/11S | tiers unit_portable/linux_integration/linux_privileged/real_node_e2e · 208fb5c |
| T-P1-004 | P1 | T-P0-001 | Catalog drift inventory (machine-generated) | PASS | scripts/generate_catalog_inventory.py · CATALOG_INVENTORY.md | script run | catalog↔executor drift 0; union 90; registry 82 = 76 profiles + 6 composites · 208fb5c |
| T-P1-005 | P1 | T-P1-001 | ADR-001 canonical architecture + engine/profile identity | PASS | docs/adr/ADR-001-canonical-architecture.md | review | legacy IDs stay aliases · 208fb5c |
| T-P1-006 | P1 | T-P0-003 | Secret hygiene doc (history-cleanup procedure) | PASS | docs/development/SECRET_HYGIENE.md | review | 208fb5c |
| T-P2-001 | P2 | T-P1-005 | Canonical data model (23 entities) | PASS | core/models.py | tests/unit/test_models.py | 23 tables; DAG chain; ownership ledger · 95b083b |
| T-P2-002 | P2 | T-P1-004 | Engine/profile identity + aliases + composite semantics | PASS | core/catalog.py | tests/unit/test_catalog.py (15) | 82→21 engines; gost=15 profiles · 95b083b |
| T-P2-003 | P2 | T-P2-001 | Alembic migrations + initial schema | PASS | migrations/ | fresh-DB upgrade-head test | revision f9cb963715a8 · 95b083b |
| T-P3-001 | P3 | T-P2-002 | Manifest schema + strict validation | PASS | engines/manifests/__init__.py | 8 negative tests | contradictions rejected · 1270772 |
| T-P3-002 | P3 | T-P3-001 | 21 engine manifests | PASS | engines/manifests/*.json | catalog==manifests invariant | 1270772 |
| T-P3-003 | P3 | T-P2-001 | Adapter SDK (12-method contract + registry) | PASS | engines/adapters/__init__.py | contract tests | probe() = truth gate · 1270772 |
| T-P4-001 | P4 | T-P2-001 | Canonical ResourceManager (9 kinds) | PASS | orchestrator/resources/ | 15 tests | idempotent reserve; live-row unique index · 666ff86 |
| T-P4-002 | P4 | T-P4-001 | Transactional deployment (7-state + reverse rollback) | PASS | orchestrator/deployment/ | 11 tests | dry-run zero-mutations proven · 21621a7 |
| T-P5-001 | P5 | T-P3-002 | Honest engine status matrix | PASS | scripts/generate_engine_status.py · ENGINE_STATUS.md | generator | per-engine evidence · 04c211a |
| T-P5-002 | P5 | T-P3-003 | First kernel adapters (wireguard, gre) | PASS | engines/adapters/kernel.py | 15 tests | command-plan pattern · 04c211a |
| T-P5-003 | P5 | T-P5-002 | Canonical executors + package service | PASS | engines/executors.py · engines/packages.py | 5 tests | honest BLOCKED on unknown distro · d82ef5b |
| T-P5-004 | P5 | T-P5-003 | Userspace framework + 9 families (42 profiles) | PASS | engines/adapters/userspace.py | table-driven tests | one adapter per engine · d82ef5b |
| T-P5-005 | P5 | T-P5-003 | Kernel remainder + ssh family + hedioum/hajsaman | PASS | engines/adapters/{kernel_extra,ssh_family}.py | table-driven tests | 21/21 engines · d82ef5b |
| T-P5-006 | P5 | T-P5-004/5 | Honesty negatives + redaction + coverage gate + profile matrix | PASS | tests/unit/test_adapter_families.py · ENGINE_PROFILE_MATRIX.json | suite 158P | 76/76 profiles; 8 false-positive probes FAIL · d82ef5b |
| T-P6-001 | P6 | T-P5-006 | Benchmark core: compat resolver + profiles + honest stats | PASS | orchestrator/benchmarking/__init__.py | 13 tests | INCOMPATIBLE≠BLOCKED; p99 gate · 16e5d67 |
| T-P6-002 | P6 | T-P6-001 | Scoring + deterministic ranking | PASS | orchestrator/benchmarking/scoring.py | scoring tests | hard gates; documented tie-breaks · 16e5d67 |
| T-P6-003 | P6 | T-P6-002 | BenchmarkRunner (bounded, timeouts, cleanup, receipts) | PASS | orchestrator/benchmarking/runner.py | 11 tests | ORPHANED_RESOURCE events · 16e5d67 |
| T-P6-004 | P6 | T-P6-003 | Benchmark HTTP API (non-blocking Job semantics) | PASS | apps/api/benchmark_api.py | 6 tests | request never blocks · 16e5d67 |
| T-P7-001 | P7 | T-P6-004 | Ranking UI + selection persistence | PASS | apps/web/ | 5 tests | selection ≠ deployment (0 deployments proven) · 8940f13 |
| T-GATE-001 | P8 | — | Consistency gate: ledger normalization + canonical counts + invariants | PASS | core/counts.py · tests/unit/test_counts.py · this file | 10 count tests | 82/21/76/6/6/88; drift auto-detected · (this commit) |
| T-P8-001 | P8 | T-GATE-001 | Composition engine (resolver/DAG/MTU/MSS/route-guard/placement/maturity/preflight/plan) | PASS | orchestrator/composition/core.py | 80 composition tests incl. 33 spec examples | 32/32 spec examples + invalids; profile-qualified capabilities; real-adapter-only rule · (P8 commit) |
| T-P8-002 | P8 | T-P8-001 | Composition service (CRUD/dry-run/parents/overlays) + legacy mapping + migration 0002 | PASS | orchestrator/composition/service.py · migrations/versions/4040fb150042 | service tests | 6/6 legacy templates valid canonical chains; preview zero-mutation · (P8 commit) |
| T-P9-001 | P9 | T-P8-001 | Bounded chain candidate search + chain benchmark + shared domains + combined ranking | PASS | orchestrator/benchmarking/chains.py | 15 chain tests | budgets enforced; dedupe; PREDICTED≠MEASURED; full-chain truth gate (components-pass-but-e2e-fail → FAILED); reverse-topo teardown; ORPHANED surfaced; shared-underlay warning · (P9 commit) |
| T-P10-001 | P10 | T-P9-001 | Failover groups: FSM (TunnelGuard semantics), repair-before-abandon, underlay propagation, diversity warnings, decision receipts, API + UI flow | PASS | orchestrator/failover/ · apps/api/failover_api.py · apps/web/ranking.html | 31 tests (21 FSM + 10 API) | membership-is-law; thresholds/cooldown/flap-lock/emergency; pin; maintenance; PREFER_PRIMARY/BEST_SCORE; unselected never chosen · (P10 commit) |
| T-P11-001 | P11 | T-P10-001 | Topology + true multi-hop (model, bounded search, loop prevention, per-hop state, e2e truth gate, path metrics, shared domains, routing plan, failover integration, UI) | PASS | orchestrator/topology.py · core/models.py (4 tables) · migrations/versions/7b6b540f5991 · apps/web/topology.html + web_api routes | 21 topology tests | bottleneck/weakest-hop/combined-loss metrics; e2e gate; HOP vs PATH failure; bounded search terminates on time budget; paths as FailoverGroup members · (P11 commit) |
| T-P12-001 | P12 | T-P10-001 | Observability (lightweight sampling, rollups+retention, stability history, prometheus export) + alert engine (rules/severities/dedupe/cooldown/resolution) + Telegram bot core (authz, confirmations, redaction) | PASS | orchestrator/observability.py · orchestrator/alerting.py · apps/bot/core.py | 22 tests | 100 recurrences → 1 notification; FAST_BUT_UNSTABLE classifier; naive-datetime UTC guard · (P12 commit) |
| T-P13-001 | P13 | — | Linux CI: portable matrix + linux-integration + install acceptance + security + release build | PASS | .github/workflows/*.yml | **CI GREEN on 7f3fa22** (portable-tests + security success; 5 real runner bugs found & fixed: os-release VERSION collision, py3.11 f-string backslash, useradd guard, backup staging ownership, IFNAMSIZ probe) | hosted-runner verified · 7f3fa22 |
| T-P13-002 | P13 | — | Security hardening (RBAC, audit, rate limit) | TODO | — | — | — |
| T-P13-003 | P13 | — | install.sh (canonical app, Ubuntu/Debian, idempotent, generated RBAC tokens shown once, install receipt) + upgrade.sh (backup→migrate→health, rollback hint) + uninstall.sh (owned-only removal) | PASS | install.sh · scripts/{upgrade,uninstall}.sh · requirements-canonical.txt · requirements-dev.txt | bash -n all; contract test; CI install acceptance job | legacy Gen1 installer preserved in git history · (P13.2 commit) |
| T-P13-004 | P13 | — | Canonical backup (VACUUM INTO/pg_dump, manifests, checksummed, secret-free) + restore (checksum gate, double-confirm, safety copy, health) | PASS | scripts/{backup,restore}.sh | CI backup→mutate→restore round-trip job | restore proven: mutation rolled back, health OK · (P13.2 commit) |
| T-P14-001 | P14 | P0-P13 | Real-node validation (E2E receipts) | BLOCKED | — | — | **FRESH_REAL_NODE_CREDENTIALS_REQUIRED** — old leaked credentials are permanently untrusted (§77); operator must supply fresh disposable Linux nodes. Per §P14 gate: stop before P15. |
| T-P15-001 | P15 | T-P14-001 | Production release (tag, matrices, acceptance) | TODO | — | — | — |

## Canonical counts (single source: core/counts.py — invariant-tested)

LEGACY_METHOD_IDS **82** · CANONICAL_ENGINES **21** · ENGINE_PROFILES **76** ·
COMPOSITE_TEMPLATES **6** · ALIASES **6** · TOTAL_RESOLVABLE_LEGACY_IDS **88**.

Historical discrepancies resolved: "77" = Gen1 executor/catalog (subset, internally drift-free);
"82" = registry superset; "90" = union incl. Gen3 bare names + abstract BASE/SIM;
"22 engines" (early P2 smoke) included the `composite` pseudo-engine, excluded since.

## Standing blockers

- OPERATOR_ACTION_REQUIRED: rotate the two exposed passwords + GitHub token (history retains them).
- linux_privileged / real_node_e2e tiers require a Linux host (CI in P13, validation in P14).
