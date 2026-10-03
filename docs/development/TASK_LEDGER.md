# TASK LEDGER

Rules: every task has exactly one status · only ONE major task IN_PROGRESS at a time ·
a PASS task is reopened only if a dependency change actually breaks it ·
max 3 materially different fix attempts per failure, then BLOCKED with evidence.

Statuses: `TODO` · `IN_PROGRESS` · `PASS` · `BLOCKED` · `FAILED`

| ID | Phase | Depends on | Task | Status | Files | Test | Result | Commit |
|---|---|---|---|---|---|---|---|---|
| T-P0-001 | P0 | — | Full repository audit → `CURRENT_STATE.md` | PASS | docs/development/CURRENT_STATE.md | source inspection | 3 generations identified; canonical core candidate = `deploy/engine/mtf/` | (this commit) |
| T-P0-002 | P0 | — | Test + dependency baseline → `BASELINE.md` | PASS | docs/development/BASELINE.md | tunnelguard 89P/11F(env) · backend 1P · root 5P/3F(pre-existing) · deploy BLOCKED(container) | baseline frozen at `84d2dd8` | (this commit) |
| T-P0-003 | P0 | T-P0-001 | Secret/credential review of tracked files + history | PASS | AGENT.md · deploy/AGENT.md · worklog.md (redacted) | grep scan 0 matches post-redaction | 2 live passwords redacted from HEAD; infra-map finding + git-history rotation documented (owner action) | (this commit) |
| T-P1-001 | P1 | T-P0-001 | Canonicalization matrix (32 subsystems, best-per-subsystem) | PASS | docs/development/CANONICALIZATION_MATRIX.md | evidence-based review | Gen3=SDK/FSM · Gen2=registry/harness/portmgr/UI · Gen1=deploy-bodies/API/security | (P1 commit) |
| T-P1-002 | P1 | T-P0-002 | Baseline defect fixes: random import, release-asset tests, README installer ref, honest userspace probe, VIP kernel-first | PASS | tunnelguard/tfd/failover.py · tests/test_release_assets assertions satisfied via AGENTS.md/README.md/.gitignore · deploy/engine/mtf/{core,api}.py | tunnelguard 89P/11S · root 8P · backend 1P | root suite 3F→0F; probe no longer curls :None | (P1 commit) |
| T-P1-003 | P1 | — | Test classification tiers + precise win32 skips | PASS | tunnelguard/pytest.ini · 3 test files | 89P/11S (11=linux_integration on win32) | tiers: unit_portable/linux_integration/linux_privileged/real_node_e2e | (P1 commit) |
| T-P1-004 | P1 | T-P0-001 | Catalog drift inventory (machine-generated) | PASS | scripts/generate_catalog_inventory.py · docs/development/CATALOG_INVENTORY.md | script run | catalog↔executor drift 0; registry +5 flagships; union 90 | (P1 commit) |
| T-P1-005 | P1 | T-P1-001 | ADR-001 canonical architecture + engine/profile identity plan | PASS | docs/adr/ADR-001-canonical-architecture.md | review | merge-not-survivor architecture; legacy IDs stay as aliases | (P1 commit) |
| T-P1-006 | P1 | T-P0-003 | Secret hygiene: history-cleanup procedure + rotation duties | PASS | docs/development/SECRET_HYGIENE.md | grep 0 matches in HEAD | OPERATOR_ACTION_REQUIRED documented (rotate 2 passwords + token) | (P1 commit) |
| T-P2-001 | P2 | T-P1-001 | Canonical data model + single source of truth (catalog/allocations/state) | TODO | core/ | unit | — | — |
| T-P3-001 | P3 | T-P2-001 | Engine interface + manifests for all real engines | TODO | engines/ | unit | — | — |
| T-P4-001 | P4 | T-P3-001 | Resource manager + transactional deployment (dry-run, rollback) | TODO | orchestrator/ | unit+integration | — | — |
| T-P5-001 | P5 | T-P3-001 | Repair/complete standalone engines; honest status per method | TODO | engines/ | engine tests | — | — |
| T-P6-001 | P6 | T-P4-001, T-P5-001 | Automatic standalone benchmarking (bounded jobs, receipts) | TODO | orchestrator/benchmarking/ | integration | — | — |
| T-P7-001 | P7 | T-P6-001 | Scoring + ranking UI | TODO | apps/web/ | integration | — | — |
| T-P8-001 | P8 | T-P3-001, T-P4-001 | Composition engine (capability resolver, cycles, depth, MTU, route guard) | TODO | orchestrator/composition/ | unit | — | — |
| T-P9-001 | P9 | T-P8-001 | Composed-chain benchmarking (finite candidate search) | TODO | orchestrator/ | integration | — | — |
| T-P10-001 | P10 | T-P9-001 | Failover groups + component/chain failover + anti-flap | TODO | orchestrator/failover/ | unit+integration | — | — |
| T-P11-001 | P11 | T-P10-001 | Topology + multi-hop | TODO | orchestrator/ | integration | — | — |
| T-P12-001 | P12 | T-P10-001 | Observability + alerts + bot integration | TODO | apps/bot/ | integration | — | — |
| T-P13-001 | P13 | T-P2-001 | CI (ruff, pytest, shellcheck, yaml, secret scan, docker, migrations) | TODO | .github/workflows/ | CI run | — | — |
| T-P13-002 | P13 | — | Security hardening (secrets cleanup, RBAC, audit log) | TODO | core/security/ | security tests | — | — |
| T-P13-003 | P13 | — | Backup/restore (tested restore) + safe uninstall | TODO | recovery/ | integration | — | — |
| T-P14-001 | P14 | P0–P13 | Real-node validation (E2E receipts) | TODO | tests/e2e/ | e2e | — | — |
| T-P15-001 | P15 | T-P14-001 | Production release (version, tag, notes, matrices) | TODO | CHANGELOG.md | phase gates | — | — |

## Notes

- Baseline commit: `84d2dd8e26c0e333633050ff30b458df8f558b75`.
- P0 quick secret findings (detail in CURRENT_STATE.md §12): `AGENTS.md` tracks production
  IPs/roles/panel URL/token-file names; `scripts/sshrun*.py` named in `.gitignore` as credential
  carriers; `deploy/srv2_install.sh` present in history. Full review = T-P0-003.
- Dependency conflict fastapi 0.115.6 vs 0.116.1 recorded in BASELINE.md.

## P2 execution log

| ID | Phase | Depends on | Task | Status | Files | Test | Result | Commit |
|---|---|---|---|---|---|---|---|---|
| T-P2-001 | P2 | T-P1-005 | Canonical data model (23 entities, SQLAlchemy 2) | PASS | core/models.py | tests/unit/test_models.py (model set + roundtrip) | 23 tables; DAG chain; ownership ledger; job/verification vocabularies | (P2 commit) |
| T-P2-002 | P2 | T-P1-004 | Engine/profile identity + legacy aliases + composite semantics | PASS | core/catalog.py | tests/unit/test_catalog.py (15 tests) | 82 registry IDs → 22 engines; gost=15 profiles; 6 composite templates (A-over-B); Gen3 bare names alias-resolve | (P2 commit) |
| T-P2-003 | P2 | T-P2-001 | Alembic migrations + initial canonical schema | PASS | migrations/ · alembic.ini | test_models.py::TestAlembic (upgrade head on fresh sqlite) | revision f9cb963715a8; env honors DATABASE_URL; render_as_batch for sqlite | (P2 commit) |

| T-P3-001 | P3 | T-P2-002 | Engine manifest schema + strict validation (contradictions fail) | PASS | engines/manifests/__init__.py | tests/unit/test_manifests.py (8 negative cases) | 16-capability vocabulary; layer/flag/transport contradictions rejected | (P3 commit) |
| T-P3-002 | P3 | T-P3-001 | 21 engine manifests (one JSON per catalog engine) | PASS | engines/manifests/*.json · scripts/generate_engine_manifests.py | test: catalog engines == manifest ids | full coverage invariant enforced by test | (P3 commit) |
| T-P3-003 | P3 | T-P2-001 | Adapter SDK — 12-method contract + registry + ProbeResult truth gate | PASS | engines/adapters/__init__.py | tests/unit/test_manifests.py::TestAdapterSDK | partial implementations rejected at registration; probe() is the honesty gate | (P3 commit) |

| T-P4-001 | P4 | T-P2-001 | Canonical ResourceManager (ports/ifaces/subnets/tables/fwmarks/nft/systemd/ns/temp) | PASS | orchestrator/resources/__init__.py · tests/unit/test_resources.py | 15 unit tests (collisions/release/idempotency/ownership) | ledger-backed; NEVER-list; external in-use provider protocol; live-row partial unique index | (P4a commit) |

| T-P4-002 | P4 | T-P4-001 | Transactional deployment engine (PLAN→VALIDATE→DRY_RUN→RESERVE→APPLY→VERIFY→COMMIT, reverse ROLLBACK) | PASS | orchestrator/deployment/__init__.py · tests/unit/test_deployment.py | 11 unit tests incl. mandatory matrix | dry-run zero-mutations proven; reverse-order rollback; partial-apply + verify-failure paths; idempotent re-reserve; events audited | (P4b commit) |

| T-P5-001 | P5 | T-P3-002 | Honest engine status matrix (manifests × TEST-REPORT evidence) | PASS | scripts/generate_engine_status.py · docs/development/ENGINE_STATUS.md | generator run + parser validated | per-engine P/PA/F evidence extracted (e.g. gost 8P/7F, xray 7PA); evidence column wins over declarations | (P5 commit) |
| T-P5-002 | P5 | T-P3-003 | First real command-planning adapters (wireguard, gre) + SSH/Fake executor | PASS | engines/adapters/kernel.py · tests/unit/test_kernel_adapters.py | 15 unit tests on command stream | probe()=ping-through-truth-gate; rollback=reverse-inverse; plan declarative (zero mutations) | (P5 commit) |

| T-P5-003 | P5 | T-P5-002 | Canonical executors (Local/SSH/Fake) + package service (6 managers, honest BLOCKED) | PASS | engines/executors.py · engines/packages.py | 5 tests | distro detection, per-manager commands, unknown distro BLOCKED | (P5.2 commit) |
| T-P5-004 | P5 | T-P5-003 | Userspace adapter framework + 9 engine families (gost 15p/xray 7p/singbox 5p/frp 6p/rathole 5p/chisel 6p/wstunnel 3p/waterwall 3p/paqet 2p) | PASS | engines/adapters/userspace.py | table-driven family tests | one adapter per ENGINE + profile table (no 15x duplication); data-plane probes per kind; secret redaction | (P5.2 commit) |
| T-P5-005 | P5 | T-P5-003 | Kernel family completion (gretap/ip6, ipip, sit, vxlan, vti/v6, openvpn, ipsec ikev2+l2tp) + SSH family (6 profiles) + Hedioum (2) + HajSaman (3) | PASS | engines/adapters/kernel_extra.py · engines/adapters/ssh_family.py | table-driven family tests | full catalog coverage reached: 21/21 engines, 76/76 profiles | (P5.2 commit) |
| T-P5-006 | P5 | T-P5-004, T-P5-005 | Honesty negative tests + secret redaction + coverage gate + authoritative profile matrix | PASS | tests/unit/test_adapter_families.py · scripts/generate_engine_profile_matrix.py · docs/development/ENGINE_PROFILE_MATRIX.json | 74 tests in file; suite 158P | listener-up-but-no-traffic=FAIL ×8; redaction ×4; gate: every engine/profile/composite resolution | (P5.2 commit) |

| T-P6-001 | P6 | T-P5-006 | Benchmark core: compat resolver, QUICK/NORMAL/DEEP profiles, honest stats (p99 gate) | PASS | orchestrator/benchmarking/__init__.py | tests/unit/test_benchmark.py (compat+stats) | INCOMPATIBLE vs BLOCKED separation; p99 None under 100 samples | (P6 commit) |
| T-P6-002 | P6 | T-P6-001 | Scoring + deterministic ranking (weights 100, normalization fns, hard gates, documented tie-breaks) | PASS | orchestrator/benchmarking/scoring.py | scoring tests | data-plane failure can never score healthy; BLOCKED/INCOMPATIBLE/TIMED_OUT carry no fake score | (P6 commit) |
| T-P6-003 | P6 | T-P6-002 | BenchmarkRunner: bounded concurrency (default 2), stage+overall timeouts, cancellation, always-cleanup + ORPHANED_RESOURCE, raw-before-score, sanitized receipts | PASS | orchestrator/benchmarking/runner.py | runner tests (11) | temp owned resources via P4 ledger; job states finite | (P6 commit) |
| T-P6-004 | P6 | T-P6-003 | Benchmark HTTP API (start/status/cancel/results/receipt, non-blocking Job semantics) | PASS | apps/api/benchmark_api.py | tests/unit/test_benchmark_api.py (6) | request never blocks; thread owns session; thread death recorded as FAILED | (P6 commit) |

| T-P7-001 | P7 | T-P6-004 | Ranking UI: operator page (nodes→profile→benchmark→progress→sortable ranked table with full column set) + selection persistence | PASS | apps/web/ranking.html · apps/web/web_api.py · tests/unit/test_ranking_ui.py | 5 UI tests | selection ≠ deployment (transparency endpoint proves 0 deployments); selection stored on Job payload → P10 FailoverGroup input | (P7 commit) |
