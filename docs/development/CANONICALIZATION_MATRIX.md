# CANONICALIZATION MATRIX — best implementation per subsystem (T-P1-001)

Evidence base: P0 source audit (`CURRENT_STATE.md`), test baseline (`BASELINE.md`),
machine-generated `CATALOG_INVENTORY.md`. Decisions follow **actual source + tests**, not
file count / recency / README claims / method count.

Decision legend:
- **CANONICAL** — becomes the one implementation the product ships
- **REUSE** — code moves into the canonical architecture largely as-is
- **MIGRATE** — concepts/logic ported, code rewritten behind the canonical interface
- **LEGACY** — kept working behind a compatibility layer, frozen
- **REMOVE-LATER** — dead/duplicated; deleted once callers are migrated & tests pass

| # | Subsystem | Gen1 (NetAuto) | Gen2 (MTF) | Gen3 (TunnelGuard) | Tests | Known bugs / risk | Decision |
|---|---|---|---|---|---|---|---|
| 1 | Tunnel registry/catalog | `backend/app/tunnel_catalog.py` 77 (dict entries; in sync with executor, drift 0) | `deploy/methods_registry.json` 82 (richest: adds HAJSAMAN/HEDIOUM flagships) | 11 engine `name` ids | inventory script (new) | 3 divergent sources | **CANONICAL: Gen2 registry format** (JSON, superset) + Gen1 dict as generator input |
| 2 | Engine adapters | none (monolith executor) | none (per-family runner functions) | **9 adapters + SimAdapter, uniform base class** | test_engines etc. | — | **MIGRATE: Gen3 adapter pattern becomes the engine SDK** (`engines/adapters/`) |
| 3 | Tunnel installation (persistent deploy) | **`executor.py` 77 real SSH deploy paths** incl. systemd, rollback, artifacts | st_profiles persistent pair installs (subset) | adapter `up()` for 9 engines | none (Gen1) / receipts (Gen2) | Gen1 patch-append redefinitions | **REUSE: Gen1 deploy bodies** wrapped as engine adapters (P5); fix redefinitions during wrap |
| 4 | Prechecks | executor pair prechecks (deep) | probe_engine capability fingerprint | adapter `precheck()` (honest, tested) | Gen3 tested | — | **MIGRATE: Gen3 precheck contract**; Gen1 checks become per-engine data |
| 5 | Data-plane verification | executor verify steps per method | **harness receipts: ping-through / curl-through evidence** | probes with ok/why | Gen2 receipts in DB | userspace teardown gap (fixed honest-why; persistent deploy = P4) | **CANONICAL: Gen2 evidence model** (receipts) + Gen3 probe semantics |
| 6 | Real E2E harness | none | `mtf_kernel.sh` netns + `mtf_userspace.py` loopback + `run_all_tests.py` | `selftest.py`, `run_hedioum_e2e.py` | container-only | needs Linux container | **REUSE: Gen2 harness** as LINUX_PRIVILEGED test tier |
| 7 | Resource allocation | `free_port/free_udp_port` + subnet pool w/ conflicts | **`portmgr.py`: all-sides v4+v6, IP-proto space, NEVER-list, persisted ledger** | none | none | — | **CANONICAL: Gen2 portmgr** → grows into full resource manager (P4) |
| 8 | Port conflict handling | first-free scan only | **pre-allocation scan + re-verify + release** | none | none | — | **CANONICAL: Gen2** (part of #7) |
| 9 | Routing (tables/rules/policy) | executor per-method route cmds | `core.py` VIP table 51000 + MSS clamp | **`routing.py`: VIP + nft SNAT + MSS + peer route-sync** | Gen3 partial | — | **MIGRATE: Gen3 routing.py** semantics into orchestrator |
| 10 | VIP handling | none | VIP on lo + policy table | **VIP + ownership guard (SOCKS-only never carries VIP)** | Gen3 tested | — | **CANONICAL: Gen3** |
| 11 | Failover FSM | none | simple: hysteresis-N + cooldown + weighted score | **full FSM: streaks, proactive upgrade, flap lock, emergency override, persisted** | test_failover_fsm (8) | Gen3 `random` import bug — **FIXED this phase** | **CANONICAL: Gen3 FSM** |
| 12 | Anti-flap / hysteresis / cooldown | none | hysteresis_n + cooldown_s settings | **sliding window + flap lock + max switches** | tested | — | **CANONICAL: Gen3** (subset) |
| 13 | Health probes | job-based, manual | ping/SOCKS-curl classify UP/DEG/DOWN | **probes.py: RTT/loss/jitter rollups, throughput loop** | test_probes (11) | — | **CANONICAL: Gen3 probes**; Gen2 classify thresholds REUSE |
| 14 | Metrics | Redis heartbeats + job events | **/proc sampler: CPU/RAM/load/rx/tx/tcp/conntrack, 240-pt history** | rollup+throughput tables | none | — | **REUSE: Gen2 metrics.py** as node-local sampler |
| 15 | Benchmark capability | **iperf3 throughput per run (executor)** | RTT/loss from probes | RTT/loss/jitter/throughput history | none portable | neither has bounded-profile benchmark runs | **MIGRATE: both** → P6 benchmark engine (profiles QUICK/NORMAL/DEEP don't exist yet anywhere) |
| 16 | Scoring/recommendation | none | weighted `score()` for failover | weighted health score | Gen3 indirect | no 0-100 product scoring w/ weights exists | **MIGRATE (new build, P7)** using Gen2/3 formulas as input |
| 17 | Composition capability | **6 composites in executor (GRE/SIT over WG/SSH/GOST)** | registry composites (GRE_OVER_*) | none | none | no capability model anywhere | **MIGRATE (new build, P8)**; Gen1 composite deploy code REUSE per-pair |
| 18 | Server inventory | **worker: listeners, WG, routes, ports → Postgres, timestamped** | scan (st/scan): kernel ifaces, services, procs | none | none | — | **REUSE: Gen1 worker inventory** (richest) |
| 19 | SSH execution | **paramiko + host-key pinning + Fernet creds + sudo modes** | paramiko **AutoAddPolicy** (weak), in-memory passwords | paramiko + encrypted peer creds | healthcheck asserts pinning | Gen2 accepts any host key | **CANONICAL: Gen1 Remote** (pinning); Gen2 flows keep in-memory-only passwords |
| 20 | Node handling (model) | endpoints + credentials + roles | servers JSON | tunnels w/ peer | none | — | **MIGRATE: Gen1 model** → canonical Node (P2) |
| 21 | API | **FastAPI /api/v1: auth, endpoints, composer, execution, admin, bot-control** | panel API (session cookie) | JWT + WS | test_api (12, Gen3) | Gen1 has no tests | **REUSE: Gen1 API surface** (largest), Gen3 auth style optional |
| 22 | Authentication/security | **argon2 + JWT + rate limit + audit log + RBAC-ish admin** | session cookie + random bootstrap pw | JWT + users table | partial | — | **CANONICAL: Gen1** security stack |
| 23 | Database / data model | Postgres + SQLAlchemy models (but **no migrations**, raw-SQL run tables drift) | SQLite + JSON files | SQLite WAL + schema version | none | migration debt | **MIGRATE: Gen1 ORM + Alembic (new, P2)**; SQLite stays for single-node panel mode |
| 24 | Job handling | **Redis queue + jobs + job_events + cancel** | threading + progress JSON | none | none | — | **REUSE: Gen1 jobs** → canonical Job system (add timeouts/states) |
| 25 | Worker/scheduler | worker (real) + **scheduler (stub)** | apply thread | FSM thread | none | scheduler dead | **REUSE: Gen1 worker; REMOVE-LATER: scheduler stub** |
| 26 | Telegram bot | **aiogram 3, 5 locales, full wizard, bot-control API** | none | none | none | — | **REUSE: Gen1 bot** (rewire to canonical core in P12) |
| 27 | Web UI | web/ static (3 asset generations) | **deploy/panel shipped** + root panel/ v3 (unwired) | tunnelguard web (WS live) | none | triple drift | **CANONICAL: Gen2 v3 panel** (root `panel/`) once wired; REMOVE-LATER web/ |
| 28 | Backup/restore | **pg_dump + AES-256-CBC DR + double-confirm restore + healthchecks** | none | none | scripts assert markers | b64/CRLF fragility | **REUSE: Gen1 DR scripts**; re-encode artifact gitattributes |
| 29 | Installer | root install.sh (Gen1 stack, apt-only) | **multi-distro _pkg (apt/dnf/yum/zypper/pacman/apk) + docker** | own install.sh (systemd) | installer markers test | README/installer mismatch — **FIXED this phase** | **REUSE: Gen2 distro logic**; unify installers in P13 |
| 30 | Tests | import smoke only | container harness (real evidence) | **real pytest suite (100 tests)** | — | — | **CANONICAL: Gen3 test discipline**; extend to all areas |
| 31 | Linux portability | Docker-centric | **strongest: distro-aware, netns harness** | systemd-native | — | — | **CANONICAL: Gen2** |
| 32 | Maintainability | executor.py 6.9k lines, patch-append redefs | small focused modules | **cleanest: base-adapter + small modules + docs** | — | — | **CANONICAL: Gen3 style** as the code-organization template |

## Summary — the canonical product is a merge, not a survivor

- **From Gen1 (NetAuto):** SSH execution + security stack, API surface, worker inventory,
  job queue, Telegram bot, DR scripts, and the 77 per-method deploy bodies (wrapped as adapters).
- **From Gen2 (MTF):** 82-method registry (canonical catalog format), data-plane receipt model,
  netns/loopback E2E harness, portmgr (→ resource manager), metrics sampler, v3 panel UI,
  distro-portable install.
- **From Gen3 (TunnelGuard):** engine adapter SDK pattern, failover FSM (anti-flap),
  VIP/routing semantics, probe semantics, and the test discipline.

Nothing whole-generation is deleted: Gen1 stays running behind its compatibility layer until
each subsystem's canonical replacement passes equivalent tests (P1.5 migration rule).
