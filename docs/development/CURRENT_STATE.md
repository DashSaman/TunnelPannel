# CURRENT STATE — P0 Engineering Audit

- **Commit audited:** `84d2dd8e26c0e333633050ff30b458df8f558b75` (`main`)
- **Date:** 2026-10-03 · based on source inspection, not READMEs
- **Feeds:** P1 standardization decisions (see TASK_LEDGER)

## Executive summary

The repository contains **three coexisting generations** of tunnel orchestration plus one
standalone product, with triplicated domain logic and drifting catalogs:

| Gen | Name | Areas | Stack | Status |
|---|---|---|---|---|
| 1 | NetAuto / TehranNetwork | `backend/ bot/ worker/ scheduler/ plan_executor/ web/ proxy/` + root `docker-compose.yml`, `install.sh`, `ops/legacy-host/`, `.netauto-master/` | Postgres + Redis + FastAPI + aiogram | wired into root `install.sh`; scheduler is a stub |
| 2 | MTF (Multi-Tunnel Failover) | `deploy/` (+ root `panel/` v3 UI, unwired) | FastAPI + SQLite + bash/python harnesses, privileged Docker `:9443` | self-contained; **what the root README actually documents** |
| 3 | TunnelGuard | `tunnelguard/` | FastAPI + SQLite WAL + systemd | independent product; only area with a real test suite |

**Catalog drift:** backend catalog = 77 methods · executor SUPPORTED = 77 · deploy registry = **82**
(77 + HAJSAMAN×3 + HEDIOUM×2). Three port allocators, three failover FSMs, three UIs, three DBs.

## Canonical core candidate (P1 decision input)

**`deploy/engine/mtf/`** — the only area that already unifies: 82-method registry, real
kernel/userspace verification harnesses (`mtf_kernel.sh` netns ping-through, `mtf_userspace.py`
loopback data-through receipts), VIP failover, conflict-safe port manager (strongest of the
three), remote multi-distro installer, and monitoring. Consolidation path: fold
`plan_executor`'s per-method deploy depth (77 real SSH deploy paths) and `tunnelguard`'s tested
failover FSM into it; retire the other generations incrementally behind compatibility layers.

## Key facts per area

- **backend/** — FastAPI :8000, 5 routers (`main`, endpoint, composer, execution, bot-control, admin). Auth: argon2 + JWT + rate limit; credentials Fernet-encrypted (key = SHA256(APP_SECRET_KEY)). **No migrations** — `create_all()` only; executor additionally uses raw SQL against `tunnel_plan_runs*` tables that have **no ORM model and no create_all** (schema drift risk).
- **worker/** — Redis job consumer: endpoint discovery, full inventory (listeners/WG/ports), pair prechecks. Paramiko with host-key pinning.
- **scheduler/** — 16-line heartbeat stub. Dead weight.
- **plan_executor/** — `executor.py` 6,876 lines, 77 real deploy methods (config gen + SSH + systemd + verify + rollback + iperf). Deepest implementation; marred by patch-append **function redefinitions** (`free_port`, `free_udp_port`, `wait_service`, `wait_listener`, `start_iperf3`×) where only the last definition is live. Zero tests.
- **bot/** — aiogram 3, 5 languages, FSM wizards (endpoints/plans/runs/prechecks), talks to backend via `BOT_INTERNAL_API_KEY` only.
- **deploy/ (MTF)** — panel :9443 TLS, cookie sessions; `/api/methods|status|mode|probe|recommend|receipts|install|st/*|ports/*|metrics`. VIP `10.10.10.5/32` via policy table `51000`; hysteresis 3, cooldown 30s. Port manager: all-sides v4+v6 scan + IP-protocol space, 48-port NEVER list, TCP 21000-25999 / UDP 26000-29999, persisted allocations. SSH = paramiko **AutoAddPolicy** (accepts any host key — weaker than Gen 1).
- **tunnelguard/** — 9 engine adapters + labeled SimAdapter (`TF_SIM_MODE`), weighted scoring, anti-flap FSM (flap lock, emergency override, routing-capability guard), JWT dashboard + WS. Cleanest engineering; separate product.
- **web/, panel/** — static UIs of different generations (`web/` = Gen 1 on :18080; `panel/` = v3 Neon Ops, not wired into any runner; `deploy/panel/` = shipped MTF UI).
- **recovery/ + scripts/** — AES-256-CBC DR snapshot (passphrase not in repo) + double-confirm restore. Sidecar `.sha256` hashes the b64 text rather than the decoded binary (fragile); `core.autocrlf=true` makes the in-repo b64 artifact round-trip fragile on this clone.

## Implementation honesty (method-level)

- **Real deploy paths (persistent, SSH):** all 77 in `plan_executor/executor.py`.
- **Real test harnesses (non-persistent):** MTF netns/loopback harnesses — produce data-through receipts for the 82-method report (25 PASS / 25 PARTIAL / 32 FAIL-with-reasons, `docs/TEST-REPORT.md`).
- **Tested-not-deployable from backend:** HAJSAMAN×3, HEDIOUM×2 (registry + tunnelguard engines only).
- **Intentional simulations:** tunnelguard SimAdapter — labeled, never fakes PASS.
- **Stub:** scheduler.

## Security findings (P0 review; fixes scheduled T-P13-002)

1. **`AGENT.md:45` (+ byte-identical `deploy/AGENT.md`)** — server **root password in clear** ("change `123456@S…` after delivery").
2. **`worklog.md:25`** — **live panel admin bootstrap password** in clear (`faZPTs6G…`).
3. **Infrastructure map in tracked files** — real IPs with roles (test `45.141.148.x` root / main `91.107.138.x`), panel URL `tun.softarg.ir:9443`, container name, token filename `.ghtoken` (`AGENT.md`, `AGENTS.md`, `worklog.md`, `README.md:175`, `deploy/srv2_install.sh`). AGENT.md itself notes a previously leaked GitHub token in chat.
4. **MTF SSH uses `AutoAddPolicy`** — no host-key verification (Gen 1 pins; MTF should too).
5. `.env.example`s are clean; no keys/tokens in tracked files beyond the above.
6. All the above remain in **git history** — removal from HEAD does not scrub history; rotation of every listed credential is required (owner action).

Immediate P0 action taken: passwords (1)(2) redacted from tracked files in this commit;
IPs/domain kept pending owner decision (they are operationally load-bearing in agent docs);
full scrub + history policy = P13.

## Real bugs found (fix queue)

- `tunnelguard/tfd/failover.py:304` — `random.gauss` with **no `random` import** in module → NameError for sim engines; swallowed by `except` so throughput silently zeros.
- MTF `core.py USERSPACE_SOCKS` maps only 3 GOST methods → other userspace methods probed with `port=None` → effectively kernel-only failover ranking.
- `tests/test_release_assets.py` fails at HEAD (AGENTS.md replaced by "never-stop contract", test expects old markers; README cross-link + `.gitignore /backups` assertions also fail).
- Root README cites `deploy/engine/mtf/installer.sh` which **does not exist** (only `installer.py`).
- `scripts/sshrun*.py` referenced by AGENTS.md are gitignored/absent.

## Baseline pointer

Test/dependency baseline at this commit: see `BASELINE.md` (95 PASS / 14 FAIL / 1 suite BLOCKED,
plus the fastapi 0.115.6-vs-0.116.1 pin conflict between tunnelguard and backend).
