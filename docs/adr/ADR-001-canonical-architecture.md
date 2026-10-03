# ADR-001 — Canonical Architecture (converge three generations into one product)

- **Status:** Accepted (P1) · **Date:** 2026-10-03 · **Supersedes:** none
- **Evidence:** `docs/development/CANONICALIZATION_MATRIX.md`, `CURRENT_STATE.md`, `CATALOG_INVENTORY.md`

## Context

Three coexisting generations (Gen1 NetAuto stack, Gen2 MTF panel, Gen3 TunnelGuard) implement
overlapping subsystems with drifting catalogs (77/77/82), three failover FSMs, three port
allocators, three UIs. The goal is **one canonical architecture built from the strongest
proven part of each subsystem** — not the survival of one whole generation.

## Decision

Target layout (conceptual; exact names may follow existing conventions where compatible):

```
apps/
  api/        ← Gen1 FastAPI surface (auth, endpoints, composer, execution, admin, bot-control)
  web/        ← Gen2 v3 panel (root panel/ today) served by the canonical API
  bot/        ← Gen1 aiogram bot (rewired to canonical core only)

core/
  models/     ← Gen1 ORM + new canonical model (Node, Engine, Chain, Deployment, …)
  security/   ← Gen1 stack: argon2 + JWT + rate-limit + audit + Fernet secrets
  config/ events/

engines/
  manifests/  ← one manifest per engine/profile (JSON schema, validated — P3)
  adapters/   ← Gen3 adapter SDK (detect…rollback); bodies REUSE Gen1 deploy code (P5)

orchestrator/
  discovery/        ← Gen1 worker inventory
  compatibility/    ← new: manifest capability resolver
  planner/          ← new: safety planner + MTU/MSS (formulas from MTF core)
  composition/      ← new (P8): capability-driven chain builder
  resources/        ← Gen2 portmgr grown into full resource ledger
  deployment/       ← transactional lifecycle wrapping adapters
  verification/     ← Gen2 receipt model (data-plane evidence)
  benchmarking/     ← new (P6): QUICK/NORMAL/DEEP profiles
  scoring/          ← new (P7): 0–100 transparent weights
  failover/         ← Gen3 FSM + anti-flap
  reconciliation/   ← drift detection (new)

agent/              ← future optional node agent (SSH stays valid)
migrations/         ← Alembic (new; ends create_all()-only)
tests/              ← Gen3 discipline; tiers: unit_portable / linux_integration /
                     linux_privileged / real_node_e2e
deploy/  docs/  scripts/
```

## Method identity (P1.7)

- **Engine** = technology (wireguard, gre, gost, xray, frp, rathole, chisel, wstunnel,
  sing-box, waterwall, paqet, hedioum, hajsaman, ssh, openvpn, ipsec…).
- **Profile** = transport variant of one engine (gost: tcp_forward / udp_forward / grpc /
  quic / ws / h2 / kcp…; xray: vless_xhttp_reality…; frp: tcp/udp/…).
- The current 82 registry entries are **engine+profile combinations**, not 82 engines
  (see CATALOG_INVENTORY.md families: GOST 15, XRAY/VLESS 7+, FRP 6, CHISEL 6…).
- Canonical model keeps **stable immutable ids** for both levels:
  `engine_id` (e.g. `gost`) + `profile_id` (e.g. `grpc`), while **legacy method ids**
  (e.g. `GOST_GRPC`) remain addressable as compatibility aliases — no existing ID breaks.

## Migration rules (P1.5 — no big-bang)

```
working legacy component → adapter/compat layer → canonical interface → tests
  → migrate callers → tests → only then deprecate old implementation
```

- Gen1 stack keeps running (root install.sh) until each canonical subsystem passes
  equivalent-or-better tests.
- No file moves happen in P1; this ADR only fixes the target. Moves begin in P2 behind
  compatibility imports.

## Consequences

- One catalog (Gen2 format, superset), one resource manager (Gen2 portmgr base),
  one failover FSM (Gen3), one deploy body library (Gen1), one API (Gen1 surface),
  one UI (Gen2 v3), one test discipline (Gen3).
- `scheduler/` stub, `.netauto-master/`, triple UI assets, duplicate READMEs → REMOVE-LATER
  after callers migrate.
- Fastapi pin conflict (0.115.6 vs 0.116.1) resolves when the canonical `apps/api` keeps a
  single requirements set.
