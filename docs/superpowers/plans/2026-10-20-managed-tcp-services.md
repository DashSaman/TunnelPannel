# Managed TCP Services Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Owner/global rules permit at most one focused assistant per request; that read-only comparison assistant is already consumed. Implement and review directly; no additional delegation.

**Goal:** Add managed fixed-target TCP forwards over existing customer route groups without bypassing accounting or restarting original tunnels.

**Architecture:** A new source-node relay connects only to the existing authenticated loopback SOCKS gateway. Canonical scoped Job/Deployment/SecretReference records and resource journals own the forward; the original gateway remains the sole payload debit/shaping point. The public site remains a lightweight portal/proxy.

**Tech Stack:** Existing Python/FastAPI/Pydantic/SQLAlchemy/SQLite, stdlib asyncio, systemd, pinned SSH and vanilla branded FA/EN HTML/JS/CSS; no new runtime dependency.

**Spec:** [Owner-approved written specification](../specs/2026-10-20-managed-tcp-services.md). Owner explicitly approved the existing-route direction, written spec and this plan with direct execution in the current conversation.

## Global Constraints

- TCP only; one existing owned route group per service; no direct fallback or TCP session migration.
- No source/assets from the reference repo; no foreign installer or unverified engine binary.
- Reuse one existing route debit point; never double-charge or add a second monthly credit client.
- Default loopback, public exposure explicit, source CIDRs visible, ports unprivileged and exact.
- Preserve all current route configs/PIDs/member identities/interfaces/credentials and usage history; never replay accepted QA/migration helpers.
- All execution/probing on the two existing execution nodes; no site-host worker or unrelated container/proxy changes.
- Native GitHub exact SHA/tree/expected-head lease, successful immutable CI, main unmerged, heartbeat paused.

## Review Focus

1. IPv6 wildcard listeners and IPv4-mapped client addresses: reject conflicting binds and normalize ACL decisions (Tasks 1/3).
2. Lost apply response followed by API restart: observe/adopt exactly owned listener instead of reinstalling or clearing a foreign reservation (Task 3).
3. Parent stop, expiry or reconcile racing a new forward: reject stale admission and clean dependencies without rebuilding the parent (Tasks 3/4).
4. Exhaustion with concurrent direct SOCKS and forwarded traffic during controller outage: the existing credit ledger must debit once and fail closed (Task 2/6).
5. Half-close, slow clients and failed SOCKS authentication: bound sockets/timeouts, preserve bytes and never include secrets in responses/logs (Tasks 2/4).

## Command and file conventions

Work only in existing isolated `work/saas-source`, branch `codex/commercial-beta-20261016`.
Do not create/reset another worktree. Commands below run from that directory using
`rtk proxy ../mesh-venv/Scripts/python.exe -m pytest ...`;
the verified interpreter absolute path is
`C:/Users/amirreza/Documents/Codex/2026-10-13/https-github-com-dashsaman-tunnelpannel-https/work/mesh-venv/Scripts/python.exe`.
Use `rtk proxy` full failure output, not a generic test filter. In each task, a missing
module/function failure is the initial RED only, not the final regression assertion.
Commit only reviewed paths with per-command existing author identity; never change global Git config.

### Task 1: Scoped service model and strict admission

**Files:** Create `core/service_forwards.py`, `tests/unit/test_service_forwards.py`.
Reuse existing scoped `Job`, `Deployment`, `SecretReference`; no schema migration or second database.

**Interfaces:** `ForwardSpec` strict Pydantic model; `service_job(session, service_id) -> Job`;
`service_public(job) -> dict`; `normalize_forward(value: dict) -> dict`.
Model fields: name, route_id, bind_host, bind_port, target_host, target_port,
source_cidrs, allow_public; updates require expected_revision. IDs remain opaque32hex.

- [ ] Write RED tests for extra fields/bool ports/privileged ports, literal target addresses, public-without-ack/ACL rejection, mapped-v4 ACL normalization and escaped display-name output. Assert default bind `127.0.0.1`, no public secret fields.
- [ ] Run `tests/unit/test_service_forwards.py -q`; watch each intended validation assertion fail before implementation.
- [ ] Implement canonical normalization/public projection; keep route ownership, entitlement and active-count checks transactional in the service layer (Task 3), not trusted from a client workspace ID.
- [ ] Run the focused tests to PASS and `tests/unit/test_workspaces.py`; read exact failures, no guessed wildcard paths.
- [ ] Commit Task 1 model/tests and ledger actual RED/GREEN evidence.

### Task 2: Bounded source relay using the existing debit point

**Files:** Create `orchestrator/service_forward_runtime.py`, `tests/unit/test_service_forward_runtime.py`.
Consume first-party `orchestrator.mesh_gateway.socks_connect`; package a verified helper copy for the standalone runtime without changing old gateway files.

**Interfaces:** `validate_runtime(config: dict) -> dict`; `client_allowed(peer: str, cidrs: list[str]) -> bool`;
`ForwardRelay(config: dict)` with `start()`, `close()`, `snapshot()` and async `handle(reader, writer)`.
Runtime config has one local SOCKS upstream and one fixed destination, no caller-selected target.

- [ ] Write real-local-socket RED tests for exact binary payload both directions, EOF/half-close, client ACL, connection/idle bounds, failed SOCKS auth and no connection to the destination except through SOCKS.
- [ ] Add an existing Gateway+TrafficLedger fixture; assert direct SOCKS plus two relay requests produce exactly one combined authoritative debit. Repeat with a tiny shared cap and controller failure; assert no payload beyond allowed credit and no new relay ledger/client.
- [ ] Run `tests/unit/test_service_forward_runtime.py -q` to observe RED; implement bounded relay/CLI/private config and sanitized status only.
- [ ] Run that file plus `tests/unit/test_mesh_gateway.py`, `tests/unit/test_monthly_client.py` and `tests/unit/test_legacy_monthly.py`. Assert route-wide concurrency/rate still apply and close cancels all owned sockets.
- [ ] Commit runtime/tests with actual evidence. No remote process starts in this task.

### Task 3: Owned lifecycle, preflight and dependency cleanup

**Files:** Create `orchestrator/service_forwards.py`, `tests/unit/test_service_forward_lifecycle.py`;
modify `orchestrator/mesh_routes.py` only at explicit dependency-stop/reconcile hooks.
Reuse `host_lease.py`, `host_inventory.py`, `host_reservations.py`, `remote_journal.py` and `resources/__init__.py`.

**Interfaces:** `ServiceForwardService(routes, *, remote_factory=None)` methods
`preflight(factory, body, limits) -> dict`, `create(factory, body, limits) -> str`,
`update(factory, service_id, body, limits) -> str`, `stop(factory, service_id) -> None`,
`reconcile(factory, service_id, limits) -> None`, `observe(factory, service_id) -> dict`,
`stop_for_route(factory, route_id) -> None`.
`routes` is the existing RouteService; route hooks call dependency cleanup while already holding their route lease, avoiding recursive acquisition.

- [ ] Write RED tests for foreign/missing/nonlive routes, unpaid grandfathered route new-work rejection, workspace forward count `max_active_routes`, stale route/config-bound token, idempotent replay and simultaneous admits.
- [ ] Write lifecycle fault tests: exact occupied port/IPv4+IPv6 wildcard conflict; lost reply adopts same owned PID; private backup before forward-only update; foreign owner blocks cleanup; route-stop/expiry and reconcile race; ordinary route without forwards remains unchanged.
- [ ] Run focused lifecycle tests to RED, implement opaque short-lived preflight, consistent lock ordering (workspace admission, route, host) and durable ownership before dispatch. Freeze the workspace factory before starting a thread.
- [ ] Install only a new ID-scoped DynamicUser systemd relay with root-owned LoadCredential config and separate writable status directory. Use unprivileged ports, bounded runtime access and null/sanitized logs; no old gateway/user/key modification.
- [ ] Recheck exact port under host lease. Observe/adopt only matching service/config identity on recovery; never generic restart-on-startup. Stop owned forward dependencies before parent cleanup, retain metadata/history, and fail closed if cleanup cannot be proved.
- [ ] Run focused lifecycle tests plus existing route/accounting migration tests; assert original parent config hash/PID preserved for create/edit/delete/reconcile, and unaffected no-forward stop behavior. Commit with full fault results.

### Task 4: Authenticated API, recoverable operations and installation wiring

**Files:** Create `apps/api/service_forwards_api.py`, `tests/unit/test_service_forwards_api.py`;
modify `apps/api/main.py` recovery/wiring and `core/subscriptions.py:authorize_operation`
to keep only exact owned-service DELETE available after expiry, like existing owned-route stop;
consume the existing `orchestrator/operations_monitor.py:expire_workspace_routes` route-stop path through the new dependency hook, without broad refactoring.

**Interfaces:** `create_service_forwards_router(factory, service) -> APIRouter`, namespace `/api/mesh/services`.
Wire the same ServiceForwardService instance to the route dependency hook and background observation.

- [ ] Write RED API tests for VIEWER-read/OPERATOR-write, other workspace ID access denied, customer owner-namespace403, cookie missing-CSRF403, no-store, extra fields422 and plan-disabled/unpaid new-work rejection.
- [ ] Add tests for replay/stale expected_revision, API restart retaining the same operation/worker and no secret/runtime path/raw SSH error in public JSON. Assert parent route credentials and old policy/usage not changed.
- [ ] Run API tests to RED, implement thin strict routes and normal workspace/subscription guards; do not add a separate authentication system or new owner bypass.
- [ ] Run API/lifecycle, `tests/unit/test_workspaces.py` and `tests/unit/test_subscriptions.py`; prove existing customers and normal route cleanup still behave as before. Verify Linux systemd unit and packaged runtime helper presence through lifecycle fixtures.
- [ ] Commit Task 4 after PASS; do not deploy before Task 6 immutable CI and backups.

### Task 5: Branded FA/EN service workflow

**Files:** Create `apps/web/mesh-services.js`; modify `apps/web/mesh.html`, `apps/web/mesh.js`,
`apps/web/theme.css`, `scripts/container_web_gateway.py` asset list and `apps/web/web_api.py` exact asset whitelist.
Add focused package/static contract tests to `tests/unit/test_container_web_gateway.py`.

**Interfaces:** `renderServices(...)` and `bindServices(...)` use existing authenticated API helpers;
no browser-local persistent credentials. Form/copy handles loopback on source versus destination explicitly.

- [ ] Add a RED static/package regression proving the new JS is in the actual static bundle and whitelist, rather than a fixture-only view.
- [ ] Implement route-bound add/preflight/apply/status/edit/disable/delete views, inherited rate/quota/mode labels and an existing-user-inbound preset. Show source ACL/public exposure and forward-only edit interruption; no x-ui password/UUID extraction.
- [ ] Run package/static tests, JS syntax and CSS/diff checks. Use the browser testing skill/CUA for local isolated fixture FA/EN desktop/mobile/focus before live installation; mark fixture evidence as local.
- [ ] Commit UI changes; keep existing unrelated portal/site behavior and all private material outside Git.

### Task 6: Immutable CI, two-node acceptance and publication

**Files:** New inert ownership-checked helpers under ignored `work/` only; bilingual
`docs/MANAGED-TCP-SERVICES{,-fa}.md`, redacted installed JSON and actual screenshots under
`docs/evidence/commercial/`; current `AGENTS.md`, README and installer pin updated only after actual deployment.

- [ ] Run fresh full required portable suite/fatal Ruff/JS/package checks; publish immutable functional tree through PR2 using verified blob hashes/tree/parent/expected-head lease. Wait exact functional CI SUCCESS; never merge main.
- [ ] Read current activities on both execution APIs first; if busy, wait without cancellation/API restart. Capture current full original+retained QA config/PID/interface/service ownership and every customer policy/credential identity.
- [ ] Make fresh per-install resident encrypted backups with separate keys/env and decrypt/hash verification. Review helper locally and verify uploaded SHA before use; no legacy accepted helper replay or sensitive export.
- [ ] Upgrade execution APIs only after drained, preserving gateways/members/keys. Add only new loopback QA service listeners and owned payload origins on both sources; use actual customer session/API with plan admission. Keep all existing route PIDs/configs.
- [ ] Prove real receipts each direction, same-pool single debit across concurrent direct/forward traffic, forward-only restart durability and conflict refusal. A temporary QA-only cap must exhaust exactly; retain actual usage, restore100GiB SAMEperiod, then fresh receipt each source. No original quota/reset or deliberate original-path failure.
- [ ] Exercise failover in an isolated local gateway or separately owned new QA group with genuine entitlement; never fault either existing original or retained QA group. Record which environment proved each assertion.
- [ ] Clean only new forward/origin resources after owned-resource proof; keep source ledgers/audit and all pre-existing routes. Verify original full config/PID/identity/interface comparisons, short owned receipts and coexistence canaries; refresh encrypted rescue independently on both nodes.
- [ ] Back up the own static site container, preserve all unrelated containers/links/PIDs/nginx, replace only own bundle after functional acceptance. Verify actual public FA/EN/customer/owner/mobile with CUA and save inspected real photos.
- [ ] Publish bilingual real results and reviewed public files with credential exclusion; update PR2 final behavior/limits and verify final exact tree/lease/CI/main-unmerged/heartbeat-paused. Update private handoff COMPLETE only if all acceptance passed; disclose any remaining limitation.

## Inline plan self-review and execution handoff

All spec sections map to Tasks1–6; the five Review Focus cases have named owning tests.
No new engine/UDP/payment/SSO is smuggled into this plan. The API/controller/runtime
interfaces above agree on route_id/service_id/revision and the sole debit point.
Package paths must be verified against originals before editing; they are not inferred
from the external repo. Current original/retained routes must be freshly captured rather
than assuming any historical group count. Prior100GiB acceptance must not be replayed.

Recommended execution: **Native/direct in this existing session** because lifecycle,
accounting and auth interfaces are tightly connected. The single allowed assistant
was already used for source mapping, so direct documented review replaces an extra
review dispatch. Owner plan review and direct execution choice are complete; continue
through all tasks without requesting those approvals again.
