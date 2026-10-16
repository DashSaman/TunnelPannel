# Commercial beta implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the two-server-testable product and operations foundation for a closed commercial beta.

**Architecture:** Add narrow registry-backed identity/subscription services around the existing workspace boundary; preserve the canonical paired executor and durable ownership model. Add bounded campaign admission/quality policies, opt-in operation history, a self-contained portal and an optional mutually authenticated telemetry service.

**Tech Stack:** Existing Python/FastAPI/SQLite/SQLAlchemy/cryptography/Paramiko, standard-library scrypt/TOTP, local vanilla HTML/CSS/JS, systemd. No new external paid service or CDN.

**Spec:** ../specs/2026-10-16-commercial-beta.md

## Global constraints

- Preserve existing releases, data, keys, management connectivity and warm groups.
- No credentials belong in tracked files, screenshots or support exports.
- Only 65.109.209.194 and 65.109.213.64 are authorized physical targets in this continuation.
- Existing API keys remain compatible. TCP SOCKS remains explicit; no fabricated Iran, payment, multi-destination hardware, seven-day or bonding outcome.
- User requested continuous execution inline. One read-only mapping assistant already used; no additional assistants or recursive delegation.

## Review focus

- Cookie session must never substitute a tenant/account from an untrusted body/header or bypass a role, disabled workspace, CSRF or subscription gate.
- Concurrent duplicate/stale billing events and campaign requests must not grant duplicate access or overspend a quota.
- Expired access must still permit read/export/stop while optional expiry cleanup touches only the opted-in tenant's routes.
- Support exports, validation errors, snapshots and screenshots must not reveal credential-bearing fields.
- Credential/agent rotation, restart and cleanup must preserve foreign keys/resources and both existing independent installations.

### Task1: Accounts, invitation sessions and TOTP
Files: core/accounts.py, apps/api/accounts_api.py, core/workspaces.py, core/security.py, apps/api/main.py, tests/unit/test_accounts.py.
Interfaces: AccountStore(registry), create_invite(workspace_id,role,ttl), accept_invite(token,email,password), login(email,password,otp), authenticate_session(token), logout(token), scope_for(workspace_id). Middleware sets the same scoped principal for sessions and bearer keys; state-changing cookie requests require CSRF.
- [x] RED: invite expiry/reuse, scrypt verification, scoped cookie/role/CSRF/logout/disabled workspace; TOTP RFC vectors/replay/recovery and throttling.
- [x] Implement minimal registry schema/services/routes and integration.
- [x] GREEN: focused tests; full canonical suite under correct platform harness; commit and ledger.633 PASS/21 platform skips; Ruff PASS. Physical acceptance remains Task7.

### Task2: Plan entitlements and signed sandbox billing
Files: core/subscriptions.py, apps/api/billing_api.py, core/workspaces.py, apps/api/main.py, tests/unit/test_subscriptions.py.
Interfaces: SubscriptionStore(registry).status(workspace_id), apply_event(raw,timestamp,signature), effective_limits(workspace_id,base), authorize_operation(workspace_id,method,path), due_expiry_actions(). Default no-subscription compatibility; sandbox labelled.
- [x] RED: duplicate/id collision/stale revision/tamper/skew, grace transitions, scoped caps, read/stop allowed after expiry and explicit scoped opt-in cleanup candidates. Actual cleanup integration remains Task4.
- [x] Implement catalog/status/owner management and signed test adapter, with no actual charge.
- [x] GREEN: focused plus boundary regressions; commit and ledger.642 PASS/21 platform skips; Ruff PASS. Input/HTTPS edge regressions also passed.

### Task3: Estimates, bounded queue, objectives and explanations
Files: orchestrator/campaign_budget.py, orchestrator/mesh_campaign.py, orchestrator/mesh_service.py, apps/api/mesh_api.py, core/workspaces.py, tests/unit/test_campaign_budget.py.
Interfaces: estimate_campaign(...), reserve_campaign_units(session,...), objective_rank(rows,objective), bounded worker claims. Extend campaign request with selected directions/objective and optional receipt-matched estimate confirmation.
- [x] RED: hand-derived2node108=216 and10node108=9720 units, concurrent admission, stale estimates/foreign nodes, worker slots, objective order and unchanged qualification/diversity.
- [x] Implement estimate endpoint/admission accounting and explicit duration uncertainty; objective-aware recommendation persistence and durable bounded standalone/mesh workers.
- [x] GREEN: focused/legacy campaign tests and full suite656 PASS/21 platform skips; checkpoint commit and ledger. Actual worker restart acceptance remains Task7.

### Task4: Operational history, support export and monitoring
Files: core/operations.py, orchestrator/operations_monitor.py, apps/api/operations_api.py, apps/api/main.py, tests/unit/test_operations.py.
Interfaces: record_observation(workspace,route,snapshot), tenant_summary(...), support_export(...), monitor.tick(). Store bounded snapshots/events; monitor disabled until opt-in. Owned cleanup expiry integration uses RouteService.
- [x] RED: secret canaries, cross-tenant isolation, unavailable sample distinction, transition deduplication/retention and no repeated cleanup after restart.
- [x] Implement allowlisted support/history endpoints and durable opt-in monitoring integrated into existing recovery lifecycle.
- [x] GREEN: focused operations/workspace/billing and migration tests; checkpoint commit and ledger. Physical history/expiry acceptance remains Task7.

### Task5: Dedicated SSH credential lifecycle and restricted telemetry
Files: orchestrator/node_keys.py, core/agent_identity.py, apps/api/agent_api.py, agent/telemetry.py, agent/hub.py, scripts/agent-install.sh, apps/api/nodes_api.py, tests/unit/test_node_keys.py, tests/unit/test_telemetry_agent.py.
Interfaces: provision_managed_key(factory,node_id), rotate/revoke exact owned key, issue/revoke_node_certificate(...), accept_telemetry(cert_identity,nonce,body). Agent accepts no arbitrary command payload.
- [x] RED: exact foreign-key/collision/rollback preservation, cert wrong tenant/revoked/replay/malformed report; POSIX no-follow test added (runs on Linux).
- [x] Implement owned bootstrap/key lifecycle and optional unprivileged typed telemetry services/install/revoke; real local mutual TLS verified.
- [ ] GREEN: portable checkpoint665 PASS/22 Windows skips, lint PASS; actual pair key/TLS/restart/revoke/cleanup remains Task7. Commit and ledger checkpoint only.

### Task6: Guided customer/owner UI and product clarity
Files: apps/web/portal.html, apps/web/portal.js, apps/web/portal.css, apps/web/web_api.py, apps/web/mesh.html, apps/web/ranking.html, apps/web/topology.html, tests/unit/test_portal_api.py.
Interfaces: session login/invite/MFA/logout; owner invitation/plans/usage; customer wizard/estimate/objective/history/support with existing Mesh route controls. All pages can use a scoped cookie+CSRF; bearer login remains.
- [x] RED: portal route/static assets/session integration and authorization outcomes at API boundaries (no source-string tests).
- [x] Implement local assets, Persian/English RTL/LTR responsive controls, DOM text rendering and memory-only access, sandbox/TCP limits visible.
- [ ] GREEN: local browser customer/owner/session continuity/plan/logout and390px verified; API gates PASS. Actual server onboarding/budget/export and final UI shots remain Task7. Local software checkpoint committed separately.

### Task7: Two-server acceptance, docs and publication
Files: scripts/commercial_acceptance.py, docs/COMMERCIAL-BETA.md, docs/COMMERCIAL-BETA-fa.md, docs/evidence/commercial/, README.md, README.fa.md, AGENTS.md, docs/development/COMMERCIAL_LEDGER.md, install-one-line.txt.
- [ ] Run isolated actual beta-tenant lifecycle and representative paired data/restart checks, preserve existing7+5 groups; record every failure and fix.
- [ ] Test installed upgrade/idempotence/backup/restore with new account/billing tables and both independent keys; full canonical/TunnelGuard/backend suites, Ruff/catalog/shell and CI.
- [ ] Review full relevant diff, verify native Git blobs/commit/tree, publish without credentials, validate pinned installation and final UI; update bilingual docs/screenshots/report with honest scope.
- [ ] Report only verified outcomes. If long-term monitoring is running, label elapsed time and remaining duration explicitly.
