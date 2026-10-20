# Shared monthly allowance implementation plan

**Goal:** Administrator-managed customer periods with one safe payload allowance across every participating route/node.

**Architecture:** Controller-side durable credit reservations; route-scoped HTTPS clients with atomic local debit and fenced credit return. Preserve every existing live worker/configuration.

**Tech stack:** Existing FastAPI/Pydantic/SQLite, standalone Python stdlib gateway, current FA/EN frontend.

**Spec:** ../specs/2026-10-19-shared-monthly-design.md

## Constraints and review focus

Manual grants, default30days with explicit end; customer workspace is the pool. No private exports or existing-worker mutation. One read-only transport mapping assistant already completed; implement directly. Main unmerged and heartbeat PAUSED. Audit retries, cross-tenant tokens, pending-response crashes, early refunds, expired/offline leases and exact double-entry local debit.

## Tasks

- [ ] RED/GREEN central `core/monthly_usage.py`: period revisions/history, atomic reservation/status/report, idempotence, quota bound, route-scoped credential/revocation, corruption/expiry. Tests `tests/unit/test_monthly_usage.py` include concurrent two-node simulations and lost-response replay.
- [ ] RED/GREEN standalone `orchestrator/monthly_client.py` plus gateway: durable pending requests/credit, online recovery, lease expiry, idle fenced return, same-transaction route/credit debit and usage state. Tests prove exact payload cap and restart/offline behavior.
- [ ] Wire owner/customer APIs, bounded private callback, route admission/deployment/owned stop. Add positive/negative authorization and historical coverage tests; refuse incomplete monthly configuration before changing remote resources.
- [ ] Add administrator period/ceiling/history UI and customer usage/held/balance display in FA/EN. Verify actual browser flows/mobile; keep account credentials untouched.
- [ ] Fresh appropriate regression checks, immutable publication/CI, fresh drained baseline/resident backups, reviewed helper upgrade of own APIs only. Create independent same-customer opposite-source routes on the two test nodes; exercise shared cap, restart/top-up/credit return/expiry and clean only QA.
- [ ] Publish website static container; authenticate/read owner/customer; encrypt fresh resident after backups and document exact tests/limitations. Final tree/lease/CI/PR2 proof and owner handoff; preserve originals and main.
