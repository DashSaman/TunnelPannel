# Tunnel expansion implementation plan

**Goal:** Add three real engines and source-node route traffic limits with an usable TehNet control panel.
**Architecture:** Extend existing canonical engine and gateway flows, isolate engine installation, retain historical workers untouched. Static website publishes reviewed assets only.
**Tech stack:** Python/asyncio/SQLite, Linux iproute2/systemd, official Backhaul and AmneziaWG, native HTML/CSS/JS.
**Spec:** ../specs/2026-10-19-tunnel-expansion-design.md
**Execution:** Direct implementation by the primary agent under the owner's explicit instruction to proceed.

## Tasks

- [ ] Add failing durable usage/rate/concurrency and policy validation tests. Implement standalone gateway ledger and shaping, API caps and old-worker refusal; verify focused tests.
- [ ] Add failing canonical engine family/config/ownership tests. Implement pinned Backhaul TCP, AmneziaWG and native4in6, registry/manifests/capabilities and persistent egress; verify focused tests and derived inventory.
- [ ] Complete TehNet staged setup, requirements and route usage controls in FA/EN, mobile and existing subpath. Verify DOM/browser and authorization.
- [ ] Run appropriate regression suite, publish exact tree to PR2, verify CI.
- [ ] Fresh drain/baseline/backups, reviewed helper upload hash, install execution nodes with existing workers/configs unchanged. Run new owned canonical campaigns and isolated traffic tests; remove only QA.
- [ ] Publish dedicated website static container, public UI acceptance; encrypted post backups and bilingual docs/evidence/AGENTS, verified final PR head. Keep main and heartbeat unchanged.

## Review focus

Native4in6 uses next-header4 on IPv6, unlike SIT's protocol41 on IPv4. Concurrent quotas must charge before awaits/forwarding. Old-worker acceptance must not silently promise enforcement. Failed node accounting cannot become unlimited. Route reconciliation must retain cumulative usage; tenant ceilings must never be client-overridable. Root copying of runtime cannot be prevented.
