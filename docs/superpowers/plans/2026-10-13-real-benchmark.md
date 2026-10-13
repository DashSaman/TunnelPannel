# Real panel benchmark and profile remediation implementation plan

**Goal:** Start real two-node benchmarks in the canonical panel, repair the 50 failed/partial legacy profiles, test both supplied disposable nodes, and publish a pinned one-line installation.

**Architecture:** Keep canonical jobs, results, RBAC and ownership as the public contract. Reuse and repair the existing two-endpoint deployment bodies in `plan_executor/executor.py` through a bounded pair adapter rather than rerun local loopback probes. Store node credentials encrypted with the install secret and require a pinned host key. Each candidate gets unique owned resources, actual traffic probes, measured metrics, and teardown; failures remain failures.

**Constraints:** Only the two user-supplied nodes. No credentials in source/logs/reports. Preserve management routes and unowned resources. Two nodes prove a two-node route, not a three-node path. Use the port manager, actual IPv4/IPv6 capability and bounded profiles. No upstream protocol substitution disguised as the named method.

## Tasks

- [x] Decouple deployment body imports from legacy Redis/PostgreSQL startup; regressions for import without legacy services and explicit host-key checks.
- [x] Add encrypted node registration, capability discovery and backend role enforcement. Connect request-scoped real pair factories to the canonical runner. Record actual node IDs, job-isolated results and scores; bounded cancellation/cleanup and active-node serialization.
- [x] Add panel node/auth controls, real errors and progress. Prove a browser-started real benchmark with data-plane receipts on the two nodes.
- [x] Repair shared SSH and IPv6/IPsec/VPN deployment and probe defects using the previous per-method error receipts. Verify actual traffic and teardown for each profile.
- [x] Repair GOST/FRP/Rathole/Xray/sing-box configuration and probes against installed binary versions. Verify each named transport and composite path with positive traffic and negative outage checks.
- [x] Implement genuine WaterWall/Paqet/Hedioum/HajSaman paths; verify named profiles rather than aliases or binary-help smoke. If upstream lacks a named protocol, preserve truthful unsupported status and document evidence instead of claiming success.
- [ ] Run complete software suites, real-node per-method matrix and fresh/repeated installer lifecycle. Publish bilingual measured documentation, CI-green reviewed candidate, ZIP/checksums and pinned installer. Remove test-only credentials/resources; preserve application node registration for operator use.

## Review focus

Wrong SSH host key; viewer attempting network mutation; forged client capabilities; concurrent jobs on the same nodes; partial configure failure before an artifact is returned; cleanup failure; SSH control timeout; cancellation during setup; proxy requests bypassing the tunnel; carrier success mislabeled as composite success.
