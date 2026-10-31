# Mesh release validation — 2026-10-16

> Historical transport release report. The current installed commercial runtime and installer pin are documented in [Commercial acceptance](COMMERCIAL-VALIDATION.md).

[فارسی](MESH-VALIDATION-fa.md) · [Panel manual](PANEL-GUIDE-fa.md) · [Workflow/API](MESH.md) · [Public evidence index](evidence/mesh/INDEX.md)

This historical transport release used `a115027e357f5ea5ce279445e40a678a06949c5b`. Both disposable Ubuntu 24.04.4 amd64 servers passed installation acceptance at that revision. The [current installer](../install-one-line.txt) now pins the later commercial beta described above; the transport evidence below retains its original revisions.

Physical scope: two nearby Hetzner HEL1 machines, labelled A and B in the matrix. These results do not establish Iran connectivity, intercontinental performance, arbitrary NAT traversal, a three-server physical path, every Linux distribution, or production SaaS/payment readiness.

## What was delivered

- Isolated customer databases, hashed scoped keys, encrypted SSH/runtime credentials, owner-managed quotas and access.
- Directed all-pairs campaigns, history, cancellation and restart cleanup; receipt-qualified recommendations prefer distinct outer carriers before remaining quality rank.
- Five default warm members per route when enough qualify, custom order and larger selections within quota; independent simultaneous destination groups.
- Stable authenticated loopback TCP SOCKS entry, actual nonce probes, failover, healthy manual pin, and quality-weighted least-active-connections sharing.
- Persian/English Mesh UI, authenticated single-pair ranking, and authenticated Topology planning. Topology saves edges and planned paths; it does not install a physical multi-hop network.
- Catalog: 108 identities (91 profiles + 17 explicit compositions), 21 technology families and 6 additional aliases. The original 82 are preserved and 26 identities added. [Source review](MESH-SOURCES.md) covers all 33 accessible owner repositories; t4 is PBX and t6's WG/SIT concept overlaps the existing implementation. An arbitrary protocol pairing is not supported merely because both names exist.

## Physical campaign and targeted follow-ups

| Evidence | Result | Scope |
|---|---|---|
| Campaign `716cd920944b498f8761e95a1638a0ac` | **216/216 NORMAL PASS** | 108 identities A→B and B→A, actual paired setup, traffic, recovery and cleanup |
| XFRM/VTI follow-up `08de697d549f4be0af5152cb9d8dc945` | **6/6 PASS** | IKEV2_IPSEC, VTI and VTI6, both directions |
| Kernel/composition follow-up `723d39050d6f4fbfa2aba9c3387012b5` | **18/18 NORMAL PASS** | GRE, GRETAP, IP6GRETAP, GRE/GRETAP/IPIP/SIT over WireGuard, HAJSAMAN_WG and HAJSAMAN_FULL |
| Existing dotted GRE-key exclusion | PASS | Real iproute key `80.136.25.200` excluded as packed 32-bit value; proof interface and allocations cleaned |

The complete campaign preceded the final shared-carrier corrections. Affected methods were rechecked with the 18-candidate follow-up at `eb3f1bf0`; the final dotted-key allocator correction and installed lifecycle were checked at `a115027e`. This is not a claim that all 216 candidates were rerun at every subsequent commit.

Each direction had 98 methods eligible for persistent TCP egress and 10 exclusions. A successful benchmark is not automatically a supported persistent TCP adapter. The public [matrix](evidence/mesh/public-campaign-matrix.json) retains each method's status, safe measured metrics and the SHA-256 of its private ownership receipt; private deployment secrets and full runtime artifacts are excluded. These hashes identify retained receipts, not an independent network attestation.

Original recommendations:
- A→B: IP6GRE, VXLAN, HAJSAMAN_SIT, IPIP, IKEV2_IPSEC.
- B→A: IP6GRE, SIT_6IN4, VXLAN, IPIP, IKEV2_IPSEC.

The original 23 partial and 27 failed isolated-lab methods were the historical remediation baseline, not remaining current failures. The [82-method RC3 report](releases/v0.9.0-rc3/REAL_BENCHMARK.md) preserves that work and its failed attempts separately.

## Persistent groups and connection sharing

The [balancing drill](evidence/mesh/balancing-latest.json) used two simultaneous five-member groups at the shared-carrier revision `cf676eab`. It verified destination public exits, manual pins, a real stopped member, the other group's continued operation, gateway restart, restored health, unchanged management routes and exact owned cleanup.

There were 12 comparison rounds: three failover and three balance rounds per direction, eight independent 64 MiB TCP streams per round. Including simultaneous-direction, failure and pin checks, **128/128 streams passed SHA-256 integrity: 8 GiB total**.

| Direction | Failover mean, Mbps | Balance mean, Mbps | Change |
|---|---:|---:|---:|
| A→B | 1370.370 | 1405.211 | +2.54% |
| B→A | 1401.621 | 1183.837 | −15.54% |

These are three sequential samples per mode on one nearby pair, not a controlled statistical speed claim. Sharing was faster in one direction and slower in the other. It distributes separate TCP connections, **not packets of one TCP connection**. Bandwidth, CPU and shared carriers can remain the bottleneck.

The stopped IP6GRE member was excluded after 21.502 seconds and received zero new measured streams. Its durable reservations remained held. Healthy manual pinning sent all four test streams to the chosen IKEV2_IPSEC member in each direction. An earlier [five-member failover drill](evidence/mesh/five-member-failover-drill-latest.json) measured switches of 21.424, 20.821, 20.927 and 20.928 seconds through an unchanged authenticated entry.

Later the actual UI rebuilt A→B as **seven members**: SSH_REMOTE_FORWARD, IPIP, SIT_6IN4, WIREGUARD, GOST_SOCKS5, WATERWALL_H_HTTP2_TLS and VMESS_TCP_TLS. [Reconciliation](evidence/mesh/custom-seven-reconcile.json) preserved entry host, port, username and password. The reverse five-member group remained healthy. Final [installed acceptance](evidence/mesh/final-installed-acceptance.json) observed all 7+5 members healthy. The throughput table describes the preceding 5+5 drill, not a seven-member throughput test.

Existing TCP sessions reconnect after a failed engine. Five protocols to one destination do not survive that destination's complete outage. Independent controllers must not concurrently manage the same physical host.

## Transport, ownership and customer checks

- WaterWall-H source `613bb32c93db40b09cb915070e5f7ff09ad3c81d`, patch `ca1-h2drain3`: eight wrong-CA negative checks; 24 verified 64 MiB downloads and 24 uploads across four profiles and both directions. CA/hostname verification remains enabled. H2 upload memory stayed around 30 MiB after bounded flow-control fixes. Empty source/build cache compilation passed in **567.976 s**; an earlier 16.471 s build reused source/build state and is not the cold-build evidence.
- VMess TCP/WS TLS, AnyTLS and ShadowTLS3+SS2022 passed eight directional candidates. Naive leaf-certificate/client-option fixes and SIT-over-WireGuard correction passed four targeted candidates; other new compositions passed 20 candidates. These are staged validation records, not extra independent identities added to the 108-method count.
- [IPv4/IPv6 owned firewall lifecycle](evidence/mesh/owned-firewall-lifecycle.json): allow → blocked while owned allow stopped → allow after restart; prior effective rules preserved and 11 proof allocations released.
- [Workspace lifecycle](evidence/mesh/workspace-lifecycle.json): owner isolation, independent databases, key rotation/revocation, entitlement changes, quota rejection before SSH, online backup restoration with decryptable credentials, tamper rejection and disabled-key rejection.
- Root-owned stopped-member reservations persist. Shared keyless GRE/IP6GRE/IPIP/SIT carriers retain per-member references and are removed only by the last owned reference. Foreign resources and malformed books fail closed.
- Real browser checks covered clean onboarding, cleared password fields, history, bidirectional progress, Persian/English, mobile 390×844 without horizontal overflow, mode/pin/reconcile controls and authenticated Topology add/search/reload/logout. Saved Topology paths remain explicitly PLANNED.

## Installed lifecycle and software checks

Both machines use the canonical unprivileged `tunnelpannel-api` service, loopback port 8080 and their own existing encryption key and credentials. A's databases were migrated on A with A's key; they were not copied to B.

The final installed acceptance verifies A's pinned upgrade and idempotent second install, preserved identity/history/warm workers, and a native backup with three workspaces and two real SSH credentials successfully decrypted and connected under A's key. B's [installed lifecycle](evidence/mesh/installed-lifecycle-final-b.json) verifies upgrade, second install, backup/mutate/restore, uninstall/reinstall and preservation of unrelated interfaces and A-managed remote engine units. The private backup excludes the installation key; its SHA-256 is recorded in the sanitized report. Backups and environment secrets are not repository artifacts.

At the immutable functional revision:
- **643 canonical + 100 TunnelGuard + 1 backend tests passed separately on both Python 3.11 and 3.12.**
- Canonical Ruff, catalog invariants, ShellCheck, Bash syntax and Linux fresh/idempotent install, health, backup/restore and safe uninstall passed.
- [Portable/install CI](https://github.com/DashSaman/TunnelPannel/actions/runs/38914599544) and [security CI](https://github.com/DashSaman/TunnelPannel/actions/runs/38914599641) succeeded. Counts were read from decoded job logs. [CI metadata](evidence/mesh/ci-summary.json) keeps software and physical results separate.
- The latest disposable-host software run also returned exit 0 for all three suites.

## Retained failures and corrections

| Observed failure | Correction / verification |
|---|---|
| Two differently named keyless IP6GRE carriers to the same outer endpoints produced 100% reverse inner-ping loss | Shared owned carrier with per-member addresses/routes and explicit preferred source; real simultaneous groups and follow-up passed |
| Shared carrier wildcard endpoint and missing alias | Normalize iproute's `any`, set alias explicitly, verify boot/ifindex/owner before cleanup |
| Rebuilding a group allowed a new SSH member to consume stable entry port 22000 | Reserve entry before member allocations; seven-member UI rebuild preserved exact entry |
| Existing GRE key rendered as dotted IPv4 was missed by allocation | Decode packed 32-bit key; three regressions and real occupied-key proof |
| WaterWall-H H2 queued EOF data lost / unbounded upload memory | Drain queued data and apply bounded flow control; strict TLS and large transfers passed; initial failure/OOM retained |
| Naive client rejected certificate/options; SIT-over-WireGuard recipe failed | Correct leaf certificate/options and carrier setup; targeted reruns passed |
| Raw iptables-save comparison failed on counters/empty default tables | Compare effective rules/order/policy; earlier failed comparison retained |
| Initial canonical SSH credential refresh used the wrong credential field | Store `auth_method: PASSWORD` with encrypted `secret`; both real nodes verified before successful installed backup acceptance |
| Topology lacked scoped login and crashed after saved-path reload | Memory-only key, scoped requests, session-response guard, explicit forms and edge-derived paths; browser checks and software CI passed |

Failed attempts were not relabelled as successful. The matrix, follow-ups and the initial historical reports describe different runs.

## Operation and remaining product scope

Use the [complete Persian guide](PANEL-GUIDE-fa.md) for every page, criteria, errors, roles, installation, maintenance and backup. Keep the environment/encryption key private and paired with the databases. Restoring a registry restores old key hashes, so review access and rotate keys again if necessary.

The owner APIs are a foundation for future subscriptions. Public signup, payment collection/webhooks, domain/TLS ingress and automatic subscription enforcement are not connected. API-key disable does not stop already running systemd routes. Select encrypted protocols when confidentiality is required; GRE/IPIP/SIT/VXLAN alone add no encryption.

The desktop preview is an SSH forwarding session; it is not a public hosted endpoint. Reconnect it from your own computer when needed:

```sh
ssh -N -L 8080:127.0.0.1:8080 root@YOUR_PANEL_SERVER
```

Then open `http://127.0.0.1:8080/mesh`. Fresh installations display role tokens once; existing installations retain their hashes. Neither an accessible login page nor a listening socket proves that a measured tunnel is healthy.
