# TehNet: Backhaul, AmneziaWG, native 4in6 and traffic controls

Installed on both execution nodes and the public website. See [actual acceptance and limits](TUNNEL-EXPANSION-VALIDATION.md): six paired outcomes passed, original routes preserved, source-node limits verified.

| Method | Actual carrier | Requirements | Encryption |
|---|---|---|---|
| BACKHAUL_TCP | Official Backhaul v0.7.2 reverse TCP | Peer-reachable TCP; private local payload listener | None; token authentication only |
| AMNEZIAWG | Official userspace AmneziaWG pinned b5928efb6ca19f0153958460c3d141f04abc5c2e | Linux root, TUN, UDP; isolated source preparation | ChaCha20-Poly1305; configured junk/padding/header values |
| IP4IN6 | Linux ip6tnl, mode ipip6 | Real IPv6 endpoints, next-header4, IPv4 payload | None |

4in6 is distinct from existing SIT/6in4 and IP6GRE. Matching foreign keyless carriers are rejected. Proven-owned carriers share references; deleting a QA member cannot remove another member. No default route, global forwarding, BBR/fq or operator binary is changed. Backhaul uses skip_optz=true, sniffer=false and web_port=0. Official binary archives are SHA256 pinned. AmneziaWG builds single-threaded with a pinned, digest-verified private Go toolchain and source commit. Preparation is excluded from performance measurement.

Build preparation retains at least 128 MiB of then-available host memory, requires at least 256 MiB available, and caps its own transient cgroup memory, existing swap use and CPU. It never creates swap or changes host memory settings. For matching architectures, a verified engine is built once on the roomier execution node and transferred over pinned SSH with source and binary-hash checks; the smaller peer does not compile it. Insufficient resources or unsupported cgroups block preparation rather than consuming unbounded host memory.

## Traffic policy

Route creation accepts `traffic: {rate_mbps, quota_bytes, max_connections}`. Active v1 workers accept `PUT /api/mesh/routes/{id}/traffic`; requests remain workspace/role scoped. Zero rate/allowance uses the workspace/plan ceiling. Owner caps are `max_route_mbps`, `max_route_bytes`, `max_route_connections`. They are per-route ceilings, not a pooled monthly customer allowance. Existing commercial limits and paid admission remain independent; offline payment receipts do not reset traffic counters.

The source worker shapes combined upload/download payload across every route member and connection. The SQLite ledger debits before forwarding with synchronous durable transactions, persists under `/var/lib/tunnelpannel/route-usage`, and survives worker restart/reconciliation. Usage means payload accepted for forwarding, including data subsequently lost on connection failure; it excludes SOCKS negotiation and independent health probes. Concurrent debit cannot exceed the allowance. Editing/raising limits never clears use. Corrupt/unavailable accounting fails closed. Usage is not link-layer bytes, target acknowledgements or an ISP invoice.

Historical workers expose no v1 accounting capability. The UI labels them and the API refuses unsupported traffic edits. This release does not restart/rewrite existing groups. Explicit reconciliation can activate the new gateway, but interrupts existing TCP sessions; do it only when the owner chooses. New plan/customer ceilings apply when creating, changing traffic policy or reconciling a route; they do not silently rewrite historical live workers. Counters must be backed up independently on the node where they live; the earlier canonical DB backup does not include a remote node's accounting ledger.

## Panel

The FA/EN responsive TehNet surface provides Servers → Measure → Results → Routes & usage navigation, a dedicated new-engine filter, requirement cards and collapsed advanced controls. Set defaults for new routes under Results. For a v1 active route, inspect upload/download/combined GiB, then edit rate/allowance/concurrency under its traffic controls. Zero means the plan ceiling. Owner users/plans/quota/manual payment controls remain under the public Portal administration section. No gateway payment integration or SSO is introduced. Website hosting contains only static UI and proxy; builds, state, usage enforcement and traffic remain on execution nodes.

## Upstream licences / provenance

Independent panel UI; no Arange code/CSS/assets imported. Backhaul: [official pinned source and licence](https://github.com/Musixal/Backhaul/tree/df7966f8f725837a680ea7b90bd37ea52666c277). AmneziaWG: [official pinned source and licence](https://github.com/amnezia-vpn/amneziawg-go/tree/b5928efb6ca19f0153958460c3d141f04abc5c2e). Their source and licence notices remain in the upstream distributions/build source. Linux kernel/iproute2 are supplied by the host distribution. No benchmark result proves throughput or DPI behaviour on an unmeasured Iran path. Root operators can inspect runtime material; copy prevention is not promised.
