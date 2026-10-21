# Arange-tun comparison — 2026-10-19

[فارسی](ARANGE-COMPARISON-20261019-fa.md)

The owner requested a design/capability comparison to improve the paid TehNet
tunnel service. This is a **source review and prioritised backlog**, not a new
engine installation or a performance comparison. Existing site/container,
customers, keys and live tunnels were not changed for this review.

Reviewed upstream: [MAHDI-byte64/Arange-tun](https://github.com/MAHDI-byte64/Arange-tun)
at immutable revision `f10849338e2b9182f041c5ea14d4d07557925e66`,
tree `c3be3146ba3468c61b9168f2e2a14b43c3562abe`. Twenty-nine selected source/docs
files were downloaded for private review and each Git blob SHA was verified.
The local comparison baseline is TunnelPannel revision
`8cf24d31dff9ebe471b958255e7604cec3a8218c`; initial installed commercial runtime was e85; the previously pending97 follow-up was installed and accepted after this comparison, as recorded below.

## What 6in4, 4in6 and 6to4 mean here

| Capability | TunnelPannel evidence | Result |
|---|---|---|
| Configured IPv6 inside IPv4, SIT/6in4 | `SIT_6IN4` in the canonical registry, SIT adapter and real `deploy_kernel()` body using `mode sit`; inner IPv6/outer IPv4 checks | Implemented; not a missing engine |
| Existing installed SIT transport | [Previous installed evidence](evidence/commercial/waterwall-gateway-installed.json): current warm group includes `SIT_6IN4`, two nonce receipts recorded | Historical physical evidence, not a fresh test in this review |
| SIT compositions | `SIT_OVER_SSH`, `SIT_OVER_GOST`, `SIT_OVER_WIREGUARD`; `HAJSAMAN_SIT`/`HAJSAMAN_WG` | Present; each has its own constraints and receipt history |
| IPv4 carried over IPv6 using GRE | `IP6GRE` body uses `ip -6 tunnel ... mode ip6gre`, accepts an IPv4 inner prefix; retained warm group/receipts | Present, with GRE encapsulation |
| Native 4in6 without GRE (`ip6tnl`/`ipip6`) | No independent canonical method or deploy branch found; inventory merely recognises existing `ip6tnl` interfaces | A real adapter gap; detection is not deployment support |
| Automatic/anycast 6to4 | Not the same thing as a configured SIT pair | Do not add a duplicate label and claim support |

The deprecated part in [RFC7526](https://datatracker.ietf.org/doc/html/rfc7526)
is **6to4 anycast relay operation**. It does not make every configured
IPv6-over-IPv4 SIT pair obsolete. Native 4in6 would need public IPv6 reachability,
address-family checks, owned interface/firewall/routes, MTU/PMTUD handling,
rollback, restart recovery and real transfer receipts before admission.

The previous fix97 removes an unnecessarily broad forwarding guard for
host-local HajSaman SIT/WG. Its CI completed successfully during this review,
so the already-authorised follow-up was installed on both execution nodes after
fresh backup/drain checks. New paired campaign257d3f9b7f9c43d198f99fdfde993bf7
passed4/4 with receipts, recovery and cleanup;12 coexistence canaries passed per
node. FULL still refuses a disabled global-forwarding change. Existing workers
were preserved. This is acceptance of our adapter fix, not an Arange installation.


## Transport and operations gaps

| Arange capability | Current TehNet equivalent | Assessment / action |
|---|---|---|
| Built-in Backhaul TCP/Mux/UDP/KCP/QUIC/WS/WSS, Noise/Stealth variants | Similar transports exist in GOST/FRP/Xray, but no Backhaul engine identity or adapter | **Missing engine**; create a version-pinned, isolated adapter, not an alias to a different protocol |
| AmneziaWG userspace client/config parameters | Standard WireGuard and HajSaman WG exist; no AWG adapter/config fields found | **Missing extension**; plain WG is not AWG; validate supported config versions separately |
| FRP and Rathole v2 | FRP six profiles, Rathole five profiles | Family coverage exists; upstream Go reimplementations and obfuscation wrapping are not assumed wire-compatible or identical to ours |
| Packet raw TCP/KCP engine | `PAQET_RAW_KCP` and `PAQET_SOCKS5` | Comparable family exists; do not count a renamed embedded engine as a new verified transport |
| Hedioum pooled camouflaged egress | Native pinned Hedioum pool profiles, mixed mode and TUN | Substantial overlap; our current recipe fixes several knobs instead of exposing their complete tuning UI |
| xDi/ICMP, IP Spoofing and TCP+PCK variants | No canonical identities for these specific carriers | Experimental backlog; provider/path suitability and independent two-node proof required; README DPI claims are not our measurements |
| Per-tunnel throughput and connection caps | Warm gateway has a default connection ceiling; no per-route bandwidth field in the current route API/console | **Product gap**; configurable caps must reach actual forwarding, not just billing metadata |
| Real client IP via PROXY Protocol v2 | No matching end-to-end route option found | **Missing feature** for suitable reverse TCP backends; explicit backend support and opt-in required |
| Persistent per-tunnel bytes/connections and KCP FEC/retransmit metrics | Route health/latency history, benchmark metrics and optional Prometheus exist | **Partial**; add durable data-plane counters with reset semantics; host traffic is not billable per-customer traffic |
| Node-local watchdog and update/edit rollback | Our local gateway probes/reselection, systemd services, explicit reconcile, owned rollback and backups | Partial overlap; verified loss-of-connectivity restart with hysteresis and visible safe rollback needs a unified operator flow |
| Telegram configuration and alerts | Canonical bot core and alert logic already exist | Not absent; parity of settings UX and actual alert delivery was not validated in this review |
| Multi-address balance/failover | Independent per-destination warm groups with quality-weighted new-connection sharing | Different semantics: their documented backup addresses must reach the same server; preserve our independent destination groups |
| Dashboard PWA, per-engine guides and details/control dialogs | Branded FA/EN portal, owner tabs, mesh/topology/ranking | UI discovery and navigation gap; retain our account/quota/payment flows and execution boundaries |

Source references: [transport guide](https://github.com/MAHDI-byte64/Arange-tun/blob/f10849338e2b9182f041c5ea14d4d07557925e66/docs/transports.md),
[AWG runtime](https://github.com/MAHDI-byte64/Arange-tun/blob/f10849338e2b9182f041c5ea14d4d07557925e66/internal/wireguard/wg.go),
[actual limiter](https://github.com/MAHDI-byte64/Arange-tun/blob/f10849338e2b9182f041c5ea14d4d07557925e66/internal/server/transport/limits.go),
[PROXYv2](https://github.com/MAHDI-byte64/Arange-tun/blob/f10849338e2b9182f041c5ea14d4d07557925e66/docs/real-client-ip.md),
[address balancing semantics](https://github.com/MAHDI-byte64/Arange-tun/blob/f10849338e2b9182f041c5ea14d4d07557925e66/docs/failover-load-balancing.md).

## Design assessment

The upstream dashboard uses a dark violet/black background, a configurable warm
accent, translucent cards, consistent spacing, semantic status colours and
reduced-motion handling. Its information hierarchy is useful: Overview,
Control Center, settings accordions, grouped Reverse/Direct choices, short
per-engine setup help and a details dialog for lifecycle actions. Its login
and PWA assets are separate from the dashboard.

The private static preview rendered the actual HTML/CSS at desktop1280, with
all upstream JavaScript disabled and no API, credentials or live metrics.
This confirms the base visual layout only; dynamic charts, wizard behaviour,
PWA operation and mobile runtime were not accepted as tested. The initial
preview connection failure was isolated to the local sandbox endpoint; a fresh
host-accessible static preview rendered. No upstream engine or installer ran.

Recommended TehNet layout: a concise signed-in overview of owned nodes/routes,
plan/remaining budget and recent real measurements; separate pages for servers,
tests, live routes, usage and owner sales. Make each tunnel's details show the
two endpoints, direction, inner/outer address families, encryption, required
protocol/port, last verified receipt and cleanup/recovery status. Put advanced
tuning behind an explicit section. Label catalog-supported, physically-tested
and currently-running states separately. Preserve Persian RTL, English, mobile
layout and TehNet identity; the source's red theme is not our brand requirement.

## Priorities and admission criteria

1. **P0 — preserve accepted coverage:** CI97 and paired SIT/WG follow-up are complete with current groups preserved. Improve
   engine descriptions/6in4 naming and service discovery without inventing IDs.
2. **P1 — useful new coverage:** independently integrate Backhaul and AWG, then
   native4in6. Each needs a pinned build/hash, actual two-node data transfer,
   integrity, directional latency/jitter, sustained throughput, restart recovery
   and owned cleanup. Reject unavailable prerequisites with a clear reason.
3. **P1 — commercial operations:** per-route connection/throughput limits and
   durable usage counters with customer isolation; keep test-unit quotas separate
   from byte quotas. Add presets that change owned application settings first.
   Never silently change global BBR/fq/sysctls on shared hosts.
4. **P2 — operator experience:** staged workflow, per-engine guides, compatible
   reverse TCP PROXYv2, alert delivery/settings and visible rollback/reconcile.
5. **P3 — experiments:** ICMP/xDi and other raw carriers only after scope,
   conflict checks, provider suitability and measured evidence. No arbitrary
   all-by-all composition or unverified claims of faster single downloads.

Our canonical catalog has108 identities (91 profiles +17 compositions), resolving
to21 engine labels. Those are not108 independent engines or108 proven Iran
paths. Upstream README says eight types, while its reviewed chooser/table lists
seven. Its update guide also describes prebuilt releases, while current
`ApplyUpdate` rebuilds source and restarts managed services. Code and actual
receipts must resolve such documentation drift before making comparisons.

Upstream is [AGPL-3.0](https://github.com/MAHDI-byte64/Arange-tun/blob/f10849338e2b9182f041c5ea14d4d07557925e66/LICENSE).
No upstream code, CSS or assets were added to the product in this review.
Use independent TehNet design work and review component licences before any
future code reuse. Website remains static/proxy only; all new data-plane work
belongs on execution/customer nodes. Root inspection/copy prevention is not a
feature that an embedded binary or public repository can guarantee.
