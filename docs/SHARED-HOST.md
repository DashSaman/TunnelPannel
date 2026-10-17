# Shared hosts: inspection and limits

Use **Portal → Servers → Discover → Existing tunnels, ports and services**.
Discovery saves a timestamped, workspace-scoped report. Reading the saved
report makes no SSH connection. Download includes all rows; tables display
the first 200 rows each. A fresh read-only inspection runs on BOTH endpoints
before the first benchmark resource journal is created. WaterWall-H dependency
preparation also requires a successful inspection.

The collector reads IPv4/IPv6 TCP/UDP listeners, running systemd services,
process **names**, Docker/Podman published port mappings, tunnel link names and
kinds, addresses, all routing tables, routing rules, XFRM policy **count**,
IPv4 forwarding state and available memory. Tunnel links include kernel
fallback devices such as `sit0`; their presence does not prove a live tunnel
or working traffic. A binary or process name alone does not prove a tunnel
works. Existing tunnels remain externally managed; they are never adopted,
stopped, imported or removed by discovery.

The collector does not read command arguments, environments, private
WireGuard configuration or XFRM encryption state. External stderr is omitted
from reports. Missing tools, failed container inspection, malformed reserved
ranges and incomplete scans block new deployment instead of assuming the
host is empty. Ubuntu24.04 emits text for XFRM policies even with `ip -j`;
the collector deliberately counts the plain-text policy listing.

## Allocation and shared daemon protection

The canonical port manager skips observed listener/container bindings, durable
owned reservations, the never-allocate list and operator-reserved ranges.
Every canonical executor port allocation obtains a fresh port snapshot.
IPv4 and IPv6 binds are conservatively reserved by protocol and numerical port,
regardless of local bind address. Existing prefix, interface and policy
identifier allocation also avoids occupied resources.

New IKEv2/VTI/VTI6/L2TP profiles are refused when an IPsec daemon, XFRM policy,
UDP500/4500 listener or reserved IKE port exists, including already-running
panel IPsec resources. This conservative guard preserves the existing daemon;
it does not automatically decide that a foreign configuration is compatible.
L2TP also checks fixed UDP1701. HAJSAMAN profiles refuse to enable global IPv4
forwarding on a host where it is currently disabled.

Reserve future/dynamic application ports on **each applicable endpoint** in
`/etc/tunnelpannel/reserved-ports.json` (root-owned regular JSON file):

```json
{"tcp": [18081, 18082, [22000, 22009]], "udp": [[10000, 20000]]}
```

These are examples, not inferred Tehran Network/MyTel port ranges. Use the
actual application's configured ranges, especially when a service opens
ports on demand. No listener scan can discover every future allocation.

Fresh installation tries loopback8080. If this implicit default is occupied or
reserved, the installer chooses a free canonical TCP port and records it in
the environment and install receipt. An explicit or previously saved port is
preserved and installation refuses a foreign collision. Reruns permit an
existing listener only when **all** TCP LISTEN socket inodes at that number
belong to the systemd API unit's MainPID. Container publications remain
foreign. The port is checked again before replacing the API unit; health
requires the active unit's own listener plus HTTP health, preventing a foreign
`/health` response from masquerading as a successful install.

## Practical capacity and coexistence limits

Measured API memory on a1GiB test node was approximately116MiB at idle with
warm routes. This is a snapshot, not peak capacity. Existing tunnel workers,
source builds, traffic, SQLite retention and queued work add consumption.
For a small controller, budget roughly512MiB–1GiB **additional available RAM**,
1 available CPU core and2–4GiB available disk initially. These are planning
estimates; measure the actual workload. Full matrix preparation and many warm
engines should run on separate nodes with at least2vCPU/2GiB to start, preferably
4GiB or more for heavy builds/concurrency. The earlier1GiB test nodes used swap
and do not establish a safe shared-production minimum.

On the owner-authorized Tehran Network/MyTel host, the initial read-only
snapshot found2 CPUs,3.73GiB RAM with about1.84GiB available, approximately16GiB
free disk,10 running containers,23 running services and31 tunnel-class links
(including kernel fallback links). Ports80/443/9443 and application mappings
were occupied; no resources were changed by this inspection. The recommended
layout is a loopback-only controller alongside those applications and tunnel
execution on separate nodes. This is not a completed workload capacity test
or a guarantee of compatibility with all existing software.

There is no universal “zero interference” promise: custom nftables/NAT rules,
rootless containers under another user, other network namespaces, stopped
services, future dynamic binds, independent controllers and concurrent
administrators can require explicit reservations or manual review. Snapshot
checks cannot eliminate the race before bind. Unknown shared-daemon conflicts
must be resolved before enabling that method. No automatic firewall flush,
foreign-service restart or takeover is part of this feature.

## Recovery before deleting test servers

The standard backup contains encrypted node credentials, workspace data and
hashed access tokens, but **not** the installation encryption key. Keep the
corresponding root-only environment/key separately. A locally rescued copy
of both test-node backups, checksums, separate installation environments and
owner handoff access was encrypted with Windows DPAPI and round-trip verified;
it requires the same Windows account/machine. Private recovery material stays
outside Git. Preserve that machine/account or create a separately protected
portable recovery copy before losing it.

Deleting a tunnel endpoint destroys the live tunnel regardless of saved
panel data. A new controller must not be treated as a replacement for the
actual tunnel servers. Do not run two active controllers against the same
restored queue/ownership state during a cutover. Verify restored credentials,
optional telemetry enrollment, fresh discovery and real receipts on the new
endpoints before relying on them.

## Validation

The isolated candidate passed12 named coexistence checks on EACH of the two
test nodes: IPv4/IPv6 TCP/UDP canaries, tunnel/service detection, listener
avoidance, explicit-port refusal, fresh-default relocation, reserved ranges,
missing-tool refusal, existing-IPsec protection, API socket ownership,
canary/API preservation and scoped cleanup. Existing tunnel link lists and
active group entry hashes, methods, modes and worker PIDs were unchanged.
The entering baseline was two groups with10 healthy members; the historical
7-member source group had already been stopped and replaced by a5-member
failover group before this acceptance. It was not recreated.

Docker NAT-without-socket and failure behavior have unit coverage; the two
canary nodes had no Docker daemon. Actual existing Docker publications were
read on the separate shared host without modifying containers. That read is
not a synthetic Docker NAT failure-injection test. Installed revision, CI and
UI evidence are recorded in the release follow-up rather than inferred here.
