# TehNet tunnel expansion and route traffic control

Owner approved the Arange comparison priorities and requested implementation, two-node acceptance and publication. This extends the existing canonical campaign, owned pair and paid portal flows. No external UI code is copied.

## Engine boundary

Add BACKHAUL_TCP (official Backhaul v0.7.2, digest-verified isolated binary), AMNEZIAWG (official userspace engine at an immutable commit, actual obfuscation parameters and owned UAPI/TUN), IP4IN6 (native ip6tnl/ipip6: IPv4 payload, IPv6 endpoints, next-header 4). No aliases for existing WG, SIT or IP6GRE. Each is independently selectable for measurement and persistent SOCKS TCP egress. Validate both endpoints, port/interface/protocol ownership, management routes, transfer integrity, recovery and cleanup. Do not alter global forwarding, congestion control, default routes or operator binaries. Missing native IPv6 is an explicit incompatibility.

## Traffic semantics

New route gateways enforce an aggregate payload rate in Mbps, cumulative combined upload/download byte allowance, and bounded concurrent connections on the source execution node. Zero means unlimited rate/bytes. The customer may lower limits; owner workspace limits are upper bounds. Durable accounting must survive a worker restart and route reconciliation; concurrent sessions cannot exceed the byte allowance. Debit payload before forwarding; bytes accepted for forwarding can conservatively exceed bytes delivered after a transport failure. SOCKS handshakes and independent health probes are excluded. Corrupt/unavailable ledger fails closed. No automatic reset on policy edits; raising allowance preserves used bytes. Display enforcement capability explicitly for historical workers, and reject limit edits that an old worker cannot enforce. Never restart or rewrite existing groups during this upgrade.

## Product flow

Independently branded TehNet FA/EN RTL/LTR responsive pages: overview, servers, test setup, route controls and usage; short engine requirement guidance and advanced settings collapsed. Surface measured/active/catalog distinctions and IPv4/IPv6/encryption caveats. Owner plans/customer caps include traffic limits, with existing manual payment and entitlement isolation intact. Website host remains static/proxy only.

## Delivery invariants

Preserve all existing group entries/order/modes/pins/configs and worker PIDs. Snapshot fresh before installation; retain separate encrypted installation backups/env/keys on each original host with decrypt/hash proof. Publish immutable source to existing PR2 with tree verification and expected-head lease, CI before rollout, main unmerged. Only owned QA is removed. Real tests use the two authorized nodes; website update touches only its dedicated static container. No payment gateway, SSO, domain change or server deletion.

## Acceptance

Unit/integration tests cover version pins, family/protocol requirements, ownership, actual gateway throttling, exact quota exhaustion across concurrent sessions and restart, invalid policy, tenant caps and old-worker refusal. Real canonical campaign each method/both directions obtains transfer/RTT/jitter/throughput/recovery/cleanup receipts; limitations are retained as failures rather than relabelled. An isolated owned route demonstrates rate/byte limits and restart durability. FA/EN/mobile/public subpath owner/customer screens and fresh existing-route fingerprints complete acceptance.
