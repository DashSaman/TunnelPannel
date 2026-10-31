# TunnelGuard comparison — 2026-10-20

[فارسی](TUNNELGUARD-COMPARISON-20261020-fa.md)

## Scope and provenance

The owner supplied [this ParsDigital video](https://www.youtube.com/watch?v=0cT4iHGzk30)
and a text file identifying [Mehdi682007/TunnelGuard](https://github.com/Mehdi682007/TunnelGuard).
This is a read-only source/history and video-transcript review, **not** an installation
or a new two-server transport acceptance. Commands inside the attachment were not run.
Existing original and retained 100 GiB customer routes were not changed for this review.

Reference head: `f1176f8b7a4d0d75ace30318102ec1ba401269a8`.
Our reviewed local head: `6c4692d3c9f0aef5d908e3a31ce284764c7dd45a`, whose exact
tree `3a097fcae95226a50b0da6d85e885815c9701870` was published as
`65a16817266c506c611702a83d8e15305374da6c`. Installed runtime remains
`83335745ad3e2a75a8c13c43026801c18729c2bc`.

The reference's reachable root commit is
[`c333798`](https://github.com/Mehdi682007/TunnelGuard/commit/c333798f56fb631a6f4fe09cfdfa744a8d0f2ec9),
dated October 5. Our tracked `tunnelguard/` package first appears in the October 14
import commit `e73aa88`. A shared package name and imported commit dates do not
establish authorship or copying direction. Our package uses a `tfd/` daemon,
database, engine adapters and API; the reference uses a different stdlib asyncio
guard, paired manager and node scripts. The production mesh gateway is another
explicitly separate component; legacy-daemon features must not be advertised as
current mesh-console features without checking that path.

[Machine-readable comparison](evidence/commercial/tunnelguard-comparison-20261020.json):
333 unique source-file SHA256 hashes in our tracked Python/JS/HTML/CSS/shell files
of at least 200 bytes versus 43 in the reference; **zero exact file matches**.
1,348 unique complete Python function-body AST hashes versus 215, considering
functions with at least 80 AST nodes and removing docstrings/locations;
**zero exact body matches**, no Python parse errors. This is not rename-resistant
or fragment-level plagiarism detection and cannot prove independent authorship.
We found no evidence sufficient to claim that the reference copied this panel.

No root LICENSE/COPYING file was found at the reviewed reference head; GitHub's
license field was null. No source or assets were copied from it. Any new feature
should be implemented independently and use separately verified upstream engines.

## Actual feature differences

| Feature | Reference evidence | Our current product | Result |
|---|---|---|---|
| Per-service TCP port forwarding | [FORWARDING.md](https://github.com/Mehdi682007/TunnelGuard/blob/f1176f8b7a4d0d75ace30318102ec1ba401269a8/FORWARDING.md), `tunnelguard.py:dial/tcp_forward`, manager forward operations | The production gateway exposes authenticated SOCKS5 CONNECT; no equivalent canonical service-forward CRUD/UI was found | **Confirmed product gap**: a fixed inbound TCP port to an explicit destination through selected healthy routes |
| Forward route selection | Explicit route restrictions or following managed healthy tunnels; add/edit/remove live forwards | Our existing route order/pin and failover/balance apply to stable SOCKS gateways | Add per-forward route binding without conflating it with the existing route group |
| Forward existing 3x-ui inbound | Video approximately 12:32–13:54 and 18:50–19:21; destination service must already exist | No dedicated service wizard | Useful convenience over generic TCP forwarding; never install/edit x-ui or publish its management login implicitly |
| SSH, Chisel, Rathole, WireGuard, Paqet, IPIP, GRE, VXLAN | Nine identities in [`tunnel_methods.py`](https://github.com/Mehdi682007/TunnelGuard/blob/f1176f8b7a4d0d75ace30318102ec1ba401269a8/tunnel_methods.py) | Already represented in our canonical engine catalog | Do not duplicate engines or count forward rules as new tunnel methods |
| Reverse WireGuard/Paqet; Spoof carrier plus encrypted overlay | Typed reference plans and source implementation | WireGuard/Paqet manifests currently declare reverse=false; no Spoof manifest | **Candidate gaps**, requiring pinned upstream/provenance, coexistence design and fresh paired receipts before availability claims |
| Automatic/manual failover and stabilization | Reference quality/priority policies, consecutive rounds, cooldown and quarantine | Production gateway has verified nonce health, failure/recovery thresholds, hold-down, manual order/pin; legacy `tfd` also has score hysteresis/flap lock | Overlap; do not replace the working gateway with the reference's daemon |
| Balancing and customer accounting | No equivalent pooled commercial allowance was found in the reviewed source surface | Production gateway balances new connections and enforces durable route caps plus shared customer credits; owner user/plan/manual-payment administration | Retain our implementation; forwards must use the same accounting rather than bypass it |
| FA/EN UI and account settings | Reference dashboard/account pages | Existing branded FA/EN owner/customer console | Overlap; adapt interaction ideas, no template/code import |

Reference `applied` indicates configuration applied, not an end-to-end Xray receipt.
Its TCP forwards cannot migrate an established connection or provide application UDP.
The video itself shows some unsuccessful installations/tests; it does not demonstrate
that all listed direct/reverse combinations work. Our two datacenter nodes also do not
establish Iran-path performance or filtering resistance.

## Proposed next implementation: managed TCP services

This is an **architectural extension awaiting design review**, not a shipped feature.
The owner selected forwarding over an existing route group; the
[written specification](superpowers/specs/2026-10-20-managed-tcp-services.md)
is now ready for owner review before implementation planning.
Add a customer-owned service-forward object with source node, bind address/port,
explicit destination node/address/port and an existing owned route group. Offer
“existing 3x-ui inbound” as a labelled preset, not a separate tunnel protocol.
All forwarding and probing run on execution nodes; tehnet.ir remains the light portal.

Reuse the canonical host inventory, reservation/lease and ownership ledger, RBAC,
subscription admission, rate/concurrency controls and shared customer credit protocol.
Port conflicts fail closed; loopback is the default, public exposure is explicit,
and source ACLs are visible. Only selected routes may reach the specified target;
never fall back to a direct Internet connection. A local SOCKS client handshake is
not customer payload, while forwarded application bytes must be charged once.
Do not create a second unmetered relay or debit the same bytes twice.

Apply changes to an individual new forward without restarting original route groups.
Record preview/ownership and immutable configuration versions; preserve source bind,
target and accounting on reconciliation. Keep secrets out of UI/log exports. Deleting
a forward removes only resources proven to belong to it. Existing routes remain intact.

Acceptance must include tenant/CSRF checks, loop/conflicting-port rejection, actual
TCP bytes to an owned destination through two QA paths, path failure and fail-closed
behavior, cumulative accounting across concurrent forwards, exact small-cap exhaustion,
restart persistence and snapshots proving original configs/PIDs/interfaces unchanged.
Only new QA resources may be stopped or cleaned. No present report claims these new
forwarding tests or the reverse/Spoof candidates have already passed.

See [the completed isolated 100 GiB acceptance](QA-100GIB.md) for the previous task;
it is separate evidence and must not be relabelled as forwarding acceptance.
