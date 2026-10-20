# Managed TCP services over existing route groups

Status: **direction selected by owner; written specification awaiting owner review**.
Date: 2026-10-20. No product code or remote forward has been installed for this feature.

## Intent and selected approach

The owner wants useful capabilities from the separately reviewed TunnelGuard project
in the paid TehNet panel, preserving all current tunnels and keeping computation off
the tehnet.ir website host. The owner explicitly selected **a forward on an existing
customer route group**, rather than a new dedicated tunnel group for every service.

The outcome is a customer-managed TCP service listener with an explicit fixed target,
forwarded through the existing source-node authenticated SOCKS gateway. Users of an
existing Xray/3x-ui inbound can point their client at the new listener without changing
UUID/TLS/Reality settings. This feature does not install or configure Xray itself.

Alternatives considered:

1. Selected: independent listener on the source node, using the existing route's
   authenticated SOCKS endpoint. It reuses health, path selection and accounting,
   and can be applied without restarting that gateway or its member workers.
2. Dedicated route per service: stronger independent path/limit controls but duplicates
   warm transports and consumes more resources; not the selected owner direction.
3. Add listeners inside the existing gateway process: less local relay overhead but
   couples initial deployment to changing/restarting working gateways. Not selected
   because preservation and low interruption take precedence.

## Boundaries

- New subsystem under the canonical API/orchestrator, not the legacy `tfd` daemon.
- TCP only. No SOCKS UDP ASSOCIATE, general UDP VPN, transparent IP routing,
  single-stream bonding, or migration of established TCP sessions.
- One forward references exactly one existing owned route group; it follows that
  group's current failover/balance/order/pin. No independent method subset in v1.
- Initial target is a literal loopback address or an explicitly inventoried address
  on that group's destination node. Arbitrary DNS destinations and cross-workspace
  targets are outside v1. The target is reached by the exit SOCKS gateway, never
  from the website/API host.
- No new payment provider, domain, SSO, automatic x-ui installation, global BBR,
  firewall reset, default-route change, or existing-tunnel reconstruction.
- No source/assets from the unlicensed reference repository. Use our own relay and
  SOCKS implementation with tests. Engine names are not new methods just because a
  port is forwarded through them.

## Data flow and exact accounting

```text
client -> source-node TCP service listener
       -> local authenticated SOCKS5 CONNECT to the existing route gateway
       -> selected healthy warm member -> destination-node explicit TCP target

tehnet.ir portal -> existing authenticated controller -> pinned source-node SSH
                -> owned service installation, observation and reconciliation
```

Only the existing route gateway is the enforcement/debit point. Its durable traffic
ledger, token-bucket shaping, connection ceiling and leased shared customer credits
apply to all forwarded application bytes together with direct SOCKS users of that
route. The new relay must not create a second debit or monthly reservation client.
SOCKS authentication/negotiation is not application payload. A forward may report
diagnostic byte counts, but these are not added to the authoritative customer total.

The local relay connects solely to the already owned loopback SOCKS endpoint with
the route's existing credentials. No direct-destination fallback, cache of a last
healthy external endpoint or foreign upstream credentials. If the route is down,
disabled, out of credit, expired or has no healthy member, new requests fail closed.
On a path failure existing clients reconnect; do not replay bytes already sent.

The relay uses bounded stream buffers, connection limits and connect/idle timeouts,
and handles EOF/half-close/cancellation without leaking sockets. Admission at the
existing gateway still owns route-wide concurrency. A small relay-local ceiling
and admission deadline bound idle/unestablished clients before SOCKS admission.

## Canonical storage and API

Use existing scoped `Job` records with new kind `mesh_service_forward`, existing
`Deployment`/resource ownership records, and encrypted `SecretReference` for runtime
configuration. Do not introduce a second database or plaintext credentials in Job
payloads. New service records include:

- ID, workspace identity, owner account for audit, route ID, source/destination IDs;
- display name, bind address/port, target address/port, source CIDR allowlist;
- explicit public-exposure acknowledgement, config revision/hash, state, operation ID;
- owned deployment/runtime-secret reference, timestamps and redacted error codes.

Proposed namespace `/api/mesh/services`:

- `GET /` and `GET /{id}`: scoped, redacted status and current actual observation;
- `POST /preflight`: validate plan/scope/live route/target/address/ports and return
  an expiring opaque preflight token bound to the configuration and route identity;
- `POST /`: explicit idempotent apply with that token, returning 202/operation ID;
- `PUT /{id}`: revision-checked edit; re-preflight for bind/target/ACL changes;
- `DELETE /{id}`: asynchronous owned-resource stop/cleanup with durable result;
- `POST /{id}/reconcile`: explicit repair of that forward, not its route group.

VIEWER can read; OPERATOR/SUPER_ADMIN can mutate within their workspace; system-owner
cross-customer inspection remains in the owner namespace. Reuse existing secure
session/origin/CSRF/no-store and workspace SQLite scoping. Never accept a caller-supplied
workspace ID or runtime-secret reference to bypass scope. Unknown fields rejected;
ports are strict integers, configuration size and CIDR count are bounded, CIDRs are
normalized, display names are bounded text escaped by the UI.

Creation/edit apply goes through normal paid/new-work admission. An old route's
grandfathered traffic enrollment does not authorize unpaid new forwards. Internal
test access works only for the legitimately entitled isolated QA customer. Bound
active forwards per workspace by its existing `max_active_routes` limit in v1, with
a hard bounded installer ceiling; label the service allowance clearly. Do not silently
change existing customer plans, grant credit, invent payment or reset usage.

## Port and target safety

Bind defaults to `127.0.0.1` on the route's actual source node. UI choices are limited
to source addresses found in fresh inventory, plus explicit wildcard with public
acknowledgement. Public rules require a visible source CIDR policy and a warning
that the destination application's authentication is still required. No anonymous
general-purpose proxy target selection is exposed to clients.

Use existing `HostLease`, fresh host inventory, operator-reserved ranges, host-side
reservations and `RemoteJournal` before mutation. Inspect both TCP listener ownership
and containers/systemd rules; recheck under the host lease immediately before bind.
A requested port is exact: if occupied/foreign/reserved, reject rather than silently
moving the service or stopping another process. Store reservation before dispatch
and retain it until a positive cleanup/ownership result. IPv4/IPv6 wildcard conflicts
must be considered together; reject listeners that could overlap a live gateway.

Reject targets back to this or another panel-owned service listener, controller/API
management ports and known tunnel-control/health endpoints; combine local/static
checks with fresh destination inventory. A loopback x-ui user inbound is permitted
only as the user's explicit destination, not by discovering/publishing management
logins. Never scan arbitrary third-party addresses. UI must distinguish source
loopback from loopback on the destination node.

## Runtime and lifecycle

New orchestrator module owns preflight, idempotence, installation and reconciliation.
A small new source-node Python relay imports or receives the verified first-party
SOCKS helper; the installer packages the helper explicitly. Runtime files live under
an ID-scoped `/var/lib/tunnelpannel` directory, with root-owned private config and
systemd service resources journaled before creation. Do not replace any old gateway
script, reuse its service name, alter its config, rotate its credentials or restart it.

Run the relay with least privilege under a dedicated service account/group. Obtain
private config through an ID-scoped controlled file/directory or systemd credentials;
it must not read unrelated customer configs. Use unprivileged listener ports in v1.
No shell-built customer strings, arbitrary commands or arbitrary writable paths.

States: `PREFLIGHTED -> APPLYING -> ACTIVE`, or `FAILED` with retained ownership;
`ACTIVE -> UPDATING -> ACTIVE/DEGRADED`; `STOPPING -> STOPPED` only after verified
owned cleanup. Durable operation ownership and revision checks reject simultaneous
edits, duplicate apply, route-stop races and stale preflight tokens. Startup observes
existing services before repair; it must not blindly replay unfinished installs.

Route stop/expiry: stop admitting new forwards immediately and fence existing forward
listeners as part of the owning route's normal cleanup. Preserve service metadata and
usage history. Do not stop any other route or relax subscription guards. If old route
cleanup lacks a dependency hook, add one that is inert for routes without forwards;
regression-test legacy stop behavior and exact resource ownership.

Editing bind/target requires an explicit forward-only operation. For a new port,
validate and reserve the replacement before dropping the old owned listener; retain
the old config if preparation fails. For the same port, short forward-only downtime
is allowed and displayed; bound it with actual measurements, no zero-outage claim.
Always preserve parent-route/member configs/PIDs and cumulative accounting.

Observe actual listener PID/config identity and a bounded destination receipt through
the service. `ACTIVE`/saved settings alone are not an end-to-end success. Destination
probes must be size/rate bounded and distinguished from billable customer traffic;
v1 should reuse an owned QA endpoint for acceptance rather than promise application
health for arbitrary TLS/Xray targets. For a real customer target display reachability
separately from application authentication; do not synthesize an Xray success result.

## UI and operational documents

Add a branded FA/EN service section with route chooser, explicit source/exit labels,
bind/target ports, CIDRs, loopback/public indicator, preflight reasons and apply/status.
Cards/table support add/edit/disable/delete with operation results and clear ownership.
Provide a preset for an **existing user inbound**, keeping UUID/SNI/keys outside this
form. Explain that source address/port changes while existing client transport settings
remain the destination service's responsibility. Never request destination passwords
or extract x-ui databases.

Show inherited route mode/rate/concurrency and shared remaining customer quota with
links to the current route and owner quota views; no misleading per-forward independent
allowance. Accessibility: visible focus, labelled inputs, RTL/LTR port/address handling,
mobile layout and reduced-motion behavior matching the existing console. Save actual
FA/EN desktop/mobile screenshots, not fixture illustrations, for final acceptance.

## Test and rollout acceptance

1. Portable red/green tests: scoped access/CSRF, strict input and port collision,
   stale token/revision/idempotence, concurrent admission, ownership-safe rollback,
   route-stop/expiry dependencies, no private credentials in public responses.
2. Real loopback sockets: relay preserves bytes/half-close, bounded idle and active
   clients, upstream authentication failure, connect failure and no direct fallback.
   Reuse existing gateway traffic tests to prove one debit, route shaping/concurrency,
   pooled quota across direct SOCKS and two forwards, restart durability and exact cap.
3. Fresh full required CI for the immutable functional SHA and Linux lifecycle/package
   inclusion before any deployment. No foreign installer or unverified engine binary.
4. Read both execution APIs for active work first. Never cancel the user's campaign
   or restart during active work. Capture all current route configurations, worker PIDs,
   member identities/interfaces and service ownership, including both retained QA routes.
5. Fresh independent encrypted resident backups and separate install keys/env on each
   node before upgrade; review/upload the current helper and verify SHA, never replay
   earlier accepted destructive QA helpers. Site backup/preservation before own-container
   replacement; do not change WordPress, other containers or host nginx/proxy.
6. Use only new expendable forward resources and payload origins on the existing
   isolated 100 GiB customer's two execution-node routes. Keep that period and actual
   usage; if a temporary small cap is needed, retain usage and restore 100 GiB in the
   SAME period after exact exhaustion. Do not mutate the original customer's quota.
7. Verify actual bidirectional payload receipts through both forwards, inherited routing
   and accounting, forward-only restart/repair, conflict refusal and tenant isolation.
   Exercise path failure only in a newly owned QA group or simulated local gateway;
   do not deliberately fail either retained/main group just to test this feature.
8. After tests, stop/remove only new owned forward/origin resources unless the owner
   asks to retain them. Keep old routes and their credentials unchanged. Verify all
   original configs/PIDs/interfaces and actual short receipts/canaries again; preserve
   audit/history, refresh encrypted rescue and save redacted proof plus real screenshots.
9. Publish bilingual docs/site/repository through the existing PR2 branch, exact tree
   and expected-head lease; wait successful final CI, leave main unmerged and heartbeat
   paused. Distinguish local tests, physical acceptance and unsupported capabilities.

## Review check

Inline review found the central accounting risk: a second raw relay must use the
existing authenticated gateway, not bypass or duplicate its debit. Addressed above.
Existing groups must not be fault-injected/restarted; path-failure tests therefore
require separate QA resources or a local isolated gateway. Public port exposure is
explicit and default loopback. No implementation placeholders, invented receipts or
claims of deployed forwarding remain. The next gate is owner review of this written
specification; only then create the detailed implementation plan and choose execution.
