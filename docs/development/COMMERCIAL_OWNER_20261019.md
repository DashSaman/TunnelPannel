# Tehran Network owner console and manual paid access

Owner scope on 2026-10-19: extend the existing account/registry/subscription
flows, preserve every existing live tunnel, and retain the website-only host.
Username login supplements existing email login. The system administrator can
create/edit accounts and customer workspaces, set quotas, define priced plans,
and record a confirmed offline payment to activate or renew a subscription.
The owner selected manual confirmation, without an online payment provider.
Production installs use manual billing mode: unpaid customer workspaces cannot
start new tests/deployments. Reading, support export and owned stop remain
available; expiry does not silently destroy existing tunnels.

The design extends the existing SQLite registry with additive columns/tables.
Passwords use existing scrypt hashing. Managed account edits revoke sessions;
the last enabled system administrator cannot be disabled or demoted. Username
and email remain unique; no customer can choose an owner workspace or access
owner APIs. CSRF, Origin checks, role gates and customer DB isolation remain.

Manual receipts record the administrator's confirmation, not a gateway charge.
Their amount/currency must match a configured enabled plan. A unique request
identity and payment reference serialize confirmation with entitlement update
in one SQLite transaction. Identical retries return the original result;
changed payloads/reused references reject without extending time. Renewals add
to remaining paid time. Each purchase snapshots plan limits; later catalog
edits apply at the next purchase, while explicit customer caps still apply.
No prices or collected payments are invented for the owner's real customers.

The frontend follows the existing native portal/auth API and takes visual
inspiration from the owner's reseller login: clear username sign-in, owner
navigation and user/plan/payment forms. It does not transplant PVNetwork's
framework, database, live settings or account information. Branding is TehNet /
Tehran Network on the existing tehnet.ir origin. API, account/payment database,
queue, builds, measurements and tunnel execution stay off the website host.

Source review: T6 has newer recovery/MTU/ownership behavior; its source is
private and is not imported. A clean shared-carrier MTU clamp is covered by
targeted regression tests. Gold's checksum/atomic instance update behavior is
standalone packaging, not evidence of a new transport improvement. WaterWall-H
upstream matches the panel's existing immutable source; accepted panel-specific
tail-drain/backpressure fixes and historical failing receipts remain intact.

Node privacy has a real boundary: a root operator can inspect runtime files and
memory. New owned generated service units discard process stdout/stderr and
use private umask. Temporary owned test resources are cleaned, while essential
tunnel binaries/configuration remain for operation. No existing node journal,
customer tunnel or unrelated service is purged. Central account/payment/audit
records are retained for correct charging and access control; zero footprint
or source-copy prevention against root is not claimed.

Acceptance sequence: failing tests first, focused and complete regression
suites, isolated admin/customer UI journey, immutable code publication and CI,
fresh drained live baselines/backups, guarded two-node upgrade, owned physical
receipts/canaries and public admin/customer UI verification. Rebuild only the
owned website container and keep its previous release for rollback. Publish
actual installed bilingual evidence after success. Main remains unmerged.
